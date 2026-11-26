//! SQLite persistence: one writer thread behind a bounded queue, group commit,
//! an append-only event log, a published in-memory snapshot for readers and an
//! index of evidence files that live on disk under their content hash.

use std::fs::{self, File};
use std::io::Write;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, PoisonError, RwLock};
use std::thread::JoinHandle;

use ledger_core::{CoreError, Event, EvidenceId, EvidenceKind, HttpExchange, Ledger};
use rusqlite::{Connection, OpenFlags, params};

/// Bumped by every schema change; each bump needs a forward migration and a
/// ledger file of the old version under `tests/fixtures`.
const SCHEMA_VERSION: i64 = 2;

/// Jobs waiting for the writer. A full queue blocks the producer.
const QUEUE: usize = 1024;

/// How long the writer waits for one more job before it commits what it has.
const GATHER: std::time::Duration = std::time::Duration::from_micros(100);

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    Core(#[from] CoreError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("transaction rolled back: {0}")]
    Aborted(String),
    #[error("ledger file has schema version {0}, this build reads version {SCHEMA_VERSION}")]
    Schema(i64),
    #[error("evidence {0} no longer matches its hash")]
    Corrupt(EvidenceId),
    #[error("writer thread is gone")]
    Closed,
}

// `kind` is generated from the payload so the two can never disagree.
const SCHEMA: &str = "
CREATE TABLE events (
    seq         INTEGER PRIMARY KEY,
    kind        TEXT GENERATED ALWAYS AS (payload ->> '$.event') VIRTUAL,
    payload     TEXT NOT NULL CHECK (json_valid(payload)),
    recorded_at TEXT NOT NULL
);
CREATE TABLE evidence (
    hash      TEXT PRIMARY KEY,
    path      TEXT NOT NULL,
    size      INTEGER NOT NULL,
    added_seq INTEGER NOT NULL,
    method    TEXT,
    url       TEXT,
    status    INTEGER
) WITHOUT ROWID;
CREATE TRIGGER events_no_update BEFORE UPDATE ON events
    BEGIN SELECT RAISE(ABORT, 'events are append-only'); END;
CREATE TRIGGER events_no_delete BEFORE DELETE ON events
    BEGIN SELECT RAISE(ABORT, 'events are append-only'); END;
PRAGMA user_version = 2;
";

/// Forward-only migrations: entry `n` takes a file from schema version `n + 1` to `n + 2`.
/// Version 2 indexes HTTP evidence by its request line; rows from version 1 stay unindexed.
const MIGRATIONS: [&str; 1] = ["
ALTER TABLE evidence ADD COLUMN method TEXT;
ALTER TABLE evidence ADD COLUMN url TEXT;
ALTER TABLE evidence ADD COLUMN status INTEGER;
PRAGMA user_version = 2;
"];

/// The ledger as of event `seq`. Never changes once published.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Snapshot {
    pub seq: i64,
    pub ledger: Ledger,
}

/// Evidence bytes, memory-mapped and checked against their hash.
#[derive(Debug)]
pub struct Evidence(memmap2::Mmap);

impl Deref for Evidence {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

type Job = (Work, flume::Sender<Result<i64, StoreError>>);

/// What a stored HTTP exchange is a capture of: the index key for finding evidence by endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestLine {
    pub method: String,
    pub url: String,
    /// `None` if the request was never answered.
    pub status: Option<u16>,
}

enum Work {
    Events(Vec<Event>),
    /// Hash, kind, size and request line of a file already in the evidence directory.
    Evidence(EvidenceId, EvidenceKind, i64, Option<RequestLine>),
}

pub struct Store {
    path: PathBuf,
    evidence_dir: PathBuf,
    published: Arc<RwLock<Arc<Snapshot>>>,
    tx: Option<flume::Sender<Job>>,
    writer: Option<JoinHandle<()>>,
}

impl Store {
    /// Opens or creates a ledger file in WAL mode, replays its events through
    /// ledger-core and starts the writer thread. Evidence files go in the
    /// sibling directory `<path>.evidence`.
    ///
    /// # Errors
    /// The file cannot be opened, has another schema version, or its events no longer replay.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        Self::open_with(path.as_ref(), "FULL")
    }

    /// [`Store::open`] for an import that can be redone: commits are not synced,
    /// so a power cut can lose the most recent ones.
    ///
    /// # Errors
    /// See [`Store::open`].
    pub fn open_bulk(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        Self::open_with(path.as_ref(), "NORMAL")
    }

    fn open_with(path: &Path, synchronous: &str) -> Result<Self, StoreError> {
        let conn = Connection::open(path)?;
        conn.execute_batch(&format!(
            "PRAGMA journal_mode = WAL; PRAGMA synchronous = {synchronous};"
        ))?;
        let objects = "SELECT count(*) FROM sqlite_master";
        if conn.query_one(objects, [], |r| r.get::<_, i64>(0))? == 0 {
            conn.execute_batch(SCHEMA)?;
        }
        // Each migration is one transaction, so a crash leaves a whole version either way.
        let version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
        let done = usize::try_from(version)
            .unwrap_or(usize::MAX)
            .saturating_sub(1);
        for migration in MIGRATIONS.iter().skip(done).filter(|_| version >= 1) {
            conn.execute_batch(&format!("BEGIN;{migration}COMMIT;"))?;
        }
        let live = Arc::new(load(&conn)?);
        let evidence_dir = sidecar(path, ".evidence");
        fs::create_dir_all(&evidence_dir)?;
        let published = Arc::new(RwLock::new(Arc::clone(&live)));
        let (tx, rx) = flume::bounded(QUEUE);
        let writer = Writer {
            conn,
            spare: Arc::new(Snapshot::clone(&live)),
            live,
            lag: Vec::new(),
            published: Arc::clone(&published),
        };
        let writer = std::thread::Builder::new()
            .name("ledger-writer".into())
            .spawn(move || writer.run(&rx))?;
        Ok(Self {
            path: path.to_path_buf(),
            evidence_dir,
            published,
            tx: Some(tx),
            writer: Some(writer),
        })
    }

    fn call(&self, work: Work) -> Result<i64, StoreError> {
        let (reply, rx) = flume::bounded(1);
        self.tx
            .as_ref()
            .ok_or(StoreError::Closed)?
            .send((work, reply))
            .map_err(|_| StoreError::Closed)?;
        rx.recv().map_err(|_| StoreError::Closed)?
    }

    /// Appends an event if it applies to the current state, and returns once it
    /// is durable. Proposing a claim that is already in the ledger is a no-op.
    /// Returns a sequence number at which [`Store::snapshot`] includes the event.
    ///
    /// # Errors
    /// The event is invalid for the current ledger, or the write fails.
    pub fn append(&self, event: Event) -> Result<i64, StoreError> {
        self.append_batch(vec![event])
    }

    /// [`Store::append`] for several events, all or nothing: readers see every
    /// one of them or none.
    ///
    /// # Errors
    /// An event is invalid for the ledger as left by the ones before it, or the write fails.
    pub fn append_batch(&self, events: Vec<Event>) -> Result<i64, StoreError> {
        self.call(Work::Events(events))
    }

    /// The latest committed state. Cheap, never blocks on the writer, and never
    /// shows part of a batch.
    #[must_use]
    pub fn snapshot(&self) -> Arc<Snapshot> {
        Arc::clone(
            &self
                .published
                .read()
                .unwrap_or_else(PoisonError::into_inner),
        )
    }

    /// Stores bytes as a file named by their content hash, indexes it and records
    /// an `EvidenceAdded` event. Does nothing if the hash is already indexed.
    /// Hashing and the file write happen on the calling thread, not the writer.
    ///
    /// # Errors
    /// The file or the index cannot be written.
    pub fn add_evidence(&self, kind: EvidenceKind, bytes: &[u8]) -> Result<EvidenceId, StoreError> {
        static TEMP: AtomicU64 = AtomicU64::new(0);
        let id = EvidenceId::of(bytes);
        let file = self.evidence_dir.join(id.as_str());
        if !file.exists() {
            // Own temporary name, sync, rename: the hash-named file is whole or absent, even
            // after a crash, and concurrent adds of the same bytes cannot tear each other.
            let n = TEMP.fetch_add(1, Ordering::Relaxed);
            let tmp = file.with_extension(format!("{}-{n}.tmp", std::process::id()));
            let mut f = File::create(&tmp)?;
            f.write_all(bytes)?;
            f.sync_all()?;
            fs::rename(&tmp, &file)?;
        }
        let size = i64::try_from(bytes.len()).unwrap_or(i64::MAX);
        // An exchange that does not parse is still stored; its checker will say what is wrong.
        let line = (kind == EvidenceKind::HttpExchange)
            .then(|| serde_json::from_slice::<HttpExchange>(bytes).ok())
            .flatten()
            .map(|exchange| RequestLine {
                method: exchange.request.method,
                url: exchange.request.url,
                status: exchange.response.map(|r| r.status),
            });
        self.call(Work::Evidence(id.clone(), kind, size, line))?;
        Ok(id)
    }

    /// Up to `limit` indexed HTTP captures whose id sorts after `after`, in id order,
    /// read on a connection of its own. Callers page by passing the last id back.
    ///
    /// # Errors
    /// The read connection or the query fails.
    pub fn http_evidence(
        &self,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Vec<(String, RequestLine)>, StoreError> {
        let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let conn = Connection::open_with_flags(&self.path, flags)?;
        let mut stmt = conn.prepare(
            "SELECT hash, method, url, status FROM evidence
             WHERE method IS NOT NULL AND hash > ?1 ORDER BY hash LIMIT ?2",
        )?;
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let rows = stmt.query_map(params![after.unwrap_or(""), limit], |r| {
            let line = RequestLine {
                method: r.get(1)?,
                url: r.get(2)?,
                status: r.get(3)?,
            };
            Ok((r.get(0)?, line))
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// [`Store::add_evidence`] for a saved capture on disk, mapped rather than read into memory.
    ///
    /// # Errors
    /// The file cannot be read or the write fails.
    pub fn add_evidence_file(
        &self,
        kind: EvidenceKind,
        path: impl AsRef<Path>,
    ) -> Result<EvidenceId, StoreError> {
        // SAFETY: a capture handed over as evidence is a finished file. Another process
        // truncating it while we hash and copy it could fault the read.
        let map = unsafe { memmap2::Mmap::map(&File::open(path)?)? };
        self.add_evidence(kind, &map)
    }

    /// Evidence bytes by hash, verified against that hash. `None` if there is no such file.
    ///
    /// # Errors
    /// The file cannot be mapped, or its content no longer matches its name.
    pub fn evidence(&self, id: &EvidenceId) -> Result<Option<Evidence>, StoreError> {
        read_evidence(&self.evidence_dir, id)
    }
}

/// [`Store::evidence`] for a ledger file that is not open here, such as one the
/// CLI only reads.
///
/// # Errors
/// The file cannot be mapped, or its content no longer matches its name.
pub fn evidence_at(
    ledger: impl AsRef<Path>,
    id: &EvidenceId,
) -> Result<Option<Evidence>, StoreError> {
    read_evidence(&sidecar(ledger.as_ref(), ".evidence"), id)
}

fn read_evidence(dir: &Path, id: &EvidenceId) -> Result<Option<Evidence>, StoreError> {
    // Ids arrive from agents; only a hex name can be one of our files.
    if !id.as_str().bytes().all(|b| b.is_ascii_hexdigit()) {
        return Ok(None);
    }
    let file = match File::open(dir.join(id.as_str())) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    // SAFETY: evidence files are written once under a temporary name, renamed into
    // place and never modified afterwards.
    let map = unsafe { memmap2::Mmap::map(&file)? };
    if EvidenceId::of(&map) != *id {
        return Err(StoreError::Corrupt(id.clone()));
    }
    Ok(Some(Evidence(map)))
}

impl Drop for Store {
    fn drop(&mut self) {
        self.tx = None;
        if let Some(w) = self.writer.take()
            && w.join().is_err()
        {
            tracing::error!("ledger writer panicked");
        }
    }
}

/// `<db><suffix>`, next to the ledger file like SQLite's own `-wal`.
fn sidecar(db: &Path, suffix: &str) -> PathBuf {
    let mut p = db.as_os_str().to_owned();
    p.push(suffix);
    p.into()
}

/// Rebuilds the state from an existing file on a read-only connection, without starting a writer.
///
/// # Errors
/// The file is missing, has another schema version, or an event fails to decode or apply.
pub fn replay(path: impl AsRef<Path>) -> Result<Snapshot, StoreError> {
    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    load(&Connection::open_with_flags(path, flags)?)
}

/// Folds the log through the kernel. One statement, so one consistent snapshot;
/// `Event::decode` re-admits every stored claim.
fn load(conn: &Connection) -> Result<Snapshot, StoreError> {
    let version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
    // Every version so far has the same events table, so an older file replays as it is.
    if !(1..=SCHEMA_VERSION).contains(&version) {
        return Err(StoreError::Schema(version));
    }
    let mut snapshot = Snapshot::default();
    let mut stmt = conn.prepare("SELECT seq, payload FROM events ORDER BY seq")?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let payload = row.get_ref(1)?.as_str().map_err(rusqlite::Error::from)?;
        snapshot.ledger.apply(Event::decode(payload)?)?;
        snapshot.seq = row.get(0)?;
    }
    Ok(snapshot)
}

/// Owns the write connection and both copies of the state. Each batch is applied
/// to the unpublished copy (which validates it), committed, and only then
/// published and acknowledged; the copies then swap roles.
struct Writer {
    conn: Connection,
    /// What readers see. Always equal to the committed log.
    live: Arc<Snapshot>,
    /// The snapshot published before `live`; behind it by the events in `lag`.
    spare: Arc<Snapshot>,
    lag: Vec<Event>,
    published: Arc<RwLock<Arc<Snapshot>>>,
}

impl Writer {
    fn run(mut self, rx: &flume::Receiver<Job>) {
        while let Ok(first) = rx.recv() {
            // Group commit: everything queued shares one transaction. Producers woken by the
            // last commit arrive a moment apart; without the short wait the first of them
            // would get a disk flush to itself and the rest would queue behind it.
            let mut jobs = vec![first];
            while jobs.len() < QUEUE
                && let Ok(job) = rx.recv_timeout(GATHER)
            {
                jobs.push(job);
            }
            let (works, replies): (Vec<_>, Vec<_>) = jobs.into_iter().unzip();
            let results = match self.write_batch(works) {
                Ok(results) => results,
                Err(e) => {
                    tracing::error!(error = %e, "batch rolled back");
                    // The spare may hold events that never reached disk; rebuild it from what did.
                    self.spare = Arc::new(Snapshot::clone(&self.live));
                    self.lag.clear();
                    let msg = e.to_string();
                    (replies
                        .iter()
                        .map(|_| Err(StoreError::Aborted(msg.clone()))))
                    .collect()
                }
            };
            for (reply, result) in replies.into_iter().zip(results) {
                drop(reply.send(result)); // a dropped receiver only means the caller gave up waiting
            }
        }
        // Every sender is gone and the queue is drained: fold the WAL back into the file.
        if let Err(e) = self.conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)") {
            tracing::warn!(error = %e, "checkpoint on shutdown failed");
        }
        tracing::debug!("ledger writer stopped");
    }

    fn write_batch(
        &mut self,
        works: Vec<Work>,
    ) -> Result<Vec<Result<i64, StoreError>>, StoreError> {
        // Copies the state only if a reader still holds the snapshot from two batches ago.
        let next = Arc::make_mut(&mut self.spare);
        for event in self.lag.drain(..) {
            next.ledger.apply(event)?;
        }
        next.seq = self.live.seq;
        let tx = self.conn.transaction()?;
        let mut accepted = Vec::new();
        let mut results = Vec::with_capacity(works.len());
        for work in works {
            results.push(stage(&tx, &self.live, next, work, &mut accepted)?);
        }
        tx.commit()?;
        let seq = next.seq;
        std::mem::swap(&mut self.live, &mut self.spare);
        *(self.published.write()).unwrap_or_else(PoisonError::into_inner) = Arc::clone(&self.live);
        self.lag = accepted;
        Ok(results.into_iter().map(|r| r.map(|()| seq)).collect())
    }
}

/// Applies one piece of work to `next` and stages its rows in the transaction.
/// Outer error: the transaction must roll back. Inner error: the kernel refused
/// the work and it left no trace in `next`, `accepted` or the transaction.
fn stage(
    tx: &Connection,
    live: &Snapshot,
    next: &mut Snapshot,
    work: Work,
    accepted: &mut Vec<Event>,
) -> Result<Result<(), StoreError>, StoreError> {
    let (events, evidence) = match work {
        Work::Events(events) => (events, None),
        Work::Evidence(id, kind, size, about) => {
            let indexed = "SELECT 1 FROM evidence WHERE hash = ?1";
            if tx.prepare_cached(indexed)?.exists([id.as_str()])? {
                return Ok(Ok(()));
            }
            let event = Event::EvidenceAdded {
                id: id.clone(),
                kind,
            };
            (vec![event], Some((id, size, about)))
        }
    };
    let (start, seq) = (accepted.len(), next.seq);
    for event in events {
        match next.ledger.apply(event.clone()) {
            Ok(()) => accepted.push(event),
            Err(CoreError::DuplicateClaim(_)) => {} // proposing a claim twice is a no-op
            Err(e) => {
                if accepted.len() > start {
                    // Undo this work's earlier events: committed state plus the batch so far.
                    accepted.truncate(start);
                    *next = live.clone();
                    for event in accepted.iter().cloned() {
                        next.ledger.apply(event)?;
                    }
                    next.seq = seq;
                }
                return Ok(Err(e.into()));
            }
        }
    }
    // The timestamp lives only in this column; it never enters a hash.
    let at = jiff::Timestamp::now().to_string();
    let mut insert =
        tx.prepare_cached("INSERT INTO events (payload, recorded_at) VALUES (?1, ?2)")?;
    for event in &accepted[start..] {
        insert.execute(params![event.encode()?, at])?;
        next.seq = tx.last_insert_rowid();
    }
    if let Some((id, size, about)) = evidence {
        // `path` is relative to the evidence directory, so the ledger can be moved.
        let index = "INSERT INTO evidence (hash, path, size, added_seq, method, url, status)
                     VALUES (?1, ?1, ?2, ?3, ?4, ?5, ?6)";
        let (method, url, status) = match about {
            Some(request) => (Some(request.method), Some(request.url), request.status),
            None => (None, None, None),
        };
        (tx.prepare_cached(index)?).execute(params![
            id.as_str(),
            size,
            next.seq,
            method,
            url,
            status
        ])?;
    }
    Ok(Ok(()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ledger_core::{
        Claim, ClaimId, ClaimKind, Counterexample, MemoryLayout, Status, Verdict, admit,
    };
    use proptest::prelude::*;
    use std::collections::BTreeMap;
    use std::num::NonZeroU64;
    use std::sync::atomic::AtomicBool;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn claim(n: u64, premise: Option<u64>) -> Result<Claim, CoreError> {
        Ok(Claim {
            kind: ClaimKind::MemoryLayout(MemoryLayout {
                type_name: "T".into(),
                size: n + 1,
                fields: vec![],
            }),
            premises: match premise {
                Some(p) => [claim(p, None)?.id()?].into(),
                None => [].into(),
            },
        })
    }

    fn id(n: u64, premise: Option<u64>) -> Result<ClaimId, CoreError> {
        claim(n, premise)?.id()
    }

    fn proposed(n: u64, premise: Option<u64>) -> Result<Event, CoreError> {
        Ok(Event::Proposed {
            claim: admit(claim(n, premise)?)?,
        })
    }

    fn checked(claim: ClaimId, verdict: Verdict) -> Event {
        Event::Checked {
            claim,
            evidence: [].into(),
            verdict,
            checker: None,
        }
    }

    fn held() -> Verdict {
        Verdict::Held {
            runs: NonZeroU64::MIN,
        }
    }

    fn inconclusive() -> Verdict {
        Verdict::Inconclusive {
            reason: "no capture".into(),
        }
    }

    /// One claim and nine verdicts on it: ten events that belong together.
    fn batch(n: u64) -> Result<Vec<Event>, CoreError> {
        let mut events = vec![proposed(n, None)?];
        for _ in 0..9 {
            events.push(checked(id(n, None)?, inconclusive()));
        }
        Ok(events)
    }

    fn statuses(ledger: &Ledger) -> BTreeMap<ClaimId, Status> {
        ledger.statuses().map(|(id, s)| (id.clone(), s)).collect()
    }

    /// Seven claims covering all six statuses, and one piece of evidence.
    fn file_one_of_each(store: &Store) -> TestResult {
        let ev = store.add_evidence(EvidenceKind::MemorySnapshot, &[7; 16])?;
        let refuted = Verdict::Refuted {
            counterexample: Counterexample {
                evidence: ev,
                detail: "size is 24".into(),
            },
        };
        // 0 held, 1 refuted, 2 inconclusive, 3 unchecked, 4 retracted, 5 held on 0, 6 blocked by 1.
        for n in 0..5 {
            store.append(proposed(n, None)?)?;
        }
        store.append(proposed(5, Some(0))?)?;
        store.append(proposed(6, Some(1))?)?;
        store.append(checked(id(0, None)?, held()))?;
        store.append(checked(id(1, None)?, refuted))?;
        store.append(checked(id(2, None)?, inconclusive()))?;
        store.append(checked(id(5, Some(0))?, held()))?;
        store.append(Event::Retracted {
            claim: id(4, None)?,
            reason: "wrong build".into(),
        })?;
        Ok(())
    }

    fn one_of_each() -> Result<BTreeMap<ClaimId, Status>, CoreError> {
        Ok(BTreeMap::from([
            (id(0, None)?, Status::Held),
            (id(1, None)?, Status::Refuted),
            (id(2, None)?, Status::Inconclusive),
            (id(3, None)?, Status::Unchecked),
            (id(4, None)?, Status::Retracted),
            (id(5, Some(0))?, Status::Held),
            (id(6, Some(1))?, Status::Blocked),
        ]))
    }

    #[test]
    fn statuses_and_evidence_survive_reopen() -> TestResult {
        let dir = tempfile::tempdir()?;
        let db = dir.path().join("l.db");
        let seq = {
            let store = Store::open(&db)?;
            file_one_of_each(&store)?;
            assert_eq!(statuses(&store.snapshot().ledger), one_of_each()?);
            store.snapshot().seq
        };
        assert_eq!(seq, 13);
        // Shutdown checkpointed: nothing is left waiting in the WAL.
        let wal = fs::metadata(sidecar(&db, "-wal")).map_or(0, |m| m.len());
        assert_eq!(wal, 0);

        let store = Store::open(&db)?;
        assert_eq!(statuses(&store.snapshot().ledger), one_of_each()?);
        assert_eq!(*store.snapshot(), replay(&db)?);
        assert_eq!(store.snapshot().seq, seq);
        let bytes = store.evidence(&EvidenceId::of(&[7; 16]))?;
        assert_eq!(bytes.as_deref(), Some(&[7; 16][..]));
        Ok(())
    }

    #[test]
    fn ledger_files_of_schema_version_1_still_open() -> TestResult {
        // Written once by `file_one_of_each` and never regenerated.
        let fixture = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/v1.db");
        let dir = tempfile::tempdir()?;
        let db = dir.path().join("l.db");
        fs::copy(fixture, &db)?;
        // A file of an older version replays read-only as it is, and is migrated on open.
        assert_eq!(statuses(&replay(&db)?.ledger), one_of_each()?);
        let store = Store::open(&db)?;
        assert_eq!(statuses(&store.snapshot().ledger), one_of_each()?);
        let version: i64 =
            Connection::open(&db)?.pragma_query_value(None, "user_version", |r| r.get(0))?;
        assert_eq!(version, SCHEMA_VERSION);
        // The migrated index takes new captures and still lists none of the old rows.
        let exchange = br#"{"request": {"method": "GET", "url": "https://a.example/x?k=1"}, "response": {"status": 200}}"#;
        let id = store.add_evidence(EvidenceKind::HttpExchange, exchange)?;
        let listed = store.http_evidence(None, 10)?;
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].0, id.as_str());
        assert_eq!(listed[0].1.status, Some(200));
        Ok(())
    }

    #[test]
    fn http_evidence_is_listed_in_pages_by_id() -> TestResult {
        let dir = tempfile::tempdir()?;
        let store = Store::open(dir.path().join("l.db"))?;
        store.add_evidence(EvidenceKind::MemorySnapshot, b"not http")?;
        store.add_evidence(EvidenceKind::HttpExchange, b"not json either")?;
        for n in 0..5 {
            let exchange = format!(r#"{{"request": {{"method": "POST", "url": "/item/{n}"}}}}"#);
            store.add_evidence(EvidenceKind::HttpExchange, exchange.as_bytes())?;
        }
        let first = store.http_evidence(None, 3)?;
        let rest = store.http_evidence(first.last().map(|(id, _)| id.as_str()), 3)?;
        assert_eq!((first.len(), rest.len()), (3, 2));
        let mut urls: Vec<_> = first
            .iter()
            .chain(&rest)
            .map(|(_, l)| l.url.clone())
            .collect();
        urls.sort();
        assert_eq!(
            urls,
            ["/item/0", "/item/1", "/item/2", "/item/3", "/item/4"]
        );
        assert!(
            first
                .iter()
                .chain(&rest)
                .all(|(_, l)| l.method == "POST" && l.status.is_none())
        );
        Ok(())
    }

    #[test]
    fn other_schema_versions_are_refused() -> TestResult {
        let dir = tempfile::tempdir()?;
        let db = dir.path().join("l.db");
        drop(Store::open(&db)?);
        Connection::open(&db)?.pragma_update(None, "user_version", 99)?;
        assert!(matches!(Store::open(&db), Err(StoreError::Schema(99))));
        assert!(matches!(replay(&db), Err(StoreError::Schema(99))));
        Ok(())
    }

    #[test]
    fn evidence_is_added_once_and_verified_on_read() -> TestResult {
        let dir = tempfile::tempdir()?;
        let db = dir.path().join("l.db");
        let store = Store::open(&db)?;
        let id = store.add_evidence(EvidenceKind::CapturedRequest, b"GET /")?;
        assert_eq!(id, EvidenceId::of(b"GET /"));
        let seq = store.snapshot().seq;
        assert_eq!(
            store.add_evidence(EvidenceKind::CapturedRequest, b"GET /")?,
            id
        );
        assert_eq!(store.snapshot().seq, seq, "second add appended nothing");

        let file = sidecar(&db, ".evidence").join(id.as_str());
        let files: Vec<_> = fs::read_dir(sidecar(&db, ".evidence"))?
            .map(|e| e.map(|e| e.path()))
            .collect::<Result<_, _>>()?;
        assert_eq!(files, std::slice::from_ref(&file));
        let row: (i64, String, i64, i64) = Connection::open(&db)?.query_row(
            "SELECT (SELECT count(*) FROM events WHERE kind = 'evidence_added'), path, size, added_seq
             FROM evidence WHERE hash = ?1",
            [id.as_str()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )?;
        assert_eq!(row, (1, id.to_string(), 5, 1));

        // An empty capture and a capture from a file take the same path.
        let empty = store.add_evidence(EvidenceKind::MemorySnapshot, b"")?;
        assert_eq!(store.evidence(&empty)?.as_deref(), Some(&[][..]));
        assert_eq!(
            store.add_evidence_file(EvidenceKind::CapturedRequest, &file)?,
            id
        );

        assert!(store.evidence(&EvidenceId::of(b"never added"))?.is_none());
        let traversal = r#"{"event":"evidence_added","id":"../l.db","kind":"memory_snapshot"}"#;
        if let Event::EvidenceAdded { id, .. } = Event::decode(traversal)? {
            assert!(store.evidence(&id)?.is_none());
        }
        fs::write(&file, b"GET /admin")?;
        assert!(matches!(store.evidence(&id), Err(StoreError::Corrupt(_))));
        Ok(())
    }

    #[test]
    fn a_rejected_batch_leaves_nothing_behind() -> TestResult {
        let dir = tempfile::tempdir()?;
        let db = dir.path().join("l.db");
        let store = Store::open(&db)?;
        let seq = store.append(proposed(0, None)?)?;
        // The retraction names an unknown claim, so the proposal before it must not stick either.
        let bad = vec![
            proposed(1, None)?,
            Event::Retracted {
                claim: id(9, None)?,
                reason: String::new(),
            },
        ];
        assert!(matches!(store.append_batch(bad), Err(StoreError::Core(_))));
        assert_eq!(store.snapshot().ledger.claims().count(), 1);
        assert_eq!(*store.snapshot(), replay(&db)?);
        // Proposing a known claim again is a no-op at the same sequence number.
        assert_eq!(store.append(proposed(0, None)?)?, seq);
        // The writer's own copies were rolled back too: claim 1 is still new to it.
        assert_eq!(store.append(proposed(1, None)?)?, seq + 1);
        assert_eq!(*store.snapshot(), replay(&db)?);
        Ok(())
    }

    #[test]
    fn stored_claims_are_readmitted_on_replay() -> TestResult {
        let dir = tempfile::tempdir()?;
        let db = dir.path().join("l.db");
        drop(Store::open(&db)?);
        let zero_size = r#"{"event":"proposed","claim":{"kind":"memory_layout","type_name":"T","size":0,"fields":[]}}"#;
        Connection::open(&db)?.execute(
            "INSERT INTO events (payload, recorded_at) VALUES (?1, '')",
            [zero_size],
        )?;
        assert!(matches!(replay(&db), Err(StoreError::Core(_))));
        assert!(Store::open(&db).is_err());
        Ok(())
    }

    #[test]
    fn readers_never_see_a_partial_batch() -> TestResult {
        let dir = tempfile::tempdir()?;
        let db = &dir.path().join("l.db");
        let store = &Store::open(db)?;
        let done = &AtomicBool::new(false);
        std::thread::scope(|s| -> TestResult {
            let readers: Vec<_> = (0..7)
                .map(|r| {
                    s.spawn(move || -> Result<(), StoreError> {
                        let mut seen = 0;
                        loop {
                            let last = done.load(Ordering::Acquire);
                            // Most readers use the published snapshot, two replay over SQLite.
                            let now = if r < 5 {
                                store.snapshot()
                            } else {
                                Arc::new(replay(db)?)
                            };
                            assert!(now.seq >= seen, "snapshots went backwards");
                            assert_eq!(now.seq % 10, 0, "partial batch visible");
                            for (id, _) in now.ledger.claims() {
                                assert_eq!(
                                    now.ledger.verdicts(id).len(),
                                    9,
                                    "partial batch visible"
                                );
                            }
                            seen = now.seq;
                            if last {
                                assert_eq!(now.seq, 1000);
                                return Ok(());
                            }
                        }
                    })
                })
                .collect();
            // Two producers, so the single writer also groups several batches per transaction.
            let producers: Vec<_> = (0..2)
                .map(|p| {
                    s.spawn(move || -> Result<(), StoreError> {
                        for n in 0..50 {
                            store.append_batch(batch(p * 50 + n)?)?;
                        }
                        Ok(())
                    })
                })
                .collect();
            for p in producers {
                p.join().map_err(|_| "producer panicked")??;
            }
            done.store(true, Ordering::Release);
            for r in readers {
                r.join().map_err(|_| "reader panicked")??;
            }
            Ok(())
        })
    }

    #[test]
    fn a_batch_cut_short_is_gone_after_reopen() -> TestResult {
        let dir = tempfile::tempdir()?;
        let db = dir.path().join("l.db");
        let committed = {
            let store = Store::open(&db)?;
            store.append_batch(batch(0)?)?;
            store.snapshot()
        };
        let image = dir.path().join("image.db");
        {
            let mut conn = Connection::open(&db)?;
            // A one-page cache spills the open transaction into the WAL.
            conn.pragma_update(None, "cache_size", 1)?;
            let mut next = load(&conn)?;
            let tx = conn.transaction()?;
            let half = (1..400).map(|n| proposed(n, None));
            let half = Work::Events(half.collect::<Result<_, _>>()?);
            stage(&tx, &committed, &mut next, half, &mut Vec::new())??;
            // What a killed process leaves on disk: the file plus a WAL of uncommitted frames.
            fs::copy(&db, &image)?;
            let spilled = fs::copy(sidecar(&db, "-wal"), sidecar(&image, "-wal"))?;
            assert!(
                spilled > 0,
                "nothing reached the WAL, the image proves nothing"
            );
        } // dropped without commit
        assert_eq!(Store::open(&db)?.snapshot(), committed);
        assert_eq!(Store::open(&image)?.snapshot(), committed);
        Ok(())
    }

    #[test]
    fn replays_10k_events() -> TestResult {
        let dir = tempfile::tempdir()?;
        let db = dir.path().join("l.db");
        {
            let store = Store::open(&db)?;
            for chunk in 0..10 {
                let batches = (chunk * 100..(chunk + 1) * 100).map(batch);
                let events: Vec<Vec<Event>> = batches.collect::<Result<_, _>>()?;
                store.append_batch(events.concat())?;
            }
        }
        let start = std::time::Instant::now();
        let snapshot = replay(&db)?;
        // Shown with `cargo test -p ledger-store replays_10k -- --nocapture`.
        eprintln!("replayed 10,000 events in {:?}", start.elapsed());
        assert_eq!(snapshot.seq, 10_000);
        assert_eq!(snapshot.ledger.claims().count(), 1000);
        Ok(())
    }

    fn event() -> impl Strategy<Value = Event> {
        let verdict = prop_oneof![
            Just(held()),
            Just(inconclusive()),
            (0..3u8).prop_map(|e| Verdict::Refuted {
                counterexample: Counterexample {
                    evidence: EvidenceId::of(&[e]),
                    detail: "differs".into(),
                },
            }),
        ];
        // Small domains, so sequences hit duplicates, unknown references and real dependencies.
        let claim = || (0..3u64, proptest::option::of(0..3u64));
        let evidence = proptest::collection::btree_set(0..3u8, 0..2);
        prop_oneof![
            claim().prop_filter_map("admissible", |(n, p)| proposed(n, p).ok()),
            (0..3u8).prop_map(|e| Event::EvidenceAdded {
                id: EvidenceId::of(&[e]),
                kind: EvidenceKind::MemorySnapshot,
            }),
            (claim(), evidence, verdict).prop_filter_map(
                "claim id",
                |((n, p), evidence, verdict)| {
                    Some(Event::Checked {
                        claim: id(n, p).ok()?,
                        evidence: evidence.iter().map(|e| EvidenceId::of(&[*e])).collect(),
                        verdict,
                        checker: None,
                    })
                }
            ),
            claim().prop_filter_map("claim id", |(n, p)| {
                Some(Event::Retracted {
                    claim: id(n, p).ok()?,
                    reason: "r".into(),
                })
            }),
        ]
    }

    /// What the store promises for one batch, stated with the kernel alone.
    fn apply_all_or_nothing(ledger: &mut Ledger, events: &[Event]) -> bool {
        let mut next = ledger.clone();
        for event in events {
            match next.apply(event.clone()) {
                Ok(()) | Err(CoreError::DuplicateClaim(_)) => {}
                Err(_) => return false,
            }
        }
        *ledger = next;
        true
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]
        #[test]
        fn replay_equals_the_ledger_built_in_memory(
            batches in proptest::collection::vec(proptest::collection::vec(event(), 1..5), 0..12),
        ) {
            let dir = tempfile::tempdir()?;
            let db = dir.path().join("l.db");
            let store = Store::open(&db)?;
            let mut memory = Ledger::default();
            for events in batches {
                let accepted = apply_all_or_nothing(&mut memory, &events);
                prop_assert_eq!(store.append_batch(events).is_ok(), accepted);
                prop_assert_eq!(&store.snapshot().ledger, &memory);
            }
            prop_assert_eq!(&replay(&db)?.ledger, &memory);
            drop(store);
            prop_assert_eq!(&Store::open(&db)?.snapshot().ledger, &memory);
        }
    }
}
