//! SQLite persistence: one writer thread fed by a channel, separate read-only
//! connections, an append-only event log and an index of evidence files that
//! live on disk under their content hash.

use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::thread::JoinHandle;

use ledger_core::{CoreError, Event, EvidenceId, EvidenceKind, Ledger};
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};

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
    #[error("writer thread is gone")]
    Closed,
}

// `kind` is generated from the payload so the two can never disagree.
const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS events (
    seq         INTEGER PRIMARY KEY,
    kind        TEXT GENERATED ALWAYS AS (payload ->> '$.event') VIRTUAL,
    payload     TEXT NOT NULL CHECK (json_valid(payload)),
    recorded_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS evidence (
    hash      TEXT PRIMARY KEY,
    path      TEXT NOT NULL,
    size      INTEGER NOT NULL,
    added_seq INTEGER NOT NULL
) WITHOUT ROWID;
CREATE TRIGGER IF NOT EXISTS events_no_update BEFORE UPDATE ON events
    BEGIN SELECT RAISE(ABORT, 'events are append-only'); END;
CREATE TRIGGER IF NOT EXISTS events_no_delete BEFORE DELETE ON events
    BEGIN SELECT RAISE(ABORT, 'events are append-only'); END;
";

/// Sequence numbers of the events one piece of work appended.
type Staged = Result<Vec<i64>, StoreError>;
type Job = (Work, flume::Sender<Staged>);

enum Work {
    Events(Vec<Event>),
    Evidence(EvidenceId, EvidenceKind, Vec<u8>),
}

pub struct Store {
    path: PathBuf,
    tx: Option<flume::Sender<Job>>,
    writer: Option<JoinHandle<()>>,
}

impl Store {
    /// Opens or creates a ledger file in WAL mode, replays its events through
    /// ledger-core and starts the writer thread. Evidence files go in the
    /// sibling directory `<path>.evidence`.
    ///
    /// # Errors
    /// The file cannot be opened, or its events no longer replay.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let path = path.as_ref().to_path_buf();
        let conn = Connection::open(&path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.execute_batch(SCHEMA)?;
        let ledger = load(&conn)?;
        let dir = sidecar(&path, ".evidence");
        fs::create_dir_all(&dir)?;
        let (tx, rx) = flume::unbounded();
        let writer = std::thread::Builder::new()
            .name("ledger-writer".into())
            .spawn(move || write_loop(conn, ledger, &dir, &rx))?;
        Ok(Self {
            path,
            tx: Some(tx),
            writer: Some(writer),
        })
    }

    fn call(&self, work: Work) -> Staged {
        let (reply, rx) = flume::bounded(1);
        self.tx
            .as_ref()
            .ok_or(StoreError::Closed)?
            .send((work, reply))
            .map_err(|_| StoreError::Closed)?;
        rx.recv().map_err(|_| StoreError::Closed)?
    }

    /// Appends an event if it applies to the current state. Returns its sequence number.
    ///
    /// # Errors
    /// The event is invalid for the current ledger, or the write fails.
    pub fn append(&self, event: Event) -> Result<i64, StoreError> {
        Ok(self.append_batch(vec![event])?[0]) // one event in, one seq out
    }

    /// Appends events all or nothing: readers see every one of them or none.
    /// Returns their sequence numbers.
    ///
    /// # Errors
    /// An event is invalid for the ledger as left by the ones before it, or the write fails.
    pub fn append_batch(&self, events: Vec<Event>) -> Result<Vec<i64>, StoreError> {
        self.call(Work::Events(events))
    }

    /// Stores bytes as a file named by their content hash, indexes it and records
    /// an `EvidenceAdded` event. Does nothing if the hash is already indexed.
    ///
    /// # Errors
    /// The file or the index cannot be written.
    pub fn add_evidence(
        &self,
        kind: EvidenceKind,
        bytes: Vec<u8>,
    ) -> Result<EvidenceId, StoreError> {
        let id = EvidenceId::of(&bytes);
        self.call(Work::Evidence(id.clone(), kind, bytes))?;
        Ok(id)
    }

    /// [`Store::add_evidence`] for a saved capture on disk.
    ///
    /// # Errors
    /// The file cannot be read or the write fails.
    pub fn add_evidence_file(
        &self,
        kind: EvidenceKind,
        path: impl AsRef<Path>,
    ) -> Result<EvidenceId, StoreError> {
        // shortcut: reads the whole capture into memory; stream-hash and copy if captures outgrow RAM.
        self.add_evidence(kind, fs::read(path)?)
    }

    /// Current state, rebuilt from the event log on a fresh read connection.
    ///
    /// # Errors
    /// See [`replay`].
    pub fn ledger(&self) -> Result<Ledger, StoreError> {
        replay(&self.path)
    }

    /// # Errors
    /// The read connection or query fails, or an indexed file is missing.
    pub fn evidence(&self, id: &EvidenceId) -> Result<Option<Vec<u8>>, StoreError> {
        let q = "SELECT path FROM evidence WHERE hash = ?1";
        let path: Option<String> = reader(&self.path)?
            .query_row(q, [id.as_str()], |r| r.get(0))
            .optional()?;
        let dir = sidecar(&self.path, ".evidence");
        Ok(path.map(|p| fs::read(dir.join(p))).transpose()?)
    }
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

fn reader(path: &Path) -> Result<Connection, StoreError> {
    Ok(Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?)
}

/// Rebuilds a ledger from an existing file without starting a writer.
///
/// # Errors
/// The file is missing or an event fails to decode or apply.
pub fn replay(path: impl AsRef<Path>) -> Result<Ledger, StoreError> {
    load(&reader(path.as_ref())?)
}

/// Folds the log through the kernel. One statement, so one consistent snapshot;
/// `Event::decode` re-admits every stored claim.
fn load(conn: &Connection) -> Result<Ledger, StoreError> {
    let mut ledger = Ledger::default();
    let mut stmt = conn.prepare("SELECT payload FROM events ORDER BY seq")?;
    for payload in stmt.query_map([], |r| r.get::<_, String>(0))? {
        ledger.apply(Event::decode(&payload?)?)?;
    }
    Ok(ledger)
}

fn write_loop(mut conn: Connection, mut ledger: Ledger, dir: &Path, rx: &flume::Receiver<Job>) {
    while let Ok(first) = rx.recv() {
        // Everything already queued shares one transaction; replies wait for its commit.
        let (works, replies): (Vec<_>, Vec<_>) =
            std::iter::once(first).chain(rx.try_iter()).unzip();
        let results = match write_batch(&mut conn, &mut ledger, dir, works) {
            Ok(results) => results,
            Err(e) => {
                tracing::error!(error = %e, "batch rolled back");
                // Memory got ahead of disk; resync, or stop taking writes if even that fails.
                match load(&conn) {
                    Ok(l) => ledger = l,
                    Err(e) => {
                        tracing::error!(error = %e, "cannot reload ledger, writer stopping");
                        return;
                    }
                }
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
    tracing::debug!("ledger writer stopped");
}

fn write_batch(
    conn: &mut Connection,
    ledger: &mut Ledger,
    dir: &Path,
    works: Vec<Work>,
) -> Result<Vec<Staged>, StoreError> {
    let tx = conn.transaction()?;
    let results = (works.into_iter())
        .map(|work| stage(&tx, ledger, dir, work))
        .collect::<Result<_, _>>()?;
    tx.commit()?;
    Ok(results)
}

/// Outer error: the whole transaction must roll back. Inner error: the kernel
/// refused this work and none of it was staged.
fn stage(
    tx: &Connection,
    ledger: &mut Ledger,
    dir: &Path,
    work: Work,
) -> Result<Staged, StoreError> {
    let (id, kind, bytes) = match work {
        Work::Events(events) => return append(tx, ledger, events),
        Work::Evidence(id, kind, bytes) => (id, kind, bytes),
    };
    let indexed = "SELECT 1 FROM evidence WHERE hash = ?1";
    if tx.prepare_cached(indexed)?.exists([id.as_str()])? {
        return Ok(Ok(Vec::new()));
    }
    let file = dir.join(id.as_str());
    if !file.exists() {
        // Write aside, sync, rename: the hash-named file is whole or absent, even after a crash.
        let tmp = file.with_extension("tmp");
        let mut f = File::create(&tmp)?;
        f.write_all(&bytes)?;
        f.sync_all()?;
        fs::rename(&tmp, &file)?;
    }
    let event = Event::EvidenceAdded {
        id: id.clone(),
        kind,
    };
    let staged = append(tx, ledger, vec![event])?;
    if let Ok(seqs) = &staged {
        // `path` is relative to the evidence directory, so the ledger can be moved.
        tx.execute(
            "INSERT INTO evidence (hash, path, size, added_seq) VALUES (?1, ?1, ?2, ?3)",
            params![
                id.as_str(),
                i64::try_from(bytes.len()).unwrap_or(i64::MAX),
                seqs.first()
            ],
        )?;
    }
    Ok(staged)
}

/// Applies events to the kernel, then inserts them. If the kernel refuses one,
/// the ledger is left as it was and nothing is inserted.
fn append(tx: &Connection, ledger: &mut Ledger, events: Vec<Event>) -> Result<Staged, StoreError> {
    let mut payloads = Vec::with_capacity(events.len());
    for (i, event) in events.into_iter().enumerate() {
        let applied = event.encode().and_then(|payload| {
            ledger.apply(event)?;
            Ok(payload)
        });
        match applied {
            Ok(payload) => payloads.push(payload),
            Err(e) => {
                if i > 0 {
                    *ledger = load(tx)?; // undo this batch's earlier events
                }
                return Ok(Err(e.into()));
            }
        }
    }
    // The timestamp lives only in this column; it never enters a hash.
    let at = jiff::Timestamp::now().to_string();
    let mut insert =
        tx.prepare_cached("INSERT INTO events (payload, recorded_at) VALUES (?1, ?2)")?;
    let mut seqs = Vec::with_capacity(payloads.len());
    for payload in payloads {
        insert.execute(params![payload, at])?;
        seqs.push(tx.last_insert_rowid());
    }
    tracing::debug!(?seqs, "events staged");
    Ok(Ok(seqs))
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
    use std::sync::atomic::{AtomicBool, Ordering};

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

    fn proposed(n: u64, premise: Option<u64>) -> Result<Event, CoreError> {
        Ok(Event::Proposed {
            claim: admit(claim(n, premise)?)?,
        })
    }

    fn id(n: u64, premise: Option<u64>) -> Result<ClaimId, CoreError> {
        claim(n, premise)?.id()
    }

    fn checked(claim: ClaimId, verdict: Verdict) -> Event {
        Event::Checked {
            claim,
            evidence: [].into(),
            verdict,
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

    fn statuses(ledger: &Ledger) -> BTreeMap<ClaimId, Option<Status>> {
        let ids = ledger.claims().map(|(id, _)| id.clone());
        ids.map(|id| (id.clone(), ledger.status(&id))).collect()
    }

    #[test]
    fn statuses_and_evidence_survive_reopen() -> TestResult {
        let dir = tempfile::tempdir()?;
        let db = dir.path().join("l.db");
        let before = {
            let store = Store::open(&db)?;
            let ev = store.add_evidence(EvidenceKind::MemorySnapshot, vec![7; 16])?;
            let refuted = Verdict::Refuted {
                counterexample: Counterexample {
                    evidence: ev.clone(),
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
            statuses(&store.ledger()?)
        };
        for status in [
            Status::Held,
            Status::Refuted,
            Status::Inconclusive,
            Status::Unchecked,
            Status::Retracted,
            Status::Blocked,
        ] {
            assert!(before.values().any(|s| *s == Some(status)), "{status:?}");
        }

        let store = Store::open(&db)?;
        assert_eq!(statuses(&store.ledger()?), before);
        assert_eq!(statuses(&replay(&db)?), before);
        let ev = EvidenceId::of(&[7; 16]);
        assert_eq!(store.evidence(&ev)?, Some(vec![7; 16]));
        Ok(())
    }

    #[test]
    fn add_evidence_is_a_noop_for_a_known_hash() -> TestResult {
        let dir = tempfile::tempdir()?;
        let db = dir.path().join("l.db");
        let store = Store::open(&db)?;
        let id = store.add_evidence(EvidenceKind::CapturedRequest, b"GET /".to_vec())?;
        assert_eq!(id, EvidenceId::of(b"GET /"));
        assert_eq!(
            store.add_evidence(EvidenceKind::CapturedRequest, b"GET /".to_vec())?,
            id
        );

        let files: Vec<_> = fs::read_dir(sidecar(&db, ".evidence"))?
            .map(|e| e.map(|e| e.file_name()))
            .collect::<Result<_, _>>()?;
        assert_eq!(files, [id.as_str()]);
        let row: (i64, String, i64, i64) = reader(&db)?.query_row(
            "SELECT (SELECT count(*) FROM events WHERE kind = 'evidence_added'), path, size, added_seq
             FROM evidence WHERE hash = ?1",
            [id.as_str()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )?;
        assert_eq!(row, (1, id.to_string(), 5, 1));
        Ok(())
    }

    #[test]
    fn a_rejected_batch_leaves_nothing_behind() -> TestResult {
        let dir = tempfile::tempdir()?;
        let db = dir.path().join("l.db");
        let store = Store::open(&db)?;
        store.append(proposed(0, None)?)?;
        // Second event is a duplicate, so the first must not stick either.
        let bad = vec![proposed(1, None)?, proposed(0, None)?];
        assert!(matches!(store.append_batch(bad), Err(StoreError::Core(_))));
        assert_eq!(store.ledger()?.claims().count(), 1);
        // The writer's own ledger was rolled back too: claim 1 is still new to it.
        store.append(proposed(1, None)?)?;
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
        let store = &Store::open(dir.path().join("l.db"))?;
        let done = &AtomicBool::new(false);
        std::thread::scope(|s| -> TestResult {
            let readers: Vec<_> = (0..7)
                .map(|_| {
                    s.spawn(move || -> Result<(), StoreError> {
                        loop {
                            let last = done.load(Ordering::Acquire);
                            let ledger = store.ledger()?;
                            for (id, _) in ledger.claims() {
                                assert_eq!(ledger.verdicts(id).len(), 9, "partial batch visible");
                            }
                            if last {
                                assert_eq!(ledger.claims().count(), 100);
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
            store.ledger()?
        };
        let image = dir.path().join("image.db");
        {
            let mut conn = Connection::open(&db)?;
            // A one-page cache spills the open transaction into the WAL.
            conn.pragma_update(None, "cache_size", 1)?;
            let mut ledger = load(&conn)?;
            let tx = conn.transaction()?;
            let half = (1..400).map(|n| proposed(n, None));
            append(&tx, &mut ledger, half.collect::<Result<_, _>>()?)??;
            // What a killed process leaves on disk: the file plus a WAL of uncommitted frames.
            fs::copy(&db, &image)?;
            let spilled = fs::copy(sidecar(&db, "-wal"), sidecar(&image, "-wal"))?;
            assert!(
                spilled > 0,
                "nothing reached the WAL, the image proves nothing"
            );
        } // dropped without commit
        assert_eq!(Store::open(&db)?.ledger()?, committed);
        assert_eq!(Store::open(&image)?.ledger()?, committed);
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
        let ledger = replay(&db)?;
        // Shown with `cargo test -p ledger-store replays_10k -- --nocapture`.
        eprintln!("replayed 10,000 events in {:?}", start.elapsed());
        assert_eq!(ledger.claims().count(), 1000);
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
                let mut next = memory.clone();
                let accepted = events.iter().cloned().try_for_each(|e| next.apply(e)).is_ok();
                prop_assert_eq!(store.append_batch(events).is_ok(), accepted);
                if accepted {
                    memory = next;
                }
            }
            prop_assert_eq!(&store.ledger()?, &memory);
            drop(store);
            prop_assert_eq!(&Store::open(&db)?.ledger()?, &memory);
        }
    }
}
