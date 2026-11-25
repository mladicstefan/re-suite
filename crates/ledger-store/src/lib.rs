//! SQLite persistence: one writer thread fed by a channel, separate read-only
//! connections, an append-only event log and content-addressed evidence.

use std::fs::File;
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
    #[error("writer thread is gone")]
    Closed,
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS events (
    seq  INTEGER PRIMARY KEY AUTOINCREMENT,
    at   TEXT NOT NULL,
    body TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS evidence (
    hash  TEXT PRIMARY KEY,
    bytes BLOB NOT NULL
) WITHOUT ROWID;
CREATE TRIGGER IF NOT EXISTS events_no_update BEFORE UPDATE ON events
    BEGIN SELECT RAISE(ABORT, 'events are append-only'); END;
CREATE TRIGGER IF NOT EXISTS events_no_delete BEFORE DELETE ON events
    BEGIN SELECT RAISE(ABORT, 'events are append-only'); END;
";

type Reply<T> = flume::Sender<Result<T, StoreError>>;

enum Cmd {
    Append(Event, Reply<i64>),
    EvidenceFile(EvidenceKind, PathBuf, Reply<EvidenceId>),
}

pub struct Store {
    path: PathBuf,
    tx: Option<flume::Sender<Cmd>>,
    writer: Option<JoinHandle<()>>,
}

impl Store {
    /// Opens or creates a ledger file in WAL mode and starts its writer thread.
    ///
    /// # Errors
    /// The file cannot be opened, or its events no longer replay.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let path = path.as_ref().to_path_buf();
        let conn = Connection::open(&path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.execute_batch(SCHEMA)?;
        let mut ledger = load(&conn)?;
        let (tx, rx) = flume::unbounded::<Cmd>();
        let writer = std::thread::Builder::new()
            .name("ledger-writer".into())
            .spawn(move || {
                for cmd in rx {
                    // A dropped reply receiver only means the caller gave up waiting.
                    match cmd {
                        Cmd::Append(ev, reply) => drop(reply.send(append(&conn, &mut ledger, ev))),
                        Cmd::EvidenceFile(kind, p, reply) => {
                            drop(reply.send(add_evidence(&conn, &mut ledger, kind, &p)));
                        }
                    }
                }
                tracing::debug!("ledger writer stopped");
            })?;
        Ok(Self {
            path,
            tx: Some(tx),
            writer: Some(writer),
        })
    }

    fn call<T>(&self, cmd: impl FnOnce(Reply<T>) -> Cmd) -> Result<T, StoreError> {
        let (reply, rx) = flume::bounded(1);
        self.tx
            .as_ref()
            .ok_or(StoreError::Closed)?
            .send(cmd(reply))
            .map_err(|_| StoreError::Closed)?;
        rx.recv().map_err(|_| StoreError::Closed)?
    }

    /// Appends an event if it applies to the current state. Returns its sequence number.
    ///
    /// # Errors
    /// The event is invalid for the current ledger, or the write fails.
    pub fn append(&self, event: Event) -> Result<i64, StoreError> {
        self.call(|r| Cmd::Append(event, r))
    }

    /// Stores a saved capture by content hash and records an `EvidenceAdded` event.
    ///
    /// # Errors
    /// The file cannot be read or the write fails.
    pub fn add_evidence_file(
        &self,
        kind: EvidenceKind,
        path: impl AsRef<Path>,
    ) -> Result<EvidenceId, StoreError> {
        let path = path.as_ref().to_path_buf();
        self.call(|r| Cmd::EvidenceFile(kind, path, r))
    }

    /// Current state, rebuilt from the event log on a fresh read connection.
    ///
    /// # Errors
    /// See [`replay`].
    pub fn ledger(&self) -> Result<Ledger, StoreError> {
        replay(&self.path)
    }

    /// # Errors
    /// The read connection or query fails.
    pub fn evidence(&self, id: &EvidenceId) -> Result<Option<Vec<u8>>, StoreError> {
        let conn = reader(&self.path)?;
        let q = "SELECT bytes FROM evidence WHERE hash = ?1";
        Ok(conn.query_row(q, [id.as_str()], |r| r.get(0)).optional()?)
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

fn load(conn: &Connection) -> Result<Ledger, StoreError> {
    let mut ledger = Ledger::default();
    let mut stmt = conn.prepare("SELECT body FROM events ORDER BY seq")?;
    for body in stmt.query_map([], |r| r.get::<_, String>(0))? {
        ledger.apply(Event::decode(&body?)?)?;
    }
    Ok(ledger)
}

fn append(conn: &Connection, ledger: &mut Ledger, event: Event) -> Result<i64, StoreError> {
    let body = event.encode()?;
    ledger.apply(event)?;
    // The timestamp lives only in this column; it never enters a hash.
    let at = jiff::Timestamp::now().to_string();
    let written = conn.execute(
        "INSERT INTO events (at, body) VALUES (?1, ?2)",
        params![at, body],
    );
    if let Err(e) = written {
        *ledger = load(conn)?; // memory got ahead of disk; resync
        return Err(e.into());
    }
    let seq = conn.last_insert_rowid();
    tracing::debug!(seq, "event appended");
    Ok(seq)
}

fn add_evidence(
    conn: &Connection,
    ledger: &mut Ledger,
    kind: EvidenceKind,
    path: &Path,
) -> Result<EvidenceId, StoreError> {
    let file = File::open(path)?;
    // SAFETY: evidence files are finished captures; we hash and copy them into SQLite
    // before returning. A concurrent truncation by another process could fault the read.
    let map = unsafe { memmap2::Mmap::map(&file)? };
    let id = EvidenceId::of(&map);
    conn.execute(
        "INSERT OR IGNORE INTO evidence (hash, bytes) VALUES (?1, ?2)",
        params![id.as_str(), &map[..]],
    )?;
    if ledger.evidence_kind(&id).is_none() {
        append(
            conn,
            ledger,
            Event::EvidenceAdded {
                id: id.clone(),
                kind,
            },
        )?;
    }
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ledger_core::{Claim, ClaimKind, MemoryLayout, Status, Verdict, admit};
    use std::num::NonZeroU64;

    #[test]
    fn state_survives_reopen_and_log_is_append_only() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let db = dir.path().join("l.db");
        let snap = dir.path().join("snap.bin");
        std::fs::write(&snap, [0u8; 16])?;

        let claim = Claim {
            kind: ClaimKind::MemoryLayout(MemoryLayout {
                type_name: "T".into(),
                size: 16,
                fields: vec![],
            }),
            premises: std::collections::BTreeSet::default(),
        };
        let id = claim.id()?;
        {
            let store = Store::open(&db)?;
            let ev = store.add_evidence_file(EvidenceKind::MemorySnapshot, &snap)?;
            assert_eq!(store.evidence(&ev)?.map(|b| b.len()), Some(16));
            store.append(Event::Proposed {
                claim: admit(claim)?,
            })?;
            let verdict = Verdict::Held {
                runs: NonZeroU64::MIN,
            };
            store.append(Event::Checked {
                claim: id.clone(),
                evidence: [ev].into(),
                verdict,
            })?;
            let bogus = Event::Retracted {
                claim: ledger_core::ClaimId::of(b"nope"),
                reason: String::new(),
            };
            assert!(store.append(bogus).is_err());
        }
        assert_eq!(replay(&db)?.status(&id), Some(Status::Held));
        assert!(
            Connection::open(&db)?
                .execute("DELETE FROM events", [])
                .is_err()
        );
        Ok(())
    }
}
