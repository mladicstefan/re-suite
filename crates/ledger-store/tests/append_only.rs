//! The event log is append-only. This is the only file allowed to spell the
//! statements that would rewrite it, because it checks they are absent from
//! every crate and refused by SQLite.

use std::path::Path;

use ledger_core::EvidenceKind;
use ledger_store::Store;

const FORBIDDEN: [&str; 3] = ["UPDATE EVENTS", "DELETE FROM EVENTS", "REPLACE INTO EVENTS"];

/// Upper-cases and collapses everything but identifiers to single spaces, so
/// quoting, case and line breaks cannot hide a statement.
fn normalize(source: &str) -> String {
    let spaced: String = source
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '_' {
                c.to_ascii_uppercase()
            } else {
                ' '
            }
        })
        .collect();
    spaced.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn scan(dir: &Path, hits: &mut Vec<String>) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            scan(&path, hits)?;
        } else if path.extension().is_some_and(|e| e == "rs")
            && path.file_name() != Path::new(file!()).file_name()
        {
            let source = normalize(&std::fs::read_to_string(&path)?);
            for needle in FORBIDDEN.iter().filter(|n| source.contains(**n)) {
                hits.push(format!("{}: {needle}", path.display()));
            }
        }
    }
    Ok(())
}

#[test]
fn normalize_sees_through_formatting() {
    assert_eq!(
        normalize("delete\n  from \"events\" where"),
        "DELETE FROM EVENTS WHERE"
    );
    assert_eq!(
        normalize("BEFORE UPDATE ON events"),
        "BEFORE UPDATE ON EVENTS"
    );
}

#[test]
fn no_code_rewrites_the_event_log() -> std::io::Result<()> {
    let mut hits = Vec::new();
    scan(&Path::new(env!("CARGO_MANIFEST_DIR")).join(".."), &mut hits)?;
    assert!(hits.is_empty(), "events must stay append-only: {hits:#?}");
    Ok(())
}

#[test]
fn sqlite_refuses_to_rewrite_the_event_log() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let db = dir.path().join("l.db");
    Store::open(&db)?.add_evidence(EvidenceKind::MemorySnapshot, &[1])?;
    let conn = rusqlite::Connection::open(&db)?;
    assert!(
        conn.execute("UPDATE events SET recorded_at = ''", [])
            .is_err()
    );
    assert!(conn.execute("DELETE FROM events", []).is_err());
    assert_eq!(
        conn.query_one("SELECT count(*) FROM events", [], |r| r.get::<_, i64>(0))?,
        1
    );
    Ok(())
}
