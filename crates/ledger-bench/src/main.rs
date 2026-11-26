//! Reproduces the baseline table in ROADMAP.md section 6 and checks its budgets.
//!
//! `cargo run --release -p ledger-bench [-- <new or empty dir on the disk to measure>]`
//! Prints a Markdown table and exits non-zero if a budget is broken.

use std::error::Error;
use std::num::NonZeroU64;
use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use ledger_core::{
    Claim, ClaimId, ClaimKind, Event, FieldLayout, Ledger, MemoryLayout, Status, Verdict, admit,
};
use ledger_store::{Store, replay};

type Res<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

const AGENTS: u64 = 7;
const READERS: usize = 7;
const PER_AGENT: u64 = 2_000;
const BULK_BATCH: usize = 512;
const LARGE: usize = 1_000_000;
const MEDIUM: usize = 100_000;

/// A claim whose `Proposed` event is about 190 bytes of JSON without premises.
fn claim(n: u64, premises: &[ClaimId]) -> Claim {
    let field = |name: &str, offset| FieldLayout {
        name: name.into(),
        offset,
        len: 4,
        is: None,
    };
    Claim {
        kind: ClaimKind::MemoryLayout(MemoryLayout {
            type_name: format!("Entity{n}"),
            size: 64,
            fields: vec![field("hp", 0), field("mana", 8)],
        }),
        premises: premises.iter().cloned().collect(),
    }
}

fn proposed(n: u64, premises: &[ClaimId]) -> Res<Event> {
    Ok(Event::Proposed {
        claim: admit(claim(n, premises))?,
    })
}

/// Claim `n` rests on claim `n / 8`: a wide tree, a handful of levels deep.
fn tree(n: usize, ids: &[ClaimId]) -> Res<Event> {
    let premise = if n == 0 { &[][..] } else { &ids[n / 8..=n / 8] };
    proposed(n as u64, premise)
}

fn held(claim: &ClaimId) -> Event {
    Event::Checked {
        claim: claim.clone(),
        evidence: [].into(),
        verdict: Verdict::Held {
            runs: NonZeroU64::MIN,
        },
        checker: None,
    }
}

fn percentile(sorted: &[Duration], p: usize) -> Duration {
    sorted[(sorted.len() * p / 100).min(sorted.len() - 1)]
}

fn per_second(n: usize, took: Duration) -> f64 {
    f64::from(u32::try_from(n).unwrap_or(u32::MAX)) / took.as_secs_f64()
}

fn row(scenario: &str, result: &str) {
    println!("| {scenario} | {result} | |");
}

struct Report {
    broken: bool,
}

impl Report {
    fn budget(&mut self, scenario: &str, result: &str, budget: &str, met: bool) {
        self.broken |= !met;
        let verdict = if met { "met" } else { "BROKEN" };
        println!("| {scenario} | {result} | {budget}: {verdict} |");
    }
}

/// Hash, admit and apply `n` claims in memory. Returns the ledger, the ids and the time taken.
fn build(n: usize) -> Res<(Ledger, Vec<ClaimId>, Duration)> {
    let mut ledger = Ledger::default();
    let mut ids: Vec<ClaimId> = Vec::with_capacity(n);
    let start = Instant::now();
    for i in 0..n {
        let premise = if i == 0 { &[][..] } else { &ids[i / 8..=i / 8] };
        let claim = claim(i as u64, premise);
        ids.push(claim.id()?);
        ledger.apply(Event::Proposed {
            claim: admit(claim)?,
        })?;
    }
    Ok((ledger, ids, start.elapsed()))
}

fn bulk_import(db: &Path, ids: &[ClaimId]) -> Res<Duration> {
    let store = Store::open_bulk(db)?;
    let start = Instant::now();
    for chunk in (0..ids.len()).collect::<Vec<_>>().chunks(BULK_BATCH) {
        let events: Res<Vec<Event>> = chunk.iter().map(|&n| tree(n, ids)).collect();
        store.append_batch(events?)?;
    }
    Ok(start.elapsed())
}

/// Seven agents each waiting for durable writes, with `readers` threads asking
/// for the status of existing claims meanwhile. Returns sorted write latencies,
/// the wall time of the writes, and sorted read latencies.
fn interactive(
    store: &Store,
    ids: &[ClaimId],
    readers: usize,
) -> Res<(Vec<Duration>, Duration, Vec<Duration>)> {
    let done = &AtomicBool::new(false);
    std::thread::scope(|s| {
        let readers: Vec<_> = (0..readers)
            .map(|r| {
                s.spawn(move || {
                    let (mut at, mut latencies) = (r, Vec::new());
                    while !done.load(Ordering::Relaxed) {
                        let start = Instant::now();
                        let status = store.snapshot().ledger.status(&ids[at % ids.len()]);
                        latencies.push(start.elapsed());
                        std::hint::black_box(status);
                        at += 7919;
                    }
                    latencies
                })
            })
            .collect();
        let start = Instant::now();
        let writers: Vec<_> = (0..AGENTS)
            .map(|agent| {
                s.spawn(move || -> Res<Vec<Duration>> {
                    let mut latencies = Vec::new();
                    for i in 0..PER_AGENT {
                        let event = proposed(u64::MAX - agent * PER_AGENT - i, &[])?;
                        let start = Instant::now();
                        store.append(event)?;
                        latencies.push(start.elapsed());
                    }
                    Ok(latencies)
                })
            })
            .collect();
        let mut latencies = Vec::new();
        for w in writers {
            latencies.extend(w.join().map_err(|_| "writer panicked")??);
        }
        let took = start.elapsed();
        done.store(true, Ordering::Relaxed);
        let mut reads = Vec::new();
        for r in readers {
            reads.extend(r.join().map_err(|_| "reader panicked")?);
        }
        latencies.sort();
        reads.sort();
        Ok((latencies, took, reads))
    })
}

/// Median time to make a 4 KB append durable in `dir`.
fn flush_time(dir: &Path) -> Res<Duration> {
    use std::io::Write as _;
    let path = dir.join("flush.probe");
    let mut file = std::fs::File::create(&path)?;
    let mut times = Vec::new();
    for _ in 0..200 {
        file.write_all(&[0; 4096])?;
        let start = Instant::now();
        file.sync_data()?;
        times.push(start.elapsed());
    }
    std::fs::remove_file(path)?;
    times.sort();
    Ok(percentile(&times, 50))
}

/// The alternative the roadmap rules out: every event its own synced transaction.
fn one_transaction_per_event(db: &Path) -> Res<(Vec<Duration>, Duration)> {
    drop(Store::open(db)?); // creates the schema
    let conn = rusqlite::Connection::open(db)?;
    conn.execute_batch("PRAGMA synchronous = FULL")?;
    let conn = &Mutex::new(conn);
    let per_agent = PER_AGENT / 10;
    std::thread::scope(|s| {
        let start = Instant::now();
        let writers: Vec<_> = (0..AGENTS)
            .map(|agent| {
                s.spawn(move || -> Res<Vec<Duration>> {
                    let mut latencies = Vec::new();
                    for i in 0..per_agent {
                        let payload = proposed(agent * per_agent + i, &[])?.encode()?;
                        let start = Instant::now();
                        conn.lock().map_err(|_| "poisoned")?.execute(
                            "INSERT INTO events (payload, recorded_at) VALUES (?1, '')",
                            [payload],
                        )?;
                        latencies.push(start.elapsed());
                    }
                    Ok(latencies)
                })
            })
            .collect();
        let mut latencies = Vec::new();
        for w in writers {
            latencies.extend(w.join().map_err(|_| "writer panicked")??);
        }
        latencies.sort();
        Ok((latencies, start.elapsed()))
    })
}

/// Status as its definition reads: recurse into every premise, remember nothing.
fn status_by_recursion(ledger: &Ledger, id: &ClaimId, calls: &mut u64) -> Status {
    *calls += 1;
    let Some(claim) = ledger.claim(id) else {
        return Status::Unchecked;
    };
    let verdicts = ledger.verdicts(id);
    if verdicts
        .iter()
        .any(|v| matches!(v, Verdict::Refuted { .. }))
    {
        return Status::Refuted;
    }
    let mut blocked = false;
    for p in &claim.premises {
        blocked |= status_by_recursion(ledger, p, calls) != Status::Held;
    }
    if blocked {
        Status::Blocked
    } else if verdicts.is_empty() {
        Status::Unchecked
    } else {
        Status::Held
    }
}

/// `levels` held claims, each resting on the two before it.
fn chained_diamonds(levels: u64) -> Res<(Ledger, ClaimId)> {
    let mut ledger = Ledger::default();
    let mut ids: Vec<ClaimId> = Vec::new();
    for n in 0..levels {
        let event = proposed(n, &ids[ids.len().saturating_sub(2)..])?;
        if let Event::Proposed { claim } = &event {
            ids.push(claim.get().id()?);
        }
        ledger.apply(event)?;
        ledger.apply(held(&ids[ids.len() - 1]))?;
    }
    let last = ids.pop().ok_or("no levels")?;
    Ok((ledger, last))
}

fn writes(latencies: &[Duration], took: Duration) -> String {
    format!(
        "{:.0} events/s; write latency p50 {:.2?}, p99 {:.2?}",
        per_second(latencies.len(), took),
        percentile(latencies, 50),
        percentile(latencies, 99)
    )
}

fn main() -> Res {
    let dir = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "target/ledger-bench".into());
    let dir = Path::new(&dir);
    let created = prepare(dir)?;
    let mut report = Report { broken: false };
    println!("| Scenario | Result | Budget |\n| --- | --- | --- |");
    let ids = core_rows(&mut report)?;
    storage_rows(&mut report, dir, &ids)?;
    interactive_rows(&mut report, dir, &ids[..MEDIUM])?;
    clean(dir, created)?;
    if report.broken {
        return Err("a budget is broken".into());
    }
    Ok(())
}

/// Makes `dir` ready for the run, or refuses it if it holds anything: none of that
/// would be the run's to delete. Returns whether the run created `dir`.
fn prepare(dir: &Path) -> Res<bool> {
    if !dir.exists() {
        std::fs::create_dir_all(dir)?;
        return Ok(true);
    }
    if std::fs::read_dir(dir)?.next().is_some() {
        return Err(format!(
            "{} is not empty; give a new or empty directory",
            dir.display()
        )
        .into());
    }
    Ok(false)
}

/// Removes what the run put in `dir`, and `dir` itself if the run created it.
fn clean(dir: &Path, created: bool) -> Res {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            std::fs::remove_dir_all(entry.path())?;
        } else {
            std::fs::remove_file(entry.path())?;
        }
    }
    if created {
        std::fs::remove_dir(dir)?;
    }
    Ok(())
}

/// In-memory rows. Returns the ids of the 1,000,000 claims for the storage rows.
fn core_rows(report: &mut Report) -> Res<Vec<ClaimId>> {
    let (mut ledger, ids, took) = build(LARGE)?;
    row(
        "Core: hash, admit and apply a claim",
        &format!("{:.0} claims/s", per_second(LARGE, took)),
    );
    let start = Instant::now();
    let held_now = ledger
        .statuses()
        .filter(|(_, s)| *s == Status::Held)
        .count();
    row(
        "Status of 1,000,000 claims, one pass in dependency order",
        &format!("{:.1?}", start.elapsed()),
    );
    let start = Instant::now();
    ledger.apply(held(&ids[0]))?;
    let held_after = ledger
        .statuses()
        .filter(|(_, s)| *s == Status::Held)
        .count();
    let took = start.elapsed();
    assert_eq!(
        (held_now, held_after),
        (0, 1),
        "the verdict changed one status"
    );
    report.budget(
        "Recompute status after one verdict, 1,000,000 claims",
        &format!("{took:.1?}"),
        "under 50 ms",
        took < Duration::from_millis(50),
    );
    drop(ledger);

    // One page of a claim list, the way `ask` builds it: the last page is the worst case.
    let (medium, _, _) = build(MEDIUM)?;
    let cursor = &ids[MEDIUM - 201];
    let start = Instant::now();
    let rows = medium.claims().zip(medium.statuses());
    let page: Vec<String> = rows
        .skip_while(|((id, _), _)| *id != cursor)
        .skip(1)
        .take(200)
        .map(|((id, claim), (_, status))| format!("{status:?} {id} {}", claim.sentence()))
        .collect();
    let took = start.elapsed();
    assert_eq!(page.len(), 200);
    report.budget(
        "One page of a claim list (200 rows) at 100,000 claims",
        &format!("{took:.1?}"),
        "under 16 ms",
        took < Duration::from_millis(16),
    );
    drop(medium);

    let (diamonds, last) = chained_diamonds(35)?;
    let (mut calls, start) = (0, Instant::now());
    let by_recursion = status_by_recursion(&diamonds, &last, &mut calls);
    let slow = start.elapsed();
    let start = Instant::now();
    assert_eq!(diamonds.status(&last), Some(by_recursion));
    row(
        "Status over 35 chained diamond dependencies",
        &format!(
            "plain recursion: {calls} calls, {slow:.1?}; the core: {:.0?}",
            start.elapsed()
        ),
    );

    Ok(ids)
}

fn storage_rows(report: &mut Report, dir: &Path, ids: &[ClaimId]) -> Res {
    let took = bulk_import(&dir.join("large.db"), ids)?;
    let rate = per_second(LARGE, took);
    report.budget(
        "Bulk import, batches of 512, `synchronous=NORMAL`",
        &format!("{rate:.0} events/s"),
        "at least 50,000 events/s",
        rate >= 50_000.0,
    );
    let size = std::fs::metadata(dir.join("large.db"))?.len();
    row(
        "Database size",
        &format!("{} MB for 1,000,000 events", size / 1_000_000),
    );
    let start = Instant::now();
    assert_eq!(replay(dir.join("large.db"))?.ledger.claims().count(), LARGE);
    let took = start.elapsed();
    report.budget(
        "Cold start by replay, 1,000,000 events",
        &format!("{took:.2?} ({:.0} events/s)", per_second(LARGE, took)),
        "under 10 s",
        took < Duration::from_secs(10),
    );
    bulk_import(&dir.join("medium.db"), &ids[..MEDIUM])?;
    Ok(())
}

/// Interactive use on a ledger of 100,000 claims.
fn interactive_rows(report: &mut Report, dir: &Path, ids: &[ClaimId]) -> Res {
    let start = Instant::now();
    let store = Store::open(dir.join("medium.db"))?;
    let took = start.elapsed();
    report.budget(
        "Cold start by replay, 100,000 events",
        &format!("{took:.0?}"),
        "under 1 s",
        took < Duration::from_secs(1),
    );

    // A durable write cannot be faster than the disk's flush, so the write budgets are
    // stated against a flush measured here, on the same disk.
    let flush = flush_time(dir)?;
    row(
        "One disk flush (sync of a 4 KB append), median",
        &format!("{flush:.2?}"),
    );
    let (latencies, took, reads) = interactive(&store, ids, READERS)?;
    let (p50, p99) = (percentile(&latencies, 50), percentile(&latencies, 99));
    report.budget(
        "7 agents, each waiting for a durable write (group commit, `synchronous=FULL`), 7 readers running",
        &writes(&latencies, took),
        "p50 under one flush plus 2 ms, p99 under 25 ms",
        p50 < flush + Duration::from_millis(2) && p99 < Duration::from_millis(25),
    );
    let rate = per_second(latencies.len(), took);
    let floor = (5.0 / flush.as_secs_f64()).min(1000.0);
    report.budget(
        "Sustained interactive writes, the same run",
        &format!("{rate:.0} events/s"),
        &format!("at least 1,000 events/s, or 5 per flush on a slower disk ({floor:.0})"),
        rate >= floor,
    );
    let p99 = percentile(&reads, 99);
    report.budget(
        "Status of one claim while writing, 7 readers",
        &format!(
            "{:.0} reads/s in total; p50 {:.1?}, p99 {p99:.1?}",
            per_second(reads.len(), took),
            percentile(&reads, 50)
        ),
        "p99 under 1 ms",
        p99 < Duration::from_millis(1),
    );
    drop(store);
    let store = Store::open_bulk(dir.join("normal.db"))?;
    let (latencies, took, _) = interactive(&store, &ids[..1], 0)?;
    row(
        "Same writes, `synchronous=NORMAL`, no readers",
        &writes(&latencies, took),
    );
    drop(store);
    let (latencies, took) = one_transaction_per_event(&dir.join("single.db"))?;
    row(
        "Same writes, one transaction per event (no group commit)",
        &writes(&latencies, took),
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_scratch_directory_is_left_as_it_was() -> Res {
        let parent = tempfile::tempdir()?;
        // What is in the directory already is never the run's to delete.
        let full = parent.path().join("full");
        std::fs::create_dir(&full)?;
        std::fs::write(full.join("keep"), b"")?;
        assert!(prepare(&full).is_err());
        assert!(full.join("keep").exists());
        // An empty directory is emptied again, and one the run made is removed.
        let empty = parent.path().join("empty");
        std::fs::create_dir(&empty)?;
        for (dir, kept) in [(empty, true), (parent.path().join("new"), false)] {
            let created = prepare(&dir)?;
            std::fs::write(dir.join("large.db"), b"")?;
            std::fs::create_dir(dir.join("large.db.evidence"))?;
            clean(&dir, created)?;
            assert_eq!(dir.exists(), kept);
            if kept {
                assert_eq!(std::fs::read_dir(&dir)?.count(), 0);
            }
        }
        Ok(())
    }
}
