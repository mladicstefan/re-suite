//! Prints every claim in a ledger file with its derived status, or re-checks the
//! claims it holds against the captures of a new build of the target.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Context as _;
use clap::Parser;
use ledger_checkers::rerun::{Build, Outcome, rerun};
use ledger_core::{ClaimKind, Ledger};

#[derive(Parser)]
#[command(about = "Print claims in a ledger file with their status, or rerun them on a new build")]
struct Args {
    /// Ledger file (SQLite).
    ledger: PathBuf,
    /// Rerun held web claims on this HAR file, recorded from a new build of the target.
    #[arg(long)]
    rerun_har: Option<PathBuf>,
    /// Rerun held snapshot claims on this directory: one subdirectory per type name,
    /// each file in it one snapshot of that type from the new build.
    #[arg(long)]
    rerun_snapshots: Option<PathBuf>,
}

/// Reads the new build's captures. Signing keys come from the ledger's own evidence.
fn build(args: &Args, ledger: &Ledger) -> anyhow::Result<Build> {
    let mut build = Build::default();
    if let Some(har) = &args.rerun_har {
        let bytes = std::fs::read(har).with_context(|| format!("reading {}", har.display()))?;
        let exchanges = ledger_checkers::har_exchanges(&bytes)
            .with_context(|| format!("{} is not a HAR file", har.display()))?;
        build.add_exchanges(exchanges);
    }
    if let Some(dir) = &args.rerun_snapshots {
        for (type_name, file) in snapshot_files(dir)? {
            build.add_snapshot(&type_name, std::fs::read(&file)?);
        }
    }
    for (_, claim) in ledger.claims() {
        if let ClaimKind::RequestSignature(signature) = &claim.kind
            && let Some(key) = ledger_store::evidence_at(&args.ledger, &signature.key)?
        {
            build.add_secret(signature.key.clone(), key.to_vec());
        }
    }
    Ok(build)
}

/// Every `<dir>/<type name>/<file>`, as the type name and the file.
fn snapshot_files(dir: &Path) -> anyhow::Result<Vec<(String, PathBuf)>> {
    let mut files = Vec::new();
    for subdir in std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let subdir = subdir?.path();
        let Some(type_name) = subdir.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if subdir.is_dir() {
            for file in std::fs::read_dir(&subdir)? {
                let file = file?.path();
                // Only files are snapshots; a directory inside cannot be read as one.
                if file.is_file() {
                    files.push((type_name.to_owned(), file));
                }
            }
        }
    }
    files.sort();
    Ok(files)
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let ledger = ledger_store::replay(&args.ledger)
        .with_context(|| format!("opening {}", args.ledger.display()))?
        .ledger;
    if args.rerun_har.is_none() && args.rerun_snapshots.is_none() {
        for ((id, claim), (_, status)) in ledger.claims().zip(ledger.statuses()) {
            println!("{status:?}\t{id}\t{}", claim.sentence());
        }
        return Ok(());
    }
    let build = build(&args, &ledger)?;
    for row in rerun(&ledger, &build, Duration::from_secs(5)) {
        let (outcome, detail) = match row.outcome {
            Outcome::Holds { runs } => ("holds", format!("on {runs} captures")),
            Outcome::Failed { detail } => ("failed", detail),
            Outcome::Moved { to, runs } => ("moved", format!("{to}, on {runs} captures")),
            Outcome::NoEvidence => (
                "no evidence",
                "the new build has no capture this claim is about".to_owned(),
            ),
            Outcome::Unknown { reason } => ("unknown", reason),
        };
        println!(
            "{outcome}\t{}\t{}\n\t{detail}",
            &row.id.as_str()[..12],
            row.claim.sentence()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::snapshot_files;

    #[test]
    fn a_subdirectory_of_a_type_directory_is_not_a_snapshot() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let player = dir.path().join("Player");
        std::fs::create_dir_all(player.join("older"))?;
        std::fs::write(player.join("one.bin"), [0u8; 4])?;
        std::fs::write(dir.path().join("notes.txt"), "not a type")?;
        assert_eq!(
            snapshot_files(dir.path())?,
            [("Player".to_owned(), player.join("one.bin"))]
        );
        Ok(())
    }
}
