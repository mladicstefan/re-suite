//! Prints every claim in a ledger file with its derived status.

use std::path::PathBuf;

use anyhow::Context as _;
use clap::Parser;

#[derive(Parser)]
#[command(about = "Print claims in a ledger file with their status")]
struct Args {
    /// Ledger file (SQLite).
    ledger: PathBuf,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let ledger = ledger_store::replay(&args.ledger)
        .with_context(|| format!("opening {}", args.ledger.display()))?;
    for (id, claim) in ledger.claims() {
        let status: ledger_core::Status =
            ledger.status(id).context("claim vanished during listing")?;
        println!("{status:?}\t{id}\t{}", claim.sentence());
    }
    Ok(())
}
