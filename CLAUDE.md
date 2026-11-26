# re-suite: replay ledger

Backend of an agent-first reverse-engineering workbench (binaries, web APIs,
games, firmware, network captures). AI agents do the analysis; a human verifies
and steers. The core is a replay ledger: every finding is filed as a typed,
machine-checkable claim, re-checked offline against saved evidence (memory
snapshots, captured requests), and shown to the human as a plain sentence with a
status and a counterexample when it fails. Nothing is ever sent to a live
target; all checks replay captures.

## Crate map
- `crates/ledger-core`: pure sync model (claims, `admit`, events, verdicts, derived status). No IO.
- `crates/ledger-os`: everything that differs by operating system, picked at compile time. No other crate uses `#[cfg]` on the system or `std::os`.
- `crates/ledger-store`: SQLite WAL, single writer thread with group commit, published snapshots, append-only events, evidence files by hash.
- `crates/ledger-checkers`: offline checkers behind the `Checker` trait.
- `crates/ledger-mcp`: stdio MCP server (propose, ask, explain, add_evidence, retract). Only crate with tokio.
- `crates/ledger-cli`: prints claims with status from a ledger file.
- `crates/ledger-bench`: `cargo run --release -p ledger-bench` checks the ROADMAP.md budgets.

## Checks
- Full CI: `scripts/ci.sh` (fmt, clippy -D warnings, clippy of ledger-os for Windows and macOS, nextest, doctests, cargo deny, cargo machete).
  The two extra targets come from `rustup target add x86_64-pc-windows-gnu aarch64-apple-darwin`.
- Hooks in `.claude/settings.json` run `cargo check -p <crate>` after `.rs` edits and
  `scripts/ci.sh` before `git commit`; they also guard protected config, hand-written
  versions and uncommented `#[allow]`.
- New insta snapshots: `INSTA_UPDATE=always cargo test -p ledger-core`, then review the `.snap` diff.

## Rules
Read the `ledger-rules` skill (`.claude/skills/ledger-rules/SKILL.md`) before
changing any crate. Add dependencies with `cargo add` only.
