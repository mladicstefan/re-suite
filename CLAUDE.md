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
- `crates/ledger-cli`: prints claims with status from a ledger file. Its second binary, `ledger-capture`, is how a person takes a live capture.
- `crates/ledger-bench`: `cargo run --release -p ledger-bench` checks the ROADMAP.md budgets.

## Checks
- Tools: `flake.nix` pins every outside tool (Rust, cargo tools, Rizin, Kaitai compiler, gdb, uv, llvm, Node, Chromium).
  Run anything that needs one with `nix develop -c <command>`. Never install a tool on the machine; add it to the flake.
  npm tools are pinned in `tools/js`: add one with `npm install --package-lock-only --save-exact --ignore-scripts <name>` there.
  `tools/fingerprint` is a Go wrapper; after changing its dependencies, refresh `vendorHash` in the flake.
- Full CI: `scripts/ci.sh` (fmt, clippy -D warnings, clippy of ledger-os for Windows and macOS, nextest, doctests, cargo deny, cargo machete, uv lock check).
  It enters the flake's shell itself.
- Hooks in `.claude/settings.json` run `cargo check -p <crate>` after `.rs` edits and
  `scripts/ci.sh` before `git commit`; they also guard protected config, hand-written
  versions and uncommented `#[allow]`.
- Python (trial scripts, pypcode, kaitaistruct, Z3): `uv run --locked <script>`. Packages and the Python version
  are pinned in `pyproject.toml`, `.python-version` and `uv.lock`; uv downloads both into `.venv`. Add a package
  with `uv add` only, never with pip or the system's package manager.
- New insta snapshots: `INSTA_UPDATE=always cargo test -p ledger-core`, then review the `.snap` diff.

## Rules
Read the `ledger-rules` skill (`.claude/skills/ledger-rules/SKILL.md`) before
changing any crate. Add dependencies with `cargo add` only.
