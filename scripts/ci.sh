#!/usr/bin/env bash
# Full local CI. Run from anywhere; fails on the first broken step.
set -euo pipefail
cd "$(dirname "$0")/.."
# Every tool below comes from flake.lock, not from this machine.
[ -n "${IN_NIX_SHELL:-}" ] || exec nix develop --command scripts/ci.sh "$@"

run() { printf '\n==> %s\n' "$*"; "$@"; }

run cargo fmt --all --check
run cargo clippy --workspace --all-targets -- -D warnings
# ledger-os picks the system's functions at compile time; the other systems must lint too.
for target in x86_64-pc-windows-gnu aarch64-apple-darwin; do
  run cargo clippy -p ledger-os --target "$target" -- -D warnings
done
run cargo nextest run --workspace
run cargo test --workspace --doc
run cargo deny check
run cargo machete
run uv lock --check
printf '\nci: all checks passed\n'
