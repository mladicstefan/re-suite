#!/usr/bin/env bash
# Full local CI. Run from anywhere; fails on the first broken step.
set -euo pipefail
cd "$(dirname "$0")/.."

run() { printf '\n==> %s\n' "$*"; "$@"; }

run cargo fmt --all --check
run cargo clippy --workspace --all-targets -- -D warnings
run cargo nextest run --workspace
run cargo test --workspace --doc
run cargo deny check
run cargo machete
printf '\nci: all checks passed\n'
