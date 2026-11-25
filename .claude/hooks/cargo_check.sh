#!/usr/bin/env bash
# PostToolUse: after an edit to a .rs file, `cargo check` only the crate that owns it.
# Exit 2 puts the errors in front of the agent; the edit itself already happened.
set -uo pipefail

file=$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("tool_input",{}).get("file_path",""))')
[[ "$file" == *.rs ]] || exit 0

dir=$(dirname "$file")
while [[ "$dir" != / && ! -f "$dir/Cargo.toml" ]]; do dir=$(dirname "$dir"); done
[[ -f "$dir/Cargo.toml" ]] || exit 0
crate=$(python3 -c 'import sys,tomllib; print(tomllib.load(open(sys.argv[1],"rb")).get("package",{}).get("name",""))' "$dir/Cargo.toml")
[[ -n "$crate" ]] || exit 0

cd "$dir" || exit 0
if ! out=$(cargo check -p "$crate" --quiet --message-format short 2>&1); then
    { echo "cargo check -p $crate failed:"; grep -E '^(error|.*: error)' <<<"$out" | head -40; } >&2
    exit 2
fi
exit 0
