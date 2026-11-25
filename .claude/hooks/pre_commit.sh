#!/usr/bin/env bash
# PreToolUse on Bash: before `git commit`, run scripts/ci.sh and block the commit if it fails.
set -uo pipefail

cmd=$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("tool_input",{}).get("command",""))')
# The `if` filter is best effort, so confirm this really is a commit.
grep -qE '(^|[;&|[:space:]])git([[:space:]]+-[cC][[:space:]]+[^[:space:]]+)*[[:space:]]+commit\b' <<<"$cmd" || exit 0

root=${CLAUDE_PROJECT_DIR:-$(git rev-parse --show-toplevel)}
if ! out=$("$root/scripts/ci.sh" 2>&1); then
    { echo "scripts/ci.sh failed; commit blocked. Last output:"; tail -40 <<<"$out"; } >&2
    exit 2
fi
exit 0
