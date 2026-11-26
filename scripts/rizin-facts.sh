#!/bin/sh
# Exports what Rizin recovers from a binary as one JSON document, for
# `add_evidence kind=binary_facts`. The binary is read, never run.
# usage: scripts/rizin-facts.sh <binary> > facts.json
set -eu
bin=${1:?usage: rizin-facts.sh <binary>}
ANALYSIS=aaa
printf '{"tool":"%s (%s)","hashes":' "$(rizin -v | head -n1)" "$ANALYSIS"
rizin -q -e scr.color=0 -c iTj "$bin"
printf ',"imports":'
rizin -q -e scr.color=0 -c iij "$bin"
printf ',"relocs":'
rizin -q -e scr.color=0 -c irj "$bin"
printf ',"functions":'
rizin -q -e scr.color=0 -c "$ANALYSIS; aflj" "$bin"
printf '}\n'
