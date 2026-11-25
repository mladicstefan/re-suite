# Trial 1: Half-Life save files

25 November 2026. The Phase 1 trial run: one agent session on one small
target, through the real `ledger-mcp` binary, with the three metrics from
ROADMAP.md section 11.

## Setup

- **Target:** the six `.sav` files left in a Steam Half-Life install. The
  format is publicly documented, so a claim can be graded.
- **Evidence:** the six files, plus 780 snapshots carved from them (every
  directory entry, the first bytes of every embedded `.HL1`, `.HL2` and
  `.HL3` file, and the first bytes after each token table). 165 are
  distinct; identical snapshots share one id.
- **Agent:** Claude, in the coding session that built the ledger. It read
  the bytes with `xxd` and small scripts, and filed every claim as a
  JSON-RPC `tools/call` to the server over stdio. It was not a separate
  agent with the server attached as an MCP tool.
- **Ledger:** on tmpfs, so write latency here says nothing about the disk.
- **Record:** `half-life-saves.session.jsonl` has every call except the
  786 `add_evidence` calls, whose arguments are local paths.

## What held

| Claim | Size | Held on |
| --- | --- | --- |
| `SaveFile`: magic `JSAV`, version 113, size, token count 4095, token size 4166, 76 zero bytes | 96 | 6 saves |
| `SaveDirEntry`: name as text in 260 bytes, then a 4-byte size | 264 | 95 entries |
| `Hl1Header`: magic `VALV`, version 113, expanded size, entity count, token count 4095, token size | 24 | 21 files |
| `Hl2Header`: magic `VALV`, version 113, count | 12 | 21 files |
| `Hl3Header`: a count | 4 | 16 files |
| `GameHeaderRecords`: three (size, token, value) records, the third a 32-byte map name | 52 | 5 saves |

`SaveDirEntry` rests on `SaveFile`, and the three embedded headers rest
on `SaveDirEntry`.

## What was caught

The agent's first reading of `.HL3` was "a constant 6, then a small
count". The ledger refuted it: `field format at +0x0 is 7, outside 6 to
6`. Looking at that snapshot showed the first word is the count of the
words that follow, and that it can be 0. The revised claim held. A claim
built on the refuted one was refused with `premise_refuted`.

## Metrics

1. **Deliberately wrong claims caught: 20 of 21 (95.2%).** Each was one
   plausible mistake applied to a true claim: a field moved, a constant
   changed, a range too tight, a type swapped. The one that held put the
   map name four bytes early, where the bytes are `20 00`: a one-space
   string followed by NUL, which `text` accepts.
2. **Attempts per accepted claim: 7 hypotheses for 6 accepted claims
   (1.17).** Counting every `propose` call it is 11 for 6: two were
   deliberate replays on more evidence and two were refused by a ledger
   bug (below). Tool input and output for those 11 calls was 10,668
   characters, about 440 tokens per accepted claim. The agent's own
   reasoning tokens could not be measured from inside the session.
3. **Claims that passed and later failed: 0 of 2.** Two claims were filed
   on a small sample first (1 of 6 saves, 3 of 95 entries) and replayed
   on everything; both still held.

Every call started a fresh server process on the same ledger file, about
820 reopens; no status changed across them.

## Findings

- **Fixed: admission ordered fields by name, not offset.** The first
  claim of the trial was refused as "overlapping" because its field names
  were not in offset order. No earlier test had such a claim.
- **Fixed: the row cut off "contents checked for N of M fields".** The
  count now comes before the field list.
- **Open: `text` is weak.** One printable character before a NUL is
  enough. A minimum length, or a vacuity check, would have caught the
  one miss.
- **Open: `ask about=affected` lists refuted dependents too**, which
  would not be "put on hold" by anything.
- **Open: adding evidence is one call per file.** 786 calls took most of
  the session's wall time.
