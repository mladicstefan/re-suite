# Trial 4: a new build

26 November 2026. The version rerun on a prepared pair of builds.

## Setup

`version-rerun.sim.py` writes two builds of a toy game backend as HAR
files, and four save records of each build. Build 2 differs from build 1
in five known ways:

| Part | Change in build 2 |
| --- | --- |
| Score endpoint | renamed from `/api/v1/score` to `/api/v2/score`; signature unchanged |
| Purchase response | `balance` is a string where it was an integer |
| Profile response | unchanged |
| Legacy ping | removed |
| Save record | four bytes inserted after the magic |

Five claims were filed on build 1 through the real `ledger-mcp` binary,
one per part, and all five held. The CLI then reran them on build 2:

```
ledger-cli ledger.db --rerun-har build2.har --rerun-snapshots saves2
```

## Result

Every part was reported as what it is.

| Claim | Report |
| --- | --- |
| Score requests carry an HMAC-SHA256 signature | **moved**: it holds for `POST game.example/api/v2/score`, on 6 captures |
| Purchase responses have an integer `balance` | **failed**: `"990.00" is not of type "integer" at /balance (6 of 6 captures disagree)` |
| Profile responses have `id`, `level` and `name` | **holds** on 6 captures |
| The legacy ping only answers 200 | **no evidence**: the new build has no capture this claim is about |
| `SaveRecord` is 20 bytes with four typed fields | **moved**: the fields from +0x4 on are 4 bytes later, and the type is 24 bytes, on 4 captures |

Rerunning on build 1 itself gives five times "holds".

## How a claim finds its captures in a new build

A web claim is tied to its endpoint and the responses it covers. A claim
about snapshots is tied to its type name: the new build's snapshots are
given as one directory per type. Signing keys are read from the ledger's
own evidence.

"Moved" comes from a bounded search, and is a suggestion for a new claim:

- a failed layout is tried with all fields from one offset on shifted by
  up to 64 bytes, and at least two typed fields must move together;
- a web claim with no captures is tried under endpoints that differ in at
  most two literal path segments or the host.

## Limits

- **The pair is simulated.** The five changes are ones the search was
  built for. Which anchor survives real version changes with the fewest
  false matches is still an open question in the roadmap.
- **The rerun records nothing.** It reads the ledger and prints a report.
  A verdict per build needs contexts, which are Phase 6: today one
  refuted verdict refutes a claim for good, so recording build 2's
  failures would overwrite what is known about build 1.
- **Only held claims are rerun.** Claims that are refuted, retracted,
  unchecked or on hold are left out.
- **Moves are not combined.** An endpoint that was renamed and whose
  response also changed is reported as no evidence, not as moved.
