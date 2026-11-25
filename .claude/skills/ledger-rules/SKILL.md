---
name: ledger-rules
description: Invariants of the replay ledger in this repo. Use before changing any crate under crates/, adding a claim kind, evidence type, checker, event or dependency.
---

# Ledger rules

These are invariants, not style. A change that breaks one is wrong even if CI passes.

## ledger-core stays pure
- Synchronous only: no IO, no async, no SQLite, no network.
- No clocks (`SystemTime`, `Instant`, `jiff::Timestamp::now`) and no randomness
  without an explicit seed passed in by the caller.
- IO belongs in ledger-store, async and tokio in ledger-mcp only.

## IDs are content hashes
- `ClaimId` and `EvidenceId` are blake3 hashes of canonical content
  (`ClaimId::of`, `EvidenceId::of`, `Claim::id`).
- Never mint random, sequential or time-based IDs for them. No uuid.
- Timestamps may be stored on events (ledger-store `at` column) but never
  enter a hash.
- Use `BTreeMap`/`BTreeSet` in hashed types so canonical JSON is deterministic.

## Status is derived, never stored
- `Ledger::status` computes it from verdicts and premises on read.
- Never add a status column, field, setter or event that sets it directly.

## One way in, one way to change
- Nothing enters the ledger except through `admit`, which returns
  `WellFormed<Claim>`. Do not add another constructor for `WellFormed`.
- The ledger changes only through `Event`s applied by `Ledger::apply`.
  The events table is append-only; never UPDATE or DELETE it.

## Verdicts carry their proof
- A refutation must carry a `Counterexample` (evidence ID + detail).
- A held verdict must carry a non-zero run count (`NonZeroU64`).
- A certificate is built only by prover code; never construct one in a
  checker, the MCP server, the CLI or a test helper outside the prover.

## Adding a claim kind
Every new `ClaimKind` variant needs all four, in the same change:
1. A schema: derive `JsonSchema` so MCP tool inputs pick it up.
2. An admission check in `admit`.
3. A sentence template in `Claim::sentence` with an insta snapshot test.
4. A checker in ledger-checkers behind the `Checker` trait, wired into
   `check_claim`, with at least one test.

## Checkers are offline
- Checkers replay saved evidence only. Never send anything to a live target.

## Dependencies
- Add with `cargo add -p <crate> <dep>`; never write or edit a version in a
  `Cargo.toml` by hand. Commit `Cargo.lock`.
- Do not add: sonic-rs, mimalloc, rustc-hash, smallvec, petgraph, zerocopy,
  salsa, uuid, or any UI crate.
