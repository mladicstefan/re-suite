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
- Timestamps may be stored on events (ledger-store `recorded_at` column) but never
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

## Compile time first
- Prefer `const` items and `const fn` over values computed at run time, and
  over macros wherever a `const fn`, an associated const or a generic can say
  the same thing.
- Limits, versions and ids are named constants, never repeated literals.
- `clippy::missing_const_for_fn` is on for the whole workspace, so CI fails on
  a function that could be `const` and is not.

## OS-dependent code lives in its own crate
- Anything that differs by operating system (memory mapping, file locking,
  flush calls, process and memory limits, sandboxing) goes in a crate of its
  own, never inline in the core, the store, the checkers or the server.
- That crate selects the system's functions at compile time with `#[cfg(...)]`
  and exposes one portable API. No run-time checks of the operating system.

## IO is never skipped
- Blocking work (SQLite, hashing, file IO, checks) never runs on the async
  executor: hand it to the blocking pool or use async IO.
- Do not put off IO, durability or concurrency work behind a `shortcut:`
  comment, even where existing code did.

## Dependencies
- Add with `cargo add -p <crate> <dep>`; never write or edit a version in a
  `Cargo.toml` by hand. Commit `Cargo.lock`.
- Do not add: sonic-rs, mimalloc, rustc-hash, smallvec, petgraph, zerocopy,
  salsa, uuid, or any UI crate.
