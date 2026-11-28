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
- A verdict counts only while its checker is at the version the log last listed
  (`Event::CheckersSet`, written by the server when it starts). Bump a checker's
  `VERSION` whenever it could answer differently, and add every new checker to
  `ledger_checkers::CHECKERS`; an unlisted checker is refused.

## One way in, one way to change
- Nothing enters the ledger except through `admit`, which returns
  `WellFormed<Claim>`. Do not add another constructor for `WellFormed`.
- Stored proposals are admitted again when a ledger loads. One that today's
  rules refuse is loaded as withdrawn (`Event::Lapsed`), never as a live
  claim and never as an error: tightening a rule must not make a ledger
  unreadable.
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

## Format descriptions
- A `format` claim's description is Kaitai Struct, and only part of it is read
  (`ledger_core::format`). A key or type outside that part is refused by name at
  admission, never skipped.
- For now the checker walks the description itself (`ledger_checkers::format`).
  The decision is to replace that reader with the Kaitai compiler's generated
  parser, run in a worker process with time and memory limits. Do not grow the
  reader; build the worker instead.
- `tests/kaitai_oracle.rs` compares the reader with the Kaitai compiler's parser.
  Reading more of the language means adding a case there, and bumping
  `FormatChecker::VERSION`.

## Checkers are offline
- Checkers replay saved evidence only. Never send anything to a live target.

## Outside tools run in one place
- Only `ledger-mcp`'s `runner` module starts a process. Checkers, the store and
  the CLI never do; a checker reads what a tool printed from stored evidence. The
  one exception is `ledger-capture web`, which starts Chromium for a person (below).
- A tool is one entry in `runner::ADAPTERS` and its output parser. Adding one
  changes nothing else but the flake.
- A program is found only by the absolute path in `LEDGER_TOOL_<ID>`, which
  `flake.nix` sets to a store path. Never search PATH, and refuse a relative path.
- It runs with an empty environment and no stdin, on copies of its inputs in a
  private temporary directory that is its working directory, with a time limit,
  one run at a time per tool.
- Every run is confined by `ledger_os::confined`, and the runner has no other way
  to start a program. On Linux that is bubblewrap, found by `LEDGER_TOOL_BWRAP`:
  the tool sees the Nix store read-only, its directory, an empty `/tmp` of 64 MiB,
  its own `/proc` and a read-only `/dev`. No network, no home directory, no ledger
  or evidence files, no other process, and it dies with the server. A program
  outside the store cannot be started, so a tool that loads anything from the host
  (a prebuilt binary that asks for `/lib64/ld-linux-x86-64.so.2`) is patched in the
  flake. Where no confinement is written, no tool starts (`tool_unconfined`).
- Each adapter names a memory limit and an output limit. The runner reads the
  resident memory of the tool's processes every 20 ms (`ledger_os::resident`) and
  stops it above the limit (`tool_over_memory`); it keeps at most the output limit
  of what the tool prints and stops it past that (`tool_over_output`).
- Not confined: the size of files a tool writes in its own directory, memory the
  kernel holds for it outside its processes (pipes, `memfd`), which system calls
  it makes (no seccomp filter), and the CPU it uses until its time limit. `ledger-capture web` and its browser are
  started by a person, not by the runner, and are not confined.
- What it prints is stored as evidence and logged as `Event::Derived`: the tool,
  the version it reported, the inputs and the output, all evidence the ledger
  holds. The same tool, version and inputs never run twice. A file stored as it
  is, such as a program or a script, is `artifact` evidence.

## Live captures are a person's
- Memory of a running process is read by `ledger-capture` only, for a person at a
  terminal who types the process's name. Never read a process from the server, a
  checker or a test of another process, and never give the tool a terminal it does
  not have (`script`, a pty) to get past the question.
- What the person saw travels in the capture's first line, so it is under the
  evidence's hash. A layout field named like a seen value must read as it.
- A browser session is captured by `ledger-capture web` only, for a person at a
  terminal who names the hosts with `--host` and types the first one; `memory` and
  `web` share one gate. Chromium is found by `LEDGER_TOOL_CHROMIUM`, gets a new
  profile and the cache off, and keeps the person's environment (a window needs
  their display). A request to any other host is refused before it is sent, by the
  protocol's fetch interception on every page, and no other host name resolves; the
  refused hosts are listed in the session, never fetched.
- A real host's name is given at run time only. Tests serve their own site on
  loopback, and no file in the repository names a real target.

## Playbooks
- A playbook is a file in `playbooks/` and one row in `ledger-mcp`'s
  `playbooks::PLAYBOOKS`: an id, a title, a function of the ledger that says
  whether it applies, one line saying why, and the file compiled in. Adding one
  changes nothing else.
- Write it in short, plain sentences, and say what the agent cannot do itself.

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
- That crate is `crates/ledger-os`. It selects the system's functions at
  compile time with `#[cfg(...)]` and exposes one portable API. No run-time
  checks of the operating system.
- No other crate uses `#[cfg]` on the system, `std::os` or a crate that wraps
  system calls (memmap2 and the like). Add what you need to `ledger-os`.
- A change there must still compile for the other systems:
  `cargo clippy -p ledger-os --target x86_64-pc-windows-gnu -- -D warnings`,
  and the same for `aarch64-apple-darwin`.

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
