# Roadmap

This file fixes the direction, the order of work, the technology choices and
the engineering rules. It does not fix data structures, module layout or
function signatures. Those belong to whoever implements a milestone, human or
AI, within the rules in the last section.

## 1. What we are building

An agent-first reverse-engineering workbench for binaries, web APIs, games,
firmware and network captures. AI agents do the analysis. A human verifies
their findings and steers.

The core is a **replay ledger**. Every finding an agent makes is filed as a
typed, machine-checkable claim. Each claim is re-checked automatically
against saved evidence, and shown to the human as a plain sentence with a
status and a counterexample when it fails.

The ledger is built first and proven headless. **Interface design is a
critical decision point owned by the human.** Everything that can be built
and proven without that decision is done before it (see the proof gate in
section 9).

## 2. Principles that do not change

1. **Nothing is sent to a live target without human approval.** Checks
   replay captured data.
2. **No finding without a claim.** Agents cannot record free text as a fact.
3. **Nothing enters the ledger without admission.** Malformed or ill-typed
   claims are refused with a reason the agent can act on.
4. **The ledger changes only through events.** Events are appended, never
   edited or removed.
5. **Status is derived, never stored.** A claim shows no stronger than its
   weakest premise.
6. **Refuting a claim puts its dependents on hold.** It does not refute them.
7. **Every verdict carries its evidence.** A refutation has a counterexample,
   a "held" verdict has a non-zero run count, a proof has a certificate.
8. **Identity is content.** Claims and evidence are named by the hash of
   their content.
9. **Three statuses that differ in kind:** agent's reading only, held on N
   runs, proved (with its assumptions listed).
10. **The core is a small, pure, deterministic state machine.** The same
    events in the same order give the same state, bit for bit.

## 3. Technology choices

| Area | Choice | Notes |
| --- | --- | --- |
| Language | Rust, current stable | One workspace, several crates |
| Ledger core | Pure, synchronous Rust library | No IO, no async, no database, no clock |
| Storage | SQLite, embedded, WAL mode | One writer, many readers; append-only event log |
| Evidence | Files on disk, named by hash | The database only indexes them |
| Hashing | BLAKE3 | For all content addressing |
| Claim format | Closed set of typed kinds; JSON on the wire | JSON Schema generated from the Rust types |
| Agent interface | MCP server over stdio | Five verbs: propose, ask, explain, add evidence, retract |
| Async runtime | Tokio, in the MCP server binary only | Never in a library crate |
| CPU-bound checks | Rayon worker pool | Outside the write path |
| Heavy checks | Separate worker processes | May be Python where the libraries live |
| File and protocol formats | Kaitai Struct | Phase 2 |
| Binary analysis | Rizin | Phase 2 onwards |
| Second lifter | P-code through pypcode | Phase 5, for cross-checking |
| Solver | Bitwuzla or Z3 | Phase 5, small scope first |
| Proof certificates | Lean 4, bit-level lemmas only | Phase 6, optional |
| Testing | Property, snapshot, crash and doc tests | Lemmas are property tests first |
| Quality gates | Formatter, strict lints, dependency audit, CI script, editor hooks | Lints may not be weakened to pass |
| Desktop interface | Native and cross-platform; framework undecided | Chosen by the human at the UI gate |

**Deliberately not used:** a custom database, TigerBeetle (fixed schema),
a graph or Datalog database, random or time-based IDs for claims,
performance crates added before a profile asks for them.

**Undecided, with a decision point:**

- Desktop framework and visual design: the UI gate (section 9).
- Bitwuzla or Z3: the solver spike in Phase 5.
- Whether Rizin alone can support proofs: the Phase 2 lifter measurement.

## 4. Shape of the system

```
agents (7+)            human
   |  five verbs (MCP)   |  read model (later: desktop interface)
   v                     v
+------------------- server process -------------------+
|  async edge (Tokio)  ->  bounded queue  ->  writer    |
|                                            thread     |
|  readers: published snapshot + SQLite read conns      |
+----------+-------------------------------+------------+
           | events (append-only)          | check jobs
           v                               v
     SQLite event log            checker pool / worker processes
     + evidence files   <- read -   (replay, formats, solver, Lean)
                                           |
                        verdicts return as events through the same queue
```

Crates: a pure core, a store, the checkers, the MCP server, a small CLI.
The desktop interface will be one more consumer of the same read model.

## 5. Concurrency and async model

These rules are fixed. How they are implemented is not.

**Core**

- Single-threaded and deterministic. It takes an event and returns the new
  state or a rejection. No locks, threads, clocks or unseeded randomness
  inside it.
- All library crates expose synchronous APIs. Async appears only at the
  server's edge.

**Writes**

- Exactly one writer thread owns the SQLite write connection and the
  mutable ledger state.
- Producers reach it through one **bounded** queue. A full queue blocks or
  rejects the producer. Nothing buffers without limit.
- **Group commit:** the writer takes everything queued and commits it as
  one transaction. A producer is acknowledged only after its event is
  durable.
- Order of work per batch: validate, commit to disk, apply to memory,
  publish, acknowledge. The sequence number assigned at commit is the one
  total order of the system.
- Proposing the same claim twice is a no-op that returns the same id.

**Reads**

- Readers never block the writer and never see part of a batch.
- Status questions are answered from a published, immutable snapshot of
  the in-memory state. History, paging and search go through read-only
  SQLite connections, one per reader.
- Every response carries the sequence number it was computed at, so a
  caller can tell when what it holds is stale.

**Async edge**

- Tokio lives in the MCP server binary only.
- SQLite calls, hashing of large evidence and checks are blocking work.
  They never run on the async executor.
- No lock is held across an await.
- Handlers stay thin: parse, hand to the writer or read the snapshot,
  reply.

**Checks**

- Checks never run on the writer thread or inside a write transaction.
- A check is a pure function of the claim, its premises, the evidence it
  reads and the checker's version. Those inputs form its cache key.
- Two requests for the same cache key share one run.
- Every check has a time limit and a memory limit, and can be cancelled.
  A check that exceeds a limit yields "unknown", never "held".
- One slow check or one busy agent must not delay other agents' writes or
  reads.
- Verdicts come back as events through the same queue as everything else.

**Lifecycle**

- Shutdown drains the queue, commits and checkpoints.
- A crash at any point loses at most events that were never acknowledged.
  Reopening rebuilds the state by replaying the log.

## 6. Performance

### Measured baseline

Measured on 25 November 2026 with the benchmark in `ledger-bench`
(`cargo run --release`), on a 2-core cloud VM with 7 GB of memory. Events
were about 190 bytes of JSON. Seven writers and seven readers ran at once.

| Scenario | Result |
| --- | --- |
| 7 agents, each waiting for a durable write (group commit, `synchronous=FULL`) | 5,049 events/s; write latency p50 0.50 ms, p99 9.4 ms |
| Same, `synchronous=NORMAL` | 15,659 events/s; p50 0.06 ms, p99 6.5 ms |
| Same, one transaction per event (no group commit) | 961 events/s; p50 5.7 ms, p99 23.2 ms |
| Point reads while writing, 7 readers | 0.6 to 1.5 million reads/s in total; p99 under 60 microseconds |
| Bulk import, batches of 512 | 222,952 events/s |
| Replay: read and parse the log | 922,294 events/s (700,000 events in 0.76 s) |
| Database size | 151 MB for 700,000 events |
| Core: hash, admit and apply a claim | 364,651 claims/s |
| Status of 1,000,000 claims, one pass in dependency order | 6.8 ms |
| Status by plain recursion over 35 chained diamond dependencies | 24 million calls, 48 ms, and about 11 times more for every 5 further levels |

What the baseline shows:

- The load we expect (7 agents, thousands of queries) is far below what
  one writer and SQLite handle. The ledger is not the bottleneck; checks
  are.
- Group commit is worth about 5 times the throughput and 11 times the
  median latency. It is required, not an optimisation.
- Plain recursion for status is exponential on shared premises. Status
  must be computed in dependency order or incrementally.

Caveat: a cloud VM's disk can acknowledge flushes faster than a laptop
SSD. Re-run the benchmark on the target machine before trusting the write
figures.

### Budgets

Budgets are set with margin over the baseline. They are checked by a
benchmark that lives in the repository.

| Operation | Budget |
| --- | --- |
| Durable `propose` with 7 concurrent agents | p50 under 2 ms, p99 under 25 ms |
| Status or point query | p99 under 1 ms |
| Sustained interactive writes | at least 1,000 events/s |
| Bulk import | at least 50,000 events/s |
| Cold start by replay | 100,000 events in under 1 s; 1,000,000 in under 10 s |
| Recompute status after one verdict, 1,000,000 claims | under 50 ms |
| One page of a claim list (200 rows) at 100,000 claims | under 16 ms, one display frame |
| Agent-facing response size | bounded and paged; no response grows with ledger size |

Check time limits are policy, not measurements: start with 5 s for replay
checks and 10 s for solver checks, both configurable per claim kind.

### Rules

- Commit in groups. Never open one transaction per event in a loop.
- Use `synchronous=FULL` for interactive writes, because an acknowledged
  write must survive power loss. `NORMAL` is allowed for bulk import,
  which can be redone.
- Reuse prepared statements.
- Page every list with a key, not an offset.
- Hash each evidence blob once, when it is added. Read large evidence
  through memory mapping instead of copying it.
- Compute status in one pass in dependency order, or incrementally over
  the dependents of what changed. Never by unmemoised recursion.
- Add a performance crate or an unsafe block only with a profile that
  shows the need and a before-and-after benchmark.
- A change that breaks a budget is a failed milestone, the same as a
  failing test.

## 7. Storage, safety and operations

**Storage**

- One SQLite file per ledger in WAL mode, plus a directory of evidence
  files named by hash.
- The event table is append-only, and that is enforced in the database,
  not only by convention.
- Evidence files are immutable. They are written to a temporary name and
  renamed into place, and their hash is verified when read.
- The schema carries a version. Migrations only move forward and are
  tested against ledger files kept in the repository.
- Old events are never reinterpreted. A change of meaning is a new event
  kind.
- Any derived state on disk (snapshots, caches, indexes) can be deleted
  and rebuilt from the log.

**Safety**

- Evidence is untrusted input. Parsing it must never panic, and every
  parser has size limits.
- Checks have no network access. Worker processes run with time and
  memory limits.
- Nothing executes code from a target in Phases 1 to 3. Emulation arrives
  later, behind approval.
- Secrets supplied by the user, such as signing keys, are stored as
  evidence and are never echoed in responses, logs or error messages.

**Errors and observability**

- Library crates return typed errors and do not panic.
- Every rejection an agent sees has a stable code, the offending claim or
  premise, and what to do next.
- Each verb and each check emits a trace span with the claim id, checker
  id and version, duration and verdict.
- Logs never contain evidence bytes.

**Versioning**

- Claim kinds, event formats and checkers each carry a version.
- A checker's version is part of its cache key, so a new checker version
  re-runs its checks.

## 8. Agent interface

- Five verbs only: propose, ask, explain, add evidence, retract. No SQL
  and no free-form query language is exposed.
- Tool schemas are generated from the core's types, so the agent's
  constrained decoding and the kernel's admission agree by construction.
- `ask` offers a small set of fixed question shapes, for example: what is
  known about this subject, what is on hold and why, what would be
  affected if this claim failed.
- `explain` returns why a claim has its status: its own verdict, the
  weakest premise, or the counterexample.
- Responses are short and paged. Ids are shown in short form.
- Writes are gated at the boundary: a claim that cites a refuted or
  unknown premise is refused. The system does not rely on the agent
  remembering the ledger.

## 9. Phases

Each milestone ends with the CI script passing and a short written report.
Tick a box only when its "done when" line is true.

### Phase 0: Setup

- [ ] Workspace, crates, toolchain, lints, CI script
- [ ] Agent tooling: one Rust skill pack, language-server plugin, project
      rules skill, hooks
- [ ] Core crate seeded from the existing type sketch, tests passing
- [ ] Benchmark crate in the workspace, reproducing the baseline table

Done when a clean checkout builds and passes CI with no warnings.

### Phase 1: Prototype, the replay ledger (about two weeks)

Goal: an agent's wrong claim about a game or a web API is caught, with a
concrete failing case.

- [ ] **Store.** Event log, evidence index, group commit, state rebuilt
      by replay
- [ ] **Checkers.** Memory layout over snapshots, signature replay over
      captured requests, response shape over captured exchanges
- [ ] **Agent tools.** The five verbs, with rejections worded for an
      agent
- [ ] **Trial run.** A real agent session on one small target, with the
      three metrics recorded

Left out on purpose: caching, re-anchoring, lifting, any interface.

Done when deliberately wrong claims are refuted with a failing case, a
claim resting on a refuted one shows as on hold, closing and reopening
the ledger changes no status, and the write and read budgets hold.

### Phase 2: Every target type, plus version reruns

- [ ] **Hardening.** Cache each check on what it read; grow to 8-10 claim
      kinds; counterexample shrinking; checks against vacuous or weakened
      claims
- [ ] **Version reruns.** Rerun the whole ledger on a new build, with
      anchors that survive rebuilds and a status diff
- [ ] **Formats.** File and protocol claims through Kaitai Struct
- [ ] **First binary claims.** Facts exported from Rizin; structural
      claims checked "within the recovered code", assumptions listed
- [ ] **Measure RzIL coverage** on our own targets

Done when all five target types have at least one checked claim kind, and
a new build of a target produces a correct "holds / moved / failed"
report.

### Phase 3: The human layer, headless

Everything the interface will need, built and tested with no pixels.

- [ ] **Read model.** One documented, tested API for: a claim card
      (sentence, status, evidence, assumptions, premises, dependents), a
      counterexample (failing input, the field that differs), a version
      diff, and paged, sortable claim lists
- [ ] **Sentences.** One template per claim kind, pinned by snapshot
      tests so wording cannot drift from what was checked
- [ ] **Review queue.** Ordering by evidence strength and number of
      dependents, as pure logic with tests
- [ ] **Change feed.** A consumer can subscribe from a sequence number
      and receive what changed, so a live view never polls
- [ ] **Export.** SARIF
- [ ] **Text stand-in.** A terminal view of the claim card,
      counterexample, queue and version diff, good enough for a real
      review session

Done when the human has reviewed a real agent session end to end in the
text stand-in.

### Proof gate: before any interface design

Interface design starts only when every item below has been shown, not
asserted. The evidence is collected in one report.

- [ ] **One-command demo.** A script that replays a recorded agent
      session against two targets (a game snapshot set and a captured
      API session) and prints the resulting ledger
- [ ] **It catches errors.** On seeded wrong claims for every claim
      kind, the share caught is reported; the starting target is 95%
      for kinds with deterministic checkers
- [ ] **It is fast enough.** Benchmark output from the human's own
      machine, every budget in section 6 met
- [ ] **It does not lose data.** Crash tests pass: kill at any point,
      reopen, last acknowledged state intact
- [ ] **Its rules hold.** The lemmas pass as property tests at a high
      case count
- [ ] **It survives a new build.** A prepared pair of target versions
      yields the expected holds / moved / failed report
- [ ] **The read model is frozen.** Documented, versioned, and exercised
      by the text stand-in; a 200-row page at 100,000 claims renders
      within one frame
- [ ] **A design brief exists.** Written from the review session: what
      was confusing, how "held on N runs" was read, what the reviewer
      needed and could not find

### Phase 4: Interface design and desktop build (human-led)

The human owns framework choice and visual design. Known direction: a
desktop application with a dense, professional-tool feel; findings shown
in their original format on the left, agent conversation on the right.

- [ ] Framework chosen and recorded in section 3
- [ ] Design reviewed against the brief from the proof gate
- [ ] Interface built as a consumer of the frozen read model and change
      feed, with no logic of its own about status

Implementers do not choose the framework, restyle, or add interface
features on their own initiative.

### Phase 5: Trust for binaries (headless, may run alongside Phase 4)

- [ ] Second lifter wired in; per-claim cross-check against concrete
      execution
- [ ] Solver tier for one claim kind (bit-level equivalence) on a small
      instruction subset
- [ ] Reachability witnesses for function-scoped claims

**Gate:** lifter mismatch on our targets is low enough to show "proved"
honestly.

### Phase 6: Ambitious version

- [ ] Lean certificates for bit-level lemmas
- [ ] A Lean model of the core's lemmas, fuzzed against the Rust core
- [ ] Contexts: "holds on build A, not B", "holds if this claim is
      assumed"
- [ ] Login and session flows as state-machine claims learned from
      captures
- [ ] An open claim format with adapters for other RE tools

## 10. Testing

- **Lemmas as property tests:** weakest premise, local refutation, order
  independence of verdicts, idempotent replay.
- **Determinism:** the same log always produces the same state hash. The
  hash is checked after replay and is the hook for a later Lean model.
- **Crash and recovery:** interrupt the writer mid-batch and reopen.
- **Concurrency:** readers running during heavy writes never observe a
  partial batch.
- **Fuzzing:** claim parsing, admission and every evidence parser.
- **Snapshots:** every sentence template and every agent-facing rejection.
- **Benchmarks:** the budgets in section 6.
- **Seeded errors:** for each claim kind, a set of deliberately wrong
  claims that its checker must refute.

## 11. Measured from the first day

1. Share of deliberately wrong claims the checkers catch.
2. Tokens and attempts per accepted claim.
3. Claims that pass and later fail.

## 12. Not goals

- Autonomous exploitation or autonomous bug-finding.
- Writing our own lifter or instruction-set semantics.
- General protocol or grammar inference.
- Proving whole-program properties in Lean.
- Competing with existing decompilers on decompilation quality.

## 13. Open questions

| Question | Answer by |
| --- | --- |
| Does the loop cut tokens and false claims on real RE tasks? | End of Phase 1 |
| Which anchor survives real version changes with the fewest false matches? | Phase 2, version reruns |
| How much of x86-64 and AArch64 does RzIL lift, and how often does it disagree with a second lifter? | End of Phase 2 |
| What evidence is enough for "held on N runs", and how should it be worded so it is not read as "proved"? | Proof gate, design brief |
| How far does VerifiedIDA's standard overlap, and should we build on it or interoperate? | Before the open format in Phase 6 |

## 14. Rules for whoever implements a milestone

- **Yours to decide:** data structures, module layout, function
  signatures, SQL schema details, test design, internal naming, and how
  the rules in sections 5 to 8 are realised.
- **Not yours to change without asking:** the principles, the technology
  table, the concurrency rules, the budgets, the order of phases, the
  lint and CI configuration, anything about the interface.
- **Dependencies** are added with `cargo add`, never by writing versions
  by hand. Confirm a crate exists and is maintained first. Read the docs
  for the resolved version instead of writing from memory.
- **Scope:** do the milestone you were given and nothing from a later
  one.
- **Prove, don't claim.** A milestone report includes test output,
  benchmark output and, where a rule in this file applies, the test that
  enforces it.
- **When blocked** by something this file leaves undecided, or when a
  principle and a requirement conflict, stop and ask.
- **Report** at the end of each milestone: what was built, what was
  skipped and why, every deviation from this file, and any rule that
  proved awkward in practice.
- **Keep this file current:** tick boxes, record decisions on the
  undecided items, update the baseline table when it is re-measured, and
  add newly found open questions. Do not rewrite the principles.
