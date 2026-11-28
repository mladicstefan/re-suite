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
| File and protocol formats | Kaitai Struct, through the parser its own compiler generates, run in a worker process | Decided 28 November 2026. Until the worker is built, a subset of the language is read by our own checker (`ledger_checkers::format`), which the worker replaces |
| Binary analysis | Rizin | Phase 2 onwards; paused |
| Outside tools | Run in one place as sandboxed processes; their output is stored as evidence | Checkers stay in-process and pure. Phase 2W |
| Web capture | Chromium over the DevTools Protocol; mitmproxy for other clients | Only for a person at a terminal who approves the hosts |
| Minified JavaScript | Source maps, Wakaru, webcrack | Phase 2W |
| Technology fingerprints | Wappalyzer rules on saved captures; retire.js on script contents | Phase 2W |
| Searching code | ast-grep | Phase 2W |
| Second lifter | P-code through pypcode | Phase 5, for cross-checking |
| Solver | Bitwuzla or Z3 | Phase 5, small scope first |
| Proof certificates | Lean 4, bit-level lemmas only | Phase 6, optional |
| Testing | Property, snapshot, crash and doc tests | Lemmas are property tests first |
| Quality gates | Formatter, strict lints, dependency audit, CI script, editor hooks | Lints may not be weakened to pass |
| Outside tools | Nix flake for every tool; uv lock for Python packages | Nothing is taken from the machine but Nix itself. Linux only so far |
| Desktop interface | Native and cross-platform; framework undecided | Chosen by the human at the UI gate |

**Deliberately not used:** a custom database, TigerBeetle (fixed schema),
a graph or Datalog database, random or time-based IDs for claims,
performance crates added before a profile asks for them.

**Undecided, with a decision point:**

- Desktop framework and visual design: the UI gate (section 9).
- Bitwuzla or Z3: the solver spike in Phase 5.
- Whether Rizin alone can support proofs: **not on x86-64.** The Phase 2
  measurement found three instructions RzIL gives a wrong meaning with
  nothing to mark them (`neg`, SSE2 `movsd`, `rep stos`). A proof needs
  the second lifter to agree on every instruction of the function.

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
(`cargo run --release -p ledger-bench`), on an 8-core Ryzen 7 3700X with
46 GB of memory and an NVMe SSD under btrfs on dm-crypt, where one
`fdatasync` takes 6.2 ms at the median. Events were about 190 bytes of
JSON, about 290 with a premise. Seven writers and seven readers ran at
once, on a ledger of 100,000 claims.

| Scenario | Result |
| --- | --- |
| 7 agents, each waiting for a durable write (group commit, `synchronous=FULL`) | 961 events/s; write latency p50 7.2 ms, p99 12.6 ms |
| Same, `synchronous=NORMAL` | 21,320 events/s; p50 0.26 ms, p99 0.37 ms |
| Same, one transaction per event (no group commit) | 151 events/s; p50 6.6 ms, p99 760 ms |
| Status of one claim while writing, 7 readers | 4.1 million reads/s in total; p99 2.8 microseconds |
| Bulk import, batches of 512, `synchronous=NORMAL` | 74,851 events/s |
| Cold start by replay: read, parse, admit and apply the log | 200,643 events/s (1,000,000 events in 4.98 s, 100,000 in 0.44 s) |
| Database size | 293 MB for 1,000,000 events |
| Core: hash, admit and apply a claim | 274,059 claims/s |
| Status of 1,000,000 claims, one pass in dependency order | 16.1 ms |
| One page of a claim list (200 rows) at 100,000 claims, last page | 4.7 ms |
| Status by plain recursion over 35 chained diamond dependencies | 24 million calls, 1.6 s, and about 11 times more for every 5 further levels; the core settles the same claim in 11 microseconds |

What the baseline shows:

- Reads, replay and status are far inside their budgets. The ledger is
  not the bottleneck for them; checks are.
- Durable writes cost one disk flush per commit, whatever the software
  does. On this disk that is 6.2 ms, so a durable write has a median of
  about 7 ms. On tmpfs, where a flush is free, the same code has a median
  of 0.26 ms.
- Group commit is worth about 6 times the throughput and 60 times the
  p99 latency. It is required, not an optimisation.
- Plain recursion for status is exponential on shared premises. Status
  must be computed in dependency order or incrementally.

The first baseline, on a 2-core cloud VM whose disk acknowledged flushes
in well under a millisecond, gave 5,049 durable events/s at a median of
0.50 ms. Re-run the benchmark whenever the ledger moves to another disk
or filesystem.

### Budgets

Budgets are set with margin over the baseline. They are checked by a
benchmark that lives in the repository.

| Operation | Budget |
| --- | --- |
| Durable `propose` with 7 concurrent agents | p50 under one disk flush plus 2 ms, p99 under 25 ms |
| Status or point query | p99 under 1 ms |
| Sustained interactive writes | at least 1,000 events/s, or 5 events per disk flush where a flush takes over 5 ms |
| Bulk import | at least 50,000 events/s |
| Cold start by replay | 100,000 events in under 1 s; 1,000,000 in under 10 s |
| Recompute status after one verdict, 1,000,000 claims | under 50 ms |
| One page of a claim list (200 rows) at 100,000 claims | under 16 ms, one display frame |
| Agent-facing response size | bounded and paged; no response grows with ledger size |

The write budgets are stated against the disk's flush time because a
durable write cannot be faster than one flush; the benchmark measures the
flush on the disk it runs on. They were restated on 26 November 2026: the
first version asked for a 2 ms median, which the current disk (6.2 ms per
flush) cannot give at any amount of software work.

**Performance work still owed.** The software's own share of a durable
write is about 0.3 ms, of which 0.1 ms is the group-commit wait. What is
left to gain is outside that: put the ledger on a filesystem that flushes
faster (the same NVMe drive under btrfs on dm-crypt takes 6.2 ms; a
flush on a plain ext4 or xfs partition is usually well under 1 ms), and
make the group-commit wait adapt to the flush time instead of a fixed
100 microseconds. Writes also stall when the disk is busy with something else: two
benchmark runs started straight after another disk-heavy run had a p99 of
130 to 143 ms and a third of the throughput, while three runs taken a
minute later met every budget (972 to 977 events/s, median 7.0 ms, p99 9
to 13 ms). The ledger has no defence against that yet.
Replay is single-threaded at about 200,000 events/s,
which meets the cold-start budget for 1,000,000 events with a factor of
two to spare and no more.

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

**Code structure**

- Values that can be fixed at compile time are: `const` items and
  `const fn` are preferred over run-time computation and over macros.
- Every feature that depends on the operating system lives in a crate of
  its own. That crate selects the system's functions at compile time and
  exposes one portable API; no other crate calls the system directly.
- IO is never skipped or deferred: blocking work stays off the async
  executor, and no shortcut is taken on IO, durability or concurrency.

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

- [x] Workspace, crates, toolchain, lints, CI script
- [x] Agent tooling: one Rust skill pack, language-server plugin, project
      rules skill, hooks
- [x] Core crate seeded from the existing type sketch, tests passing
- [x] Benchmark crate in the workspace, reproducing the baseline table

Done when a clean checkout builds and passes CI with no warnings.

### Phase 1: Prototype, the replay ledger (about two weeks)

Goal: an agent's wrong claim about a game or a web API is caught, with a
concrete failing case.

- [x] **Store.** Event log, evidence index, group commit, state rebuilt
      by replay
- [x] **Checkers.** Memory layout over snapshots, signature replay over
      captured requests, response shape over captured exchanges
- [x] **Agent tools.** The five verbs, with rejections worded for an
      agent
- [x] **Trial run.** A real agent session on one small target, with the
      three metrics recorded

Left out on purpose: caching, re-anchoring, lifting, any interface.

Done when deliberately wrong claims are refuted with a failing case, a
claim resting on a refuted one shows as on hold, closing and reopening
the ledger changes no status, and the write and read budgets hold.

### Phase 2: Every target type, plus version reruns

- [x] **Hardening.** Cache each check on what it read; grow to 8-10 claim
      kinds; counterexample shrinking; checks against vacuous or weakened
      claims
- [x] **Version reruns.** Rerun the whole ledger on a new build, with
      anchors that survive rebuilds and a status diff
- [ ] **Live captures.** Snapshots of a running process, taken only with
      human approval, that carry what the human observed at capture time
      (the HUD showed 73 HP); a layout claim must decode to those values.
      Built: `ledger-capture` and `live_snapshot` evidence, tested on the
      tool's own process. Still to do: the first capture of another
      process, by a person, with an agent working from it
- [x] **Formats.** File claims through Kaitai Struct: a `format` claim
      carries a description, and the checker walks it over each file. It
      places fields at offsets a count decides (`docs/trials/format-claims.md`).
      A subset of the language, read by our own code: to be replaced by
      the Kaitai compiler's parser in a worker process. Protocol messages
      are not tried yet
- [x] **First binary claims.** Facts exported from Rizin; structural
      claims checked "within the recovered code", assumptions listed.
      One claim kind so far, a direct call between two functions
      (`docs/trials/crash-handler.md`)
- [x] **Measure RzIL coverage** on our own targets: 96% to 98% of
      instructions, but only 55% to 80% of functions in full, and on
      x86-64 an unlifted instruction looks like one that does nothing
      (`docs/trials/rzil-coverage.md`). Against P-code the effects of an
      instruction differ in 9.5% to 17.9% of x86-64 instructions, 0.06% to
      0.49% once one flag P-code leaves out is set aside, and never on
      AArch64; three RzIL meanings are wrong

Done when all five target types have at least one checked claim kind, and
a new build of a target produces a correct "holds / moved / failed"
report.

### Paused: binaries, file formats and live memory (TODO)

Paused on 28 November 2026 so that web work comes first. Nothing here is
dropped; it resumes after the web phase.

- [ ] TODO: the first live capture of another process by a person, and an
      agent working from it (the Live captures item above)
- [ ] TODO: format descriptions through the Kaitai compiler's parser in a
      worker process, replacing our own reader
- [ ] TODO: more binary claim kinds; function starts from the exception
      table; reruns that read binary facts
- [ ] TODO: all of Phase 5

### Phase 2W: Web, fully working

Comes before Phase 3 and before any interface work: **the interface is not
started until every box here is ticked.** The work is cut into playbooks,
each a scenario an agent meets, the pinned tools it uses and the claims it
ends in.

Two pieces every playbook stands on:

- [x] **Tool output is evidence.** One module of the server
      (`ledger-mcp`'s `runner`) starts outside processes: found by
      absolute path, with no environment and no input, on copies of their
      inputs in a private directory, time-limited, one run at a time per
      tool. What a tool prints is stored as evidence, and the log records
      which tool, at which version, read which inputs (`Event::Derived`);
      the same run is not made twice. Checkers stay in-process and pure.
      Rizin runs through it. No memory limit or system sandbox yet
- [x] **Every tool is pinned.** Nix for programs, a lockfile for npm
      packages: Wakaru, webcrack, retire.js, ast-grep, mitmproxy, wabt,
      wasm-tools, prettier, and a Wappalyzer rule engine that runs on
      saved captures. Each was tried on real input
      (`docs/trials/web-tools.md`); jsluice was dropped after that

The playbooks:

- [ ] **1. Capture a session.** A person at a terminal approves the hosts.
      Chromium is driven over the DevTools Protocol with its cache off;
      mitmproxy serves clients that are not browsers. The result is a
      session: exchanges in order, the script and line that started each,
      and every script's source.
      Built: `ledger-capture web` and `session` evidence, tested on loopback; not yet mitmproxy or a real capture
- [ ] **2. Fingerprint the stack.** Offline, on a session: frameworks,
      servers, CDNs and bot walls from headers, cookies, HTML and script
      addresses, and libraries with versions from script contents. A
      `uses_technology` claim, checked within what the rules detect. The
      result picks the next playbook; a bot wall stops the agent
- [ ] **3. Recover source from minified JavaScript.** A captured source
      map first; otherwise unbundle and unminify, with library code set
      aside. Recovered modules are derived evidence; names stay the
      agent's reading
- [ ] **4. Find the API in the code.** Endpoints, GraphQL documents and
      secrets the scripts name, and which of them no capture shows
- [ ] **5. Map the API from traffic.** `ask` lists endpoints no claim
      covers; an endpoint can be scoped by content type and by a body
      field; held claims export as OpenAPI, each statement marked with
      what it held on
- [ ] **6. Trace a request to its code.** From the session's record of
      what started a request to the function in recovered source; a
      claim that an endpoint's requests start there; signing keys as
      secret evidence
- [ ] **7. Sessions and login.** A flow claim: a value in one request
      comes from an earlier response or cookie
- [ ] **8. GraphQL, WebSocket and WebAssembly.** Operations and frames as
      claims; a module's imports and exports as facts
- [ ] **9. Compare two versions.** Rerun on a new session, plus which
      modules changed
- [ ] **Playbooks reach any agent.** The server lists the playbooks that
      apply to what the ledger holds; they are files in this repository
- [ ] **Trial.** One approved capture of a real site taken through every
      playbook, with the three numbers of section 11

Later, behind approval of each request: active tests (replaying a request
with changes), fetching what the browser did not, captures on a schedule.

Done when an agent that is given only the server and one approved session
of a real site files held claims from every playbook, a deliberately wrong
claim of each new kind is refuted, the export validates as OpenAPI, and a
second session produces a correct "holds / moved / failed" report.

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

### Phase 5: Trust for binaries (TODO, paused with the rest of binary work)

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

| Trial | Wrong claims caught | Attempts per accepted claim | Passed, later failed |
| --- | --- | --- | --- |
| 1, Half-Life saves (`docs/trials/half-life-saves.md`) | 20 of 21 | 1.17, about 440 tokens of tool traffic | 0 of 2 |
| 2, web traffic (`docs/trials/web-api.md`) | 19 of 19 | 1.67, about 500 tokens of tool traffic | 1 of 1 |
| 3, real websites (`docs/trials/real-sites.md`) | 14 of 15; the one that held is true of the captures | 2.0, about 600 tokens of tool traffic | not measured |
| 5, the staging site (`docs/trials/staging-site.md`) | 8 of 8 | 1.36, about 120 tokens of tool traffic | none staged |
| 6, a binary (`docs/trials/crash-handler.md`) | 3 of 3 | 1.63, about 270 tokens of tool traffic | none staged |
| 8, format claims (`docs/trials/format-claims.md`) | 10 of 10; the ledger's count of contradicting files equals a count by hand | 2.0, about 1,500 characters of description | none staged |
| 7, with and without the ledger (`docs/trials/ledger-loop.md`) | 0: none of 302 proposals was wrong on the evidence the ledger held | 1.0, about 310 tokens of tool traffic | 60 of 298: held on 40 files, refuted by 6,554 held out |

## 12. Not goals

- Autonomous exploitation or autonomous bug-finding.
- Writing our own lifter or instruction-set semantics.
- General protocol or grammar inference.
- Proving whole-program properties in Lean.
- Competing with existing decompilers on decompilation quality.

## 13. Open questions

| Question | Answer by |
| --- | --- |
| Does the loop cut tokens and false claims on real RE tasks? **Not when the ledger holds only what the agent has already read:** on one file-format task, three runs with the ledger and three without made 20.0 and 21.3 wrong statements for 100,000 and 106,000 tokens, and the ledger refuted nothing (`docs/trials/ledger-loop.md`). Does it when the ledger holds more evidence than the agent reads, or evidence captured later? | A second run of trial 7 with that arm |
| A verdict lists every piece of evidence its check read: 430 KB for one check on 6,554 files, and the log is replayed at every start. Should a set of evidence be recorded once and cited by its hash? | Before a ledger holds thousands of captures of one kind |
| A snapshot claim must list its evidence ids; a web claim can say `all_captures`. What selects "every snapshot of this type"? | Phase 2, formats |
| A `format` claim places fields at offsets a count decides (`docs/trials/format-claims.md`), in a subset of Kaitai Struct: no enums, parameters, `process`, bit fields. Which of these do agents reach for, and does an agent with format claims get past the first table where six without them did not? | A second run of trial 7 with format claims |
| A rerun ties a web claim to its endpoint and a snapshot claim to its type name, and suggests a move from a bounded search (`docs/trials/version-rerun.md`). That was tried on a simulated pair of builds only. Which anchor survives real version changes with the fewest false matches? | The first real pair of target versions |
| RzIL and P-code agree on the effects of every AArch64 instruction both lift, and differ on 0.06% to 0.49% of x86-64 ones once the auxiliary carry flag is set aside (`docs/trials/rzil-coverage.md`). That compares which registers and memory are written, not the values. How often do the values differ? | Phase 5, concrete execution |
| What evidence is enough for "held on N runs", and how should it be worded so it is not read as "proved"? | Proof gate, design brief |
| A web claim covers an endpoint and a status, not a content type, so `GET /{page}` cannot mean "pages, not files". And no claim kind speaks about a page load as a whole (which hosts it contacts) or reads HTML. Which of these should become claims? | Phase 2, formats |
| With a wider analysis Rizin still leaves 11.5% of one Windows program's code ranges in no function, and now reads some padding and data as functions (`docs/trials/rzil-coverage.md`). Should function starts come from the exception table instead? And should "held on N" need two tools to agree? | Before the second binary claim kind |
| Without symbols a function's name is its address. What ties a binary claim to the same function in the next build? | The first real pair of target versions |
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
