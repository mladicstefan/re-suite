# Roadmap

This file fixes the direction, the order of work and the technology choices.
It does not fix implementation details. Those belong to whoever implements
each milestone, human or AI, within the rules in the last section.

## What we are building

An agent-first reverse-engineering workbench for binaries, web APIs, games,
firmware and network captures. AI agents do the analysis. A human verifies
their findings and steers.

The core is a **replay ledger**. Every finding an agent makes is filed as a
typed, machine-checkable claim. Each claim is re-checked automatically
against saved evidence, and shown to the human as a plain sentence with a
status and a counterexample when it fails.

The ledger is built first. Everything else (binary analysis, solvers, the
desktop interface) is added around it.

## Principles that do not change

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
   a "held" verdict has a run count, a proof has a certificate.
8. **Identity is content.** Claims and evidence are named by the hash of
   their content.
9. **Three statuses that differ in kind:** agent's reading only, held on N
   runs, proved (with its assumptions listed).
10. **The core stays small and pure** so its rules can be tested exhaustively
    and later proved.

## Technology choices

| Area | Choice | Notes |
| --- | --- | --- |
| Language | Rust, current stable | One workspace, several crates |
| Ledger core | Pure, synchronous Rust library | No IO, no async, no database |
| Storage | SQLite, embedded, WAL mode | One writer, many readers; append-only event log |
| Evidence | Files on disk, named by hash | The database only indexes them |
| Hashing | BLAKE3 | For all content addressing |
| Claim format | Closed set of typed kinds; JSON on the wire | JSON Schema generated from the Rust types |
| Agent interface | MCP server over stdio | Five verbs: propose, ask, explain, add evidence, retract |
| Async runtime | Tokio, in the MCP server only | Never in the core |
| Checkers | Rust for replay checks; worker processes for the rest | Workers may be Python where the libraries live |
| File and protocol formats | Kaitai Struct | Phase 2 |
| Binary analysis | Rizin | Phase 2 onwards |
| Second lifter | P-code through pypcode | Phase 3, for cross-checking |
| Solver | Bitwuzla or Z3 | Phase 3, small scope first |
| Proof certificates | Lean 4, bit-level lemmas only | Phase 4, optional |
| Testing | Property tests, snapshot tests, doctests | Lemmas are property tests first |
| Quality gates | Formatter, strict lints, dependency audit, CI script, editor hooks | Lints may not be weakened to pass |
| Desktop interface | Native and cross-platform; framework undecided | Deferred until the ledger works |

**Deliberately not used:** a custom database, TigerBeetle (fixed schema),
a graph or Datalog database, random or time-based IDs for claims,
performance crates added before a profile asks for them.

**Undecided, with a decision point:**

- Desktop framework: decide at the start of the interface work in Phase 2.
- Bitwuzla or Z3: decide during the solver spike in Phase 3.
- Whether Rizin alone can support proofs: decided by the Phase 2 gate.

## Shape of the system

```
agents and human
   |  five verbs (MCP)
checkers  <-- read --  evidence (snapshots, captures, lifted code)
   |  premises out, verdicts back
ledger core  -- events -->  SQLite event log
```

Crates: a pure core, a store, the checkers, the MCP server, a small CLI.
The desktop interface will be a further consumer of the same core.

## Phases

Each milestone ends with the CI script passing and a short written report.
Tick a box only when its "done when" line is true.

### Phase 0: Setup

- [ ] Workspace, crates, toolchain, lints, CI script
- [ ] Agent tooling: one Rust skill pack, language-server plugin, project
      rules skill, hooks
- [ ] Core crate seeded from the existing type sketch, tests passing

Done when a clean checkout builds and passes CI with no warnings.

### Phase 1: Prototype, the replay ledger (about two weeks)

Goal: an agent's wrong claim about a game or a web API is caught, with a
concrete failing case.

- [ ] **Store.** Event log, evidence index, state rebuilt by replay
- [ ] **Checkers.** Memory layout over snapshots, signature replay over
      captured requests, response shape over captured exchanges
- [ ] **Agent tools.** The five verbs, with rejections worded for an agent
- [ ] **Trial run.** A real agent session on one small target

Left out on purpose: caching, re-anchoring, lifting, interface polish.

Done when deliberately wrong claims are refuted with a failing case, a claim
resting on a refuted one shows as on hold, and closing and reopening the
ledger changes no status.

### Phase 2: Every target type, plus version reruns (to about month three)

- [ ] **Hardening.** Cache each check on what it read; grow to 8-10 claim
      kinds; counterexample shrinking; checks against vacuous or weakened
      claims
- [ ] **Version reruns.** Rerun the whole ledger on a new build, with
      anchors that survive rebuilds and a status diff
- [ ] **Formats.** File and protocol claims through Kaitai Struct
- [ ] **Human layer, first cut.** Claim card and counterexample view
- [ ] **First binary claims.** Facts exported from Rizin; structural claims
      checked "within the recovered code", assumptions listed
- [ ] **Measure RzIL coverage** on our own targets

**Gate:** the measured lifter coverage decides whether the proof tier builds
on Rizin alone or needs the second lifter first.

Done when all five target types have at least one checked claim kind, and a
new build of a target produces a correct "holds / moved / failed" report.

### Phase 3: Trust for binaries

- [ ] Review queue and SARIF export
- [ ] Second lifter wired in; per-claim cross-check against concrete
      execution
- [ ] Solver tier for one claim kind (bit-level equivalence) on a small
      instruction subset
- [ ] Reachability witnesses for function-scoped claims

**Gate:** lifter mismatch on our targets is low enough to show "proved"
honestly, and Phase 1 metrics show the loop reduces false claims.

### Phase 4: Ambitious version

- [ ] Lean certificates for bit-level lemmas
- [ ] A Lean model of the core's lemmas, fuzzed against the Rust core
- [ ] Contexts: "holds on build A, not B", "holds if this claim is assumed"
- [ ] Login and session flows as state-machine claims learned from captures
- [ ] An open claim format with adapters for other RE tools

## Measured from the first day

1. Share of deliberately wrong claims the checkers catch.
2. Tokens and attempts per accepted claim.
3. Claims that pass and later fail.

## Not goals

- Autonomous exploitation or autonomous bug-finding.
- Writing our own lifter or instruction-set semantics.
- General protocol or grammar inference.
- Proving whole-program properties in Lean.
- Competing with existing decompilers on decompilation quality.

## Open questions

Each has a phase where it must be answered.

| Question | Answer by |
| --- | --- |
| Does the loop cut tokens and false claims on real RE tasks? | End of Phase 1 |
| What evidence is enough for "held on N runs", and how should it be worded so it is not read as "proved"? | Phase 2, human layer |
| Which anchor survives real version changes with the fewest false matches? | Phase 2, version reruns |
| How much of x86-64 and AArch64 does RzIL lift, and how often does it disagree with a second lifter? | Phase 2 gate |
| How far does VerifiedIDA's standard overlap, and should we build on it or interoperate? | Before the open format in Phase 4 |

## Rules for whoever implements a milestone

- **Yours to decide:** data structures, module layout, function signatures,
  SQL schema details, test design, internal naming.
- **Not yours to change without asking:** the principles above, the
  technology choices table, the order of phases, the lint and CI
  configuration.
- **Dependencies** are added with `cargo add`, never by writing versions by
  hand. Confirm a crate exists and is maintained first. Read the docs for the
  resolved version instead of writing from memory.
- **Scope:** do the milestone you were given and nothing from a later one.
- **When blocked** by a choice this file leaves undecided, or when a
  principle and a requirement conflict, stop and ask.
- **Report** at the end of each milestone: what was built, what was skipped
  and why, every deviation from this file, and any principle that proved
  awkward in practice.
- **Keep this file current:** tick boxes, record decisions on the undecided
  items, and add newly found open questions. Do not rewrite the principles.
