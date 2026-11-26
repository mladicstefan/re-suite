# re-suite: replay ledger

Backend of an agent-first reverse-engineering workbench. Agents file findings as
typed, machine-checkable claims; each claim is re-checked offline against saved
evidence (memory snapshots, captured requests and exchanges) and shown to a human
as a plain sentence with a status, plus a counterexample when it fails. Nothing is
ever sent to a live target.

## How it works

The agent finds things. The ledger checks them against saved recordings of the
target and remembers the answer.

<img src="docs/how-it-works.svg" alt="The target is recorded once into capture files. The agent reads them and writes a claim. The ledger tests the claim against the captures, returns a verdict, logs it, and shows the human a sentence, a status and the capture that disagrees." width="900">

1. **Record.** The target is recorded once into capture files: a web request with
   its response, or a snapshot of memory.
2. **Read.** The agent reads the captures and forms a guess about how the target works.
3. **Claim.** The agent writes the guess as a precise statement and names the
   captures to test it on.
4. **Verdict.** The ledger replays the statement on each capture. It answers
   `held on N`, or `refuted` with the capture and field that disagree.
5. **Remember.** The claim and its verdict go into a log that is never edited.
6. **Show.** The human gets one sentence per finding, its status, and the failing
   case if there is one.

The ledger knows nothing about the target and cannot come up with a claim. The
agent can, but is often wrong without noticing. A real run on six captures of
crates.io:

```
claim    200 responses to `GET crates.io/api/v1/crates/{name}` have documentation: null
verdict  refuted by capture 70f35bf33291
         "https://docs.rs/regex" is not of type "null" at /crate/documentation

claim    the same, with documentation and homepage allowed to be a string or null
verdict  held on 6 captures
```

"Held on 6" means six captures did not contradict the claim. It is not proof.

## Claim kinds

A claim is one of ten typed statements. Each has an admission rule, a sentence, and a
checker that replays it on saved evidence.

| Kind | Says | Checked on |
| :- | :- | :- |
| `memory_layout` | a type is N bytes, with typed fields at fixed offsets | snapshots |
| `record_array` | a count is followed by that many fixed-size records | snapshots |
| `field_relation` | one integer equals a length or a sum taken from the rest | snapshots |
| `tagged_records` | a run of (size, tag, value) records | snapshots |
| `string_table` | a region holds a stated number of NUL-terminated strings | snapshots |
| `request_signature` | requests carry a MAC of stated parts, under a key kept as secret evidence | HTTP exchanges |
| `request_header` | requests carry a header whose value matches a schema | HTTP exchanges |
| `request_body_schema` | request bodies match a JSON Schema | HTTP exchanges |
| `response_schema` | responses with one status match a JSON Schema | HTTP exchanges |
| `status_set` | an endpoint only answers with the listed statuses | HTTP exchanges |

Toolchain: Rust 1.100.0 (pinned in `rust-toolchain.toml`), edition 2024, resolver 3.

## Crates

| Crate | Purpose |
| :- | :- |
| `ledger-core` | Pure, synchronous model: claim kinds (one serde-tagged enum), content-hash IDs, `admit` → `WellFormed<Claim>`, events, verdicts, status derived from verdicts and premises. |
| `ledger-store` | SQLite in WAL mode. One writer thread behind a bounded flume queue commits everything queued as one transaction, then publishes an immutable snapshot (state plus sequence number) that readers take without touching the writer. Append-only `events` table, `evidence` table indexing files named by content hash in `<ledger>.evidence/`, versioned schema. State is rebuilt by replaying events through ledger-core. |
| `ledger-checkers` | Offline checkers behind one `Checker` trait, each with an id and a version: memory layout over snapshots (typed fields: fixed bytes, integer and float ranges, value sets, pointers, text, zero padding), signature replay and JSON Schema over captured HTTP exchanges (request line, status, headers, text or base64 bodies; an endpoint is `METHOD [host]/path` with optional query conditions; a capture of another endpoint or status is refused). A check has a time limit and parsed evidence a size limit; exceeding either never yields "held". |
| `ledger-mcp` | MCP server over stdio with five tools: `propose`, `ask`, `explain`, `add_evidence`, `retract`. Input schemas come from ledger-core types via schemars. A check that was already made on the same claim, evidence and checker version is not run again. Two identical checks arriving together share one run. A claim that says less than an earlier refuted one is marked as weaker, with what it gave up. `add_evidence` takes single captures or a whole HAR file, and `ask` can list the captures of an endpoint. Responses are short, paged by key, use short ids and start with the sequence number they were computed at; rejections carry a stable code and a next step. The only crate with tokio; blocking work runs off the executor. |
| `ledger-cli` | `ledger-cli <file>` prints every claim with its status. With `--rerun-har` or `--rerun-snapshots` it re-checks the held claims against the captures of a new build and reports what holds, moved, failed or has no evidence, without recording anything. "Moved" is a suggestion: the claim holds at shifted offsets or under a renamed endpoint. |
| `ledger-bench` | `cargo run --release -p ledger-bench` reproduces the baseline table in ROADMAP.md and exits non-zero if a budget is broken. |

## Resolved dependency versions

From `cargo tree -p <crate> --depth 1`:

| Crate | Dependencies | Dev-dependencies |
| :- | :- | :- |
| `ledger-core` | blake3 1.8.7, hex 0.4.3, schemars 1.2.3, serde 1.0.229, serde_json 1.0.154, thiserror 2.0.21 | insta 1.49.0, pretty_assertions 1.4.1, proptest 1.12.0 |
| `ledger-store` | flume 0.12.0, jiff 1.0.3, ledger-core (path), memmap2 0.9.12, rusqlite 0.43.0 (bundled), serde_json 1.0.154, thiserror 2.0.21, tracing 0.1.44 | proptest 1.12.0, tempfile 3.27.0 |
| `ledger-checkers` | base64 0.23.1, hex 0.4.3, hmac 0.13.0, jsonschema 0.63.1 (no default features), ledger-core (path), md-5 0.11.0, rayon 1.12.0, serde 1.0.229 (derive), serde_json 1.0.154, sha1 0.11.0, sha2 0.11.2, thiserror 2.0.21, tracing 0.1.44 | – |
| `ledger-mcp` | anyhow 1.0.105, ledger-checkers (path), ledger-core (path), ledger-store (path), rmcp 3.11.0 (server, macros, transport-io), schemars 1.2.3, tokio 1.54.1 (rt, macros, io-std), tracing 0.1.44, tracing-subscriber 0.3.23 | insta 1.49.0, tempfile 3.27.0 |
| `ledger-cli` | anyhow 1.0.105, clap 4.6.10, ledger-checkers (path), ledger-core (path), ledger-store (path) | – |
| `ledger-bench` | ledger-core (path), ledger-store (path), rusqlite 0.43.0 (bundled) | – |

## Running

```bash
cargo run -p ledger-mcp -- ledger.db   # MCP server on stdio
cargo run -p ledger-cli -- ledger.db   # list claims with status
scripts/ci.sh                          # fmt, clippy, nextest, doctests, deny, machete
```
