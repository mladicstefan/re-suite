# re-suite: replay ledger

Backend of an agent-first reverse-engineering workbench. Agents file findings as
typed, machine-checkable claims; each claim is re-checked offline against saved
evidence (memory snapshots, captured requests and exchanges) and shown to a human
as a plain sentence with a status, plus a counterexample when it fails. Nothing is
ever sent to a live target.

Toolchain: Rust 1.100.0 (pinned in `rust-toolchain.toml`), edition 2024, resolver 3.

## Crates

| Crate | Purpose |
| :- | :- |
| `ledger-core` | Pure, synchronous model: claim kinds (one serde-tagged enum), content-hash IDs, `admit` → `WellFormed<Claim>`, events, verdicts, status derived from verdicts and premises. |
| `ledger-store` | SQLite in WAL mode. One writer thread behind a bounded flume queue commits everything queued as one transaction, then publishes an immutable snapshot (state plus sequence number) that readers take without touching the writer. Append-only `events` table, `evidence` table indexing files named by content hash in `<ledger>.evidence/`, versioned schema. State is rebuilt by replaying events through ledger-core. |
| `ledger-checkers` | Offline checkers behind one `Checker` trait, each with an id and a version: memory layout over snapshots (typed fields: fixed bytes, integer and float ranges, value sets, pointers, text, zero padding), signature replay and JSON Schema over captured HTTP exchanges (request line, status, headers, text or base64 bodies; a capture of another endpoint or status is refused). A check has a time limit and parsed evidence a size limit; exceeding either never yields "held". |
| `ledger-mcp` | MCP server over stdio with five tools: `propose`, `ask`, `explain`, `add_evidence`, `retract`. Input schemas come from ledger-core types via schemars. Responses are short, paged by key, use short ids and start with the sequence number they were computed at; rejections carry a stable code and a next step. The only crate with tokio; blocking work runs off the executor. |
| `ledger-cli` | `ledger-cli <file>` prints every claim with its status. |
| `ledger-bench` | `cargo run --release -p ledger-bench` reproduces the baseline table in ROADMAP.md and exits non-zero if a budget is broken. |

## Resolved dependency versions

From `cargo tree -p <crate> --depth 1`:

| Crate | Dependencies | Dev-dependencies |
| :- | :- | :- |
| `ledger-core` | blake3 1.8.7, hex 0.4.3, schemars 1.2.3, serde 1.0.229, serde_json 1.0.154, thiserror 2.0.21 | insta 1.49.0, pretty_assertions 1.4.1, proptest 1.12.0 |
| `ledger-store` | flume 0.12.0, jiff 1.0.3, ledger-core (path), memmap2 0.9.12, rusqlite 0.43.0 (bundled), thiserror 2.0.21, tracing 0.1.44 | proptest 1.12.0, tempfile 3.27.0 |
| `ledger-checkers` | base64 0.23.1, hex 0.4.3, hmac 0.13.0, jsonschema 0.63.1 (no default features), ledger-core (path), md-5 0.11.0, rayon 1.12.0, serde_json 1.0.154, sha1 0.11.0, sha2 0.11.2, thiserror 2.0.21, tracing 0.1.44 | – |
| `ledger-mcp` | anyhow 1.0.105, ledger-checkers (path), ledger-core (path), ledger-store (path), rmcp 3.11.0 (server, macros, transport-io), schemars 1.2.3, tokio 1.54.1 (rt, macros, io-std), tracing 0.1.44, tracing-subscriber 0.3.23 | insta 1.49.0, tempfile 3.27.0 |
| `ledger-cli` | anyhow 1.0.105, clap 4.6.10, ledger-store (path) | – |
| `ledger-bench` | ledger-core (path), ledger-store (path), rusqlite 0.43.0 (bundled) | – |

## Running

```bash
cargo run -p ledger-mcp -- ledger.db   # MCP server on stdio
cargo run -p ledger-cli -- ledger.db   # list claims with status
scripts/ci.sh                          # fmt, clippy, nextest, doctests, deny, machete
```
