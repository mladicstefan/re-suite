//! MCP server over stdio. Agents file claims and evidence here; every check replays saved evidence.

use std::fmt::Write as _;
use std::sync::Arc;

use ledger_core::{Claim, ClaimId, Event, EvidenceId, EvidenceKind, Ledger, Verdict, admit};
use ledger_store::Store;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::transport::stdio;
use rmcp::{ErrorData, ServerHandler, ServiceExt, tool, tool_handler, tool_router};
use schemars::JsonSchema;

#[derive(rmcp::serde::Deserialize, JsonSchema)]
#[serde(crate = "rmcp::serde")]
struct ProposeArgs {
    claim: Claim,
    /// Evidence to replay the claim against right away.
    #[serde(default)]
    evidence: Vec<EvidenceId>,
}

#[derive(rmcp::serde::Deserialize, JsonSchema)]
#[serde(crate = "rmcp::serde")]
struct AskArgs {
    /// Omit to list every claim.
    claim: Option<ClaimId>,
}

#[derive(rmcp::serde::Deserialize, JsonSchema)]
#[serde(crate = "rmcp::serde")]
struct ExplainArgs {
    claim: ClaimId,
}

#[derive(rmcp::serde::Deserialize, JsonSchema)]
#[serde(crate = "rmcp::serde")]
struct AddEvidenceArgs {
    kind: EvidenceKind,
    /// Local path of a saved capture or snapshot.
    path: String,
}

#[derive(rmcp::serde::Deserialize, JsonSchema)]
#[serde(crate = "rmcp::serde")]
struct RetractArgs {
    claim: ClaimId,
    reason: String,
}

#[derive(Clone)]
struct LedgerServer {
    store: Arc<Store>,
}

fn bad(e: impl std::fmt::Display) -> ErrorData {
    ErrorData::invalid_params(e.to_string(), None)
}

fn line(ledger: &Ledger, id: &ClaimId) -> String {
    match (ledger.status(id), ledger.claim(id)) {
        (Some(s), Some(c)) => format!("{s:?}\t{id}\t{}", c.sentence()),
        _ => format!("unknown\t{id}"),
    }
}

// shortcut: store and checker calls block the current-thread runtime; move to spawn_blocking if tools get slow.
#[tool_router]
impl LedgerServer {
    #[tool(description = "File a typed claim; optionally replay it against evidence IDs at once.")]
    async fn propose(
        &self,
        Parameters(args): Parameters<ProposeArgs>,
    ) -> Result<String, ErrorData> {
        let claim = admit(args.claim).map_err(bad)?;
        let id = claim.get().id().map_err(bad)?;
        let kind = claim.get().kind.clone();
        self.store.append(Event::Proposed { claim }).map_err(bad)?;
        if !args.evidence.is_empty() {
            let snapshot = self.store.snapshot();
            let ledger = &snapshot.ledger;
            let mut raw = Vec::new();
            for e in &args.evidence {
                let k = ledger
                    .evidence_kind(e)
                    .ok_or_else(|| bad(format!("unknown evidence {e}")))?;
                let bytes = self
                    .store
                    .evidence(e)
                    .map_err(bad)?
                    .ok_or_else(|| bad(format!("missing bytes for {e}")))?;
                raw.push((e.clone(), k, bytes));
            }
            let borrowed: Vec<_> = raw
                .iter()
                .map(|(e, k, b)| (e.clone(), *k, &b[..]))
                .collect();
            let limit = std::time::Duration::from_secs(5);
            let verdict =
                ledger_checkers::check_claim(&id, &kind, &borrowed, limit).map_err(bad)?;
            let evidence = args.evidence.into_iter().collect();
            self.store
                .append(Event::Checked {
                    claim: id.clone(),
                    evidence,
                    verdict,
                })
                .map_err(bad)?;
        }
        Ok(line(&self.store.snapshot().ledger, &id))
    }

    #[tool(description = "Status and sentence for one claim, or for all claims.")]
    async fn ask(&self, Parameters(args): Parameters<AskArgs>) -> Result<String, ErrorData> {
        let snapshot = self.store.snapshot();
        let ledger = &snapshot.ledger;
        Ok(match args.claim {
            Some(id) => line(ledger, &id),
            None => ledger
                .claims()
                .map(|(id, _)| line(ledger, id))
                .collect::<Vec<_>>()
                .join("\n"),
        })
    }

    #[tool(description = "Why a claim has its status: premises, verdicts and counterexamples.")]
    async fn explain(
        &self,
        Parameters(args): Parameters<ExplainArgs>,
    ) -> Result<String, ErrorData> {
        let snapshot = self.store.snapshot();
        let ledger = &snapshot.ledger;
        let claim = ledger
            .claim(&args.claim)
            .ok_or_else(|| bad(format!("unknown claim {}", args.claim)))?;
        let mut out = line(ledger, &args.claim);
        for p in &claim.premises {
            let _ = write!(out, "\npremise: {}", line(ledger, p));
        }
        for v in ledger.verdicts(&args.claim) {
            let _ = match v {
                Verdict::Held { runs } => write!(out, "\nheld over {runs} runs"),
                Verdict::Refuted { counterexample: c } => {
                    write!(out, "\nrefuted by {}: {}", c.evidence, c.detail)
                }
                Verdict::Inconclusive { reason } => write!(out, "\ninconclusive: {reason}"),
            };
        }
        Ok(out)
    }

    #[tool(
        description = "Store a saved local capture or snapshot as evidence; returns its content hash."
    )]
    async fn add_evidence(
        &self,
        Parameters(args): Parameters<AddEvidenceArgs>,
    ) -> Result<String, ErrorData> {
        Ok(self
            .store
            .add_evidence_file(args.kind, &args.path)
            .map_err(bad)?
            .to_string())
    }

    #[tool(description = "Withdraw a claim. History is kept; status becomes retracted.")]
    async fn retract(
        &self,
        Parameters(args): Parameters<RetractArgs>,
    ) -> Result<String, ErrorData> {
        let claim = args.claim.clone();
        self.store
            .append(Event::Retracted {
                claim: args.claim,
                reason: args.reason,
            })
            .map_err(bad)?;
        Ok(line(&self.store.snapshot().ledger, &claim))
    }
}

// Why: rmcp's #[tool_handler] expands to async trait fns with no .await; the lint fires on generated code.
#[allow(
    clippy::unused_async_trait_impl,
    reason = "fires inside rmcp::tool_handler expansion"
)]
#[tool_handler]
impl ServerHandler for LedgerServer {}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    // stdout carries the protocol, so logs go to stderr.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "ledger.db".into());
    let server = LedgerServer {
        store: Arc::new(Store::open(&path)?),
    };
    tracing::info!(%path, "ledger-mcp serving on stdio");
    server.serve(stdio()).await?.waiting().await?;
    Ok(())
}
