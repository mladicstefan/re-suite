//! MCP server over stdio. Agents file claims and evidence here; every check replays saved evidence.
//! Handlers stay thin: parse, hand the blocking work to `tools` and outside programs
//! to `runner`, reply.

mod runner;
mod tools;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use ledger_core::{Claim, EvidenceKind};
use ledger_store::Store;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::transport::stdio;
use rmcp::{ErrorData, ServerHandler, ServiceExt, tool, tool_handler, tool_router};
use schemars::JsonSchema;
use tools::{About, Rejection, Source};

#[derive(rmcp::serde::Deserialize, JsonSchema)]
#[serde(crate = "rmcp::serde")]
struct ProposeArgs {
    /// Premises may be given as short ids.
    claim: Claim,
    /// Ids of evidence to replay the claim against right away.
    #[serde(default)]
    evidence: Vec<String>,
    /// For a web claim: replay it against every capture in the ledger that it is
    /// about, instead of listing them in `evidence`.
    #[serde(default)]
    all_captures: bool,
}

#[derive(rmcp::serde::Deserialize, JsonSchema)]
#[serde(crate = "rmcp::serde")]
struct AskArgs {
    about: About,
    /// Claim id, for about=claim and about=affected.
    claim: Option<String>,
    /// Type name or endpoint, for about=subject.
    subject: Option<String>,
    /// To continue a list: the id on the last line of the previous page.
    after: Option<String>,
}

#[derive(rmcp::serde::Deserialize, JsonSchema)]
#[serde(crate = "rmcp::serde")]
struct ExplainArgs {
    claim: String,
}

#[derive(rmcp::serde::Deserialize, JsonSchema)]
#[serde(crate = "rmcp::serde")]
struct AddEvidenceArgs {
    kind: EvidenceKind,
    /// Local path of a saved file. For `binary_facts` it may be the program itself:
    /// it is stored as `artifact` and Rizin reads it, never runs it. For `live_snapshot`
    /// it is a file a human made with `ledger-capture`; this server never reads a process.
    path: Option<String>,
    /// Instead of `path`: an outside tool, such as `rizin`, to run on `inputs`.
    tool: Option<String>,
    /// Ids of the evidence the tool reads.
    #[serde(default)]
    inputs: Vec<String>,
}

#[derive(rmcp::serde::Deserialize, JsonSchema)]
#[serde(crate = "rmcp::serde")]
struct RetractArgs {
    claim: String,
    reason: String,
}

/// A rejection as the protocol carries it: the sentence, and its parts as data.
fn refused(r: &Rejection) -> ErrorData {
    let data = rmcp::serde_json::json!({"code": r.code, "subject": r.subject, "next": r.next});
    ErrorData::invalid_params(r.to_string(), Some(data))
}

#[derive(Clone)]
struct LedgerServer {
    store: Arc<Store>,
}

impl LedgerServer {
    /// Store calls, hashing and checks block, so they run off the async executor,
    /// inside one trace span per verb.
    async fn blocking<T: Send + 'static>(
        &self,
        verb: &'static str,
        work: impl FnOnce(&Store) -> Result<T, Rejection> + Send + 'static,
    ) -> Result<T, ErrorData> {
        let store = Arc::clone(&self.store);
        let joined = tokio::task::spawn_blocking(move || {
            let span = tracing::info_span!("verb", verb);
            let _entered = span.enter();
            let start = Instant::now();
            let result = work(&store);
            let outcome = result.as_ref().map_or_else(|r| r.code, |_| "ok");
            tracing::info!(elapsed = ?start.elapsed(), outcome, "done");
            result
        });
        match joined.await {
            Ok(Ok(done)) => Ok(done),
            Ok(Err(r)) => Err(refused(&r)),
            Err(e) => Err(ErrorData::internal_error(e.to_string(), None)),
        }
    }
}

#[tool_router]
impl LedgerServer {
    #[tool(
        description = "File a typed claim; optionally replay it against evidence ids at once. Proposing the same claim twice is a no-op."
    )]
    async fn propose(
        &self,
        Parameters(args): Parameters<ProposeArgs>,
    ) -> Result<String, ErrorData> {
        self.blocking("propose", move |store| {
            if args.all_captures {
                tools::propose_on_all(store, args.claim)
            } else {
                tools::propose(store, args.claim, &args.evidence)
            }
        })
        .await
    }

    #[tool(
        description = "Ask a fixed question: all claims, one claim, a subject, what is on hold, or what a claim's failure would affect. Lists come 50 rows at a time."
    )]
    async fn ask(&self, Parameters(args): Parameters<AskArgs>) -> Result<String, ErrorData> {
        self.blocking("ask", move |store| {
            let (claim, subject, after) = (args.claim, args.subject, args.after);
            tools::ask(
                store,
                args.about,
                claim.as_deref(),
                subject.as_deref(),
                after.as_deref(),
            )
        })
        .await
    }

    #[tool(description = "Why a claim has its status: premises, verdicts and counterexamples.")]
    async fn explain(
        &self,
        Parameters(args): Parameters<ExplainArgs>,
    ) -> Result<String, ErrorData> {
        self.blocking("explain", move |store| tools::explain(store, &args.claim))
            .await
    }

    #[tool(
        description = "Store a saved local file as evidence, or what an outside tool prints for stored evidence; returns its id. A tool runs once per version and inputs, and can take minutes. A program given as binary_facts is read by Rizin."
    )]
    async fn add_evidence(
        &self,
        Parameters(args): Parameters<AddEvidenceArgs>,
    ) -> Result<String, ErrorData> {
        let AddEvidenceArgs {
            kind,
            path,
            tool,
            inputs,
        } = args;
        let source = self.blocking("add_evidence", move |store| {
            tools::source(store, kind, path.as_deref(), tool.as_deref(), &inputs)
        });
        let (adapter, inputs) = match source.await? {
            Source::Stored(reply) => return Ok(reply),
            Source::Tool(adapter, inputs) => (adapter, inputs),
        };
        let output = runner::derive(Arc::clone(&self.store), adapter, inputs).await;
        let output = output.map_err(|r| refused(&r))?;
        self.blocking("add_evidence", move |store| tools::made(store, &output))
            .await
    }

    #[tool(description = "Withdraw a claim. History is kept; its dependents go on hold.")]
    async fn retract(
        &self,
        Parameters(args): Parameters<RetractArgs>,
    ) -> Result<String, ErrorData> {
        self.blocking("retract", move |store| {
            tools::retract(store, &args.claim, args.reason)
        })
        .await
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
    let store = Arc::new(Store::open(&path)?);
    tools::record_checkers(&store)?;
    // Checks an older checker made are replayed while the server already answers:
    // they block, and a large ledger has many.
    let stop = Arc::new(AtomicBool::new(false));
    let (rechecked, stopping) = (Arc::clone(&store), Arc::clone(&stop));
    let rechecking = tokio::task::spawn_blocking(move || {
        tracing::info!(summary = tools::recheck(&rechecked, &stopping), "rechecked");
    });
    let server = LedgerServer { store };
    tracing::info!(%path, "ledger-mcp serving on stdio");
    let outcome = async {
        server.serve(stdio()).await?.waiting().await?;
        anyhow::Ok(())
    };
    let outcome = outcome.await;
    // However serving ended, the replay stops after the check it is on.
    stop.store(true, Ordering::Relaxed);
    rechecking.await?;
    outcome
}
