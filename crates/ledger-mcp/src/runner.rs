//! The one place that starts outside programs. Each program is an adapter in
//! [`ADAPTERS`]. What it prints is stored as evidence, and `Event::Derived` logs
//! which tool, at which version, read which inputs, so a run is never made twice.
//! The program reads copies of its inputs and never sees this server's environment.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use ledger_checkers::{MAX_PARSED_EVIDENCE, RIZIN_COMMANDS, rizin_facts};
use ledger_core::{Event, EvidenceId, EvidenceKind, Ledger, ToolRef};
use ledger_os::TempDir;
use ledger_store::{Store, StoreError};
use tokio::process::Command;
use tokio::sync::Semaphore;

use crate::tools::{Rejection, kind_name, reject, unknown_evidence};

const MISSING: &str = "No output was recorded. Tell the human: start this server inside the flake's shell (`nix develop`), which sets the path.";
const FAILED: &str = "No output was recorded. Check that the input is a file the tool can read, then tell the human.";

/// An outside program, as data: where it is, how to run it, and what of its output to store.
pub struct Adapter {
    /// The id agents name it by, and the log records.
    pub id: &'static str,
    /// The variable that holds the program's absolute path. The flake's shell sets it.
    env: &'static str,
    /// Arguments that make it print its version on the first line.
    version: &'static [&'static str],
    /// How many inputs it reads, all of this kind.
    reads: (usize, EvidenceKind),
    /// Its arguments, given the absolute path of each input.
    args: fn(&[PathBuf]) -> Vec<OsString>,
    /// Longest one run may take. The program is stopped when it runs out.
    limit: Duration,
    /// The kind its output is stored as.
    pub output: EvidenceKind,
    /// The bytes to store, from what the program printed.
    parse: fn(&ToolRef, &[u8]) -> Result<Vec<u8>, Rejection>,
    /// One run at a time, since each can take minutes and much of the memory.
    turn: Semaphore,
    /// The version the program reported, asked once per server run.
    known: OnceLock<String>,
}

pub static RIZIN: Adapter = Adapter {
    id: "rizin",
    env: "LEDGER_TOOL_RIZIN",
    version: &["-v"],
    reads: (1, EvidenceKind::Artifact),
    args: rizin_args,
    limit: Duration::from_secs(600),
    output: EvidenceKind::BinaryFacts,
    parse: rizin_output,
    turn: Semaphore::const_new(1),
    known: OnceLock::new(),
};

/// Every outside tool. The next one is an entry here and its output parser.
static ADAPTERS: [&Adapter; 1] = [&RIZIN];

/// The sandbox stops the analysis from running commands or writing files.
fn rizin_args(files: &[PathBuf]) -> Vec<OsString> {
    let options = ["-N", "-q", "-e", "scr.color=0", "-e", "cfg.sandbox=true"];
    let options = options.into_iter().chain(["-c", RIZIN_COMMANDS]);
    let files = files.iter().map(|file| file.clone().into_os_string());
    options.map(OsString::from).chain(files).collect()
}

/// The functions and direct calls Rizin recovered, as stored `binary_facts`.
fn rizin_output(tool: &ToolRef, printed: &[u8]) -> Result<Vec<u8>, Rejection> {
    let ran = format!("{} {}", tool.id, tool.version);
    let facts = rizin_facts(&ran, printed).map_err(|why| {
        reject(
            "tool_output_unreadable",
            tool.id.as_str(),
            format!("Rizin's output cannot be used: {why}."),
            "No output was recorded. Check that the file is a program Rizin can read, then tell the human.",
        )
    })?;
    let stored = rmcp::serde_json::to_vec(&facts).map_err(|e| StoreError::Core(e.into()))?;
    // Every check would refuse facts over the limit, so they are not stored either.
    if stored.len() > MAX_PARSED_EVIDENCE {
        return Err(reject(
            "evidence_too_large",
            tool.id.as_str(),
            format!(
                "What Rizin recovered is {} bytes, limit {MAX_PARSED_EVIDENCE}.",
                stored.len()
            ),
            "No output was recorded. Tell the human: this program is too large to check claims on.",
        ));
    }
    Ok(stored)
}

/// The adapter agents call `id`.
///
/// # Errors
/// No adapter has this id.
pub fn adapter(id: &str) -> Result<&'static Adapter, Rejection> {
    let found = ADAPTERS.iter().copied().find(|adapter| adapter.id == id);
    found.ok_or_else(|| {
        let ids: Vec<&str> = ADAPTERS.iter().map(|adapter| adapter.id).collect();
        reject(
            "tool_unknown",
            id,
            format!("No tool has this id. There are: {}.", ids.join(", ")),
            "Call add_evidence again with one of them.",
        )
    })
}

/// What `adapter` prints for `inputs`, stored as evidence. A run of the same tool, at
/// the same version, on the same inputs is made once: after that its output is
/// returned and no process is started.
///
/// # Errors
/// The inputs are not what the tool reads, the program is not where its variable
/// says, or it fails, runs out of time or prints something its adapter refuses.
pub async fn derive(
    store: Arc<Store>,
    adapter: &'static Adapter,
    inputs: BTreeSet<EvidenceId>,
) -> Result<EvidenceId, Rejection> {
    // Nothing is looked up on PATH: the flake's shell names each program by its store path.
    derive_with(store, adapter, std::env::var_os(adapter.env), inputs).await
}

async fn derive_with(
    store: Arc<Store>,
    adapter: &'static Adapter,
    program: Option<OsString>,
    inputs: BTreeSet<EvidenceId>,
) -> Result<EvidenceId, Rejection> {
    readable(&store.snapshot().ledger, adapter, &inputs)?;
    let program = located(adapter, program)?;
    let version = version(adapter, &program).await?;
    let tool = ToolRef {
        id: adapter.id.into(),
        version,
    };
    let ran_before = |store: &Store| {
        let output = store.snapshot().ledger.derived(&tool, &inputs).cloned();
        if let Some(output) = &output {
            tracing::info!(tool = adapter.id, %output, "already ran on these inputs");
        }
        output
    };
    if let Some(output) = ran_before(&store) {
        return Ok(output);
    }
    let closed = |e| reject("tool_failed", adapter.id, format!("{e}."), FAILED);
    let _turn = adapter.turn.acquire().await.map_err(closed)?;
    // Whoever had the turn before may have made this very run.
    if let Some(output) = ran_before(&store) {
        return Ok(output);
    }
    let (into, read) = (Arc::clone(&store), inputs.clone());
    let (dir, files) = off_executor(move || materialised(&into, &read)).await?;
    let mut command = command(&program);
    command.args((adapter.args)(&files)).current_dir(dir.path());
    let printed = finished(adapter, &mut command).await;
    // The directory is removed off the executor too, however the run ended.
    off_executor(move || {
        drop(dir);
        record(&store, adapter, tool, inputs, &printed?)
    })
    .await
}

/// Refuses inputs the tool does not read: too many, too few, or of another kind.
fn readable(
    ledger: &Ledger,
    adapter: &Adapter,
    inputs: &BTreeSet<EvidenceId>,
) -> Result<(), Rejection> {
    let (count, kind) = adapter.reads;
    let of_kind = |e: &EvidenceId| ledger.evidence_kind(e) == Some(kind);
    if inputs.len() == count && inputs.iter().all(of_kind) {
        return Ok(());
    }
    Err(reject(
        "tool_inputs_wrong",
        adapter.id,
        format!("It reads {count} input of kind {}.", kind_name(kind)),
        "No output was recorded. Add the input with add_evidence first, then name its id in `inputs`.",
    ))
}

fn located(adapter: &Adapter, program: Option<OsString>) -> Result<PathBuf, Rejection> {
    let path = program.map(PathBuf::from).filter(|path| path.is_absolute());
    path.ok_or_else(|| {
        let message = format!(
            "`{}` does not hold the program's absolute path.",
            adapter.env
        );
        reject("tool_missing", adapter.id, message, MISSING)
    })
}

/// The version the program reports on its first line, without its own name in front.
async fn version(adapter: &'static Adapter, program: &Path) -> Result<String, Rejection> {
    if let Some(known) = adapter.known.get() {
        return Ok(known.clone());
    }
    let printed = finished(adapter, command(program).args(adapter.version)).await?;
    let printed = String::from_utf8_lossy(&printed);
    let line = printed.lines().next().unwrap_or_default().trim();
    let version = line.strip_prefix(adapter.id).unwrap_or(line).trim();
    if version.is_empty() {
        return Err(reject(
            "tool_failed",
            adapter.id,
            "It printed no version.",
            FAILED,
        ));
    }
    Ok(adapter.known.get_or_init(|| version.to_owned()).clone())
}

/// A program that gets nothing of this server's: no environment, no input. Its
/// errors are dropped, and so is the program when its run is dropped.
fn command(program: &Path) -> Command {
    let mut command = Command::new(program);
    command
        .env_clear()
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    command
}

/// What the program printed, if it ended well within its limit.
async fn finished(adapter: &Adapter, command: &mut Command) -> Result<Vec<u8>, Rejection> {
    let ran = tokio::time::timeout(adapter.limit, command.output()).await;
    let ran = ran.map_err(|_| {
        reject(
            "tool_timeout",
            adapter.id,
            format!(
                "It did not finish within {:?} and was stopped.",
                adapter.limit
            ),
            "No output was recorded. Tell the human: this input needs a longer limit or a lighter run.",
        )
    })?;
    let ran = ran.map_err(|e| {
        let message = format!("It could not be started: {e}.");
        reject("tool_missing", adapter.id, message, MISSING)
    })?;
    if !ran.status.success() {
        let message = format!("It ended with {}.", ran.status);
        return Err(reject("tool_failed", adapter.id, message, FAILED));
    }
    Ok(ran.stdout)
}

/// Each input as a file named by its id, in a new directory only this user can open.
fn materialised(
    store: &Store,
    inputs: &BTreeSet<EvidenceId>,
) -> Result<(TempDir, Vec<PathBuf>), Rejection> {
    let unwritable = |e: std::io::Error| {
        let message = format!("They could not be written for the tool: {e}.");
        reject("tool_failed", "inputs", message, FAILED)
    };
    let dir = ledger_os::private_temp_dir().map_err(unwritable)?;
    // An absolute path cannot be read as an option, or as a `scheme://` target, some
    // of which start a process or open a connection.
    let root = ledger_os::absolute(dir.path()).map_err(unwritable)?;
    let mut files = Vec::with_capacity(inputs.len());
    for id in inputs {
        let bytes = store.evidence(id)?;
        let bytes = bytes.ok_or_else(|| unknown_evidence(id.as_str()))?;
        let file = root.join(id.as_str());
        std::fs::write(&file, &*bytes).map_err(unwritable)?;
        files.push(file);
    }
    Ok((dir, files))
}

/// Stores what `tool` printed for `inputs` and logs the run that made it.
///
/// # Errors
/// The adapter refuses the output, or it cannot be stored.
pub fn record(
    store: &Store,
    adapter: &Adapter,
    tool: ToolRef,
    inputs: BTreeSet<EvidenceId>,
    printed: &[u8],
) -> Result<EvidenceId, Rejection> {
    let output = store.add_evidence(adapter.output, &(adapter.parse)(&tool, printed)?)?;
    tracing::info!(tool = adapter.id, version = %tool.version, %output, "ran");
    store.append(Event::Derived {
        tool,
        inputs,
        output: output.clone(),
    })?;
    Ok(output)
}

async fn off_executor<T: Send + 'static>(
    work: impl FnOnce() -> Result<T, Rejection> + Send + 'static,
) -> Result<T, Rejection> {
    let joined = tokio::task::spawn_blocking(work).await;
    joined.map_err(|e| {
        let next = "No output was recorded. Retry once, then tell the human.";
        reject("tool_failed", "server", format!("{e}."), next)
    })?
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// A shell is the one program every test machine has at a fixed path.
    const SH: &str = "/bin/sh";

    fn script(script: &str, files: &[PathBuf]) -> Vec<OsString> {
        let args = ["-c", script, "fake"].into_iter().map(OsString::from);
        args.chain(files.iter().map(|f| f.clone().into_os_string()))
            .collect()
    }

    /// Prints the first line of its input. Only shell builtins: there is no PATH.
    fn first_line(files: &[PathBuf]) -> Vec<OsString> {
        script(r#"read -r line < "$1"; printf '%s' "$line""#, files)
    }

    fn spin(files: &[PathBuf]) -> Vec<OsString> {
        script("while :; do :; done", files)
    }

    fn fail(files: &[PathBuf]) -> Vec<OsString> {
        script("exit 3", files)
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "an adapter's parser has to be able to refuse"
    )]
    fn as_printed(_: &ToolRef, printed: &[u8]) -> Result<Vec<u8>, Rejection> {
        Ok(printed.to_vec())
    }

    /// Each test has adapters of its own, so no test waits for another's turn.
    const fn fake(args: fn(&[PathBuf]) -> Vec<OsString>, limit: Duration) -> Adapter {
        Adapter {
            id: "fake",
            env: "LEDGER_TOOL_FAKE",
            version: &["-c", "echo fake 1.2"],
            reads: (1, EvidenceKind::Artifact),
            args,
            limit,
            output: EvidenceKind::Artifact,
            parse: as_printed,
            turn: Semaphore::const_new(1),
            known: OnceLock::new(),
        }
    }

    const SECONDS: Duration = Duration::from_secs(10);

    fn ledger(dir: &Path) -> Result<(Arc<Store>, BTreeSet<EvidenceId>), StoreError> {
        let store = Store::open(dir.join("l.db"))?;
        let input = store.add_evidence(EvidenceKind::Artifact, b"first\nsecond")?;
        Ok((Arc::new(store), [input].into()))
    }

    #[tokio::test]
    async fn a_run_is_made_once_per_tool_version_and_inputs() -> TestResult {
        static ONCE: Adapter = fake(first_line, SECONDS);
        let dir = tempfile::tempdir()?;
        let (store, inputs) = ledger(dir.path())?;
        let first = derive_with(Arc::clone(&store), &ONCE, Some(SH.into()), inputs.clone()).await;
        let first = first.map_err(|r| r.to_string())?;
        assert_eq!(&store.evidence(&first)?.ok_or("not stored")?[..], b"first");
        let tool = ToolRef {
            id: "fake".into(),
            version: "1.2".into(),
        };
        let ledger = &store.snapshot().ledger;
        assert_eq!(ledger.derivation_of(&first), Some((&tool, &inputs)));
        let seq = store.snapshot().seq;
        // Starting a process now would fail: there is no program at this path.
        let nowhere = Some("/no/such/program".into());
        let again = derive_with(Arc::clone(&store), &ONCE, nowhere, inputs).await;
        assert_eq!(again.map_err(|r| r.to_string())?, first);
        assert_eq!(store.snapshot().seq, seq, "the cached run logged an event");
        Ok(())
    }

    #[tokio::test]
    async fn a_run_waits_while_another_runs() -> TestResult {
        static TURNS: Adapter = fake(first_line, SECONDS);
        let dir = tempfile::tempdir()?;
        let (store, inputs) = ledger(dir.path())?;
        let running = TURNS.turn.acquire().await?;
        let waiting = derive_with(Arc::clone(&store), &TURNS, Some(SH.into()), inputs.clone());
        let waited = tokio::time::timeout(Duration::from_millis(500), waiting).await;
        assert!(waited.is_err(), "it did not wait: {waited:?}");
        drop(running);
        let ran = derive_with(store, &TURNS, Some(SH.into()), inputs).await;
        assert!(ran.is_ok(), "{ran:?}");
        Ok(())
    }

    #[tokio::test]
    async fn every_refused_run_reads_as_expected_and_records_nothing() -> TestResult {
        static FOUND: Adapter = fake(first_line, SECONDS);
        static NOT_STARTED: Adapter = fake(first_line, SECONDS);
        static SPINS: Adapter = fake(spin, Duration::from_millis(200));
        static FAILS: Adapter = fake(fail, SECONDS);
        let dir = tempfile::tempdir()?;
        let (store, inputs) = ledger(dir.path())?;
        let snapshot = store.add_evidence(EvidenceKind::MemorySnapshot, b"memory")?;
        let seq = store.snapshot().seq;
        let refused = async |adapter: &'static Adapter, program, inputs| {
            let ran = derive_with(Arc::clone(&store), adapter, program, inputs).await;
            ran.map_or_else(|r| r.to_string(), |ok| format!("NOT REFUSED: {ok}"))
        };
        let all = [
            refused(&FOUND, None, inputs.clone()).await,
            refused(&FOUND, Some("sh".into()), inputs.clone()).await,
            refused(
                &NOT_STARTED,
                Some("/no/such/program".into()),
                inputs.clone(),
            )
            .await,
            refused(&FOUND, Some(SH.into()), BTreeSet::new()).await,
            refused(&FOUND, Some(SH.into()), [snapshot].into()).await,
            refused(&SPINS, Some(SH.into()), inputs.clone()).await,
            refused(&FAILS, Some(SH.into()), inputs).await,
        ];
        assert_eq!(store.snapshot().seq, seq, "a refused run was recorded");
        insta::assert_snapshot!("refused_runs", all.join("\n"));
        Ok(())
    }

    #[test]
    fn rizin_reads_its_input_by_absolute_path_in_its_sandbox() {
        let args = rizin_args(&[PathBuf::from("/tmp/ledger-x/abc")]);
        let last = args.last().map(OsString::as_os_str);
        assert_eq!(last, Some(Path::new("/tmp/ledger-x/abc").as_os_str()));
        assert!(args.iter().any(|a| a == "cfg.sandbox=true"));
        assert!(adapter("rizin").is_ok_and(|a| a.env == "LEDGER_TOOL_RIZIN"));
        assert_eq!(
            adapter("objdump").err().map(|r| r.code),
            Some("tool_unknown")
        );
    }
}
