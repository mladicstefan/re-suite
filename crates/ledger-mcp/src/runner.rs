//! The one place that starts outside programs. Each program is an adapter in
//! [`ADAPTERS`]. What it prints, and what it writes under [`OUT`], is stored as
//! evidence, and `Event::Derived` logs which tool, at which version, read which
//! inputs, so a run is never made twice. Every program runs confined
//! (`ledger_os::confined`): it reads copies of its inputs, never sees this server's
//! environment, files or network, and is stopped when it holds or prints more than
//! its adapter allows.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Read as _};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use ledger_checkers::{MAX_PARSED_EVIDENCE, RIZIN_COMMANDS, rizin_facts};
use ledger_core::source_tree::{Module, ModulePath, Split};
use ledger_core::{
    Event, EvidenceId, EvidenceKind, Session, SourceTree, Technology, TechnologyFacts, ToolRef,
};
use ledger_os::TempDir;
use ledger_store::{Store, StoreError};
use tokio::io::AsyncReadExt as _;
use tokio::process::{ChildStdout, Command};
use tokio::sync::Semaphore;

use crate::tools::{Rejection, kind_name, reject, unknown_evidence};

const MISSING: &str = "No output was recorded. Tell the human: start this server inside the flake's shell (`nix develop`), which sets the path.";
const FAILED: &str = "No output was recorded. Check that the input is a file the tool can read, then tell the human.";
const IMPORT_AGAIN: &str = "No output was recorded. Import the capture file again with add_evidence kind=session, then retry.";
const UNCONFINED: &str = "No output was recorded. Tell the human: outside tools run only where the server can confine them, so far Linux.";

/// How often a running program's memory is read.
const WATCH: Duration = Duration::from_millis(20);

const MIB: u64 = 1 << 20;

/// The directory, in a run's own, where its program may leave files to be stored.
const OUT: &str = "out";
/// Most entries a run may leave under [`OUT`], directories included.
const MAX_WRITTEN_FILES: usize = 10_000;
/// Most bytes one file a run leaves may hold.
const MAX_WRITTEN_FILE: u64 = 64 * MIB;
/// Most bytes all the files a run leaves may hold together. They are all held in
/// memory until they are stored.
const MAX_WRITTEN: u64 = 256 * MIB;

/// What one run reads. Only the inputs are recorded: anything else it is given, the
/// inputs name by content hash, so the inputs alone decide the output.
#[derive(Clone, Copy)]
enum Reads {
    /// This many inputs, all of this kind.
    Inputs(usize, EvidenceKind),
    /// One session, with every piece of evidence of this kind that it names written
    /// beside it under its id: its exchanges, or its scripts' sources.
    Session(EvidenceKind),
}

/// The files a run left under [`OUT`], by their path there.
pub type Wrote = BTreeMap<ModulePath, Vec<u8>>;

/// What one run stores: pieces of `artifact` evidence, then the record of the
/// adapter's output kind, which names them.
pub struct Made {
    beside: Vec<Vec<u8>>,
    record: Vec<u8>,
}

impl Made {
    const fn alone(record: Vec<u8>) -> Self {
        Self {
            beside: Vec::new(),
            record,
        }
    }
}

/// What to store, from what the program printed and the files it left for these inputs.
type Parse = fn(&Store, &ToolRef, &BTreeSet<EvidenceId>, &[u8], Wrote) -> Result<Made, Rejection>;

/// An outside program, as data: where it is, how to run it, and what of its output to store.
pub struct Adapter {
    /// The id agents name it by, and the log records.
    pub id: &'static str,
    /// The variable that holds the program's absolute path. The flake's shell sets it.
    env: &'static str,
    /// Arguments that make it print its version on the first line.
    version: &'static [&'static str],
    reads: Reads,
    /// Put after the id each file it reads is named by, for a program that decides
    /// what a file is by its name.
    named: &'static str,
    /// Its arguments, given the absolute path of each file it reads: the inputs first.
    args: fn(&[PathBuf]) -> Vec<OsString>,
    /// Longest one run may take. The program is stopped when it runs out.
    limit: Duration,
    /// Most bytes of memory one run may hold, all its processes added up. The program
    /// is stopped when it holds more.
    memory: u64,
    /// Most bytes one run may print. The program is stopped when it prints more.
    printed: u64,
    /// The kind its record is stored as.
    pub output: EvidenceKind,
    parse: Parse,
    /// One run at a time, since each can take minutes and much of the memory.
    turn: Semaphore,
    /// The version the program reported, asked once per server run.
    known: OnceLock<String>,
}

pub static RIZIN: Adapter = Adapter {
    id: "rizin",
    env: "LEDGER_TOOL_RIZIN",
    version: &["-v"],
    reads: Reads::Inputs(1, EvidenceKind::Artifact),
    named: "",
    args: rizin_args,
    limit: Duration::from_secs(600),
    memory: 4096 * MIB,
    // What it prints is several times the facts kept from it, which have a limit of their own.
    printed: 256 * MIB,
    output: EvidenceKind::BinaryFacts,
    parse: rizin_output,
    turn: Semaphore::const_new(1),
    known: OnceLock::new(),
};

/// The Wappalyzer rule set (`tools/fingerprint`) on the responses of one session.
pub static FINGERPRINT: Adapter = Adapter {
    id: "fingerprint",
    env: "LEDGER_TOOL_FINGERPRINT",
    version: &["--version"],
    reads: Reads::Session(EvidenceKind::HttpExchange),
    named: "",
    args: fingerprint_args,
    limit: Duration::from_secs(300),
    memory: 2048 * MIB,
    // Names and a few exchange ids per technology; far less than the session it read.
    printed: 64 * MIB,
    output: EvidenceKind::TechnologyFacts,
    parse: fingerprint_output,
    turn: Semaphore::const_new(1),
    known: OnceLock::new(),
};

/// Wakaru splits one script into modules and makes each readable. `--unpack=auto`
/// reads a webpack, browserify or esbuild bundle by its module table and falls back to
/// a heuristic split for a scope-hoisted one (Vite, Rollup): on the 640 KB Vite build
/// of the trial it gave 105 modules where `strict` gave 1, and `inspect` cut finer
/// (121) at boundaries its help says may not hold. A script that is no bundle comes
/// back as one module. The default rewrite level is kept, since `aggressive` changed
/// 28 bytes of 1.3 MB there; `--dce` would drop code an agent should see. The script
/// is named `.js`: Wakaru names a script that is no bundle after its input, and the
/// tools that read the module next tell its language by that name.
pub static WAKARU: Adapter = Adapter {
    id: "wakaru",
    env: "LEDGER_TOOL_WAKARU",
    version: &["--version"],
    reads: Reads::Inputs(1, EvidenceKind::Artifact),
    named: ".js",
    args: wakaru_args,
    limit: Duration::from_secs(300),
    // 170 MiB at most on the 640 KB file of the trial.
    memory: 4096 * MIB,
    // It prints nothing when it succeeds; what it makes is in the files it leaves.
    printed: MIB,
    output: EvidenceKind::SourceTree,
    parse: wakaru_output,
    turn: Semaphore::const_new(1),
    known: OnceLock::new(),
};

/// Every outside tool. The next one is an entry here and its output parser.
static ADAPTERS: [&Adapter; 3] = [&RIZIN, &FINGERPRINT, &WAKARU];

/// The sandbox stops the analysis from running commands or writing files.
fn rizin_args(files: &[PathBuf]) -> Vec<OsString> {
    let options = ["-N", "-q", "-e", "scr.color=0", "-e", "cfg.sandbox=true"];
    let options = options.into_iter().chain(["-c", RIZIN_COMMANDS]);
    let files = files.iter().map(|file| file.clone().into_os_string());
    options.map(OsString::from).chain(files).collect()
}

/// The functions and direct calls Rizin recovered, as stored `binary_facts`.
fn rizin_output(
    _: &Store,
    tool: &ToolRef,
    _: &BTreeSet<EvidenceId>,
    printed: &[u8],
    _: Wrote,
) -> Result<Made, Rejection> {
    let ran = format!("{} {}", tool.id, tool.version);
    let facts = rizin_facts(&ran, printed).map_err(|why| {
        reject(
            "tool_output_unreadable",
            tool.id.as_str(),
            format!("Rizin's output cannot be used: {why}."),
            "No output was recorded. Check that the file is a program Rizin can read, then tell the human.",
        )
    })?;
    checkable(tool, &facts).map(Made::alone)
}

/// Facts as stored, if a check can read them: every check refuses facts over the
/// limit, so they are not stored either.
fn checkable(tool: &ToolRef, facts: &impl rmcp::serde::Serialize) -> Result<Vec<u8>, Rejection> {
    let stored = rmcp::serde_json::to_vec(facts).map_err(|e| StoreError::Core(e.into()))?;
    if stored.len() > MAX_PARSED_EVIDENCE {
        return Err(reject(
            "evidence_too_large",
            tool.id.as_str(),
            format!(
                "What it found is {} bytes, limit {MAX_PARSED_EVIDENCE}.",
                stored.len()
            ),
            "No output was recorded. Tell the human: this input is too large to check claims on.",
        ));
    }
    Ok(stored)
}

/// The session's record; the tool finds its exchanges beside it, each named by its id.
fn fingerprint_args(files: &[PathBuf]) -> Vec<OsString> {
    let listed = [
        "--listed".into(),
        TechnologyFacts::LISTED.to_string().into(),
    ];
    let session = files.first().map(|file| file.clone().into_os_string());
    listed.into_iter().chain(session).collect()
}

/// What `ledger-fingerprint` prints: by host, the technologies by name.
#[derive(rmcp::serde::Deserialize)]
#[serde(crate = "rmcp::serde")]
struct Fingerprinted {
    hosts: BTreeMap<String, BTreeMap<String, Technology>>,
}

/// What the rules read in the session's responses, as stored `technology_facts`.
fn fingerprint_output(
    _: &Store,
    tool: &ToolRef,
    inputs: &BTreeSet<EvidenceId>,
    printed: &[u8],
    _: Wrote,
) -> Result<Made, Rejection> {
    let unusable = |why: String| {
        reject(
            "tool_output_unreadable",
            tool.id.as_str(),
            format!("The fingerprint tool's output cannot be used: {why}."),
            FAILED,
        )
    };
    let session = inputs.first().cloned();
    let session = session.ok_or_else(|| unusable("it read no session".into()))?;
    let printed: Fingerprinted =
        rmcp::serde_json::from_slice(printed).map_err(|e| unusable(e.to_string()))?;
    let mut hosts = printed.hosts;
    for technology in hosts.values_mut().flat_map(BTreeMap::values_mut) {
        let listed = std::mem::take(&mut technology.exchanges);
        technology.exchanges = listed.into_iter().take(TechnologyFacts::LISTED).collect();
    }
    if hosts
        .keys()
        .chain(hosts.values().flat_map(BTreeMap::keys))
        .any(String::is_empty)
    {
        return Err(unusable(
            "it names a host or a technology with no name".into(),
        ));
    }
    let tool_ran = format!("{} {}", tool.id, tool.version);
    let facts = TechnologyFacts {
        tool: tool_ran,
        session,
        hosts,
    };
    checkable(tool, &facts).map(Made::alone)
}

/// The script by absolute path; the modules go under [`OUT`] in its directory.
fn wakaru_args(files: &[PathBuf]) -> Vec<OsString> {
    let options = ["--unpack=auto", "--provenance", "--output", OUT];
    let files = files.iter().map(|file| file.clone().into_os_string());
    options
        .into_iter()
        .map(OsString::from)
        .chain(files)
        .collect()
}

/// The file Wakaru writes beside the modules, saying which bytes of the input each
/// came from.
const PROVENANCE: &str = "provenance.json";

/// What `provenance.json` says, of what is kept.
#[derive(rmcp::serde::Deserialize)]
#[serde(crate = "rmcp::serde")]
struct Provenance {
    format: String,
    strategy: Split,
    modules: BTreeMap<String, Provenanced>,
}

#[derive(rmcp::serde::Deserialize)]
#[serde(crate = "rmcp::serde")]
struct Provenanced {
    /// Byte offsets into the input, each pair counted from 0 with its end left out.
    ranges: Vec<(u64, u64)>,
}

/// The modules Wakaru left, each as `artifact` evidence, and the `source_tree` that
/// names them. Every file it left must be a module its provenance accounts for.
fn wakaru_output(
    store: &Store,
    tool: &ToolRef,
    inputs: &BTreeSet<EvidenceId>,
    _: &[u8],
    mut wrote: Wrote,
) -> Result<Made, Rejection> {
    let unusable = |why: String| {
        let message = format!("Wakaru's output cannot be used: {why}.");
        reject("tool_output_unreadable", tool.id.as_str(), message, FAILED)
    };
    let script = inputs.first().cloned();
    let script = script.ok_or_else(|| unusable("it read no script".into()))?;
    let length = store.evidence(&script)?.map(|source| source.len());
    let length = length.ok_or_else(|| unknown_evidence(script.as_str()))?;
    let length = u64::try_from(length).unwrap_or(u64::MAX);
    let provenance = wrote.remove(PROVENANCE);
    let provenance = provenance.ok_or_else(|| unusable(format!("it left no {PROVENANCE}")))?;
    let provenance: Provenance =
        rmcp::serde_json::from_slice(&provenance).map_err(|e| unusable(e.to_string()))?;
    if provenance.modules.len() != wrote.len() {
        let (left, named) = (wrote.len(), provenance.modules.len());
        return Err(unusable(format!(
            "it left {left} modules and accounts for {named}"
        )));
    }
    let (mut modules, mut beside) = (BTreeMap::new(), Vec::with_capacity(wrote.len()));
    for (name, Provenanced { ranges }) in provenance.modules {
        let path = ModulePath::new(name).map_err(unusable)?;
        let text = wrote.remove(path.as_str()).ok_or_else(|| {
            unusable(format!(
                "it accounts for {}, which it did not leave",
                path.as_str()
            ))
        })?;
        if let Some((start, end)) = ranges
            .iter()
            .find(|(start, end)| start > end || *end > length)
        {
            let path = path.as_str();
            let why = format!("{path} came from bytes {start} to {end} of a script of {length}");
            return Err(unusable(why));
        }
        let ranges = ranges.into_iter().map(|(start, end)| start..end).collect();
        let source = EvidenceId::of(&text);
        modules.insert(path, Module { source, ranges });
        beside.push(text);
    }
    let (format, split) = (provenance.format, provenance.strategy);
    let tree = SourceTree::new(tool.clone(), script, format, split, modules).map_err(unusable)?;
    let record = checkable(tool, &tree)?;
    Ok(Made { beside, record })
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
    // What the run would read is known before anything starts: a session that names
    // evidence the ledger lacks is refused here.
    let (from, read) = (Arc::clone(&store), inputs.clone());
    let files = off_executor(move || readable(&from, adapter, &read)).await?;
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
    let into = Arc::clone(&store);
    let (dir, root, command) = off_executor(move || {
        let (dir, root, paths) = materialised(&into, &files, adapter.named)?;
        let mut command = confined(adapter.id, &program, Some(&root))?;
        command.args((adapter.args)(&paths));
        Ok((dir, root, command))
    })
    .await?;
    let printed = finished(adapter, command).await;
    // The directory is removed off the executor too, however the run ended.
    off_executor(move || {
        let ran = printed.and_then(|printed| Ok((printed, written(adapter.id, &root.join(OUT))?)));
        drop(dir);
        let (printed, wrote) = ran?;
        record(&store, adapter, tool, inputs, &printed, wrote)
    })
    .await
}

/// The files a run left under `out`, by their path there. A link, a device or anything
/// else that is not a file or a directory, a name that is not a module path, or more
/// than the limits allow, and none of them are kept. The program has ended by now,
/// and with it everything it started, so nothing changes them while they are read.
fn written(id: &'static str, out: &Path) -> Result<Wrote, Rejection> {
    let unusable = |why: String| {
        let message = format!("What it left cannot be used: {why}.");
        reject("tool_output_unreadable", id, message, FAILED)
    };
    let over = |why: String| {
        let next = "No output was recorded. Tell the human: this input makes the tool leave more files than the server keeps.";
        reject("tool_over_output", id, why, next)
    };
    let failed = |e: io::Error| {
        reject(
            "tool_failed",
            id,
            format!("What it left cannot be read: {e}."),
            FAILED,
        )
    };
    let mut wrote = Wrote::new();
    match std::fs::symlink_metadata(out) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(wrote),
        Err(e) => return Err(failed(e)),
        Ok(meta) if !meta.is_dir() => return Err(unusable(format!("`{OUT}` is not a directory"))),
        Ok(_) => {}
    }
    let (mut entries, mut total) = (0_usize, 0_u64);
    let mut todo = vec![(out.to_path_buf(), None::<ModulePath>)];
    while let Some((dir, above)) = todo.pop() {
        for entry in std::fs::read_dir(&dir).map_err(failed)? {
            let entry = entry.map_err(failed)?;
            entries += 1;
            if entries > MAX_WRITTEN_FILES {
                return Err(over(format!(
                    "It left more than {MAX_WRITTEN_FILES} files."
                )));
            }
            let name = entry.file_name();
            let name = name
                .to_str()
                .ok_or_else(|| unusable(format!("{} is not a name in UTF-8", name.display())))?;
            let name = above.as_ref().map_or_else(
                || name.to_owned(),
                |above| format!("{}/{name}", above.as_str()),
            );
            let path = ModulePath::new(name).map_err(unusable)?;
            let kind = entry.file_type().map_err(failed)?;
            if kind.is_dir() {
                todo.push((entry.path(), Some(path)));
                continue;
            }
            if !kind.is_file() {
                return Err(unusable(format!(
                    "{} is a link or a device, not a file",
                    path.as_str()
                )));
            }
            let file = File::open(entry.path()).map_err(failed)?;
            let size = file.metadata().map_err(failed)?.len();
            let mut bytes = Vec::new();
            if size <= MAX_WRITTEN_FILE {
                file.take(MAX_WRITTEN_FILE + 1)
                    .read_to_end(&mut bytes)
                    .map_err(failed)?;
            }
            let size = size.max(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
            if size > MAX_WRITTEN_FILE {
                let path = path.as_str();
                return Err(over(format!(
                    "It left {path} of {size} bytes, limit {MAX_WRITTEN_FILE}."
                )));
            }
            total += size;
            if total > MAX_WRITTEN {
                return Err(over(format!(
                    "It left more than {MAX_WRITTEN} bytes of files."
                )));
            }
            wrote.insert(path, bytes);
        }
    }
    Ok(wrote)
}

/// What one run is given, inputs first and then, for a session, the evidence it names
/// that the tool reads. Refuses inputs the tool does not read, and a session that names
/// evidence this ledger does not hold.
fn readable(
    store: &Store,
    adapter: &Adapter,
    inputs: &BTreeSet<EvidenceId>,
) -> Result<Vec<EvidenceId>, Rejection> {
    let (count, kind, beside) = match adapter.reads {
        Reads::Inputs(count, kind) => (count, kind, None),
        Reads::Session(beside) => (1, EvidenceKind::Session, Some(beside)),
    };
    let held = |e: &EvidenceId, kind| store.snapshot().ledger.evidence_kind(e) == Some(kind);
    if inputs.len() != count || !inputs.iter().all(|e| held(e, kind)) {
        return Err(reject(
            "tool_inputs_wrong",
            adapter.id,
            format!("It reads {count} input of kind {}.", kind_name(kind)),
            "No output was recorded. Add the input with add_evidence first, then name its id in `inputs`.",
        ));
    }
    let mut files: Vec<EvidenceId> = inputs.iter().cloned().collect();
    let Some(beside) = beside else {
        return Ok(files);
    };
    let mut seen = inputs.clone();
    for input in inputs {
        let record = store.evidence(input)?;
        let record = record.ok_or_else(|| unknown_evidence(input.as_str()))?;
        let session = Session::read(&record)
            .map_err(|why| reject("evidence_malformed", input, format!("{why}."), IMPORT_AGAIN))?;
        for (id, kind) in session.named().filter(|(_, kind)| *kind == beside) {
            if !held(id, kind) {
                let message = format!(
                    "The session names it as {}, and this ledger does not hold it.",
                    kind_name(kind)
                );
                return Err(reject("tool_inputs_wrong", id, message, IMPORT_AGAIN));
            }
            if seen.insert(id.clone()) {
                files.push(id.clone());
            }
        }
    }
    Ok(files)
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
    let program = program.to_owned();
    let command = off_executor(move || {
        let mut command = confined(adapter.id, &program, None)?;
        command.args(adapter.version);
        Ok(command)
    })
    .await?;
    let printed = finished(adapter, command).await?;
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

/// The confined program in `work`, which gets nothing of this server's: no
/// environment, no input. Its errors are dropped. Every run starts here.
fn confined(
    id: &'static str,
    program: &Path,
    work: Option<&Path>,
) -> Result<std::process::Command, Rejection> {
    let mut command = ledger_os::confined(program, work).map_err(|e| unstartable(id, &e))?;
    command
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    Ok(command)
}

fn unstartable(id: &'static str, e: &io::Error) -> Rejection {
    if e.kind() == io::ErrorKind::Unsupported {
        let message = format!("No tool is started here: {e}.");
        return reject("tool_unconfined", id, message, UNCONFINED);
    }
    reject(
        "tool_missing",
        id,
        format!("It could not be started: {e}."),
        MISSING,
    )
}

/// What the program printed, if it ended well within its limits. It is started here,
/// on the executor's thread, which lives as long as the server: a confined program
/// dies with the thread that started it. It also dies, with every process under it,
/// when its run is dropped.
async fn finished(adapter: &Adapter, command: std::process::Command) -> Result<Vec<u8>, Rejection> {
    let mut command = Command::from(command);
    let started = command.kill_on_drop(true).spawn();
    let mut child = started.map_err(|e| unstartable(adapter.id, &e))?;
    let failed = |e: io::Error| reject("tool_failed", adapter.id, format!("{e}."), FAILED);
    let (Some(pid), Some(stdout)) = (child.id(), child.stdout.take()) else {
        return Err(failed(io::ErrorKind::BrokenPipe.into()));
    };
    let ran = async {
        let printed = within(stdout, adapter.printed).await.map_err(failed)?;
        let printed = printed.ok_or_else(|| {
            let message = format!(
                "It printed more than {} MiB and was stopped.",
                adapter.printed / MIB
            );
            let next = "No output was recorded. Tell the human: this input makes the tool print more than the server keeps.";
            reject("tool_over_output", adapter.id, message, next)
        })?;
        let status = child.wait().await.map_err(failed)?;
        if !status.success() {
            let message = format!("It ended with {status}.");
            return Err(reject("tool_failed", adapter.id, message, FAILED));
        }
        Ok(printed)
    };
    tokio::select! {
        biased;
        ran = ran => ran,
        over = over_memory(adapter, pid) => Err(over),
        () = tokio::time::sleep(adapter.limit) => Err(reject(
            "tool_timeout",
            adapter.id,
            format!("It did not finish within {:?} and was stopped.", adapter.limit),
            "No output was recorded. Tell the human: this input needs a longer limit or a lighter run.",
        )),
    }
}

/// Everything `stdout` gives until it ends, or `None` once it gives more than
/// `limit` bytes. No more than `limit` bytes are ever held.
async fn within(stdout: ChildStdout, limit: u64) -> io::Result<Option<Vec<u8>>> {
    let mut kept = Vec::new();
    let mut stdout = stdout.take(limit);
    stdout.read_to_end(&mut kept).await?;
    let more = stdout.into_inner().read(&mut [0]).await?;
    Ok((more == 0).then_some(kept))
}

/// Returns once the processes of the run `pid` started hold more memory than its
/// adapter allows, or their memory cannot be read; never while they stay within.
async fn over_memory(adapter: &Adapter, pid: u32) -> Rejection {
    loop {
        tokio::time::sleep(WATCH).await;
        // `pid` is not waited for until the run ends, so no other process can take its number.
        match off_executor(move || Ok(ledger_os::resident(pid))).await {
            Ok(Ok(held)) if held <= adapter.memory => {}
            Ok(Ok(_)) => {
                let message = format!(
                    "It held more than {} MiB of memory and was stopped.",
                    adapter.memory / MIB
                );
                let next = "No output was recorded. Tell the human: this input needs a higher memory limit or a lighter run.";
                return reject("tool_over_memory", adapter.id, message, next);
            }
            // A run whose memory cannot be watched is not confined.
            Ok(Err(e)) => {
                let message = format!("Its memory could not be read, so it was stopped: {e}.");
                return reject("tool_unconfined", adapter.id, message, UNCONFINED);
            }
            Err(rejection) => return rejection,
        }
    }
}

/// Each piece of evidence as a file named by its id and `named`, in a new directory
/// only this user can open, with the directory's absolute path.
fn materialised(
    store: &Store,
    inputs: &[EvidenceId],
    named: &str,
) -> Result<(TempDir, PathBuf, Vec<PathBuf>), Rejection> {
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
        let file = root.join(format!("{id}{named}"));
        std::fs::write(&file, &*bytes).map_err(unwritable)?;
        files.push(file);
    }
    Ok((dir, root, files))
}

/// Stores what `tool` printed and left for `inputs`, each piece the adapter keeps
/// and then the record that names them, and logs the run that made the record.
///
/// # Errors
/// The adapter refuses the output, or it cannot be stored.
pub fn record(
    store: &Store,
    adapter: &Adapter,
    tool: ToolRef,
    inputs: BTreeSet<EvidenceId>,
    printed: &[u8],
    wrote: Wrote,
) -> Result<EvidenceId, Rejection> {
    let Made { beside, record } = (adapter.parse)(store, &tool, &inputs, printed, wrote)?;
    // Checked before the first write, so that a refusal leaves nothing behind.
    {
        let ledger = &store.snapshot().ledger;
        let pieces = beside.iter().map(|piece| (piece, EvidenceKind::Artifact));
        for (bytes, kind) in pieces.chain([(&record, adapter.output)]) {
            let id = EvidenceId::of(bytes);
            match ledger.evidence_kind(&id) {
                Some(stored) if stored != kind => {
                    return Err(StoreError::OtherKind(id, stored).into());
                }
                _ => {}
            }
        }
    }
    for piece in &beside {
        store.add_evidence(EvidenceKind::Artifact, piece)?;
    }
    let output = store.add_evidence(adapter.output, &record)?;
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
    use crate::tools::About;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// A shell from the store, which the flake's shell names: a confined program sees
    /// nothing outside the store.
    fn sh() -> Option<OsString> {
        std::env::var_os("LEDGER_TEST_SH")
    }

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

    /// Doubles a string until it is stopped.
    fn grow(files: &[PathBuf]) -> Vec<OsString> {
        script("x=y; while :; do x=$x$x; done", files)
    }

    /// Prints lines of a kibibyte until it is stopped.
    fn flood(files: &[PathBuf]) -> Vec<OsString> {
        let lines =
            r#"y=y; for i in 1 2 3 4 5 6 7 8 9 10; do y=$y$y; done; while :; do echo "$y"; done"#;
        script(lines, files)
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "an adapter's parser has to be able to refuse"
    )]
    fn as_printed(
        _: &Store,
        _: &ToolRef,
        _: &BTreeSet<EvidenceId>,
        printed: &[u8],
        _: Wrote,
    ) -> Result<Made, Rejection> {
        Ok(Made::alone(printed.to_vec()))
    }

    /// Each test has adapters of its own, so no test waits for another's turn.
    const fn fake(args: fn(&[PathBuf]) -> Vec<OsString>, limit: Duration) -> Adapter {
        Adapter {
            id: "fake",
            env: "LEDGER_TOOL_FAKE",
            version: &["-c", "echo fake 1.2"],
            reads: Reads::Inputs(1, EvidenceKind::Artifact),
            named: "",
            args,
            limit,
            memory: 1024 * MIB,
            printed: MIB,
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
        let first = derive_with(Arc::clone(&store), &ONCE, sh(), inputs.clone()).await;
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
        let waiting = derive_with(Arc::clone(&store), &TURNS, sh(), inputs.clone());
        let waited = tokio::time::timeout(Duration::from_millis(500), waiting).await;
        assert!(waited.is_err(), "it did not wait: {waited:?}");
        drop(running);
        let ran = derive_with(store, &TURNS, sh(), inputs).await;
        assert!(ran.is_ok(), "{ran:?}");
        Ok(())
    }

    #[tokio::test]
    async fn every_refused_run_reads_as_expected_and_records_nothing() -> TestResult {
        static FOUND: Adapter = fake(first_line, SECONDS);
        static NOT_STARTED: Adapter = fake(first_line, SECONDS);
        static SPINS: Adapter = fake(spin, Duration::from_millis(200));
        static FAILS: Adapter = fake(fail, SECONDS);
        static GROWS: Adapter = grows();
        static FLOODS: Adapter = fake(flood, SECONDS);
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
            refused(&FOUND, sh(), BTreeSet::new()).await,
            refused(&FOUND, sh(), [snapshot].into()).await,
            refused(&SPINS, sh(), inputs.clone()).await,
            refused(&FAILS, sh(), inputs.clone()).await,
            refused(&GROWS, sh(), inputs.clone()).await,
            refused(&FLOODS, sh(), inputs).await,
        ];
        assert_eq!(store.snapshot().seq, seq, "a refused run was recorded");
        insta::assert_snapshot!("refused_runs", all.join("\n"));
        Ok(())
    }

    /// A tool that keeps allocating, with a memory limit far below what would trouble
    /// the machine. Its time limit is short too, in case the memory limit fails.
    const fn grows() -> Adapter {
        let mut grows = fake(grow, Duration::from_secs(3));
        grows.memory = 64 * MIB;
        grows
    }

    #[tokio::test]
    async fn a_tool_that_keeps_allocating_is_stopped_at_its_memory_limit() -> TestResult {
        static GROWS: Adapter = grows();
        let dir = tempfile::tempdir()?;
        let (store, inputs) = ledger(dir.path())?;
        let started = std::time::Instant::now();
        let ran = derive_with(store, &GROWS, sh(), inputs).await;
        assert_eq!(ran.map_err(|r| r.code).err(), Some("tool_over_memory"));
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "{:?}",
            started.elapsed()
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_tool_that_prints_without_end_is_stopped_and_the_server_keeps_little() -> TestResult {
        static FLOODS: Adapter = fake(flood, SECONDS);
        let dir = tempfile::tempdir()?;
        let (store, inputs) = ledger(dir.path())?;
        let me = std::process::id();
        let before = ledger_os::resident(me)?;
        let run = derive_with(store, &FLOODS, sh(), inputs);
        tokio::pin!(run);
        // This process's memory, the tool's included, read while the tool prints.
        let mut most = before;
        let ran = loop {
            tokio::select! {
                ran = &mut run => break ran,
                () = tokio::time::sleep(Duration::from_millis(5)) => {
                    most = most.max(ledger_os::resident(me)?);
                }
            }
        };
        let grew = most.saturating_sub(before);
        assert!(grew < 32 * MIB, "the server grew by {} MiB", grew / MIB);
        assert_eq!(ran.map_err(|r| r.code).err(), Some("tool_over_output"));
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

    /// A session written by hand: two hosts with the markers the rules look for.
    const STACK: &str = include_str!("../tests/fixtures/stack.session");

    /// A ledger holding the fixture session, imported as an agent imports one, and
    /// the session's id.
    fn with_session(dir: &Path) -> Result<(Arc<Store>, EvidenceId), Box<dyn std::error::Error>> {
        let store = Store::open(dir.join("l.db"))?;
        let file = dir.join("stack.session");
        std::fs::write(&file, STACK)?;
        let path = file.to_str().ok_or("path")?;
        crate::tools::add_evidence(&store, EvidenceKind::Session, path)
            .map_err(|r| r.to_string())?;
        let ledger = &store.snapshot().ledger;
        let session = ledger.evidence_of(EvidenceKind::Session).next().cloned();
        Ok((Arc::new(store), session.ok_or("no session")?))
    }

    #[tokio::test]
    async fn the_rules_read_a_session_once_and_say_what_each_host_runs() -> TestResult {
        let program = std::env::var_os(FINGERPRINT.env);
        let dir = tempfile::tempdir()?;
        let (store, session) = with_session(dir.path())?;
        let inputs = BTreeSet::from([session.clone()]);
        let ran = derive_with(
            Arc::clone(&store),
            &FINGERPRINT,
            program.clone(),
            inputs.clone(),
        );
        let output = ran.await.map_err(|r| r.to_string())?;
        let stored = store.evidence(&output)?.ok_or("not stored")?;
        let facts: TechnologyFacts = rmcp::serde_json::from_slice(&stored)?;
        assert_eq!(facts.session, session);
        assert!(
            facts.tool.starts_with("fingerprint 1, wappalyzergo v"),
            "{}",
            facts.tool
        );
        let on = |host: &str, name: &str| {
            let found = facts.hosts.get(host).and_then(|found| found.get(name));
            found.map(|t| t.named(name))
        };
        let shop = "shop.example";
        assert_eq!(on(shop, "Nginx").as_deref(), Some("Nginx 1.25.3"));
        assert_eq!(on(shop, "Next.js").as_deref(), Some("Next.js 14.2.3"));
        assert_eq!(on(shop, "jQuery").as_deref(), Some("jQuery 3.6.0"));
        assert_eq!(on(shop, "Cloudflare").as_deref(), Some("Cloudflare"));
        let wall = facts.hosts[shop]
            .get("Cloudflare Bot Management")
            .ok_or("no wall")?;
        assert!(wall.categories.contains("Security"), "{wall:?}");
        // A script's body is not a page, so markup quoted in it is not read.
        assert_eq!(on(shop, "Nuxt.js"), None);
        let api = "api.shop.example";
        assert_eq!(on(api, "Express").as_deref(), Some("Express"));
        assert_eq!(on(api, "Varnish").as_deref(), Some("Varnish 7.4"));
        assert_eq!(on(api, "Nginx"), None);
        // The server answered on both of the shop's exchanges.
        let ledger = &store.snapshot().ledger;
        let record = Session::read(&store.evidence(&session)?.ok_or("no session")?)?;
        let sent: Vec<&EvidenceId> = record.exchanges().iter().map(|s| &s.exchange).collect();
        let nginx = &facts.hosts[shop]["Nginx"].exchanges;
        assert_eq!(nginx, &BTreeSet::from([sent[0].clone(), sent[1].clone()]));
        let tool = ToolRef {
            id: FINGERPRINT.id.into(),
            version: FINGERPRINT.known.get().ok_or("no version")?.clone(),
        };
        assert_eq!(ledger.derivation_of(&output), Some((&tool, &inputs)));
        // The second call finds the run made: a process started now would fail.
        let seq = store.snapshot().seq;
        let nowhere = Some("/no/such/program".into());
        let again = derive_with(Arc::clone(&store), &FINGERPRINT, nowhere, inputs.clone());
        assert_eq!(again.await.map_err(|r| r.to_string())?, output);
        assert_eq!(store.snapshot().seq, seq, "the cached run logged an event");
        // Another ledger with the same session gets the same bytes.
        let elsewhere = tempfile::tempdir()?;
        let (other, _) = with_session(elsewhere.path())?;
        let there = derive_with(other, &FINGERPRINT, program, inputs).await;
        assert_eq!(there.map_err(|r| r.to_string())?, output);
        Ok(())
    }

    #[tokio::test]
    async fn a_session_that_names_an_exchange_the_ledger_lacks_is_refused_before_a_run()
    -> TestResult {
        let dir = tempfile::tempdir()?;
        let store = Arc::new(Store::open(dir.path().join("l.db"))?);
        // The record and its script, and all but the last exchange.
        let captured = Session::from_capture(STACK.as_bytes())?;
        let (last, rest) = captured.exchanges.split_last().ok_or("no exchange")?;
        for exchange in rest {
            store.add_evidence(EvidenceKind::HttpExchange, exchange)?;
        }
        store.add_evidence(EvidenceKind::Artifact, &captured.sources[0])?;
        let session = store.add_evidence(EvidenceKind::Session, &captured.record)?;
        let seq = store.snapshot().seq;
        // Had anything been started, this path would make it `tool_missing`.
        let nowhere = Some("/no/such/program".into());
        let ran = derive_with(Arc::clone(&store), &FINGERPRINT, nowhere, [session].into()).await;
        let refused = ran.err().ok_or("not refused")?;
        assert_eq!(
            (refused.code, refused.subject.as_str()),
            ("tool_inputs_wrong", &EvidenceId::of(last).as_str()[..12])
        );
        assert_eq!(store.snapshot().seq, seq, "a refused run was recorded");
        Ok(())
    }

    /// A minified webpack 5 bundle of three modules, written for these tests.
    const BUNDLE: &str = include_str!("../tests/fixtures/cart.bundle.js");
    /// Where the bundle was loaded from; the query string is not to be shown.
    const MAIN: &str = "https://shop.example/static/js/main.4f2a.js";

    /// A ledger holding a session whose one script is [`BUNDLE`], with a request its
    /// `fetch` sent, and the ids of the session and the script.
    fn with_bundle(
        dir: &Path,
    ) -> Result<(Arc<Store>, EvidenceId, EvidenceId), Box<dyn std::error::Error>> {
        let fetch = BUNDLE.find("fetch(").ok_or("no fetch")?;
        let lines = [
            rmcp::serde_json::json!({"session": {"tool": {"id": "chromium", "version": "158.0"}, "approved": ["shop.example", "api.shop.example"]}}),
            rmcp::serde_json::json!({"exchange": {"at": 0, "page": "https://shop.example/", "stack": [{"script": MAIN, "line": 1, "column": fetch + 1, "function": "o"}], "exchange": {"request": {"method": "GET", "url": "https://api.shop.example/v1/cart/me"}, "response": {"status": 200}}}}),
            rmcp::serde_json::json!({"script": {"address": format!("{MAIN}?v=s3cret"), "source": BUNDLE, "source_map": {"at": "main.4f2a.js.map?v=s3cret"}}}),
        ];
        let file = dir.join("cart.session");
        std::fs::write(&file, lines.map(|line| line.to_string()).join("\n"))?;
        let store = Store::open(dir.join("l.db"))?;
        crate::tools::add_evidence(&store, EvidenceKind::Session, file.to_str().ok_or("path")?)
            .map_err(|r| r.to_string())?;
        let ledger = &store.snapshot().ledger;
        let session = ledger.evidence_of(EvidenceKind::Session).next().cloned();
        let script = EvidenceId::of(BUNDLE.as_bytes());
        Ok((Arc::new(store), session.ok_or("no session")?, script))
    }

    fn tree_of(store: &Store, id: &EvidenceId) -> Result<SourceTree, Box<dyn std::error::Error>> {
        Ok(SourceTree::read(&store.evidence(id)?.ok_or("no tree")?)?)
    }

    #[tokio::test]
    async fn wakaru_splits_a_bundle_into_modules_that_say_which_bytes_they_came_from() -> TestResult
    {
        let dir = tempfile::tempdir()?;
        let (store, session, script) = with_bundle(dir.path())?;
        let inputs = BTreeSet::from([script.clone()]);
        let program = std::env::var_os(WAKARU.env);
        let ran = derive_with(Arc::clone(&store), &WAKARU, program, inputs.clone()).await;
        let output = ran.map_err(|r| r.to_string())?;
        let tree = tree_of(&store, &output)?;
        assert_eq!(
            (tree.format(), tree.split()),
            ("webpack5", Split::Structural)
        );
        assert_eq!(tree.script(), &script);
        assert_eq!(tree.tool().id, "wakaru");
        // Each module is the body of its function in the module table, counted in bytes:
        // the euro sign before module 907 is three of them.
        let ranges: Vec<(&str, Vec<(u64, u64)>)> = (tree.modules().iter())
            .map(|(path, module)| {
                let ranges = module.ranges.iter().map(|r| (r.start, r.end));
                (path.as_str(), ranges.collect())
            })
            .collect();
        assert_eq!(
            ranges,
            [
                ("entry.js", vec![(873, 879)]),
                ("module-318.js", vec![(27, 178)]),
                ("module-642.js", vec![(194, 260)]),
                ("module-907.js", vec![(276, 427)]),
            ]
        );
        let bytes = |range: std::ops::Range<usize>| &BUNDLE.as_bytes()[range];
        assert!(bytes(27..178).starts_with(br#""use strict";r.d(t,{c:()=>o})"#));
        assert!(bytes(27..178).ends_with(b".then(e=>e.json())}"));
        assert_eq!(bytes(873..879), b"r(907)");
        let text = |path: &str| -> Result<String, Box<dyn std::error::Error>> {
            let source = &tree.modules()[path].source;
            assert_eq!(
                store.snapshot().ledger.evidence_kind(source),
                Some(EvidenceKind::Artifact)
            );
            Ok(String::from_utf8(
                store.evidence(source)?.ok_or("no module")?.to_vec(),
            )?)
        };
        let api = text("module-318.js")?;
        assert!(
            api.contains("fetch(") && api.contains("https://api.shop.example/v1"),
            "{api}"
        );
        assert!(text("module-907.js")?.contains(r#"from "./module-318.js""#));
        // The request's frame names a line and a column; the module is found by its byte.
        let record = crate::tools::session(&store, &session).map_err(|r| r.to_string())?;
        let frame = &record.exchanges()[0].stack[0];
        let at = frame.offset_in(BUNDLE).ok_or("no offset")?;
        let found = tree
            .module_at(u64::try_from(at)?)
            .map(|(path, _)| path.as_str());
        assert_eq!(found, Some("module-318.js"));
        let tool = ToolRef {
            id: WAKARU.id.into(),
            version: WAKARU.known.get().ok_or("no version")?.clone(),
        };
        assert_eq!(&tree.tool(), &&tool);
        assert_eq!(
            store.snapshot().ledger.derivation_of(&output),
            Some((&tool, &inputs))
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_script_that_is_no_bundle_comes_back_whole_as_one_readable_module() -> TestResult {
        let dir = tempfile::tempdir()?;
        let store = Arc::new(Store::open(dir.path().join("l.db"))?);
        let plain =
            b"function load(){fetch(\"/api/cart\").then(function(r){return r.json()})}load();";
        let script = store.add_evidence(EvidenceKind::Artifact, plain)?;
        let program = std::env::var_os(WAKARU.env);
        let ran = derive_with(
            Arc::clone(&store),
            &WAKARU,
            program,
            [script.clone()].into(),
        );
        let tree = tree_of(&store, &ran.await.map_err(|r| r.to_string())?)?;
        assert_eq!(
            (tree.format(), tree.split()),
            ("unknown", Split::Structural)
        );
        let modules: Vec<(&str, &[std::ops::Range<u64>])> = (tree.modules().iter())
            .map(|(path, module)| (path.as_str(), &module.ranges[..]))
            .collect();
        let whole = 0..u64::try_from(plain.len())?;
        assert_eq!(
            modules,
            [(&*format!("{script}.js"), std::slice::from_ref(&whole))]
        );
        let module = &tree.modules()[&*format!("{script}.js")];
        let text = store.evidence(&module.source)?.ok_or("no module")?;
        let text = std::str::from_utf8(&text)?;
        assert!(
            text.contains("\n    fetch(\"/api/cart\")"),
            "not laid out: {text}"
        );
        Ok(())
    }

    /// Every file under `dir`, by its path there.
    fn files_in(dir: &Path) -> Result<BTreeMap<String, Vec<u8>>, Box<dyn std::error::Error>> {
        let mut files = BTreeMap::new();
        let mut todo = vec![dir.to_path_buf()];
        while let Some(at) = todo.pop() {
            for entry in std::fs::read_dir(at)? {
                let path = entry?.path();
                if path.is_dir() {
                    todo.push(path);
                } else {
                    let name = path.strip_prefix(dir)?.to_str().ok_or("name")?.to_owned();
                    files.insert(name, std::fs::read(path)?);
                }
            }
        }
        Ok(files)
    }

    #[tokio::test]
    async fn a_script_is_recovered_once_and_its_modules_are_laid_out_as_files() -> TestResult {
        let dir = tempfile::tempdir()?;
        let (store, session, script) = with_bundle(dir.path())?;
        let ask = |about| crate::tools::ask(&store, about, None, Some(session.as_str()), None);
        let playbooks = || crate::tools::ask(&store, About::Playbooks, None, None, None);
        let listed = ask(About::Evidence).map_err(|r| r.to_string())?;
        let row = format!(
            "script {}  885 bytes  {MAIN}  no tree yet; source map at main.4f2a.js.map, which only the person can get, by capturing that address\nend",
            &script.as_str()[..12]
        );
        assert!(listed.ends_with(&row), "{listed}");
        assert!(
            !listed.contains("s3cret"),
            "a query string was shown: {listed}"
        );
        assert!(
            playbooks()
                .map_err(|r| r.to_string())?
                .contains("\nrecover-source  3. ")
        );

        let inputs = BTreeSet::from([script.clone()]);
        let program = std::env::var_os(WAKARU.env);
        let ran = derive_with(Arc::clone(&store), &WAKARU, program, inputs.clone()).await;
        let output = ran.map_err(|r| r.to_string())?;
        let reply = crate::tools::made(&store, &output).map_err(|r| r.to_string())?;
        let tree = tree_of(&store, &output)?;
        let mut modules = BTreeMap::new();
        for (path, module) in tree.modules() {
            let text = store.evidence(&module.source)?.ok_or("no module")?;
            modules.insert(path.as_str().to_owned(), text.to_vec());
        }
        // The reply names the three largest, largest first.
        let mut sizes: Vec<(usize, &String)> = modules.iter().map(|(p, t)| (t.len(), p)).collect();
        sizes.sort_unstable_by(|a, b| b.cmp(a));
        let largest: Vec<String> = sizes[..3]
            .iter()
            .map(|(n, p)| format!("{p} {n} bytes"))
            .collect();
        let laid = ledger_os::absolute(&store.sources_dir().join(output.as_str()))?;
        let expected = format!(
            "\n4 modules, read as webpack5 and split structurally\nfiles in {}\nlargest: {}",
            laid.display(),
            largest.join(", ")
        );
        assert!(reply.ends_with(&expected), "{reply}\nexpected{expected}");
        // The files are the modules, and nothing else.
        assert_eq!(files_in(&laid)?, modules);

        // The second call finds the run made: a process started now would fail.
        let seq = store.snapshot().seq;
        let nowhere = Some("/no/such/program".into());
        let again = derive_with(Arc::clone(&store), &WAKARU, nowhere.clone(), inputs.clone()).await;
        assert_eq!(again.map_err(|r| r.to_string())?, output);
        assert_eq!(
            crate::tools::made(&store, &output).map_err(|r| r.to_string())?,
            reply
        );
        assert_eq!(files_in(&laid)?, modules);
        // Files that are gone are laid out again from the evidence, still with no run.
        std::fs::remove_dir_all(&laid)?;
        let again = derive_with(Arc::clone(&store), &WAKARU, nowhere, inputs).await;
        assert_eq!(again.map_err(|r| r.to_string())?, output);
        assert_eq!(
            crate::tools::made(&store, &output).map_err(|r| r.to_string())?,
            reply
        );
        assert_eq!(files_in(&laid)?, modules);
        assert_eq!(store.snapshot().seq, seq, "a cached run logged an event");

        let listed = ask(About::Evidence).map_err(|r| r.to_string())?;
        assert!(
            listed.contains(&format!("  tree {}", &output.as_str()[..12])),
            "{listed}"
        );
        let listed = playbooks().map_err(|r| r.to_string())?;
        assert!(!listed.contains("recover-source"), "{listed}");
        Ok(())
    }

    /// The bash that runs the fake tools can load these programs as builtins.
    fn loadable(name: &str) -> String {
        let sh = PathBuf::from(std::env::var_os("LEDGER_TEST_SH").unwrap_or_default());
        let lib = sh
            .parent()
            .and_then(Path::parent)
            .map(|store| store.join("lib/bash"));
        let lib = lib.unwrap_or_default();
        format!("enable -f {}/{name} {name}", lib.display())
    }

    /// Leaves 10,001 empty files.
    fn too_many(files: &[PathBuf]) -> Vec<OsString> {
        let many = format!(
            "{}; mkdir out; i=0; while [ $i -le 10000 ]; do : > out/m$i.js; i=$((i+1)); done",
            loadable("mkdir")
        );
        script(&many, files)
    }

    /// Leaves a file one byte over the limit.
    fn too_large(files: &[PathBuf]) -> Vec<OsString> {
        let large = format!(
            "{}; mkdir out; x=y; for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26; do x=$x$x; done; printf %s \"$x\" > out/big.js; printf y >> out/big.js",
            loadable("mkdir")
        );
        script(&large, files)
    }

    /// Leaves a link to the store in place of a module.
    fn a_link(files: &[PathBuf]) -> Vec<OsString> {
        let link = format!(
            "{}; {}; mkdir out; ln -s /nix/store out/module.js",
            loadable("mkdir"),
            loadable("ln")
        );
        script(&link, files)
    }

    /// Leaves a module, and a provenance that names it as a file above the directory.
    fn climbing(files: &[PathBuf]) -> Vec<OsString> {
        let provenance = r#"{"format": "webpack5", "strategy": "structural", "modules": {"../a.js": {"ranges": [[0, 1]]}}}"#;
        let climb = format!(
            "{}; mkdir out; printf x > out/a.js; printf '%s' '{provenance}' > out/provenance.json",
            loadable("mkdir")
        );
        script(&climb, files)
    }

    /// Leaves a module its provenance does not account for.
    fn unaccounted(files: &[PathBuf]) -> Vec<OsString> {
        let provenance = r#"{"format": "webpack5", "strategy": "structural", "modules": {"a.js": {"ranges": [[0, 1]]}}}"#;
        let extra = format!(
            "{}; mkdir out; printf x > out/a.js; printf x > out/b.js; printf '%s' '{provenance}' > out/provenance.json",
            loadable("mkdir")
        );
        script(&extra, files)
    }

    /// An adapter whose program leaves files, read as Wakaru's are.
    const fn leaves(args: fn(&[PathBuf]) -> Vec<OsString>) -> Adapter {
        let mut leaves = fake(args, SECONDS);
        leaves.output = EvidenceKind::SourceTree;
        leaves.parse = wakaru_output;
        leaves
    }

    #[tokio::test]
    async fn files_a_tool_leaves_that_cannot_be_kept_are_refused_and_nothing_is_recorded()
    -> TestResult {
        static TOO_MANY: Adapter = leaves(too_many);
        static TOO_LARGE: Adapter = leaves(too_large);
        static A_LINK: Adapter = leaves(a_link);
        static CLIMBING: Adapter = leaves(climbing);
        static UNACCOUNTED: Adapter = leaves(unaccounted);
        let dir = tempfile::tempdir()?;
        let (store, inputs) = ledger(dir.path())?;
        let seq = store.snapshot().seq;
        let mut refused = Vec::new();
        for adapter in [&TOO_MANY, &TOO_LARGE, &A_LINK, &CLIMBING, &UNACCOUNTED] {
            let ran = derive_with(Arc::clone(&store), adapter, sh(), inputs.clone()).await;
            refused.push(ran.map_or_else(
                |r| format!("{}: {}", r.code, r.message),
                |ok| format!("NOT REFUSED: {ok}"),
            ));
        }
        assert_eq!(
            refused,
            [
                "tool_over_output: It left more than 10000 files.",
                "tool_over_output: It left big.js of 67108865 bytes, limit 67108864.",
                "tool_output_unreadable: What it left cannot be used: module.js is a link or a device, not a file.",
                "tool_output_unreadable: Wakaru's output cannot be used: \"../a.js\" is not a relative path of plain names.",
                "tool_output_unreadable: Wakaru's output cannot be used: it left 2 modules and accounts for 1.",
            ]
        );
        assert_eq!(store.snapshot().seq, seq, "a refused run was recorded");
        Ok(())
    }

    #[test]
    fn what_the_tool_prints_is_kept_within_its_limits_or_refused() -> TestResult {
        let tool = ToolRef {
            id: "fingerprint".into(),
            version: "1, wappalyzergo v0".into(),
        };
        let session = BTreeSet::from([EvidenceId::of(b"session")]);
        let ids: Vec<String> = (0..20).map(|n| EvidenceId::of(&[n]).to_string()).collect();
        let printed = rmcp::serde_json::json!({"hosts": {"shop.example": {"Nginx": {"versions": ["1.25.3"], "categories": ["Web servers"], "exchanges": ids}}}});
        let dir = tempfile::tempdir()?;
        let store = Store::open(dir.path().join("l.db"))?;
        let parse = |printed: &str| {
            fingerprint_output(&store, &tool, &session, printed.as_bytes(), Wrote::new())
        };
        let stored = parse(&printed.to_string()).map_err(|r| r.to_string())?;
        let facts: TechnologyFacts = rmcp::serde_json::from_slice(&stored.record)?;
        let nginx = &facts.hosts["shop.example"]["Nginx"];
        assert_eq!(nginx.exchanges.len(), TechnologyFacts::LISTED);
        assert_eq!(facts.tool, "fingerprint 1, wappalyzergo v0");
        let refused = |printed: &str| parse(printed).err().map(|r| r.code);
        assert_eq!(refused("not json"), Some("tool_output_unreadable"));
        assert_eq!(
            refused(r#"{"hosts": {"": {}}}"#),
            Some("tool_output_unreadable")
        );
        assert_eq!(
            refused(r#"{"hosts": {"a.example": {"": {}}}}"#),
            Some("tool_output_unreadable")
        );
        let args = fingerprint_args(&[
            PathBuf::from("/tmp/ledger-x/session"),
            PathBuf::from("/tmp/ledger-x/exchange"),
        ]);
        assert_eq!(args, ["--listed", "8", "/tmp/ledger-x/session"]);
        Ok(())
    }
}
