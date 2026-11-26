//! Runs Rizin on a program file as a child process. The file is read, never run.

use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use ledger_checkers::RIZIN_COMMANDS;
use tokio::process::Command;
use tokio::sync::Semaphore;

use crate::tools::Rejection;

const PROGRAM: &str = "rizin";
/// Longest one analysis may take. Rizin is stopped when it runs out.
const LIMIT: Duration = Duration::from_secs(600);
/// One analysis runs at a time, since each can take minutes and much of the memory.
static TURN: Semaphore = Semaphore::const_new(1);

/// What one run of Rizin printed, and which Rizin it was.
pub struct Analysis {
    pub tool: String,
    pub output: Vec<u8>,
}

fn reject(code: &'static str, message: String, next: &'static str) -> Rejection {
    Rejection {
        code,
        subject: PROGRAM.into(),
        message,
        next,
    }
}

fn unreadable(e: &std::io::Error) -> Rejection {
    Rejection {
        code: "evidence_unreadable",
        subject: "path".into(),
        message: format!("{e}."),
        next: "Check that the path is a local file this server can read.",
    }
}

/// The file's absolute path, and whether it is a program to analyse. Facts that
/// were exported before are JSON and start with a brace; no program does.
fn locate(path: &Path) -> std::io::Result<(PathBuf, bool)> {
    let path = ledger_os::absolute(path)?;
    let mut first = [0u8; 1];
    let read = std::fs::File::open(&path)?.read(&mut first)?;
    Ok((path, read == 0 || first[0] != b'{'))
}

/// Analyses the program at `path`, or returns `None` if the file already holds facts.
///
/// # Errors
/// The file cannot be read, or Rizin cannot be started, fails or runs out of time.
pub async fn analyse(path: String) -> Result<Option<Analysis>, Rejection> {
    const MISSING: &str =
        "Install Rizin so that `rizin` is on this server's PATH, then add the evidence again.";
    const FAILED: &str = "Nothing was recorded. Check that the file is a program Rizin can read, then tell the human.";
    let located = tokio::task::spawn_blocking(move || locate(Path::new(&path))).await;
    let (path, program) = (located.map_err(std::io::Error::other))
        .and_then(|found| found)
        .map_err(|e| unreadable(&e))?;
    if !program {
        return Ok(None);
    }
    // Others wait for this turn to end, so the limit covers both runs and starts only now.
    let closed = |e: tokio::sync::AcquireError| reject("tool_failed", format!("{e}."), FAILED);
    let _turn = TURN.acquire().await.map_err(closed)?;
    let deadline = tokio::time::Instant::now() + LIMIT;
    let out_of_time = |_: tokio::time::error::Elapsed| {
        let message = format!(
            "Rizin did not finish within {} seconds and was stopped.",
            LIMIT.as_secs()
        );
        reject(
            "tool_timeout",
            message,
            "Nothing was recorded. Tell the human: this program needs a longer limit or a lighter analysis.",
        )
    };
    let missing = |e: std::io::Error| {
        reject(
            "tool_missing",
            format!("Rizin could not be started: {e}."),
            MISSING,
        )
    };
    let version = Command::new(PROGRAM)
        .arg("-v")
        .stdin(Stdio::null())
        .kill_on_drop(true)
        .output();
    let version = tokio::time::timeout_at(deadline, version).await;
    let version = version.map_err(out_of_time)?.map_err(missing)?;
    let tool = String::from_utf8_lossy(&version.stdout);
    let tool = tool.lines().next().unwrap_or(PROGRAM).trim().to_owned();
    // The path is absolute, so Rizin cannot read it as an option or as one of its
    // `scheme://` targets, some of which start a process or open a connection. The
    // sandbox stops the analysis from running commands or writing files.
    let run = Command::new(PROGRAM)
        .args(["-N", "-q", "-e", "scr.color=0", "-e", "cfg.sandbox=true"])
        .args(["-c", RIZIN_COMMANDS])
        .arg(&path)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .output();
    let ran = tokio::time::timeout_at(deadline, run).await;
    let ran = ran.map_err(out_of_time)?.map_err(missing)?;
    if !ran.status.success() {
        return Err(reject(
            "tool_failed",
            format!("Rizin ended with {}.", ran.status),
            FAILED,
        ));
    }
    Ok(Some(Analysis {
        tool,
        output: ran.stdout,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_local_file_is_located_and_only_a_program_is_analysed()
    -> Result<(), Box<dyn std::error::Error>> {
        // A target Rizin would open as a debugger, and a file that is not there.
        assert!(locate(Path::new("dbg:///usr/bin/true")).is_err());
        let dir = tempfile::tempdir()?;
        assert!(locate(&dir.path().join("missing")).is_err());
        let facts = dir.path().join("true.facts.json");
        std::fs::write(&facts, b"{\"functions\": []}")?;
        assert!(
            !locate(&facts)?.1,
            "facts exported before are not a program"
        );
        // Tests run in the crate's directory, so this path is relative.
        let (path, program) = locate(Path::new("Cargo.toml"))?;
        assert!(program && path.is_absolute(), "{}", path.display());
        Ok(())
    }

    #[tokio::test]
    async fn an_analysis_waits_while_another_runs() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let program = dir.path().join("program");
        std::fs::write(&program, b"\x7fELF")?;
        let path = program.to_str().ok_or("path")?.to_owned();
        let running = TURN.acquire().await?;
        let waited = tokio::time::timeout(Duration::from_millis(500), analyse(path)).await;
        let finished = waited
            .ok()
            .map(|r| r.map(|ran| ran.map(|a| a.tool)).map_err(|r| r.to_string()));
        assert!(finished.is_none(), "it did not wait: {finished:?}");
        drop(running);
        Ok(())
    }
}
