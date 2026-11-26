//! Runs Rizin on a program file as a child process. The file is read, never run.

use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use ledger_checkers::RIZIN_COMMANDS;
use tokio::process::Command;

use crate::tools::Rejection;

const PROGRAM: &str = "rizin";
/// Longest one analysis may take. Rizin is stopped when it runs out.
const LIMIT: Duration = Duration::from_secs(600);

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
        .output();
    let version = version.await.map_err(missing)?;
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
    let Ok(ran) = tokio::time::timeout(LIMIT, run).await else {
        let message = format!(
            "Rizin did not finish within {} seconds and was stopped.",
            LIMIT.as_secs()
        );
        return Err(reject(
            "tool_timeout",
            message,
            "Nothing was recorded. Tell the human: this program needs a longer limit or a lighter analysis.",
        ));
    };
    let ran = ran.map_err(missing)?;
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
