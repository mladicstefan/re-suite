//! Chromium, started for one capture with a profile of its own and driven over its
//! debugging protocol. Dropping it stops the browser and deletes the profile.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::io::ErrorKind;
use std::net::TcpStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context as _, anyhow, bail, ensure};
use ledger_os::TempDir;
use serde::Deserialize;
use serde_json::Value;
use tungstenite::protocol::WebSocketConfig;
use tungstenite::{Message, WebSocket};

/// Longest Chromium may take to start listening.
const START_LIMIT: Duration = Duration::from_secs(30);
/// How often to look for its port while it starts.
const POLL: Duration = Duration::from_millis(50);
/// The largest message read. A response body or a script's source arrives in one.
const MAX_MESSAGE: usize = 256 << 20;

/// One message from the browser: the reply to a command, or an event.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Incoming {
    pub id: Option<u64>,
    /// `None` in a reply to a command that failed.
    pub result: Option<Value>,
    pub method: Option<String>,
    #[serde(default)]
    pub params: Value,
    #[serde(default)]
    pub session_id: String,
}

pub enum Received {
    Message(Incoming),
    /// Nothing arrived within the wait the browser was started with.
    Quiet,
    /// The browser closed: the person closed it, or it ended.
    Closed,
}

/// The browser process, stopped when dropped.
struct Process(Child);

impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

pub struct Browser {
    socket: WebSocket<TcpStream>,
    next: u64,
    // Fields drop in order: the process is stopped before its profile is deleted.
    _process: Process,
    _profile: TempDir,
}

impl Browser {
    /// Starts Chromium with a new, empty profile, and connects to it. Every host name
    /// but the approved hosts' resolves to nothing, so even a request the protocol does
    /// not see, such as a connection opened ahead of time, cannot reach another host.
    /// `wait` is how long [`Browser::read`] waits for a message.
    pub fn start(
        program: &Path,
        approved: &BTreeSet<String>,
        headed: bool,
        wait: Duration,
    ) -> anyhow::Result<Self> {
        let profile = ledger_os::private_temp_dir().context("making a profile for Chromium")?;
        let child = Command::new(program)
            .args(flags(profile.path(), approved, headed))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .with_context(|| format!("starting Chromium at {}", program.display()))?;
        let mut process = Process(child);
        let (port, path) = listening(&mut process.0, profile.path())?;
        let stream = TcpStream::connect(("127.0.0.1", port)).context("connecting to Chromium")?;
        let config = WebSocketConfig::default()
            .max_message_size(Some(MAX_MESSAGE))
            .max_frame_size(Some(MAX_MESSAGE));
        let url = format!("ws://127.0.0.1:{port}{path}");
        let (socket, _) = tungstenite::client::client_with_config(url, stream, Some(config))
            .map_err(|e| anyhow!("connecting to Chromium: {e}"))?;
        socket.get_ref().set_read_timeout(Some(wait))?;
        Ok(Self {
            socket,
            next: 0,
            _process: process,
            _profile: profile,
        })
    }

    /// Sends a command, to a page's session or to the browser, and returns its id.
    pub fn send(
        &mut self,
        session: Option<&str>,
        method: &str,
        params: Value,
    ) -> anyhow::Result<u64> {
        self.next += 1;
        let mut command = serde_json::Map::new();
        command.insert("id".into(), self.next.into());
        command.insert("method".into(), method.into());
        command.insert("params".into(), params);
        if let Some(session) = session {
            command.insert("sessionId".into(), session.into());
        }
        self.socket
            .send(Message::text(Value::Object(command).to_string()))?;
        Ok(self.next)
    }

    /// The next message, if one arrives within the wait.
    pub fn read(&mut self) -> anyhow::Result<Received> {
        use tungstenite::Error;
        match self.socket.read() {
            Ok(Message::Text(text)) => {
                let message = serde_json::from_str(&text).context("a message from Chromium")?;
                Ok(Received::Message(message))
            }
            Ok(Message::Close(_)) => Ok(Received::Closed),
            Ok(_) => Ok(Received::Quiet),
            Err(Error::Io(e))
                if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) =>
            {
                Ok(Received::Quiet)
            }
            // A browser that was closed drops the connection without a word.
            Err(
                Error::ConnectionClosed | Error::AlreadyClosed | Error::Io(_) | Error::Protocol(_),
            ) => Ok(Received::Closed),
            Err(e) => Err(e.into()),
        }
    }
}

/// How Chromium is started: on its own profile, listening on a port it picks, with its
/// own traffic (updates, sync, reports) turned off, and with no host but the approved
/// ones resolvable.
fn flags(profile: &Path, approved: &BTreeSet<String>, headed: bool) -> Vec<OsString> {
    let names: BTreeSet<&str> = approved.iter().map(|host| hostname(host)).collect();
    let rules = (names.iter()).fold(String::from("MAP * ~NOTFOUND"), |rules, name| {
        format!("{rules}, EXCLUDE {name}")
    });
    let mut dir = OsString::from("--user-data-dir=");
    dir.push(profile);
    let fixed = [
        "--remote-debugging-port=0",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-background-networking",
        "--disable-component-update",
        "--disable-sync",
        "--disable-default-apps",
        "--disable-extensions",
        "--disable-domain-reliability",
        "--disable-client-side-phishing-detection",
        "--disable-breakpad",
        "--metrics-recording-only",
        "--no-pings",
    ];
    let headless = (!headed).then_some("--headless=new");
    let flags = [dir, format!("--host-resolver-rules={rules}").into()].into_iter();
    flags
        .chain(fixed.into_iter().chain(headless).map(OsString::from))
        .chain([OsString::from("about:blank")])
        .collect()
}

/// A host without its port: `example.com` of `example.com:8443`, `[::1]` of `[::1]:80`.
fn hostname(host: &str) -> &str {
    match host.rsplit_once(':') {
        Some((name, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => name,
        _ => host,
    }
}

/// The port and path Chromium listens on, from the file it writes into its profile.
fn listening(child: &mut Child, profile: &Path) -> anyhow::Result<(u16, String)> {
    let file = profile.join("DevToolsActivePort");
    let started = Instant::now();
    loop {
        let text = std::fs::read_to_string(&file).unwrap_or_default();
        if let Some((port, path)) = text.split_once('\n')
            && let Ok(port) = port.trim().parse()
            && path.starts_with("/devtools/browser/")
        {
            return Ok((port, path.trim().to_owned()));
        }
        if let Some(status) = child.try_wait()? {
            bail!("Chromium ended with {status} before it was ready");
        }
        ensure!(
            started.elapsed() < START_LIMIT,
            "Chromium was not ready within {START_LIMIT:?}"
        );
        std::thread::sleep(POLL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_approved_hosts_resolve() {
        let approved = BTreeSet::from(["shop.example".to_owned(), "127.0.0.1:8080".to_owned()]);
        let flags = flags(Path::new("/tmp/p"), &approved, false);
        let rules = flags
            .iter()
            .find_map(|f| f.to_str()?.strip_prefix("--host-resolver-rules="));
        assert_eq!(
            rules,
            Some("MAP * ~NOTFOUND, EXCLUDE 127.0.0.1, EXCLUDE shop.example")
        );
        assert!(flags.iter().any(|f| f == "--headless=new"));
        let headed = super::flags(Path::new("/tmp/p"), &approved, true);
        assert!(!headed.iter().any(|f| f == "--headless=new"));
        assert_eq!(hostname("[::1]:80"), "[::1]");
        assert_eq!(hostname("[::1]"), "[::1]");
    }
}
