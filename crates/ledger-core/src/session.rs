//! A browser session as the ledger keeps it: every exchange in the order its request
//! was sent, the calls that sent it, and the scripts the pages parsed.
//!
//! A capture tool hands a session over as a capture file of JSON lines: a `session`
//! line first, then one line per exchange and one per script, each with the exchange
//! or the script's source written out. [`Session::from_capture`] reads that file into
//! the record and the evidence the record names by id.

use std::collections::BTreeSet;
use std::num::NonZeroU32;

use serde::{Deserialize, Serialize};

use crate::{EvidenceId, EvidenceKind, HttpExchange, ToolRef, url_host_and_path};

/// An address as the browser reported it, such as a URL. Never empty.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct Address(String);

impl Address {
    /// # Errors
    /// The text is empty.
    pub fn new(text: impl Into<String>) -> Result<Self, &'static str> {
        let text = text.into();
        if text.is_empty() {
            Err("an address is empty")
        } else {
            Ok(Self(text))
        }
    }

    #[must_use]
    pub const fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl TryFrom<String> for Address {
    type Error = &'static str;
    fn try_from(text: String) -> Result<Self, Self::Error> {
        Self::new(text)
    }
}

/// One call on the stack that sent a request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Frame {
    /// The script's address. A script written inside a page has the page's address.
    pub script: Address,
    /// Where the call is in the file at `script`, counted from 1 as an editor does.
    pub line: NonZeroU32,
    pub column: NonZeroU32,
    /// The function the call is in; empty for code outside any function.
    #[serde(default)]
    pub function: String,
}

/// One request the session sent: in a [`Session`] the exchange is the id of its
/// `http_exchange` evidence, in a capture file the exchange itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sent<E = EvidenceId> {
    pub exchange: E,
    /// Milliseconds from the session's first request to this one.
    pub at: u64,
    /// The page it was sent for. A worker's requests name the worker's script.
    pub page: Address,
    /// The calls that sent it, innermost first and outermost last. Empty when the
    /// browser sent it for the page itself: the page, a tag in it, a redirect.
    #[serde(default)]
    pub stack: Vec<Frame>,
}

/// Where a script says its source map is.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceMap {
    /// Inside the script's own source, as a `data:` address.
    Inline,
    /// At this address, as the script writes it; a relative one is relative to the script's.
    At(String),
}

/// One script a page parsed: in a [`Session`] its source is the id of its `artifact`
/// evidence, in a capture file the source text.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Script<S = EvidenceId> {
    pub address: Address,
    pub source: S,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_map: Option<SourceMap>,
}

/// What a session was captured with and what it was allowed to reach.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    /// The browser, and the version it reported.
    pub tool: ToolRef,
    /// The hosts the person approved, as an address writes them: `example.com`, or
    /// `127.0.0.1:8080` with a port. Requests went to these and no others.
    pub approved: BTreeSet<String>,
    /// Hosts the pages asked for that were not approved. Nothing was sent to them.
    #[serde(default)]
    pub blocked: BTreeSet<String>,
}

/// One line of a capture file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureLine {
    /// The first line, and only the first.
    Session(Header),
    Exchange(Sent<HttpExchange>),
    Script(Script<String>),
}

/// Evidence format for `EvidenceKind::Session`. The exchanges and the scripts' sources
/// are evidence of their own, named here by id. Only [`Session::from_capture`] makes
/// one, and reading one back checks what it checked: no host is both approved and
/// blocked, and the exchanges are in the order they were sent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "Parts")]
pub struct Session {
    #[serde(flatten)]
    header: Header,
    exchanges: Vec<Sent>,
    scripts: BTreeSet<Script>,
}

#[derive(Deserialize)]
struct Parts {
    #[serde(flatten)]
    header: Header,
    exchanges: Vec<Sent>,
    scripts: BTreeSet<Script>,
}

impl TryFrom<Parts> for Session {
    type Error = String;
    fn try_from(parts: Parts) -> Result<Self, String> {
        let Parts {
            header,
            exchanges,
            scripts,
        } = parts;
        if let Some(host) = header.approved.intersection(&header.blocked).next() {
            return Err(format!("{host} is both approved and blocked"));
        }
        if !exchanges.is_sorted_by_key(|sent| sent.at) {
            return Err("the exchanges are not in the order they were sent".into());
        }
        Ok(Self {
            header,
            exchanges,
            scripts,
        })
    }
}

/// A capture file, read: the record, and the bytes of each piece of evidence it names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Captured {
    pub session: Session,
    /// The record as `session` evidence.
    pub record: Vec<u8>,
    /// Each exchange as `http_exchange` evidence, in the file's order.
    pub exchanges: Vec<Vec<u8>>,
    /// Each script's source as `artifact` evidence, in the file's order.
    pub sources: Vec<Vec<u8>>,
}

impl Session {
    /// The largest record read.
    pub const MAX: usize = 16 << 20;
    /// The largest capture file read: the record with every exchange and source in it.
    pub const MAX_CAPTURE: usize = 256 << 20;

    #[must_use]
    pub const fn header(&self) -> &Header {
        &self.header
    }

    /// Every exchange, in the order its request was sent.
    #[must_use]
    pub const fn exchanges(&self) -> &[Sent] {
        self.exchanges.as_slice()
    }

    /// Every script the pages parsed that has an address.
    #[must_use]
    pub const fn scripts(&self) -> &BTreeSet<Script> {
        &self.scripts
    }

    /// Every piece of evidence the record names, with the kind it is stored as: each
    /// exchange as `http_exchange`, each script's source as `artifact`.
    pub fn named(&self) -> impl Iterator<Item = (&EvidenceId, EvidenceKind)> {
        let exchanges =
            (self.exchanges.iter()).map(|sent| (&sent.exchange, EvidenceKind::HttpExchange));
        let sources = (self.scripts.iter()).map(|script| (&script.source, EvidenceKind::Artifact));
        exchanges.chain(sources)
    }

    /// A stored record.
    ///
    /// # Errors
    /// The bytes are over [`Session::MAX`] or are not a record.
    pub fn read(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > Self::MAX {
            let size = bytes.len();
            return Err(format!("a session is {size} bytes, limit {}", Self::MAX));
        }
        serde_json::from_slice(bytes).map_err(|why| format!("the session does not read: {why}"))
    }

    /// Reads a capture file. Exchanges are put in the order they were sent; a file
    /// with one line this does not read, or a request to a host nobody approved, is
    /// refused whole.
    ///
    /// # Errors
    /// What is wrong, with the line it is on.
    pub fn from_capture(bytes: &[u8]) -> Result<Captured, String> {
        if bytes.len() > Self::MAX_CAPTURE {
            let size = bytes.len();
            return Err(format!(
                "the file is {size} bytes, limit {}",
                Self::MAX_CAPTURE
            ));
        }
        let mut lines = (bytes.split(|b| *b == b'\n').zip(1_usize..))
            .filter(|(line, _)| !line.trim_ascii().is_empty())
            .map(|(line, n)| {
                // Each line is read on its own, so serde's "line 1" would mislead.
                let read = serde_json::from_slice::<CaptureLine>(line).map_err(|why| {
                    let text = why.to_string();
                    let what = text
                        .rsplit_once(" at line ")
                        .map_or(&*text, |(what, _)| what);
                    format!("line {n}, column {}: {what}", why.column())
                });
                (n, read)
            });
        let header = match lines.next() {
            Some((_, Ok(CaptureLine::Session(header)))) => header,
            Some((_, Err(why))) => {
                return Err(format!(
                    "a capture file starts with a `session` line; {why}"
                ));
            }
            _ => return Err("a capture file starts with a `session` line".into()),
        };
        let (mut exchanges, mut sent) = (Vec::new(), Vec::new());
        let (mut sources, mut scripts) = (Vec::new(), BTreeSet::new());
        for (n, line) in lines {
            match line? {
                CaptureLine::Session(_) => {
                    return Err(format!("line {n}: a second `session` line"));
                }
                CaptureLine::Exchange(Sent {
                    exchange,
                    at,
                    page,
                    stack,
                }) => {
                    let (host, _) = url_host_and_path(&exchange.request.url);
                    if !header.approved.iter().any(|a| a.eq_ignore_ascii_case(host)) {
                        return Err(format!(
                            "line {n}: a request to {host}, which was not approved"
                        ));
                    }
                    let bytes = serde_json::to_vec(&exchange).map_err(|why| why.to_string())?;
                    let exchange = EvidenceId::of(&bytes);
                    sent.push(Sent {
                        exchange,
                        at,
                        page,
                        stack,
                    });
                    exchanges.push(bytes);
                }
                CaptureLine::Script(Script {
                    address,
                    source,
                    source_map,
                }) => {
                    let source = source.into_bytes();
                    let id = EvidenceId::of(&source);
                    scripts.insert(Script {
                        address,
                        source: id,
                        source_map,
                    });
                    sources.push(source);
                }
            }
        }
        sent.sort_by_key(|sent| sent.at);
        let session = Self::try_from(Parts {
            header,
            exchanges: sent,
            scripts,
        })?;
        let record = serde_json::to_vec(&session).map_err(|why| why.to_string())?;
        if record.len() > Self::MAX {
            let size = record.len();
            return Err(format!("the session is {size} bytes, limit {}", Self::MAX));
        }
        Ok(Captured {
            session,
            record,
            exchanges,
            sources,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    /// A session as a capture tool writes it: the script line comes after the request
    /// it sent, and the last two exchanges are written out of order.
    const CAPTURE: &str = r#"{"session": {"tool": {"id": "chromium", "version": "158.0"}, "approved": ["shop.example"], "blocked": ["tracker.example"]}}
{"exchange": {"at": 0, "page": "https://shop.example/", "exchange": {"request": {"method": "GET", "url": "https://shop.example/"}, "response": {"status": 200, "body": {"text": "<script src=/app.js></script>"}}}}}

{"exchange": {"at": 40, "page": "https://shop.example/", "stack": [{"script": "https://shop.example/app.js", "line": 2, "column": 3, "function": "load"}, {"script": "https://shop.example/app.js", "line": 4, "column": 1}], "exchange": {"request": {"method": "GET", "url": "https://shop.example/api/cart"}, "response": {"status": 200, "body": {"text": "{\"items\": []}"}}}}}
{"exchange": {"at": 31, "page": "https://shop.example/", "exchange": {"request": {"method": "GET", "url": "https://shop.example/app.js"}, "response": {"status": 200}}}}
{"script": {"address": "https://shop.example/app.js", "source": "function load() {\n  fetch('/api/cart');\n}\nload();", "source_map": {"at": "app.js.map"}}}
"#;

    #[test]
    fn a_capture_file_reads_into_the_record_and_its_evidence() -> Result<(), String> {
        let captured = Session::from_capture(CAPTURE.as_bytes())?;
        let session = &captured.session;
        let header = session.header();
        assert_eq!(
            (
                header.tool.version.as_str(),
                &header.approved,
                &header.blocked
            ),
            (
                "158.0",
                &BTreeSet::from(["shop.example".to_owned()]),
                &BTreeSet::from(["tracker.example".to_owned()])
            )
        );
        // Each exchange is named by the id of the bytes stored for it, in the order sent.
        let exchanges: Vec<HttpExchange> = (captured.exchanges.iter())
            .map(|bytes| serde_json::from_slice(bytes).map_err(|e| e.to_string()))
            .collect::<Result<_, _>>()?;
        let by_id = |id: &EvidenceId| {
            let at = captured
                .exchanges
                .iter()
                .position(|b| EvidenceId::of(b) == *id);
            at.map(|at| exchanges[at].request.url.as_str())
        };
        let sent: Vec<(u64, Option<&str>)> = (session.exchanges().iter())
            .map(|sent| (sent.at, by_id(&sent.exchange)))
            .collect();
        assert_eq!(
            sent,
            [
                (0, Some("https://shop.example/")),
                (31, Some("https://shop.example/app.js")),
                (40, Some("https://shop.example/api/cart")),
            ]
        );
        let stack = &session.exchanges()[2].stack;
        let calls: Vec<(&str, u32, u32, &str)> = (stack.iter())
            .map(|f| {
                (
                    f.script.as_str(),
                    f.line.get(),
                    f.column.get(),
                    &*f.function,
                )
            })
            .collect();
        let app = "https://shop.example/app.js";
        assert_eq!(calls, [(app, 2, 3, "load"), (app, 4, 1, "")]);
        // The script's source is evidence of its own, as the page parsed it.
        let source = b"function load() {\n  fetch('/api/cart');\n}\nload();".to_vec();
        let script = Script {
            address: Address::new(app)?,
            source: EvidenceId::of(&source),
            source_map: Some(SourceMap::At("app.js.map".into())),
        };
        assert_eq!(session.scripts(), &BTreeSet::from([script]));
        assert_eq!(captured.sources, [source]);
        assert_eq!(Session::read(&captured.record)?, captured.session);
        Ok(())
    }

    #[test]
    fn a_file_that_is_not_a_capture_is_refused_whole() {
        let first = CAPTURE.lines().next().unwrap_or_default();
        let exchange = |at: u64, url: &str| {
            format!(
                r#"{{"exchange": {{"at": {at}, "page": "{url}", "exchange": {{"request": {{"method": "GET", "url": "{url}"}}}}}}}}"#
            )
        };
        let with = |line: &str| format!("{first}\n{line}\n");
        let frame = |frame: &str| {
            let sent = exchange(0, "https://shop.example/");
            with(&sent.replacen(r#""page""#, &format!(r#""stack": [{frame}], "page""#), 1))
        };
        let broken = [
            String::new(),
            r#"{"log": {"entries": []}}"#.to_owned(),
            exchange(0, "https://shop.example/"),
            with(first),
            with(&exchange(0, "https://tracker.example/pixel")),
            with(&exchange(0, "https://elsewhere.example/")),
            with("not json"),
            with(
                &exchange(0, "https://shop.example/")
                    .replace("https://shop.example/\", \"exchange", "\", \"exchange"),
            ),
            frame(r#"{"script": "", "line": 1, "column": 1}"#),
            frame(r#"{"line": 1, "column": 1}"#),
            frame(r#"{"script": "https://shop.example/app.js", "line": 0, "column": 1}"#),
            first.replace(r#"["tracker.example"]"#, r#"["shop.example"]"#),
        ];
        let refused: Vec<String> = (broken.iter())
            .map(|file| match Session::from_capture(file.as_bytes()) {
                Ok(_) => format!("NOT REFUSED: {file}"),
                Err(why) => why,
            })
            .collect();
        insta::assert_snapshot!("capture_refused", refused.join("\n"));
        // A stored record is checked the same way when it is read back.
        let shuffled = r#"{"tool": {"id": "chromium", "version": "1"}, "approved": ["a.example"], "exchanges": [{"exchange": "ab", "at": 9, "page": "p"}, {"exchange": "cd", "at": 1, "page": "p"}], "scripts": []}"#;
        assert!(Session::read(shuffled.as_bytes()).is_err());
        assert!(Session::read(&vec![b' '; Session::MAX + 1]).is_err());
    }
}
