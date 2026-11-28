//! A browser session on hosts a person approves: Chromium loads the pages, every
//! request to another host is refused before it is sent, and what the pages sent and
//! parsed is written as a capture file the ledger takes as `session` evidence.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::num::NonZeroU32;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{Context as _, ensure};
use ledger_core::session::{self, Address, CaptureLine, Frame, Script, Sent, SourceMap};
use ledger_core::{Body, Header, HttpExchange, HttpRequest, HttpResponse, Session, ToolRef};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use crate::browser::{Browser, Incoming, Received};

/// The variable that holds Chromium's absolute path. The flake's shell sets it.
pub const CHROMIUM: &str = "LEDGER_TOOL_CHROMIUM";
/// How long one read of the browser waits before the tool looks at the clock.
const TICK: Duration = Duration::from_millis(100);
/// A page has settled once it has loaded and nothing has happened for this long.
const QUIET: Duration = Duration::from_millis(500);
/// Longest one address may take to settle; what it sent by then is kept.
const PAGE_LIMIT: Duration = Duration::from_secs(30);
/// Longest the browser may take to answer a command the tool waits for.
const ANSWER_LIMIT: Duration = Duration::from_secs(30);
/// The largest request or response body kept. The browser keeps none larger.
const MAX_BODY: usize = 8 << 20;
/// Calls kept per stack, counted from the innermost.
const MAX_FRAMES: usize = 32;
/// Bodies and sources stop being read once this much is held, so the file stays
/// under what the ledger reads.
const BUDGET: usize = Session::MAX_CAPTURE / 4 * 3;

#[derive(clap::Args)]
pub struct Args {
    /// A host you approve, as an address writes it: `example.com`, or `127.0.0.1:8080`
    /// with its port. Give one for each host; a request to any other is refused.
    #[arg(long = "host", required = true, value_parser = host)]
    hosts: Vec<String>,
    /// Open a window and use the site yourself; the capture ends when you close it.
    /// Without it, each address is loaded until the page settles.
    #[arg(long)]
    headed: bool,
    /// The file to write. It must not exist yet.
    out: PathBuf,
    /// The addresses to load, each on a host you approve.
    #[arg(required = true)]
    addresses: Vec<String>,
}

fn host(text: &str) -> Result<String, String> {
    let host = text.to_ascii_lowercase();
    let allowed = |b: u8| b.is_ascii_alphanumeric() || b".-:[]".contains(&b);
    if host.is_empty() || !host.bytes().all(allowed) {
        return Err(format!(
            "`{text}` is not a host: write `example.com`, or `127.0.0.1:8080` with a port"
        ));
    }
    Ok(host)
}

/// Captures the session once `answer` gives the first host, and returns what to tell
/// the person. `answer` is `None` when nobody is at a terminal to be asked.
pub fn capture(
    args: &Args,
    answer: Option<impl FnOnce(&str) -> std::io::Result<String>>,
    chromium: Option<OsString>,
) -> anyhow::Result<String> {
    let approved: BTreeSet<String> = args.hosts.iter().cloned().collect();
    for address in &args.addresses {
        let (host, _) = ledger_core::url_host_and_path(address);
        ensure!(
            address.starts_with("http://") || address.starts_with("https://"),
            "`{address}` is not an http or https address"
        );
        ensure!(
            approved.contains(&host.to_ascii_lowercase()),
            "`{address}` is on {host}, which you have not approved: add `--host {host}`"
        );
    }
    ensure!(
        !args.out.exists(),
        "{} exists already; a capture is never overwritten",
        args.out.display()
    );
    let program = (chromium.map(PathBuf::from).filter(|path| path.is_absolute()))
        .with_context(|| format!("`{CHROMIUM}` does not hold Chromium's absolute path; run this inside the flake's shell (`nix develop`)"))?;
    let first = &args.hosts[0];
    let window = if args.headed {
        " in a window for you to use; the capture ends when you close it"
    } else {
        ""
    };
    let question = format!(
        "About to start Chromium{window} and load {}.\n\
         Requests go to {} and nowhere else; one to any other host is refused and listed.\n\
         Type the first host, `{first}`, to go ahead: ",
        args.addresses.join(", "),
        list(&approved),
    );
    crate::gate(
        answer,
        &question,
        first,
        "the first host",
        "nothing was sent",
    )?;
    let started = Instant::now();
    let mut browser = Browser::start(&program, &approved, args.headed, TICK)?;
    let mut recorder = Recorder::new(approved);
    let tool = recorder.version(&mut browser)?;
    let unsettled = if args.headed {
        recorder.headed(&mut browser, &args.addresses)?
    } else {
        recorder.headless(&mut browser, &args.addresses)?
    };
    drop(browser);
    let report = recorder.report();
    let file = recorder.file(tool)?;
    // What is written is what the ledger reads, or nothing is written.
    let captured = Session::from_capture(&file).map_err(|why| {
        anyhow::anyhow!("the capture does not read back: {why}; nothing was written")
    })?;
    // A session can hold cookies and tokens, so the file is the owner's alone, and whole or absent.
    ledger_os::write_once(&args.out, &file)
        .with_context(|| format!("writing {}", args.out.display()))?;
    let header = captured.session.header();
    let blocked = match header.blocked.len() {
        0 => "none".to_owned(),
        _ => format!(
            "{}; nothing was sent to them. To include one, add `--host` for it and capture again",
            list(&header.blocked)
        ),
    };
    Ok(format!(
        "wrote {}: {} exchanges and {} scripts in {:.0?}{unsettled}{report}\n\
         blocked hosts: {blocked}\n\
         give it to the agent as `session` evidence",
        args.out.display(),
        captured.session.exchanges().len(),
        captured.session.scripts().len(),
        started.elapsed(),
    ))
}

fn list(hosts: &BTreeSet<String>) -> String {
    hosts.iter().cloned().collect::<Vec<_>>().join(", ")
}

/// One request as the browser reported it, hop by hop through its redirects.
#[derive(Default)]
struct Request {
    /// The session that reported it, which is asked for its body.
    session: String,
    hops: Vec<Hop>,
    /// Headers as they went out, one list per hop.
    wire_requests: Vec<Vec<Header>>,
    /// Status and headers as they came in, one per hop that was answered.
    wire_responses: Vec<(u16, Vec<Header>)>,
    /// The body of the last hop's response.
    body: Option<Body>,
    done: bool,
}

struct Hop {
    /// When it was sent, in seconds on the browser's clock.
    at: f64,
    page: Address,
    stack: Vec<Frame>,
    request: HttpRequest,
    response: Option<HttpResponse>,
}

/// What the reply to a command fills in.
enum Pending {
    /// A command the tool waits on.
    Answer,
    Body(String),
    Source(Address, Option<SourceMap>),
    /// The page's requests are held for approval from now on.
    Fence(String),
}

/// Everything the browser reported, kept until the session ends.
struct Recorder {
    approved: BTreeSet<String>,
    blocked: BTreeSet<String>,
    requests: BTreeMap<String, Request>,
    scripts: BTreeSet<Script<String>>,
    pending: BTreeMap<u64, Pending>,
    answers: BTreeMap<u64, Option<Value>>,
    /// When the browser last said anything.
    last: Instant,
    /// Pages by target, each with its session.
    pages: BTreeMap<String, String>,
    fenced: BTreeSet<String>,
    loaded: BTreeSet<String>,
    /// Bytes of bodies and sources held.
    held: usize,
    /// Bodies and sources not read because the budget was spent.
    left_out: usize,
}

impl Recorder {
    fn new(approved: BTreeSet<String>) -> Self {
        Self {
            approved,
            blocked: BTreeSet::new(),
            requests: BTreeMap::new(),
            scripts: BTreeSet::new(),
            pending: BTreeMap::new(),
            answers: BTreeMap::new(),
            last: Instant::now(),
            pages: BTreeMap::new(),
            fenced: BTreeSet::new(),
            loaded: BTreeSet::new(),
            held: 0,
            left_out: 0,
        }
    }

    fn approves(&self, url: &str) -> bool {
        let (host, _) = ledger_core::url_host_and_path(url);
        self.approved.contains(&host.to_ascii_lowercase())
    }

    /// The browser's name and version, then every page it opens is attached to,
    /// paused until its requests are held for approval.
    fn version(&mut self, browser: &mut Browser) -> anyhow::Result<ToolRef> {
        #[derive(Deserialize)]
        struct Version {
            product: String,
        }
        let version: Version = read(self.call(browser, "Browser.getVersion", json!({}))?)?;
        let attach = json!({"autoAttach": true, "waitForDebuggerOnStart": true, "flatten": true, "filter": [{"type": "page"}]});
        self.call(browser, "Target.setAutoAttach", attach)?;
        let version = version.product.rsplit('/').next().unwrap_or_default();
        Ok(ToolRef {
            id: "chromium".into(),
            version: version.to_owned(),
        })
    }

    /// Loads each address in the first tab in turn, until it settles. Returns which did not.
    fn headless(&mut self, browser: &mut Browser, addresses: &[String]) -> anyhow::Result<String> {
        let session = self.tab(browser, None)?;
        let mut unsettled = Vec::new();
        for address in addresses {
            self.loaded.remove(&session);
            browser.send(Some(&session), "Page.navigate", json!({"url": address}))?;
            if !self.settle(browser, &session)? {
                unsettled.push(address.as_str());
            }
        }
        Ok(match unsettled.len() {
            0 => String::new(),
            _ => format!(
                "; not settled within {PAGE_LIMIT:?}, kept as far as it got: {}",
                unsettled.join(", ")
            ),
        })
    }

    /// Opens each address in a tab of its own, then records until the person closes the browser.
    fn headed(&mut self, browser: &mut Browser, addresses: &[String]) -> anyhow::Result<String> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Created {
            target_id: String,
        }
        for (n, address) in addresses.iter().enumerate() {
            let session = if n == 0 {
                self.tab(browser, None)?
            } else {
                let tab = json!({"url": "about:blank"});
                let created: Created = read(self.call(browser, "Target.createTarget", tab)?)?;
                self.tab(browser, Some(&created.target_id))?
            };
            browser.send(Some(&session), "Page.navigate", json!({"url": address}))?;
        }
        while self.step(browser)? {}
        Ok(String::new())
    }

    /// Handles the next message, if one comes within a tick. `false` once the browser
    /// has closed.
    fn step(&mut self, browser: &mut Browser) -> anyhow::Result<bool> {
        match browser.read()? {
            Received::Message(message) => {
                self.last = Instant::now();
                self.on(browser, message)?;
                Ok(true)
            }
            Received::Quiet => Ok(true),
            Received::Closed => Ok(false),
        }
    }

    /// Records until `found` has what it waits for, or `limit` has passed.
    fn until<T>(
        &mut self,
        browser: &mut Browser,
        limit: Duration,
        found: impl Fn(&mut Self) -> Option<T>,
    ) -> anyhow::Result<Option<T>> {
        let started = Instant::now();
        loop {
            if let Some(found) = found(self) {
                return Ok(Some(found));
            }
            if started.elapsed() >= limit {
                return Ok(None);
            }
            ensure!(
                self.step(browser)?,
                "Chromium closed before the capture was done"
            );
        }
    }

    /// Sends a command to the browser and records until its reply comes.
    fn call(
        &mut self,
        browser: &mut Browser,
        method: &str,
        params: Value,
    ) -> anyhow::Result<Value> {
        let id = browser.send(None, method, params)?;
        self.pending.insert(id, Pending::Answer);
        let answer = self.until(browser, ANSWER_LIMIT, |r| r.answers.remove(&id))?;
        let answer = answer.with_context(|| format!("Chromium did not answer {method}"))?;
        answer.with_context(|| format!("Chromium refused {method}"))
    }

    /// The session of a tab, the first one or the one `target` names, once its
    /// requests are held for approval.
    fn tab(&mut self, browser: &mut Browser, target: Option<&str>) -> anyhow::Result<String> {
        let fenced = |r: &mut Self| {
            let session = match target {
                Some(target) => r.pages.get(target),
                None => r.pages.values().next(),
            }?;
            r.fenced.contains(session).then(|| session.clone())
        };
        (self.until(browser, ANSWER_LIMIT, fenced)?).context(
            "Chromium opened no tab that holds its requests for approval; nothing was sent",
        )
    }

    /// Records until the page in `session` has loaded, every request has ended, every
    /// reply asked for has come and nothing has happened for [`QUIET`]. `false` if that
    /// took longer than [`PAGE_LIMIT`].
    fn settle(&mut self, browser: &mut Browser, session: &str) -> anyhow::Result<bool> {
        let settled = |r: &mut Self| {
            let ended =
                (r.requests.values()).all(|request| request.done || request.hops.is_empty());
            let quiet = r.last.elapsed() >= QUIET && r.pending.is_empty();
            (quiet && ended && r.loaded.contains(session)).then_some(())
        };
        Ok(self.until(browser, PAGE_LIMIT, settled)?.is_some())
    }

    fn on(&mut self, browser: &mut Browser, message: Incoming) -> anyhow::Result<()> {
        if let Some(id) = message.id {
            match self.pending.remove(&id) {
                Some(Pending::Answer) => {
                    self.answers.insert(id, message.result);
                }
                Some(pending) => self.replied(pending, message.result),
                None => {}
            }
            return Ok(());
        }
        let (session, params) = (message.session_id, message.params);
        match message.method.as_deref().unwrap_or_default() {
            "Target.attachedToTarget" => self.attached(browser, read(params)?)?,
            "Fetch.requestPaused" => self.paused(browser, &session, &read(params)?)?,
            "Network.requestWillBeSent" => self.sent(session, read(params)?),
            "Network.requestWillBeSentExtraInfo" => {
                let extra: Extra = read(params)?;
                let request = self.requests.entry(extra.request_id).or_default();
                request.wire_requests.push(headers(&extra.headers));
            }
            "Network.responseReceived" => {
                let received: Extra = read(params)?;
                let hop = (self.requests.get_mut(&received.request_id))
                    .and_then(|request| request.hops.last_mut());
                if let (Some(hop), Some(response)) = (hop, received.response) {
                    hop.response = Some(response.into());
                }
            }
            "Network.responseReceivedExtraInfo" => {
                let extra: Extra = read(params)?;
                let request = self.requests.entry(extra.request_id).or_default();
                let status = extra.status_code.unwrap_or_default();
                request
                    .wire_responses
                    .push((status, headers(&extra.headers)));
            }
            "Network.loadingFinished" => self.finished(browser, read(params)?)?,
            "Network.loadingFailed" => {
                let failed: Extra = read(params)?;
                self.requests.entry(failed.request_id).or_default().done = true;
            }
            "Debugger.scriptParsed" => self.parsed(browser, &session, read(params)?)?,
            "Page.loadEventFired" => {
                self.loaded.insert(session);
            }
            _ => {}
        }
        Ok(())
    }

    fn replied(&mut self, pending: Pending, result: Option<Value>) {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Content {
            body: Option<String>,
            #[serde(default)]
            base64_encoded: bool,
            script_source: Option<String>,
        }
        // A command can fail: the page has gone, or the browser kept no body for it.
        let Some(Ok(content)) = result.map(serde_json::from_value::<Content>) else {
            return;
        };
        match (pending, content) {
            (Pending::Fence(session), _) => {
                self.fenced.insert(session);
            }
            (
                Pending::Body(id),
                Content {
                    body: Some(body),
                    base64_encoded,
                    ..
                },
            ) => {
                self.held += body.len();
                if let Some(request) = self.requests.get_mut(&id) {
                    request.body = Some(if base64_encoded {
                        Body::Base64(body)
                    } else {
                        Body::Text(body)
                    });
                }
            }
            (
                Pending::Source(address, source_map),
                Content {
                    script_source: Some(source),
                    ..
                },
            ) => {
                self.held += source.len();
                self.scripts.insert(Script {
                    address,
                    source,
                    source_map,
                });
            }
            _ => {}
        }
    }

    /// A page, frame or worker, paused before it runs: its requests are held for
    /// approval, its scripts reported, and the same is done for what it opens.
    fn attached(&mut self, browser: &mut Browser, attached: Attached) -> anyhow::Result<()> {
        let session = attached.session_id;
        let network = json!({"maxResourceBufferSize": MAX_BODY, "maxTotalBufferSize": BUDGET, "maxPostDataSize": MAX_BODY});
        let commands = [
            ("Network.enable", network),
            // What a cache or a service worker answers is not what the server sent.
            ("Network.setCacheDisabled", json!({"cacheDisabled": true})),
            ("Network.setBypassServiceWorker", json!({"bypass": true})),
            ("Fetch.enable", json!({"patterns": [{"urlPattern": "*"}]})),
            ("Debugger.enable", json!({})),
            (
                "Debugger.setAsyncCallStackDepth",
                json!({"maxDepth": MAX_FRAMES}),
            ),
            // Without these the browser keeps only the innermost call of a stack.
            ("Runtime.enable", json!({})),
            (
                "Runtime.setMaxCallStackSizeToCapture",
                json!({"size": MAX_FRAMES}),
            ),
            ("Page.enable", json!({})),
            (
                "Target.setAutoAttach",
                json!({"autoAttach": true, "waitForDebuggerOnStart": true, "flatten": true}),
            ),
            ("Runtime.runIfWaitingForDebugger", json!({})),
        ];
        // A worker has no fetch domain of its own: its page holds its requests.
        for (method, params) in commands {
            let id = browser.send(Some(&session), method, params)?;
            if method == "Fetch.enable" && attached.target_info.kind == "page" {
                self.pending.insert(id, Pending::Fence(session.clone()));
            }
        }
        if attached.target_info.kind == "page" {
            self.pages.insert(attached.target_info.target_id, session);
        }
        Ok(())
    }

    fn paused(
        &mut self,
        browser: &mut Browser,
        session: &str,
        paused: &Paused,
    ) -> anyhow::Result<()> {
        let id = json!({"requestId": paused.request_id});
        if self.approves(&paused.request.url) {
            browser.send(Some(session), "Fetch.continueRequest", id)?;
            return Ok(());
        }
        let (host, _) = ledger_core::url_host_and_path(&paused.request.url);
        if !host.is_empty() {
            self.blocked.insert(host.to_ascii_lowercase());
        }
        let mut refusal = id;
        refusal["errorReason"] = "BlockedByClient".into();
        browser.send(Some(session), "Fetch.failRequest", refusal)?;
        Ok(())
    }

    fn sent(&mut self, session: String, sent: WillBeSent) {
        let request = self.requests.entry(sent.request_id).or_default();
        if let (Some(redirect), Some(hop)) = (sent.redirect_response, request.hops.last_mut()) {
            hop.response = Some(redirect.into());
        }
        let url = sent.request.url;
        // A page's own request names no page yet: it is for itself.
        let page = Address::new(sent.document_url).or_else(|_| Address::new(url.clone()));
        let Ok(page) = page else { return };
        request.session = session;
        request.done = false;
        request.hops.push(Hop {
            at: sent.timestamp,
            page,
            stack: frames(&sent.initiator),
            request: HttpRequest {
                method: sent.request.method,
                url,
                headers: headers(&sent.request.headers),
                body: sent.request.post_data.map(Body::Text),
            },
            response: None,
        });
    }

    fn finished(&mut self, browser: &mut Browser, finished: Extra) -> anyhow::Result<()> {
        let Some(request) = self.requests.get_mut(&finished.request_id) else {
            return Ok(());
        };
        request.done = true;
        let (session, url) = match request.hops.last() {
            Some(hop) => (request.session.clone(), hop.request.url.clone()),
            None => return Ok(()),
        };
        if !self.approves(&url) {
            return Ok(());
        }
        if self.held >= BUDGET {
            self.left_out += 1;
            return Ok(());
        }
        let params = json!({"requestId": finished.request_id});
        let id = browser.send(Some(&session), "Network.getResponseBody", params)?;
        self.pending.insert(id, Pending::Body(finished.request_id));
        Ok(())
    }

    /// Asks for the source of a script that has an address, at once: the page may go.
    fn parsed(
        &mut self,
        browser: &mut Browser,
        session: &str,
        parsed: Parsed,
    ) -> anyhow::Result<()> {
        let Ok(address) = Address::new(parsed.url) else {
            return Ok(());
        };
        if self.held >= BUDGET {
            self.left_out += 1;
            return Ok(());
        }
        let source_map = match parsed.source_map_url.as_deref() {
            None | Some("") => None,
            Some(map) if map.starts_with("data:") => Some(SourceMap::Inline),
            Some(map) => Some(SourceMap::At(map.to_owned())),
        };
        let params = json!({"scriptId": parsed.script_id});
        let id = browser.send(Some(session), "Debugger.getScriptSource", params)?;
        self.pending
            .insert(id, Pending::Source(address, source_map));
        Ok(())
    }

    fn report(&self) -> String {
        match self.left_out {
            0 => String::new(),
            n => format!("; {n} bodies and sources left out, the capture being at its size limit"),
        }
    }

    /// The capture file: the session line, every exchange on an approved host in the
    /// order it was sent, then every script.
    fn file(self, tool: ToolRef) -> anyhow::Result<Vec<u8>> {
        let mut hops: Vec<(f64, Sent<HttpExchange>)> = Vec::new();
        for request in self.requests.into_values() {
            let last = request.hops.len().saturating_sub(1);
            let wire = request.wire_requests.len() == request.hops.len();
            for (n, hop) in request.hops.into_iter().enumerate() {
                let (host, _) = ledger_core::url_host_and_path(&hop.request.url);
                if !hop.request.url.starts_with("http")
                    || !self.approved.contains(&host.to_ascii_lowercase())
                {
                    continue;
                }
                let mut sent = hop.request;
                if wire {
                    sent.headers.clone_from(&request.wire_requests[n]);
                }
                let response = hop.response.map(|mut response| {
                    // Only a status that agrees says the wire headers are this hop's.
                    match request.wire_responses.get(n) {
                        Some((status, wire)) if *status == response.status => {
                            response.headers.clone_from(wire);
                        }
                        _ => {}
                    }
                    if n == last {
                        response.body.clone_from(&request.body);
                    }
                    response
                });
                let exchange = HttpExchange {
                    request: sent,
                    response,
                };
                hops.push((
                    hop.at,
                    Sent {
                        exchange,
                        at: 0,
                        page: hop.page,
                        stack: hop.stack,
                    },
                ));
            }
        }
        hops.sort_by(|a, b| a.0.total_cmp(&b.0));
        let first = hops.first().map_or(0.0, |(at, _)| *at);
        let header = session::Header {
            tool,
            approved: self.approved,
            blocked: self.blocked,
        };
        let exchanges = hops.into_iter().map(|(at, mut sent)| {
            let since = Duration::try_from_secs_f64(at - first).unwrap_or_default();
            sent.at = u64::try_from(since.as_millis()).unwrap_or(u64::MAX);
            CaptureLine::Exchange(sent)
        });
        let lines = std::iter::once(CaptureLine::Session(header))
            .chain(exchanges)
            .chain(self.scripts.into_iter().map(CaptureLine::Script));
        let mut file = Vec::new();
        for line in lines {
            serde_json::to_writer(&mut file, &line)?;
            file.push(b'\n');
        }
        Ok(file)
    }
}

fn read<T: DeserializeOwned>(params: Value) -> anyhow::Result<T> {
    let what = std::any::type_name::<T>();
    serde_json::from_value(params).with_context(|| format!("an event from Chromium ({what})"))
}

/// Headers as the protocol gives them, one value per name with repeats on lines of
/// their own, as a list.
fn headers(headers: &BTreeMap<String, Value>) -> Vec<Header> {
    let one = |(name, value): (&String, &Value)| {
        let value = value
            .as_str()
            .map_or_else(|| value.to_string(), str::to_owned);
        let lines: Vec<Header> = (value.split('\n'))
            .map(|value| Header {
                name: name.clone(),
                value: value.to_owned(),
            })
            .collect();
        lines
    };
    headers.iter().flat_map(one).collect()
}

/// The calls that sent a request, innermost first, through the calls that scheduled
/// them. Calls in code with no address are left out.
fn frames(initiator: &Initiator) -> Vec<Frame> {
    let mut frames = Vec::new();
    let mut stack = initiator.stack.as_ref();
    while let Some(trace) = stack
        && frames.len() < MAX_FRAMES
    {
        frames.extend(trace.call_frames.iter().filter_map(|call| {
            let from_one = |n: i64| NonZeroU32::new(u32::try_from(n.checked_add(1)?).ok()?);
            Some(Frame {
                script: Address::new(call.url.clone()).ok()?,
                line: from_one(call.line_number)?,
                column: from_one(call.column_number)?,
                function: call.function_name.clone(),
            })
        }));
        stack = trace.parent.as_deref();
    }
    frames.truncate(MAX_FRAMES);
    frames
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Attached {
    session_id: String,
    target_info: TargetInfo,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TargetInfo {
    target_id: String,
    #[serde(rename = "type")]
    kind: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Paused {
    request_id: String,
    request: CdpRequest,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CdpRequest {
    url: String,
    #[serde(default)]
    method: String,
    #[serde(default)]
    headers: BTreeMap<String, Value>,
    post_data: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CdpResponse {
    status: u16,
    #[serde(default)]
    headers: BTreeMap<String, Value>,
}

impl From<CdpResponse> for HttpResponse {
    fn from(response: CdpResponse) -> Self {
        Self {
            status: response.status,
            headers: headers(&response.headers),
            body: None,
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WillBeSent {
    request_id: String,
    request: CdpRequest,
    timestamp: f64,
    #[serde(rename = "documentURL", default)]
    document_url: String,
    initiator: Initiator,
    redirect_response: Option<CdpResponse>,
}

/// Any other event about a request: its response, the headers as on the wire, its end.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Extra {
    request_id: String,
    response: Option<CdpResponse>,
    #[serde(default)]
    headers: BTreeMap<String, Value>,
    status_code: Option<u16>,
}

#[derive(Deserialize)]
struct Initiator {
    stack: Option<Trace>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Trace {
    call_frames: Vec<Call>,
    parent: Option<Box<Trace>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Call {
    function_name: String,
    url: String,
    line_number: i64,
    column_number: i64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Parsed {
    script_id: String,
    url: String,
    #[serde(rename = "sourceMapURL")]
    source_map_url: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ledger_core::EvidenceId;
    use std::io::{BufRead as _, BufReader, Write as _};
    use std::net::{TcpListener, TcpStream};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex, PoisonError};

    type Never = fn(&str) -> std::io::Result<String>;

    fn refusal(result: anyhow::Result<String>) -> String {
        result.map_or_else(|e| format!("{e:#}"), |ok| format!("NOT REFUSED: {ok}"))
    }

    #[test]
    fn nobody_at_a_terminal_and_a_wrong_answer_start_no_browser() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let args = |address: &str| Args {
            hosts: vec!["shop.example".into()],
            headed: false,
            out: dir.path().join("shop.session"),
            addresses: vec![address.into()],
        };
        let shop = args("https://shop.example/");
        // Were the browser started, the refusal would be that it is not there.
        let nowhere = || Some(OsString::from("/no/such/chromium"));
        assert_eq!(
            refusal(capture(&shop, None::<Never>, nowhere())),
            "a live capture is taken by a person at a terminal, and this is not one; nothing was sent"
        );
        let wrong = capture(&shop, Some(|_: &str| Ok("yes\n".into())), nowhere());
        assert_eq!(
            refusal(wrong),
            "that is not the first host; nothing was sent"
        );
        let right = capture(
            &shop,
            Some(|_: &str| Ok("shop.example\n".into())),
            nowhere(),
        );
        assert!(
            refusal(right).starts_with("starting Chromium at /no/such/chromium"),
            "the gate let nothing through"
        );
        assert!(!shop.out.exists());
        // What can be checked before the question is, and nothing is asked then.
        let elsewhere = args("https://elsewhere.example/");
        let refused = refusal(capture(&elsewhere, None::<Never>, nowhere()));
        assert!(refused.contains("which you have not approved"), "{refused}");
        let on_path = refusal(capture(&shop, None::<Never>, Some("chromium".into())));
        assert!(on_path.contains("absolute path"), "{on_path}");
        assert_eq!(host("Shop.Example:8443"), Ok("shop.example:8443".into()));
        assert!(host("a.example, EXCLUDE b.example").is_err());
        assert!(host("").is_err());
        Ok(())
    }

    /// A site on a loopback port. It answers each path from a table, and keeps every
    /// path it was asked for and every connection made to it.
    struct Site {
        port: u16,
        asked: Arc<Mutex<Vec<String>>>,
        connections: Arc<AtomicUsize>,
    }

    fn serve(pages: Vec<(&'static str, &'static str, String)>) -> std::io::Result<Site> {
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        let site = Site {
            port: listener.local_addr()?.port(),
            asked: Arc::default(),
            connections: Arc::default(),
        };
        let (asked, connections) = (Arc::clone(&site.asked), Arc::clone(&site.connections));
        let pages = Arc::new(pages);
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                connections.fetch_add(1, Ordering::SeqCst);
                let (asked, pages) = (Arc::clone(&asked), Arc::clone(&pages));
                std::thread::spawn(move || answer(&stream, &pages, &asked));
            }
        });
        Ok(site)
    }

    fn answer(
        stream: &TcpStream,
        pages: &[(&str, &str, String)],
        asked: &Mutex<Vec<String>>,
    ) -> std::io::Result<()> {
        let mut reader = BufReader::new(stream);
        let (mut line, mut rest) = (String::new(), String::new());
        reader.read_line(&mut line)?;
        // The rest of the head ends at an empty line.
        while reader.read_line(&mut rest)? > 2 {
            rest.clear();
        }
        let path = line
            .split_whitespace()
            .nth(1)
            .unwrap_or_default()
            .to_owned();
        let found = pages.iter().find(|(at, ..)| *at == path);
        let (status, kind, body) = found.map_or(("404 Not Found", "text/plain", ""), |page| {
            ("200 OK", page.1, page.2.as_str())
        });
        asked
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(path);
        write!(
            &mut &*stream,
            "HTTP/1.1 {status}\r\ncontent-type: {kind}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        )
    }

    /// The page's script. The test reads the lines of its calls from here.
    const APP: &str = "// The capture names this file, and the line of each call.
function load() {
  return fetch(\"/api/items\").then(() => track());
}
function track() {
  fetch(\"http://ELSEWHERE/pixel\");
}
load();
//# sourceMappingURL=app.js.map
";

    #[test]
    fn a_session_keeps_what_sent_each_request_and_sends_nothing_to_another_host()
    -> anyhow::Result<()> {
        let chromium = std::env::var_os(CHROMIUM).with_context(|| {
            format!("`{CHROMIUM}` is not set: run the tests inside `nix develop`")
        })?;
        let elsewhere = serve(vec![("/pixel", "image/gif", String::new())])?;
        let other = format!("127.0.0.1:{}", elsewhere.port);
        let app = APP.replace("ELSEWHERE", &other);
        let page = r#"<html><head><script src="/app.js"></script></head><body>shop</body></html>"#;
        let site = serve(vec![
            ("/", "text/html", page.into()),
            ("/app.js", "text/javascript", app.clone()),
            ("/api/items", "application/json", r#"{"items": []}"#.into()),
        ])?;
        let shop = format!("127.0.0.1:{}", site.port);
        let dir = tempfile::tempdir()?;
        let args = Args {
            hosts: vec![shop.clone()],
            headed: false,
            out: dir.path().join("shop.session"),
            addresses: vec![format!("http://{shop}/")],
        };
        let told = capture(
            &args,
            Some(|_: &str| Ok(format!("{shop}\n"))),
            Some(chromium.clone()),
        )?;

        let file = std::fs::read(&args.out)?;
        let captured = Session::from_capture(&file).map_err(anyhow::Error::msg)?;
        let session = &captured.session;
        let exchanges: BTreeMap<EvidenceId, HttpExchange> = (captured.exchanges.iter())
            .map(|bytes| Ok((EvidenceId::of(bytes), serde_json::from_slice(bytes)?)))
            .collect::<anyhow::Result<_>>()?;
        let url = |sent: &Sent| exchanges[&sent.exchange].request.url.as_str();
        // Headless Chromium asks for an icon too, at a moment of its own.
        let sent: Vec<&str> = (session.exchanges().iter())
            .map(url)
            .filter(|url| !url.ends_with("/favicon.ico"))
            .collect();
        let base = format!("http://{shop}");
        let script = format!("{base}/app.js");
        assert_eq!(
            sent,
            [
                format!("{base}/"),
                script.clone(),
                format!("{base}/api/items")
            ]
        );

        let api = (session.exchanges().iter())
            .find(|sent| url(sent).ends_with("/api/items"))
            .context("no API request")?;
        let calls: Vec<(&str, u32, u32, &str)> = (api.stack.iter())
            .map(|f| {
                (
                    f.script.as_str(),
                    f.line.get(),
                    f.column.get(),
                    &*f.function,
                )
            })
            .collect();
        assert_eq!(calls, [(&*script, 3, 10, "load"), (&*script, 8, 1, "")]);
        let body = exchanges[&api.exchange]
            .response
            .as_ref()
            .and_then(|r| r.body.clone());
        assert_eq!(body, Some(Body::Text(r#"{"items": []}"#.into())));

        let parsed = (session.scripts().iter())
            .find(|parsed| parsed.address.as_str() == script)
            .context("the script was not captured")?;
        assert_eq!(parsed.source_map, Some(SourceMap::At("app.js.map".into())));
        let source = (captured.sources.iter()).find(|s| EvidenceId::of(s) == parsed.source);
        assert_eq!(source.map(Vec::as_slice), Some(app.as_bytes()));

        assert_eq!(session.header().blocked, BTreeSet::from([other.clone()]));
        assert!(told.contains(&format!("blocked hosts: {other};")), "{told}");
        let contacted = elsewhere.connections.load(Ordering::SeqCst);
        assert_eq!(contacted, 0, "a host that was not approved was contacted");
        let asked = site
            .asked
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        assert!(asked.contains(&"/api/items".to_owned()), "{asked:?}");

        // A capture is never written over another.
        let again = refusal(capture(
            &args,
            Some(|_: &str| Ok(format!("{shop}\n"))),
            Some(chromium),
        ));
        assert!(again.contains("exists already"), "{again}");
        assert_eq!(std::fs::read(&args.out)?, file);
        Ok(())
    }
}
