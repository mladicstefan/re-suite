//! The five verbs as plain synchronous functions over a `Store`. Everything an
//! agent reads is produced here: short, paged, and stamped with the sequence
//! number it was computed at.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Write as _};
use std::io::Read as _;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use ledger_checkers::{
    CheckError, MAX_PARSED_EVIDENCE, check_claim, checker_of, har_exchanges, is_about, rizin_facts,
};
use ledger_core::{
    BinaryFacts, CheckerRef, Claim, ClaimId, ClaimKind, CoreError, Endpoint, Event, EvidenceId,
    EvidenceKind, HttpExchange, HttpRequest, HttpResponse, Ledger, Status, Verdict, admit,
};
use ledger_store::{Snapshot, Store, StoreError};
use schemars::JsonSchema;

/// Rows per page of any list.
pub const PAGE: usize = 50;
/// Characters of an id shown to agents. Any unique prefix is accepted back.
const SHORT: usize = 12;
/// Longest sentence shown in a row.
const SENTENCE: usize = 160;
/// Verdicts and premises listed by `explain` before it summarises the rest.
const LISTED: usize = 5;
/// Differences from a refuted claim listed before the rest are counted.
const SHOWN: usize = 3;
const CHECK_LIMIT: Duration = Duration::from_secs(5);
/// Largest HAR file `add_evidence` reads. A HAR file records a whole browser session,
/// many exchanges each within [`MAX_PARSED_EVIDENCE`], so it may be larger than any
/// one capture; it is parsed whole, which takes a few times its size in memory.
const MAX_HAR: u64 = 256 << 20;

/// A refusal an agent can act on: a stable code, what it is about, and what to do next.
#[derive(Debug)]
pub struct Rejection {
    pub code: &'static str,
    pub subject: String,
    pub message: String,
    pub next: &'static str,
}

impl fmt::Display for Rejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            code,
            subject,
            message,
            next,
        } = self;
        write!(f, "{code} [{subject}]: {message} Next: {next}")
    }
}

fn reject(
    code: &'static str,
    subject: impl fmt::Display,
    message: impl fmt::Display,
    next: &'static str,
) -> Rejection {
    Rejection {
        code,
        subject: short(&subject.to_string()).to_owned(),
        message: message.to_string(),
        next,
    }
}

impl From<StoreError> for Rejection {
    fn from(e: StoreError) -> Self {
        match e {
            StoreError::Core(CoreError::Inadmissible(why)) => reject(
                "claim_inadmissible",
                "claim",
                format!("{why}."),
                "Fix the claim and propose it again.",
            ),
            StoreError::Core(CoreError::UnknownClaim(id)) => unknown_claim(id.as_str()),
            StoreError::Core(CoreError::UnknownEvidence(id)) => unknown_evidence(id.as_str()),
            StoreError::Corrupt(id) => reject(
                "evidence_corrupt",
                id,
                "The stored file no longer matches its hash.",
                "Add the capture again from its original file and tell the human.",
            ),
            StoreError::Io(e) => reject(
                "evidence_unreadable",
                "path",
                format!("{e}."),
                "Check that the path is a local file this server can read.",
            ),
            other => reject(
                "store_failed",
                "ledger",
                format!("{other}."),
                "Nothing was recorded. Retry once, then tell the human.",
            ),
        }
    }
}

impl From<CheckError> for Rejection {
    fn from(e: CheckError) -> Self {
        let next = "The claim is filed but unchecked. Propose it again with evidence of the right kind and format.";
        match e {
            CheckError::WrongEvidence(kind) => reject(
                "evidence_wrong_kind",
                format!("{kind:?}"),
                "This kind of evidence cannot check this kind of claim.",
                next,
            ),
            CheckError::Malformed(id, _) => reject(
                "evidence_malformed",
                id,
                "The file is not in the format its kind requires.",
                next,
            ),
            CheckError::MissingKey(id) => reject(
                "key_missing",
                id,
                "The claim's key is not secret evidence in this ledger.",
                "Add the key file with add_evidence kind=secret and cite its id as `key`.",
            ),
            CheckError::NotApplicable(id, what) => reject(
                "evidence_not_applicable",
                id,
                format!("It is {what}, which the claim says nothing about."),
                "The claim is filed but unchecked. Replay only evidence the claim is about: captures of its endpoint and status, or an analysis that recovered its caller.",
            ),
            CheckError::TooLarge(id, size, max) => reject(
                "evidence_too_large",
                id,
                format!("{size} bytes, limit {max}."),
                next,
            ),
            CheckError::InvalidClaim(why) => reject(
                "claim_uncheckable",
                "claim",
                format!("{why}."),
                "Fix the claim and propose it again.",
            ),
        }
    }
}

fn unknown_claim(text: &str) -> Rejection {
    reject(
        "claim_unknown",
        text,
        "No claim has this id.",
        "Use ask with about=all to list claims, or propose the claim first.",
    )
}

fn unknown_evidence(text: &str) -> Rejection {
    reject(
        "evidence_unknown",
        text,
        "No evidence has this id.",
        "Call add_evidence with the capture file first.",
    )
}

/// An id in the short form shown to agents; anything that is not an id is left alone.
fn short(id: &str) -> &str {
    if id.len() > SHORT && id.bytes().all(|b| b.is_ascii_hexdigit()) {
        &id[..SHORT]
    } else {
        id
    }
}

/// The one id starting with `text`, or a rejection saying why there is not exactly one.
fn only<'a, T: fmt::Display>(
    mut matches: impl Iterator<Item = &'a T>,
    text: &str,
    unknown: fn(&str) -> Rejection,
) -> Result<&'a T, Rejection> {
    // Every id starts with the empty string, so it would name the only one there is.
    if text.is_empty() {
        return Err(unknown(text));
    }
    match (matches.next(), matches.next()) {
        (Some(id), None) => Ok(id),
        (None, _) => Err(unknown(text)),
        (Some(_), Some(_)) => Err(reject(
            "id_ambiguous",
            text,
            "More than one id starts with this.",
            "Give more characters of the id.",
        )),
    }
}

fn find_claim(ledger: &Ledger, text: &str) -> Result<ClaimId, Rejection> {
    only(ledger.claims_starting(text), text, unknown_claim).cloned()
}

const fn word(status: Status) -> &'static str {
    match status {
        Status::Unchecked => "unchecked",
        Status::Held => "held",
        Status::Refuted => "refuted",
        Status::Inconclusive => "inconclusive",
        Status::Blocked => "on_hold",
        Status::Retracted => "retracted",
    }
}

fn row(id: &ClaimId, claim: &Claim, status: Status) -> String {
    let mut sentence = claim.sentence();
    if let Some((at, _)) = sentence.char_indices().nth(SENTENCE) {
        sentence.truncate(at);
        sentence.push('…');
    }
    format!("{:<12} {}  {sentence}", word(status), short(id.as_str()))
}

fn row_of(ledger: &Ledger, id: &ClaimId) -> String {
    match (ledger.claim(id), ledger.status(id)) {
        (Some(claim), Some(status)) => row(id, claim, status),
        _ => format!("unknown      {}", short(id.as_str())),
    }
}

/// The first premise that does not hold: the reason a claim is on hold.
fn holding(ledger: &Ledger, claim: &Claim) -> Option<String> {
    claim.premises.iter().find_map(|p| {
        let status = ledger.status(p)?;
        (status != Status::Held)
            .then(|| format!("waiting on {} ({})", short(p.as_str()), word(status)))
    })
}

/// Checks being run right now, by what identifies them: claim, evidence and checker.
static RUNNING: Mutex<BTreeMap<String, Arc<Mutex<()>>>> = Mutex::new(BTreeMap::new());

/// A place in line for one check. Dropping it lets the next request for the same check in,
/// and clears the entry once nobody is waiting, whichever way the check ended.
struct Turn {
    key: String,
    gate: Arc<Mutex<()>>,
}

impl Turn {
    fn at(claim: &ClaimId, read: &BTreeSet<EvidenceId>, checker: &CheckerRef) -> Self {
        let read: Vec<&str> = read.iter().map(EvidenceId::as_str).collect();
        let key = format!(
            "{claim}|{}@{}|{}",
            checker.id,
            checker.version,
            read.join(",")
        );
        let mut running = RUNNING.lock().unwrap_or_else(PoisonError::into_inner);
        let gate = Arc::clone(running.entry(key.clone()).or_default());
        Self { key, gate }
    }
}

impl Drop for Turn {
    fn drop(&mut self) {
        let mut running = RUNNING.lock().unwrap_or_else(PoisonError::into_inner);
        // The table and this turn hold one reference each when nobody else is in line.
        if Arc::strong_count(&self.gate) == 2 {
            running.remove(&self.key);
        }
    }
}

/// One line saying which refuted claim this one replaces and what it gave up, if any.
fn lineage(ledger: &Ledger, id: &ClaimId) -> Option<String> {
    let (earlier, revision) = ledger.revised_from(id)?;
    let shown = |items: &[String]| {
        let first: Vec<&str> = items.iter().take(SHOWN).map(String::as_str).collect();
        match items.len().saturating_sub(SHOWN) {
            0 => first.join("; "),
            more => format!("{}; and {more} more", first.join("; ")),
        }
    };
    let earlier = short(earlier.as_str());
    Some(
        match (revision.weaker.is_empty(), revision.other.is_empty()) {
            (false, true) => format!("weaker than refuted {earlier}: {}", shown(&revision.weaker)),
            (false, false) => format!(
                "replaces refuted {earlier}; weaker in: {}; also changed: {}",
                shown(&revision.weaker),
                shown(&revision.other)
            ),
            _ => format!(
                "replaces refuted {earlier}; changed: {}",
                shown(&revision.other)
            ),
        },
    )
}

fn stamp(snapshot: &Snapshot, body: &str) -> String {
    format!("seq {}\n{body}", snapshot.seq)
}

/// Files a claim, and replays it against `evidence` if any is given.
///
/// # Errors
/// The claim, its premises or the evidence are refused; nothing is recorded
/// unless the rejection says the claim was filed.
pub fn propose(store: &Store, mut claim: Claim, evidence: &[String]) -> Result<String, Rejection> {
    let before = store.snapshot();
    let ledger = &before.ledger;
    // The gate: a claim may only rest on claims that exist and are not refuted.
    let mut premises = BTreeSet::new();
    for given in &claim.premises {
        let text = given.as_str();
        let premise = only(ledger.claims_starting(text), text, |text| {
            reject(
                "premise_unknown",
                text,
                "No claim has this id.",
                "Propose the premise first, or drop it from this claim.",
            )
        })?;
        if ledger.status(premise) == Some(Status::Refuted) {
            return Err(reject(
                "premise_refuted",
                premise,
                "This premise has a counterexample.",
                "Do not build on it. Use explain to see the counterexample.",
            ));
        }
        premises.insert(premise.clone());
    }
    claim.premises = premises;
    let mut evidence: Vec<EvidenceId> = (evidence.iter())
        .map(|text| only(ledger.evidence_starting(text), text, unknown_evidence).cloned())
        .collect::<Result<_, _>>()?;
    // A signing key is cited by id, never written into the claim. It is read
    // by every check of the claim, so it counts as evidence of that check.
    if let ClaimKind::RequestSignature(signature) = &mut claim.kind {
        const NEXT: &str =
            "Add the key file with add_evidence kind=secret and cite its id as `key`.";
        let text = signature.key.to_string();
        let found = only(ledger.evidence_starting(&text), &text, |text| {
            reject("key_unknown", text, "No evidence has this id.", NEXT)
        });
        let key = found?.clone();
        if ledger.evidence_kind(&key) != Some(EvidenceKind::Secret) {
            let message = "This evidence is not of kind secret.";
            return Err(reject("key_not_secret", &key, message, NEXT));
        }
        if !evidence.is_empty() && !evidence.contains(&key) {
            evidence.push(key.clone());
        }
        signature.key = key;
    }
    let claim = admit(claim).map_err(StoreError::Core)?;
    let id = claim.get().id().map_err(StoreError::Core)?;
    let kind = claim.get().kind.clone();
    // What the check needs is taken now and the snapshot let go: while a reader still
    // holds an old snapshot, every write has to copy the whole ledger.
    let kinds: Vec<_> = evidence.iter().map(|e| ledger.evidence_kind(e)).collect();
    drop(before);
    tracing::info!(claim = %id, "proposing");
    store.append(Event::Proposed { claim })?;

    let mut reused = false;
    if !evidence.is_empty() {
        // A check is the same check if the claim, the evidence it reads and the checker's
        // version are the same; its recorded verdict then stands and nothing is replayed.
        // An inconclusive verdict is not reused: it may only have run out of time.
        let checker = checker_of(&kind);
        let read: BTreeSet<EvidenceId> = evidence.iter().cloned().collect();
        // Two requests for the same check share one run: the second waits here, then
        // finds the first one's verdict recorded.
        let turn = Turn::at(&id, &read, &checker);
        let _mine = turn.gate.lock().unwrap_or_else(PoisonError::into_inner);
        reused = (store.snapshot().ledger.checked(&id, &read, &checker))
            .is_some_and(|v| !matches!(v, Verdict::Inconclusive { .. }));
        if !reused {
            let mut mapped = Vec::with_capacity(evidence.len());
            for (e, kind) in evidence.iter().zip(&kinds) {
                let unknown = || unknown_evidence(e.as_str());
                let kind = kind.ok_or_else(unknown)?;
                mapped.push((e.clone(), kind, store.evidence(e)?.ok_or_else(unknown)?));
            }
            let raw: Vec<_> = (mapped.iter())
                .map(|(e, kind, bytes)| (e.clone(), *kind, &bytes[..]))
                .collect();
            let verdict = check_claim(&id, &kind, &raw, CHECK_LIMIT)?;
            store.append(Event::Checked {
                claim: id.clone(),
                evidence: read,
                verdict,
                checker: Some(checker),
            })?;
        }
    }
    let after = store.snapshot();
    let mut out = row_of(&after.ledger, &id);
    // The first refutation is why the claim is refuted, whatever was checked after it.
    let refuted =
        (after.ledger.verdicts(&id).iter()).find(|v| matches!(v, Verdict::Refuted { .. }));
    if let Some(Verdict::Refuted { counterexample: c }) = refuted {
        let _ = write!(
            out,
            "\nrefuted by {}: {}",
            short(c.evidence.as_str()),
            c.detail
        );
    }
    if reused {
        out.push_str("\nalready checked on exactly this evidence; not replayed");
    }
    if let Some(line) = lineage(&after.ledger, &id) {
        let _ = write!(out, "\n{line}");
    }
    Ok(stamp(&after, &out))
}

/// [`propose`] on every capture in the ledger that the claim is about: its endpoint
/// and the responses it covers. The agent does not have to pick them out, and a
/// capture of another status cannot get in by mistake. For claims about snapshots,
/// which are not indexed by what they show, it files the claim unchecked.
///
/// # Errors
/// As [`propose`].
pub fn propose_on_all(store: &Store, claim: Claim) -> Result<String, Rejection> {
    let mut about = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let chunk = store.http_evidence(cursor.as_deref(), 500)?;
        for (id, line) in &chunk {
            // The index holds the request line and status, which is all the scope needs.
            let exchange = HttpExchange {
                request: HttpRequest {
                    method: line.method.clone(),
                    url: line.url.clone(),
                    headers: Vec::new(),
                    body: None,
                },
                response: line.status.map(|status| HttpResponse {
                    status,
                    headers: Vec::new(),
                    body: None,
                }),
            };
            if is_about(&claim.kind, &exchange) {
                about.push(id.clone());
            }
        }
        match chunk.last() {
            Some((id, _)) if chunk.len() == 500 => cursor = Some(id.clone()),
            _ => break,
        }
    }
    let found = about.len();
    let mut out = propose(store, claim, &about)?;
    if found == 0 {
        out.push_str("\nno capture in this ledger is about this claim");
    }
    Ok(out)
}

/// Which fixed question `ask` answers.
#[derive(Debug, Clone, Copy, rmcp::serde::Deserialize, JsonSchema)]
#[serde(crate = "rmcp::serde", rename_all = "snake_case")]
pub enum About {
    /// Every claim, in the order proposed.
    All,
    /// One claim: needs `claim`.
    Claim,
    /// What is known about a type name or an endpoint: needs `subject`.
    Subject,
    /// What is on hold, and the premise each one waits on.
    OnHold,
    /// What would be put on hold if a claim failed: needs `claim`.
    Affected,
    /// Which captures belong to an endpoint: needs `subject`, written as an
    /// endpoint such as `GET api.example.com/users/{id}`.
    Evidence,
}

/// Whether a claim belongs in the list being asked for.
type Filter<'a> = Box<dyn Fn(&ClaimId, &Claim, Status) -> bool + 'a>;

fn needs(about: &str, field: &str) -> Rejection {
    reject(
        "argument_missing",
        field,
        format!("about={about} needs `{field}`."),
        "Call ask again with that argument.",
    )
}

/// Answers one of the fixed question shapes, one page at a time.
///
/// # Errors
/// A missing argument, or an id that names no claim or more than one.
pub fn ask(
    store: &Store,
    about: About,
    claim: Option<&str>,
    subject: Option<&str>,
    after: Option<&str>,
) -> Result<String, Rejection> {
    let snapshot = store.snapshot();
    let ledger = &snapshot.ledger;
    if let About::Evidence = about {
        let endpoint = subject.ok_or_else(|| needs("evidence", "subject"))?;
        return captures_of(store, &snapshot, endpoint, after);
    }
    let wanted: Filter<'_> = match about {
        About::All => Box::new(|_, _, _| true),
        About::Claim => {
            let id = find_claim(ledger, claim.ok_or_else(|| needs("claim", "claim"))?)?;
            return Ok(stamp(&snapshot, &row_of(ledger, &id)));
        }
        About::Subject => {
            let subject = subject.ok_or_else(|| needs("subject", "subject"))?;
            Box::new(move |_, claim, _| claim.subject() == subject)
        }
        About::Evidence => return Err(needs("evidence", "subject")),
        About::OnHold => Box::new(|_, _, status| status == Status::Blocked),
        About::Affected => {
            let id = find_claim(ledger, claim.ok_or_else(|| needs("affected", "claim"))?)?;
            let affected: BTreeSet<&ClaimId> = ledger.dependents(&id).into_iter().collect();
            Box::new(move |id, _, _| affected.contains(id))
        }
    };
    // Paged by key: the cursor is the last id of the previous page, never an offset.
    let cursor = after.map(|text| find_claim(ledger, text)).transpose()?;
    let mut past_cursor = cursor.is_none();
    let rows = ledger
        .claims()
        .zip(ledger.statuses())
        .filter(|((id, _), _)| {
            let include = past_cursor;
            past_cursor |= cursor.as_ref() == Some(*id);
            include
        });
    let mut rows = rows.filter(|((id, claim), (_, status))| wanted(id, claim, *status));
    let mut out = String::new();
    let mut last = None;
    for ((id, claim), (_, status)) in rows.by_ref().take(PAGE) {
        let _ = write!(out, "{}", row(id, claim, status));
        if let (About::OnHold, Some(why)) = (about, holding(ledger, claim)) {
            let _ = write!(out, "  [{why}]");
        }
        out.push('\n');
        last = Some(id);
    }
    match (last, rows.next()) {
        (Some(last), Some(_)) => {
            let _ = write!(out, "more: ask again with after={}", short(last.as_str()));
        }
        (None, _) => out.push_str("nothing"),
        _ => out.push_str("end"),
    }
    Ok(stamp(&snapshot, &out))
}

/// One page of the indexed captures whose request line belongs to `endpoint`.
fn captures_of(
    store: &Store,
    snapshot: &Snapshot,
    endpoint: &str,
    after: Option<&str>,
) -> Result<String, Rejection> {
    let parsed = Endpoint::parse(endpoint).map_err(|why| {
        reject(
            "endpoint_malformed",
            endpoint,
            format!("{why}."),
            "Write the subject as an endpoint and ask again.",
        )
    })?;
    let ledger = &snapshot.ledger;
    let mut cursor = (after
        .map(|text| only(ledger.evidence_starting(text), text, unknown_evidence)))
    .transpose()?
    .map(ToString::to_string);
    let mut out = String::new();
    let mut shown = 0;
    // The index is read in id order, a chunk at a time, until one page of matches is found.
    let more = 'scan: loop {
        let chunk = store.http_evidence(cursor.as_deref(), 500)?;
        for (id, line) in &chunk {
            if !parsed.matches(&line.method, &line.url) {
                continue;
            }
            if shown == PAGE {
                break 'scan true;
            }
            // The query string can hold keys, so only the path is shown.
            let url = line.url.split(['?', '#']).next().unwrap_or_default();
            let status = line
                .status
                .map_or_else(|| "no response".into(), |s| s.to_string());
            let _ = writeln!(
                out,
                "evidence {}  {status}  {} {url}",
                short(id),
                line.method
            );
            shown += 1;
            cursor = Some(id.clone());
        }
        match chunk.last() {
            Some((id, _)) if chunk.len() == 500 => cursor = Some(id.clone()),
            _ => break false,
        }
    };
    match (shown, more, cursor) {
        (0, _, _) => out.push_str("nothing"),
        (_, true, Some(last)) => {
            let _ = write!(out, "more: ask again with after={}", short(&last));
        }
        _ => out.push_str("end"),
    }
    Ok(stamp(snapshot, &out))
}

/// Why a claim has its status: its premises, its recent verdicts and any counterexample.
///
/// # Errors
/// The id names no claim or more than one.
pub fn explain(store: &Store, claim: &str) -> Result<String, Rejection> {
    let snapshot = store.snapshot();
    let ledger = &snapshot.ledger;
    let id = find_claim(ledger, claim)?;
    let mut out = row_of(ledger, &id);
    let Some(claim) = ledger.claim(&id) else {
        return Ok(stamp(&snapshot, &out));
    };
    if let Some(why) = holding(ledger, claim) {
        let _ = write!(out, "\n{why}");
    }
    if let Some(line) = lineage(ledger, &id) {
        let _ = write!(out, "\n{line}");
    }
    for premise in claim.premises.iter().take(LISTED) {
        let _ = write!(out, "\npremise: {}", row_of(ledger, premise));
    }
    let verdicts = ledger.verdicts(&id);
    let mut earlier = verdicts.len().saturating_sub(LISTED);
    // The first refutation is why the claim is refuted, so it is listed even when older.
    let refuted = verdicts
        .iter()
        .position(|v| matches!(v, Verdict::Refuted { .. }));
    let first = refuted.filter(|&at| at < earlier);
    let listed = first.into_iter().chain(earlier..verdicts.len());
    earlier -= usize::from(first.is_some());
    for verdict in listed.map(|at| &verdicts[at]) {
        let _ = match verdict {
            Verdict::Held { runs } => write!(out, "\nheld on {runs} runs (replayed, not proved)"),
            Verdict::Refuted { counterexample: c } => {
                write!(
                    out,
                    "\nrefuted by {}: {}",
                    short(c.evidence.as_str()),
                    c.detail
                )
            }
            Verdict::Inconclusive { reason } => write!(out, "\ninconclusive: {reason}"),
        };
    }
    let more_premises = claim.premises.len().saturating_sub(LISTED);
    if earlier + more_premises > 0 {
        let _ = write!(
            out,
            "\n({earlier} earlier verdicts and {more_premises} more premises not shown)"
        );
    }
    if verdicts.is_empty() {
        out.push_str("\nno checks yet: propose it again with evidence to replay it");
    }
    Ok(stamp(&snapshot, &out))
}

/// Stores what Rizin printed for a program as the facts it holds: its functions and
/// direct calls.
///
/// # Errors
/// The output is not what the import expects, or it cannot be stored.
pub fn add_rizin_output(store: &Store, tool: &str, output: &[u8]) -> Result<String, Rejection> {
    let facts = rizin_facts(tool, output).map_err(|why| {
        reject(
            "tool_output_unreadable",
            "rizin",
            format!("Rizin's output cannot be used: {why}."),
            "Nothing was recorded. Check that the file is a program Rizin can read, then tell the human.",
        )
    })?;
    let stored = rmcp::serde_json::to_vec(&facts).map_err(|e| StoreError::Core(e.into()))?;
    let id = store.add_evidence(EvidenceKind::BinaryFacts, &stored)?;
    let calls: usize = facts.functions.iter().map(|f| f.calls.len()).sum();
    let body = format!(
        "evidence {}\nRizin recovered from the program with sha256 {}: functions {}, direct calls {calls}, called imports {}",
        short(id.as_str()),
        short(&facts.sha256),
        facts.functions.len(),
        facts.imports.len(),
    );
    Ok(stamp(&store.snapshot(), &body))
}

/// The bytes of a file that is parsed whole: a regular file of at most `max` bytes.
fn read_whole(path: &str, max: u64) -> Result<Vec<u8>, Rejection> {
    let meta = std::fs::metadata(path).map_err(StoreError::Io)?;
    if !meta.is_file() {
        return Err(reject(
            "evidence_unreadable",
            "path",
            "It is not a regular file.",
            "Check that the path is a local file this server can read.",
        ));
    }
    if meta.len() > max {
        return Err(reject(
            "evidence_too_large",
            "path",
            format!("{} bytes, limit {max}.", meta.len()),
            "Nothing was recorded. Give a smaller file, such as a HAR file of fewer requests, or tell the human.",
        ));
    }
    // The file can grow after it was measured; no more than the limit is read either way.
    let mut bytes = Vec::new();
    let file = std::fs::File::open(path).map_err(StoreError::Io)?;
    (file.take(max).read_to_end(&mut bytes)).map_err(StoreError::Io)?;
    Ok(bytes)
}

/// Stores a local capture file as evidence and returns its id. A HAR file given
/// as `http_exchange` is split into one piece of evidence per entry. A file given
/// as `binary_facts` must hold facts already; a program is analysed first, see
/// [`add_rizin_output`].
///
/// # Errors
/// The file cannot be read or stored, or is not in the format its kind requires.
pub fn add_evidence(store: &Store, kind: EvidenceKind, path: &str) -> Result<String, Rejection> {
    if kind == EvidenceKind::BinaryFacts {
        let bytes = read_whole(path, MAX_PARSED_EVIDENCE as u64)?;
        if rmcp::serde_json::from_slice::<BinaryFacts>(&bytes).is_err() {
            return Err(reject(
                "evidence_malformed",
                "path",
                "The file is not in the format its kind requires.",
                "Nothing was recorded. Give the program file itself, or facts in the format this server stores.",
            ));
        }
    }
    let har = (kind == EvidenceKind::HttpExchange)
        .then(|| read_whole(path, MAX_HAR))
        .transpose()?
        .and_then(|bytes| har_exchanges(&bytes));
    let Some(exchanges) = har else {
        let id = store.add_evidence_file(kind, path)?;
        let body = format!("evidence {}", short(id.as_str()));
        return Ok(stamp(&store.snapshot(), &body));
    };
    // Only the number: a snapshot held across the writes would make each one copy the ledger.
    let before = store.snapshot().seq;
    let total = exchanges.len();
    for exchange in exchanges {
        let exchange =
            rmcp::serde_json::to_vec(&exchange).map_err(|e| StoreError::Core(e.into()))?;
        store.add_evidence(kind, &exchange)?;
    }
    // Each new piece of evidence is one event; repeats inside the file and re-imports add none.
    let after = store.snapshot();
    let new = after.seq - before;
    let body = format!(
        "imported {total} exchanges from the HAR file, {new} of them new\n\
         list the ones for an endpoint with ask about=evidence subject=`METHOD host/path`"
    );
    Ok(stamp(&after, &body))
}

/// Withdraws a claim. Its history stays; its dependents go on hold.
///
/// # Errors
/// The id names no claim or more than one.
pub fn retract(store: &Store, claim: &str, reason: String) -> Result<String, Rejection> {
    // Dependents not on hold yet. The snapshot is let go before the write, which would
    // otherwise have to copy the ledger it still shares.
    let (id, free) = {
        let ledger = &store.snapshot().ledger;
        let id = find_claim(ledger, claim)?;
        let free: Vec<ClaimId> = (ledger.dependents(&id).into_iter())
            .filter(|d| ledger.status(d) != Some(Status::Blocked))
            .cloned()
            .collect();
        (id, free)
    };
    store.append(Event::Retracted {
        claim: id.clone(),
        reason,
    })?;
    let after = store.snapshot();
    let on_hold = (free.iter())
        .filter(|d| after.ledger.status(d) == Some(Status::Blocked))
        .count();
    let body = format!(
        "{}\ndependents now on hold: {on_hold}",
        row_of(&after.ledger, &id)
    );
    Ok(stamp(&after, &body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ledger_core::{ClaimKind, MemoryLayout, RequestSignature, SigAlgorithm, SigEncoding};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn layout(
        name: &str,
        size: u64,
        premises: &[&str],
    ) -> Result<Claim, Box<dyn std::error::Error>> {
        let premises: Result<_, _> = premises.iter().map(|p| premise(p)).collect();
        Ok(Claim {
            kind: ClaimKind::MemoryLayout(MemoryLayout {
                type_name: name.into(),
                size,
                fields: vec![],
            }),
            premises: premises?,
        })
    }

    /// A premise as an agent writes it: any string, usually a short id.
    fn premise(text: &str) -> Result<ClaimId, rmcp::serde_json::Error> {
        rmcp::serde_json::from_value(rmcp::serde_json::Value::String(text.into()))
    }

    /// The short id on a response's first row.
    fn id_in(response: &str) -> &str {
        let row = response.lines().nth(1).unwrap_or_default();
        row.split_whitespace().nth(1).unwrap_or_default()
    }

    fn rejected(result: Result<String, Rejection>) -> String {
        result.map_or_else(|r| r.to_string(), |ok| format!("NOT REJECTED: {ok}"))
    }

    #[test]
    fn a_session_reads_as_expected() -> TestResult {
        let dir = tempfile::tempdir()?;
        let store = Store::open(dir.path().join("l.db"))?;
        let snapshot = dir.path().join("player.bin");
        std::fs::write(&snapshot, [0u8; 32])?;
        let path = snapshot.to_str().ok_or("path")?;
        let added =
            add_evidence(&store, EvidenceKind::MemorySnapshot, path).map_err(|r| r.to_string())?;
        let ev = added.rsplit(' ').next().unwrap_or_default().to_owned();

        let mut log = format!("add_evidence\n{added}\n");
        let mut say = |verb: &str, result: Result<String, Rejection>| {
            let text = result.unwrap_or_else(|r| format!("REJECTED {r}"));
            let _ = write!(log, "\n{verb}\n{text}\n");
            text
        };
        let player = say(
            "propose Player (32 bytes) with the snapshot",
            propose(
                &store,
                layout("Player", 32, &[])?,
                std::slice::from_ref(&ev),
            ),
        );
        let player = id_in(&player).to_owned();
        say(
            "propose it again: a no-op",
            propose(&store, layout("Player", 32, &[])?, &[]),
        );
        let boss = say(
            "propose Boss (64 bytes) with the snapshot: refuted",
            propose(&store, layout("Boss", 64, &[])?, std::slice::from_ref(&ev)),
        );
        let boss = id_in(&boss).to_owned();
        say(
            "propose Boss again with the same snapshot: the verdict stands, nothing is replayed",
            propose(&store, layout("Boss", 64, &[])?, &[ev]),
        );
        let pet = say(
            "propose Pet resting on Player",
            propose(&store, layout("Pet", 8, &[&player])?, &[]),
        );
        let pet = id_in(&pet).to_owned();
        say(
            "propose Minion resting on Boss: refused",
            propose(&store, layout("Minion", 8, &[&boss])?, &[]),
        );
        say(
            "ask about=affected claim=Player",
            ask(&store, About::Affected, Some(&player), None, None),
        );
        say(
            "retract Player",
            retract(&store, &player, "wrong build".into()),
        );
        say(
            "ask about=on_hold",
            ask(&store, About::OnHold, None, None, None),
        );
        say(
            "ask about=subject subject=Boss",
            ask(&store, About::Subject, None, Some("Boss"), None),
        );
        say(
            "ask about=claim claim=Pet",
            ask(&store, About::Claim, Some(&pet), None, None),
        );
        say("explain Boss", explain(&store, &boss));
        say("explain Pet", explain(&store, &pet));
        say("ask about=all", ask(&store, About::All, None, None, None));
        insta::assert_snapshot!("session", log);
        Ok(())
    }

    #[test]
    fn every_rejection_reads_as_expected() -> TestResult {
        let dir = tempfile::tempdir()?;
        let store = Store::open(dir.path().join("l.db"))?;
        let request = dir.path().join("request.json");
        let exchange =
            br#"{"request": {"method": "POST", "url": "https://game.example/score?key=s3cret"}}"#;
        std::fs::write(&request, exchange)?;
        let garbage = dir.path().join("garbage.json");
        std::fs::write(&garbage, b"not json")?;
        let add = |path: &std::path::Path| -> Result<String, Box<dyn std::error::Error>> {
            let path = path.to_str().ok_or("path")?;
            let added = add_evidence(&store, EvidenceKind::HttpExchange, path)
                .map_err(|r| r.to_string())?;
            Ok(added.rsplit(' ').next().unwrap_or_default().to_owned())
        };
        let (request, garbage) = (add(&request)?, add(&garbage)?);
        let key_file = dir.path().join("key.bin");
        std::fs::write(&key_file, [0x00, 0xff])?;
        let key_path = key_file.to_str().ok_or("path")?;
        let key =
            add_evidence(&store, EvidenceKind::Secret, key_path).map_err(|r| r.to_string())?;
        let key = key.rsplit(' ').next().unwrap_or_default().to_owned();
        let cite = |text: &str| -> Result<EvidenceId, rmcp::serde_json::Error> {
            rmcp::serde_json::from_value(rmcp::serde_json::Value::String(text.into()))
        };
        let (key, unknown_key, not_a_key) = (cite(&key)?, cite("0123abcd")?, cite(&request)?);
        // Every id starts with the empty string; with one claim and one piece of evidence
        // it must still name neither.
        let lone = Store::open(dir.path().join("lone.db"))?;
        add_evidence(&lone, EvidenceKind::Secret, key_path).map_err(|r| r.to_string())?;
        propose(&lone, layout("T", 8, &[])?, &[]).map_err(|r| r.to_string())?;
        // Files one byte over the limits for files read whole, made without writing them.
        let sparse = |name: &str, len: u64| -> Result<String, Box<dyn std::error::Error>> {
            let file = dir.path().join(name);
            std::fs::File::create(&file)?.set_len(len)?;
            Ok(file.to_str().ok_or("path")?.to_owned())
        };
        let big_har = sparse("big.har", MAX_HAR + 1)?;
        let big_facts = sparse("big.facts.json", MAX_PARSED_EVIDENCE as u64 + 1)?;
        let dir_path = dir.path().to_str().ok_or("path")?;
        let signature = |endpoint: &str, key: &EvidenceId| Claim {
            kind: ClaimKind::RequestSignature(RequestSignature {
                endpoint: endpoint.into(),
                header: "X-Sig".into(),
                algorithm: SigAlgorithm::HmacSha256,
                encoding: SigEncoding::Hex,
                key: key.clone(),
                signed: vec![],
            }),
            premises: BTreeSet::new(),
        };
        let all = [
            rejected(propose(&store, layout("", 0, &[])?, &[])),
            rejected(propose(&store, layout("T", 8, &["0123abcd"])?, &[])),
            rejected(propose(&store, layout("T", 8, &[])?, &["0123abcd".into()])),
            rejected(propose(
                &store,
                layout("T", 8, &[])?,
                std::slice::from_ref(&request),
            )),
            rejected(propose(&store, signature("POST /score", &key), &[garbage])),
            rejected(propose(
                &store,
                signature("POST /purchase", &key),
                &[request],
            )),
            rejected(propose(&store, signature("POST /score", &unknown_key), &[])),
            rejected(propose(&store, signature("POST /score", &not_a_key), &[])),
            rejected(propose(&store, signature("/score", &key), &[])),
            rejected(ask(&store, About::Claim, None, None, None)),
            rejected(ask(&store, About::Subject, None, None, None)),
            rejected(ask(&store, About::All, None, None, Some("0123abcd"))),
            rejected(explain(&store, "0123abcd")),
            rejected(explain(&store, "")),
            rejected(retract(&store, "0123abcd", String::new())),
            rejected(add_evidence(
                &store,
                EvidenceKind::MemorySnapshot,
                "/no/such/capture.bin",
            )),
            rejected(explain(&lone, "")),
            rejected(retract(&lone, "", String::new())),
            rejected(propose(&lone, layout("U", 8, &[])?, &[String::new()])),
            rejected(add_evidence(&store, EvidenceKind::HttpExchange, dir_path)),
            rejected(add_evidence(&store, EvidenceKind::HttpExchange, &big_har)),
            rejected(add_evidence(&store, EvidenceKind::BinaryFacts, &big_facts)),
        ];
        insta::assert_snapshot!("rejections", all.join("\n"));
        Ok(())
    }

    #[test]
    fn a_har_file_is_imported_and_listed_by_endpoint() -> TestResult {
        let dir = tempfile::tempdir()?;
        let store = Store::open(dir.path().join("l.db"))?;
        let entry = |method: &str, url: &str, status: u16| {
            rmcp::serde_json::json!({
                "startedDateTime": "2026-11-26T10:00:00Z",
                "request": {"method": method, "url": url, "headers": [{"name": "accept", "value": "*/*"}]},
                "response": {"status": status, "headers": [], "content": {"mimeType": "application/json", "text": "{\"id\": 1}"}},
            })
        };
        let har = rmcp::serde_json::json!({"log": {"version": "1.2", "entries": [
            entry("GET", "https://crates.io/api/v1/crates/serde?include=x&token=s3cret", 200),
            entry("GET", "https://crates.io/api/v1/crates/tokio", 200),
            entry("GET", "https://crates.io/api/v1/crates/nope", 404),
            entry("GET", "https://crates.io/assets/app.js", 200),
            entry("POST", "https://crates.io/api/v1/crates/serde", 0),
        ]}});
        let file = dir.path().join("session.har");
        std::fs::write(&file, har.to_string())?;
        let path = file.to_str().ok_or("path")?;
        let mut log = String::new();
        let mut say = |what: &str, result: Result<String, Rejection>| {
            let text = result.unwrap_or_else(|r| format!("REJECTED {r}"));
            let _ = write!(log, "{what}\n{text}\n\n");
        };
        say(
            "add_evidence session.har",
            add_evidence(&store, EvidenceKind::HttpExchange, path),
        );
        say(
            "add it again",
            add_evidence(&store, EvidenceKind::HttpExchange, path),
        );
        let crates = "GET crates.io/api/v1/crates/{name}";
        say(
            "ask about=evidence, the crate endpoint",
            ask(&store, About::Evidence, None, Some(crates), None),
        );
        say(
            "ask about=evidence, only requests with include",
            ask(
                &store,
                About::Evidence,
                None,
                Some("GET crates.io/api/v1/crates/{name}?include"),
                None,
            ),
        );
        // A claim about 200 responses, replayed on all its captures: the 404 and the script stay out.
        let found = Claim {
            kind: ClaimKind::ResponseSchema(ledger_core::ResponseSchema {
                endpoint: crates.into(),
                status: 200,
                schema: rmcp::serde_json::json!({"required": ["id"]}),
            }),
            premises: BTreeSet::new(),
        };
        say(
            "propose on all captures: 200 responses of the crate endpoint",
            propose_on_all(&store, found.clone()),
        );
        let mut elsewhere = found;
        if let ClaimKind::ResponseSchema(schema) = &mut elsewhere.kind {
            schema.endpoint = "GET docs.rs/crate/{name}".into();
        }
        say(
            "propose on all captures: an endpoint nothing was captured for",
            propose_on_all(&store, elsewhere),
        );
        say(
            "ask about=evidence, an endpoint nothing was captured for",
            ask(
                &store,
                About::Evidence,
                None,
                Some("GET docs.rs/crate/{name}"),
                None,
            ),
        );
        say(
            "ask about=evidence, not an endpoint",
            ask(&store, About::Evidence, None, Some("crates"), None),
        );
        say(
            "ask about=evidence, no subject",
            ask(&store, About::Evidence, None, None, None),
        );
        insta::assert_snapshot!("har_import", log);
        assert!(!log.contains("s3cret"), "a query string was echoed");
        Ok(())
    }

    #[test]
    fn a_rizin_export_is_imported_and_call_edges_replay_on_it() -> TestResult {
        let dir = tempfile::tempdir()?;
        let store = Store::open(dir.path().join("l.db"))?;
        // What Rizin prints, one value per command; fields the import ignores are left in.
        let output = rmcp::serde_json::json!([
            {"bintype": "elf", "arch": "x86", "bits": 64},
            {"md5": "b6e0", "sha256": "3141dd3506805dc7a68851abaf0bd3fd8466ca0ff1746f61c8243e2a869f55e0"},
            [{"ordinal": 1, "name": "setlocale"}],
            [{"name": "setlocale", "type": "R_X86_64_GLOB_DAT", "vaddr": 40864}],
            [
                {"offset": 9344, "name": "main", "size": 262, "callrefs": [
                    {"from": 9350, "to": 40864, "type": "CALL"},
                    {"from": 9360, "to": 9616, "type": "CALL"}]},
                {"offset": 9616, "name": "fcn.00002590", "size": 40},
            ],
        ]);
        let lines: Vec<String> = (output.as_array().into_iter().flatten())
            .map(ToString::to_string)
            .collect();
        let (tool, output) = ("rizin 0.9.1 @ linux-x86-64", lines.join("\n"));
        let added = add_rizin_output(&store, tool, output.as_bytes());
        let added = added.map_err(|r| r.to_string())?;
        let facts = id_in(&added).to_owned();
        // Facts exported before can be added as a file; anything else under that kind cannot.
        let stored = rmcp::serde_json::to_vec(&rizin_facts(tool, output.as_bytes())?)?;
        let file = dir.path().join("true.facts.json");
        std::fs::write(&file, &stored)?;
        let again = add_evidence(
            &store,
            EvidenceKind::BinaryFacts,
            file.to_str().ok_or("path")?,
        );
        assert_eq!(id_in(&again.map_err(|r| r.to_string())?), facts);
        std::fs::write(&file, "{\"functions\": 3}")?;
        let wrong = add_evidence(
            &store,
            EvidenceKind::BinaryFacts,
            file.to_str().ok_or("path")?,
        );
        assert_eq!(wrong.err().map(|r| r.code), Some("evidence_malformed"));
        let calls = |caller: &str, callee: &str| Claim {
            kind: ClaimKind::CallEdge(ledger_core::CallEdge {
                binary: "true".into(),
                caller: ledger_core::FunctionRef::Name(caller.into()),
                callee: ledger_core::FunctionRef::Name(callee.into()),
            }),
            premises: BTreeSet::new(),
        };
        let mut log = format!("add_evidence, a program Rizin has analysed\n{added}\n\n");
        let mut say = |what: &str, result: Result<String, Rejection>| {
            let text = result.unwrap_or_else(|r| format!("REJECTED {r}"));
            let _ = write!(log, "{what}\n{text}\n\n");
        };
        say(
            "propose: main calls setlocale",
            propose(
                &store,
                calls("main", "setlocale"),
                std::slice::from_ref(&facts),
            ),
        );
        say(
            "propose: fcn.00002590 calls main",
            propose(
                &store,
                calls("fcn.00002590", "main"),
                std::slice::from_ref(&facts),
            ),
        );
        say(
            "ask about=subject true",
            ask(&store, About::Subject, None, Some("true"), None),
        );
        insta::assert_snapshot!("rizin_import", log);
        Ok(())
    }

    #[test]
    fn a_claim_that_says_less_than_a_refuted_one_is_marked() -> TestResult {
        let dir = tempfile::tempdir()?;
        let store = Store::open(dir.path().join("l.db"))?;
        let capture = |name: &str, body: &str| -> Result<String, Box<dyn std::error::Error>> {
            let exchange = rmcp::serde_json::json!({
                "request": {"method": "GET", "url": format!("https://code.example/repos/{name}")},
                "response": {"status": 200, "body": {"text": body}},
            });
            let file = dir.path().join(format!("{name}.json"));
            std::fs::write(&file, exchange.to_string())?;
            let added = add_evidence(
                &store,
                EvidenceKind::HttpExchange,
                file.to_str().ok_or("path")?,
            )
            .map_err(|r| r.to_string())?;
            Ok(added.rsplit(' ').next().unwrap_or_default().to_owned())
        };
        let evidence = [
            capture(
                "org",
                r#"{"id": 1, "organization": {"login": "rust-lang"}, "homepage": "https://x"}"#,
            )?,
            capture("user", r#"{"id": 2, "homepage": null}"#)?,
        ];
        let record = |schema| Claim {
            kind: ClaimKind::ResponseSchema(ledger_core::ResponseSchema {
                endpoint: "GET code.example/repos/{name}".into(),
                status: 200,
                schema,
            }),
            premises: BTreeSet::new(),
        };
        let mut log = String::new();
        let mut say = |what: &str, result: Result<String, Rejection>| {
            let text = result.unwrap_or_else(|r| format!("REJECTED {r}"));
            let _ = write!(log, "{what}\n{text}\n\n");
            text
        };
        let first = rmcp::serde_json::json!({"required": ["id", "organization"], "properties": {"homepage": {"type": "string"}}});
        say(
            "first guess, from the organisation's record",
            propose(&store, record(first), &evidence),
        );
        let looser = rmcp::serde_json::json!({"required": ["id"], "properties": {"homepage": {"type": ["string", "null"]}}});
        let second = say(
            "the same claim with what failed taken out",
            propose(&store, record(looser), &evidence),
        );
        say("explain it", explain(&store, id_in(&second)));
        let other = rmcp::serde_json::json!({"required": ["id"], "properties": {"id": {"type": "integer"}}});
        say(
            "a claim that drops things and adds one",
            propose(&store, record(other), &evidence),
        );
        insta::assert_snapshot!("revision", log);
        Ok(())
    }

    #[test]
    fn a_refuted_claim_always_shows_its_counterexample() -> TestResult {
        let dir = tempfile::tempdir()?;
        let store = Store::open(dir.path().join("l.db"))?;
        let snapshot = |len: usize| -> Result<String, Box<dyn std::error::Error>> {
            let file = dir.path().join(format!("{len}.bin"));
            std::fs::write(&file, vec![0u8; len])?;
            let path = file.to_str().ok_or("path")?;
            let added = add_evidence(&store, EvidenceKind::MemorySnapshot, path)
                .map_err(|r| r.to_string())?;
            Ok(added.rsplit(' ').next().unwrap_or_default().to_owned())
        };
        let boss = || layout("Boss", 64, &[]);
        propose(&store, boss()?, &[snapshot(32)?]).map_err(|r| r.to_string())?;
        // Later checks on snapshots that are large enough hold; the claim stays refuted.
        let mut last = String::new();
        for len in 64..64 + LISTED {
            last = propose(&store, boss()?, &[snapshot(len)?]).map_err(|r| r.to_string())?;
        }
        let explained = explain(&store, id_in(&last)).map_err(|r| r.to_string())?;
        let why = "refuted by 1a541fc8f6f7: snapshot is 32 bytes, `Boss` needs 64";
        assert!(
            last.contains(why) && explained.contains(why),
            "{last}\n\n{explained}"
        );
        let held = explained.lines().filter(|l| l.starts_with("held on"));
        assert_eq!(held.count(), LISTED);
        assert!(!explained.contains("not shown"), "{explained}");
        Ok(())
    }

    #[test]
    fn retracting_counts_only_the_claims_it_puts_on_hold() -> TestResult {
        let dir = tempfile::tempdir()?;
        let store = Store::open(dir.path().join("l.db"))?;
        let file = dir.path().join("player.bin");
        std::fs::write(&file, [0u8; 32])?;
        let path = file.to_str().ok_or("path")?;
        let added =
            add_evidence(&store, EvidenceKind::MemorySnapshot, path).map_err(|r| r.to_string())?;
        let snapshot = [added.rsplit(' ').next().unwrap_or_default().to_owned()];
        let filed = |claim, evidence: &[String]| -> Result<String, Box<dyn std::error::Error>> {
            let out = propose(&store, claim, evidence).map_err(|r| r.to_string())?;
            Ok(id_in(&out).to_owned())
        };
        let player = filed(layout("Player", 32, &[])?, &snapshot)?;
        let map = filed(layout("Map", 8, &[])?, &[])?;
        // Four claims rest on Player. Only Pet goes on hold: Boss is refuted, Minion
        // waits on Map already and Ghost is retracted.
        filed(layout("Pet", 8, &[&player])?, &[])?;
        filed(layout("Boss", 64, &[&player])?, &snapshot)?;
        filed(layout("Minion", 8, &[&player, &map])?, &[])?;
        let ghost = filed(layout("Ghost", 8, &[&player])?, &[])?;
        retract(&store, &ghost, "gone".into()).map_err(|r| r.to_string())?;
        let out = retract(&store, &player, "wrong build".into()).map_err(|r| r.to_string())?;
        assert!(out.ends_with("dependents now on hold: 1"), "{out}");
        Ok(())
    }

    #[test]
    fn a_check_holds_no_snapshot_the_writer_would_copy() -> TestResult {
        let dir = tempfile::tempdir()?;
        let store = Store::open(dir.path().join("l.db"))?;
        let file = dir.path().join("player.bin");
        std::fs::write(&file, [0u8; 32])?;
        let path = file.to_str().ok_or("path")?;
        let added =
            add_evidence(&store, EvidenceKind::MemorySnapshot, path).map_err(|r| r.to_string())?;
        let evidence = [added.rsplit(' ').next().unwrap_or_default().to_owned()];
        let claim = layout("Player", 32, &[])?;
        let id = claim.id()?;
        let read: BTreeSet<EvidenceId> = (store.snapshot().ledger)
            .evidence_starting(&evidence[0])
            .cloned()
            .collect();
        // Taking this check's place in line stops propose just before it checks.
        let turn = Turn::at(&id, &read, &checker_of(&claim.kind));
        let gate = turn.gate.lock().unwrap_or_else(PoisonError::into_inner);
        let start = Arc::downgrade(&store.snapshot());
        let (held, proposed) = std::thread::scope(|s| {
            let proposing = s.spawn(|| propose(&store, claim, &evidence));
            // The table, this turn and propose's turn.
            while Arc::strong_count(&turn.gate) < 3 && !proposing.is_finished() {
                std::thread::yield_now();
            }
            let held = start.strong_count();
            drop(gate);
            (held, proposing.join().map_err(|_| "propose panicked"))
        });
        assert!(proposed?.map_err(|r| r.to_string())?.contains("held"));
        // The store keeps the snapshot propose started from as its spare; nothing else may.
        assert!(
            held <= 1,
            "{held} holders of the snapshot propose started from"
        );
        Ok(())
    }

    #[test]
    fn identical_checks_arriving_together_run_once() -> TestResult {
        let dir = tempfile::tempdir()?;
        let store = Store::open(dir.path().join("l.db"))?;
        // Large enough that reading and hashing it takes a moment, so the requests overlap.
        let snapshot = dir.path().join("big.bin");
        std::fs::write(&snapshot, vec![0u8; 8 << 20])?;
        let added = add_evidence(
            &store,
            EvidenceKind::MemorySnapshot,
            snapshot.to_str().ok_or("path")?,
        )
        .map_err(|r| r.to_string())?;
        let evidence = [added.rsplit(' ').next().unwrap_or_default().to_owned()];
        let claim = layout("Big", 64, &[])?;
        let id = claim.id()?;
        let start = std::sync::Barrier::new(8);
        let responses: Vec<String> = std::thread::scope(|s| {
            let asked: Vec<_> = (0..8)
                .map(|_| {
                    s.spawn(|| {
                        start.wait();
                        propose(&store, claim.clone(), &evidence).unwrap_or_else(|r| r.to_string())
                    })
                })
                .collect();
            asked
                .into_iter()
                .map(|t| t.join().unwrap_or_default())
                .collect()
        });
        assert!(
            responses.iter().all(|r| r.contains("held")),
            "{responses:#?}"
        );
        assert_eq!(
            store.snapshot().ledger.verdicts(&id).len(),
            1,
            "the check ran more than once"
        );
        let waited = responses
            .iter()
            .filter(|r| r.contains("not replayed"))
            .count();
        assert_eq!(waited, 7, "seven requests took the first one's verdict");
        assert!(
            RUNNING
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .keys()
                .all(|k| !k.starts_with(id.as_str()))
        );
        Ok(())
    }

    #[test]
    fn lists_are_paged_by_key_and_stay_bounded() -> TestResult {
        let dir = tempfile::tempdir()?;
        let store = Store::open(dir.path().join("l.db"))?;
        let events: Result<Vec<Event>, Box<dyn std::error::Error>> = (1..=120)
            .map(|n| {
                Ok(Event::Proposed {
                    claim: admit(layout("T", n, &[])?)?,
                })
            })
            .collect();
        store.append_batch(events?)?;
        let (mut seen, mut after, mut pages) = (0, None::<String>, 0);
        loop {
            let page =
                ask(&store, About::All, None, None, after.as_deref()).map_err(|r| r.to_string())?;
            assert!(
                page.lines().count() <= PAGE + 2,
                "a page is bounded whatever the ledger size"
            );
            seen += page.lines().filter(|l| l.starts_with("unchecked")).count();
            pages += 1;
            match page
                .lines()
                .last()
                .and_then(|l| l.strip_prefix("more: ask again with after="))
            {
                Some(cursor) => after = Some(cursor.to_owned()),
                None => break,
            }
        }
        assert_eq!((seen, pages), (120, 3));
        Ok(())
    }
}
