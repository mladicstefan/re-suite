//! The five verbs as plain synchronous functions over a `Store`. Everything an
//! agent reads is produced here: short, paged, and stamped with the sequence
//! number it was computed at.

use std::collections::BTreeSet;
use std::fmt::{self, Write as _};
use std::time::Duration;

use ledger_checkers::{CheckError, check_claim};
use ledger_core::{
    Claim, ClaimId, CoreError, Event, EvidenceId, EvidenceKind, Ledger, Status, Verdict, admit,
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
const CHECK_LIMIT: Duration = Duration::from_secs(5);

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
    let evidence: Vec<EvidenceId> = (evidence.iter())
        .map(|text| only(ledger.evidence_starting(text), text, unknown_evidence).cloned())
        .collect::<Result<_, _>>()?;
    let claim = admit(claim).map_err(StoreError::Core)?;
    let id = claim.get().id().map_err(StoreError::Core)?;
    let kind = claim.get().kind.clone();
    tracing::info!(claim = %id, "proposing");
    store.append(Event::Proposed { claim })?;

    if !evidence.is_empty() {
        let mut mapped = Vec::with_capacity(evidence.len());
        for e in &evidence {
            let unknown = || unknown_evidence(e.as_str());
            let kind = ledger.evidence_kind(e).ok_or_else(unknown)?;
            mapped.push((e.clone(), kind, store.evidence(e)?.ok_or_else(unknown)?));
        }
        let raw: Vec<_> = (mapped.iter())
            .map(|(e, kind, bytes)| (e.clone(), *kind, &bytes[..]))
            .collect();
        let verdict = check_claim(&id, &kind, &raw, CHECK_LIMIT)?;
        store.append(Event::Checked {
            claim: id.clone(),
            evidence: evidence.into_iter().collect(),
            verdict,
        })?;
    }
    let after = store.snapshot();
    let mut out = row_of(&after.ledger, &id);
    if let Some(Verdict::Refuted { counterexample: c }) = after.ledger.verdicts(&id).last() {
        let _ = write!(
            out,
            "\nrefuted by {}: {}",
            short(c.evidence.as_str()),
            c.detail
        );
    }
    Ok(stamp(&after, &out))
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
    for premise in claim.premises.iter().take(LISTED) {
        let _ = write!(out, "\npremise: {}", row_of(ledger, premise));
    }
    let verdicts = ledger.verdicts(&id);
    let earlier = verdicts.len().saturating_sub(LISTED);
    for verdict in &verdicts[earlier..] {
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

/// Stores a local capture file as evidence and returns its id.
///
/// # Errors
/// The file cannot be read or stored.
pub fn add_evidence(store: &Store, kind: EvidenceKind, path: &str) -> Result<String, Rejection> {
    let id = store.add_evidence_file(kind, path)?;
    let body = format!("evidence {}", short(id.as_str()));
    Ok(stamp(&store.snapshot(), &body))
}

/// Withdraws a claim. Its history stays; its dependents go on hold.
///
/// # Errors
/// The id names no claim or more than one.
pub fn retract(store: &Store, claim: &str, reason: String) -> Result<String, Rejection> {
    let id = find_claim(&store.snapshot().ledger, claim)?;
    store.append(Event::Retracted {
        claim: id.clone(),
        reason,
    })?;
    let after = store.snapshot();
    let on_hold = after.ledger.dependents(&id).len();
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
            propose(&store, layout("Boss", 64, &[])?, &[ev]),
        );
        let boss = id_in(&boss).to_owned();
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
        std::fs::write(&request, br#"{"headers": {}, "body": ""}"#)?;
        let garbage = dir.path().join("garbage.json");
        std::fs::write(&garbage, b"not json")?;
        let add = |path: &std::path::Path| -> Result<String, Box<dyn std::error::Error>> {
            let path = path.to_str().ok_or("path")?;
            let added = add_evidence(&store, EvidenceKind::CapturedRequest, path)
                .map_err(|r| r.to_string())?;
            Ok(added.rsplit(' ').next().unwrap_or_default().to_owned())
        };
        let (request, garbage) = (add(&request)?, add(&garbage)?);
        let signature = |key: &str| Claim {
            kind: ClaimKind::RequestSignature(RequestSignature {
                endpoint: "/score".into(),
                header: "X-Sig".into(),
                algorithm: SigAlgorithm::HmacSha256,
                encoding: SigEncoding::Hex,
                key_hex: key.into(),
            }),
            premises: BTreeSet::new(),
        };
        let all = [
            rejected(propose(&store, layout("", 0, &[])?, &[])),
            rejected(propose(&store, layout("T", 8, &["0123abcd"])?, &[])),
            rejected(propose(&store, layout("T", 8, &[])?, &["0123abcd".into()])),
            rejected(propose(&store, layout("T", 8, &[])?, &[request])),
            rejected(propose(&store, signature("00ff"), &[garbage])),
            rejected(propose(&store, signature("secret, not hex"), &[])),
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
        ];
        insta::assert_snapshot!("rejections", all.join("\n"));
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
