//! Re-checks what a ledger holds against the captures of a new build of the target.
//!
//! Read-only: it reports what still holds and records nothing, so a new build can
//! never change a claim's status behind anyone's back. A web claim is tied to its
//! endpoint and a claim about snapshots to its type name; that is how the captures
//! of the new build are matched to it.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use ledger_core::{
    Claim, ClaimId, ClaimKind, Endpoint, EvidenceId, EvidenceKind, HttpExchange, Ledger, Status,
    Verdict, admit, url_host_and_path,
};

use crate::{Raw, check_claim, is_about};

/// The captures of one build, sorted by what they can be evidence for.
#[derive(Default)]
pub struct Build {
    exchanges: Vec<(EvidenceId, Vec<u8>, HttpExchange)>,
    snapshots: BTreeMap<String, Vec<(EvidenceId, Vec<u8>)>>,
    secrets: BTreeMap<EvidenceId, Vec<u8>>,
}

impl Build {
    /// Adds captured HTTP exchanges, for instance the entries of a HAR file.
    pub fn add_exchanges(&mut self, exchanges: impl IntoIterator<Item = HttpExchange>) {
        for exchange in exchanges {
            // An exchange that cannot be written back as JSON cannot be evidence either.
            if let Ok(bytes) = serde_json::to_vec(&exchange) {
                self.exchanges
                    .push((EvidenceId::of(&bytes), bytes, exchange));
            }
        }
    }

    /// Adds a snapshot of one instance of the type called `type_name`.
    pub fn add_snapshot(&mut self, type_name: &str, bytes: Vec<u8>) {
        let snapshots = self.snapshots.entry(type_name.to_owned()).or_default();
        snapshots.push((EvidenceId::of(&bytes), bytes));
    }

    /// Makes a signing key available under the id signature claims cite it by.
    pub fn add_secret(&mut self, id: EvidenceId, bytes: Vec<u8>) {
        self.secrets.insert(id, bytes);
    }

    /// The captures in this build that `claim` is about, as evidence for a check.
    fn evidence_for(&self, claim: &ClaimKind) -> Vec<Raw<'_>> {
        let mut evidence: Vec<Raw<'_>> = match claim {
            ClaimKind::MemoryLayout(_)
            | ClaimKind::RecordArray(_)
            | ClaimKind::FieldRelation(_)
            | ClaimKind::TaggedRecords(_)
            | ClaimKind::StringTable(_)
            | ClaimKind::Format(_) => {
                let snapshots = self
                    .snapshots
                    .get(claim_subject(claim))
                    .map_or(&[][..], Vec::as_slice);
                (snapshots.iter())
                    .map(|(id, bytes)| (id.clone(), EvidenceKind::MemorySnapshot, &bytes[..]))
                    .collect()
            }
            _ => (self.exchanges.iter())
                .filter(|(_, _, exchange)| is_about(claim, exchange))
                .map(|(id, bytes, _)| (id.clone(), EvidenceKind::HttpExchange, &bytes[..]))
                .collect(),
        };
        // A signature claim is checked with its key, if this build was given it.
        if let (ClaimKind::RequestSignature(s), false) = (claim, evidence.is_empty())
            && let Some(key) = self.secrets.get(&s.key)
        {
            evidence.push((s.key.clone(), EvidenceKind::Secret, &key[..]));
        }
        evidence
    }
}

/// What a claim's kind is about, without the premises: its type name or endpoint.
fn claim_subject(kind: &ClaimKind) -> &str {
    match kind {
        ClaimKind::MemoryLayout(c) => &c.type_name,
        ClaimKind::RecordArray(c) => &c.type_name,
        ClaimKind::FieldRelation(c) => &c.type_name,
        ClaimKind::TaggedRecords(c) => &c.type_name,
        ClaimKind::StringTable(c) => &c.type_name,
        ClaimKind::Format(c) => &c.type_name,
        ClaimKind::CallEdge(c) => &c.binary,
        ClaimKind::RequestSignature(c) => &c.endpoint,
        ClaimKind::RequestHeader(c) => &c.endpoint,
        ClaimKind::RequestBodySchema(c) => &c.endpoint,
        ClaimKind::ResponseSchema(c) => &c.endpoint,
        ClaimKind::ResponseHeader(c) => &c.endpoint,
        ClaimKind::StatusSet(c) => &c.endpoint,
    }
}

/// The furthest a layout's fields are looked for from where the claim puts them.
const MAX_SHIFT: i64 = 64;
/// The most literal path segments, or host, that may differ for an endpoint to count as moved.
const MAX_SEGMENTS_CHANGED: usize = 2;

/// Whether `kind` is admissible and holds on `evidence`; the number of runs if so.
fn holds(id: &ClaimId, kind: &ClaimKind, evidence: &[Raw<'_>], limit: Duration) -> Option<u64> {
    let claim = Claim {
        kind: kind.clone(),
        premises: BTreeSet::new(),
    };
    admit(claim).ok()?;
    match check_claim(id, kind, evidence, limit) {
        Ok(Verdict::Held { runs }) => Some(runs.get()),
        _ => None,
    }
}

/// A layout that failed may only have had bytes added or removed in the middle: looks
/// for one offset from which every field sits the same distance away, on all snapshots.
/// At least two typed fields must move together, since one alone fits by accident.
fn shifted_layout(
    id: &ClaimId,
    kind: &ClaimKind,
    evidence: &[Raw<'_>],
    limit: Duration,
) -> Option<Outcome> {
    let ClaimKind::MemoryLayout(layout) = kind else {
        return None;
    };
    let mut starts: Vec<u64> = layout.fields.iter().map(|f| f.offset).collect();
    starts.sort_unstable();
    starts.dedup();
    let mut fits = Vec::new();
    for from in starts {
        let typed = |f: &&ledger_core::FieldLayout| f.offset >= from && f.is.is_some();
        if layout.fields.iter().filter(typed).count() < 2 {
            continue;
        }
        for delta in (-MAX_SHIFT..=MAX_SHIFT).filter(|delta| *delta != 0) {
            let mut shifted = layout.clone();
            let moved = (shifted.fields.iter_mut().filter(|f| f.offset >= from))
                .try_for_each(|f| f.offset.checked_add_signed(delta).map(|at| f.offset = at));
            let Some(size) = moved.and_then(|()| shifted.size.checked_add_signed(delta)) else {
                continue;
            };
            shifted.size = size;
            if let Some(runs) = holds(id, &ClaimKind::MemoryLayout(shifted), evidence, limit) {
                fits.push((delta.unsigned_abs(), from, delta, size, runs));
            }
        }
    }
    fits.sort_unstable();
    let (distance, from, delta, size, runs) = *fits.first()?;
    let direction = if delta > 0 { "later" } else { "earlier" };
    let others = match fits.len() - 1 {
        0 => String::new(),
        n => format!("; {n} other shifts also fit"),
    };
    Some(Outcome::Moved {
        to: format!(
            "the fields from +{from:#x} on are {distance} bytes {direction}, and the type is {size} bytes{others}"
        ),
        runs,
    })
}

/// The same web claim under another endpoint.
fn with_endpoint(kind: &ClaimKind, endpoint: String) -> Option<ClaimKind> {
    let mut kind = kind.clone();
    match &mut kind {
        ClaimKind::RequestSignature(c) => c.endpoint = endpoint,
        ClaimKind::RequestHeader(c) => c.endpoint = endpoint,
        ClaimKind::RequestBodySchema(c) => c.endpoint = endpoint,
        ClaimKind::ResponseSchema(c) => c.endpoint = endpoint,
        ClaimKind::ResponseHeader(c) => c.endpoint = endpoint,
        ClaimKind::StatusSet(c) => c.endpoint = endpoint,
        _ => return None,
    }
    Some(kind)
}

/// A web claim with no captures may have had its endpoint renamed: looks for an
/// endpoint in the new build that differs in at most a couple of path segments or
/// the host, and on whose captures the claim holds.
fn moved_endpoint(
    id: &ClaimId,
    kind: &ClaimKind,
    build: &Build,
    limit: Duration,
) -> Option<Outcome> {
    let written = claim_subject(kind);
    let (method, host, path, conditions) = Endpoint::parse(written).ok()?.parts();
    let template: Vec<&str> = path.split('/').collect();
    let mut candidates: BTreeMap<String, usize> = BTreeMap::new();
    for (_, _, exchange) in &build.exchanges {
        let (seen_host, seen_path) = url_host_and_path(&exchange.request.url);
        let seen: Vec<&str> = seen_path.split('/').collect();
        if !exchange.request.method.eq_ignore_ascii_case(method) || seen.len() != template.len() {
            continue;
        }
        // Variable segments stay variable; literal ones take what the new build has.
        let variable = |segment: &str| segment.starts_with('{') && segment.ends_with('}');
        let segments = template.iter().zip(&seen);
        let renamed: Vec<&str> = (segments.clone())
            .map(|(t, s)| if variable(t) { *t } else { *s })
            .collect();
        let host_changed = host.is_some_and(|h| !h.eq_ignore_ascii_case(seen_host));
        let changed =
            segments.filter(|(t, s)| !variable(t) && t != s).count() + usize::from(host_changed);
        if (1..=MAX_SEGMENTS_CHANGED).contains(&changed) {
            let host = host.map_or("", |_| seen_host);
            let query = if conditions.is_empty() {
                String::new()
            } else {
                format!("?{conditions}")
            };
            candidates.insert(
                format!("{method} {host}{}{query}", renamed.join("/")),
                changed,
            );
        }
    }
    let mut fits = Vec::new();
    for (endpoint, changed) in candidates {
        let Some(renamed) = with_endpoint(kind, endpoint.clone()) else {
            continue;
        };
        let evidence = build.evidence_for(&renamed);
        let runs = (!evidence.is_empty()).then(|| holds(id, &renamed, &evidence, limit));
        if let Some(runs) = runs.flatten() {
            fits.push((changed, endpoint, runs));
        }
    }
    fits.sort();
    let (_, endpoint, runs) = fits.first()?.clone();
    let others = match fits.len() - 1 {
        0 => String::new(),
        n => format!("; {n} other endpoints also fit"),
    };
    Some(Outcome::Moved {
        to: format!("it holds for `{endpoint}`{others}"),
        runs,
    })
}

/// What became of one held claim in the new build.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// It holds on this many captures of the new build.
    Holds { runs: u64 },
    /// A capture of the new build contradicts it.
    Failed { detail: String },
    /// It no longer holds as written, or has no captures, but the same claim holds
    /// somewhere near: at shifted offsets or under another endpoint. `to` says where.
    /// This is a suggestion for a new claim; nothing is filed.
    Moved { to: String, runs: u64 },
    /// The new build has no capture the claim is about.
    NoEvidence,
    /// The check could not finish or could not run; the reason says why.
    Unknown { reason: String },
}

/// One held claim and what became of it.
pub struct Row<'l> {
    pub id: &'l ClaimId,
    pub claim: &'l Claim,
    pub outcome: Outcome,
}

/// Re-checks every claim the ledger currently holds against `build`, giving each
/// check `limit`. Claims that are refuted, retracted, unchecked or on hold are
/// left out: the rerun answers what became of what was known.
#[must_use]
pub fn rerun<'l>(ledger: &'l Ledger, build: &Build, limit: Duration) -> Vec<Row<'l>> {
    let held = ledger.claims().zip(ledger.statuses());
    let held = held.filter(|(_, (_, status))| *status == Status::Held);
    held.map(|((id, claim), _)| {
        let evidence = build.evidence_for(&claim.kind);
        let outcome = if evidence.is_empty() {
            moved_endpoint(id, &claim.kind, build, limit).unwrap_or(Outcome::NoEvidence)
        } else {
            match check_claim(id, &claim.kind, &evidence, limit) {
                Ok(Verdict::Held { runs }) => Outcome::Holds { runs: runs.get() },
                Ok(Verdict::Refuted { counterexample }) => {
                    let failed = Outcome::Failed {
                        detail: counterexample.detail,
                    };
                    shifted_layout(id, &claim.kind, &evidence, limit).unwrap_or(failed)
                }
                Ok(Verdict::Inconclusive { reason }) => Outcome::Unknown { reason },
                Err(e) => Outcome::Unknown {
                    reason: e.to_string(),
                },
            }
        };
        Row { id, claim, outcome }
    })
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ledger_core::{
        CoreError, Event, FieldKind, FieldLayout, HttpRequest, HttpResponse, MemoryLayout,
        ResponseSchema,
    };
    use std::num::NonZeroU64;

    fn exchange(url: &str, status: u16, body: &serde_json::Value) -> HttpExchange {
        HttpExchange {
            request: HttpRequest {
                method: "GET".into(),
                url: url.into(),
                headers: vec![],
                body: None,
            },
            response: Some(HttpResponse {
                status,
                headers: vec![],
                body: Some(ledger_core::Body::Text(body.to_string())),
            }),
        }
    }

    /// Files a claim and gives it the status the test needs.
    fn file(ledger: &mut Ledger, kind: ClaimKind, held: bool) -> Result<ClaimId, CoreError> {
        let claim = Claim {
            kind,
            premises: BTreeSet::new(),
        };
        let id = claim.id()?;
        ledger.apply(Event::Proposed {
            claim: admit(claim)?,
        })?;
        if held {
            ledger.apply(Event::Checked {
                claim: id.clone(),
                evidence: BTreeSet::new(),
                verdict: Verdict::Held {
                    runs: NonZeroU64::MIN,
                },
                checker: None,
            })?;
        }
        Ok(id)
    }

    fn schema(endpoint: &str, schema: serde_json::Value) -> ClaimKind {
        ClaimKind::ResponseSchema(ResponseSchema {
            endpoint: endpoint.into(),
            status: 200,
            schema,
        })
    }

    fn header(magic: &str) -> ClaimKind {
        ClaimKind::MemoryLayout(MemoryLayout {
            type_name: "SaveFile".into(),
            size: 8,
            fields: vec![FieldLayout {
                name: "magic".into(),
                offset: 0,
                len: 4,
                is: Some(FieldKind::Bytes(hex::encode(magic))),
            }],
        })
    }

    #[test]
    fn held_claims_are_sorted_into_holds_failed_and_no_evidence() -> Result<(), CoreError> {
        let mut ledger = Ledger::default();
        let profile = file(
            &mut ledger,
            schema(
                "GET /profile/{id}",
                serde_json::json!({"required": ["level"]}),
            ),
            true,
        )?;
        let score = file(
            &mut ledger,
            schema("GET /score", serde_json::json!({"required": ["rank"]})),
            true,
        )?;
        let shop = file(
            &mut ledger,
            schema("GET /shop", serde_json::json!({"required": ["items"]})),
            true,
        )?;
        let save = file(&mut ledger, header("JSAV"), true)?;
        let unchecked = file(&mut ledger, header("NOPE"), false)?;

        let mut build = Build::default();
        build.add_exchanges([
            exchange(
                "https://game.example/profile/7",
                200,
                &serde_json::json!({"level": 3}),
            ),
            exchange(
                "https://game.example/profile/8",
                200,
                &serde_json::json!({"level": 9}),
            ),
            exchange(
                "https://game.example/profile/9",
                404,
                &serde_json::json!({"error": "gone"}),
            ),
            exchange(
                "https://game.example/score",
                200,
                &serde_json::json!({"position": 4}),
            ),
            exchange(
                "https://game.example/assets/app.js",
                200,
                &serde_json::json!({}),
            ),
        ]);
        build.add_snapshot("SaveFile", b"JSAVq\0\0\0".to_vec());
        build.add_snapshot("Other", b"zzzzzzzz".to_vec());

        let rows = rerun(&ledger, &build, Duration::from_secs(5));
        let outcome = |id: &ClaimId| {
            rows.iter()
                .find(|row| row.id == id)
                .map(|row| row.outcome.clone())
        };
        // The 404 and the script are not about the profile claim, so two captures count.
        assert_eq!(outcome(&profile), Some(Outcome::Holds { runs: 2 }));
        assert!(
            matches!(outcome(&score), Some(Outcome::Failed { detail }) if detail.contains("rank"))
        );
        assert_eq!(outcome(&shop), Some(Outcome::NoEvidence));
        assert_eq!(outcome(&save), Some(Outcome::Holds { runs: 1 }));
        assert_eq!(outcome(&unchecked), None, "only held claims are rerun");
        Ok(())
    }

    /// A record with a magic, a version and a level, as it is laid out in one build.
    fn record(pad: usize, level: u32) -> Vec<u8> {
        let mut bytes = b"SAVE".to_vec();
        bytes.extend(vec![0u8; pad]);
        bytes.extend(7u32.to_le_bytes());
        bytes.extend(level.to_le_bytes());
        bytes
    }

    fn record_layout(typed_after_magic: usize) -> ClaimKind {
        let field = |name: &str, offset, is| FieldLayout {
            name: name.into(),
            offset,
            len: 4,
            is,
        };
        let version = Some(FieldKind::Uint { min: 7, max: 7 });
        let level = Some(FieldKind::Uint { min: 1, max: 99 });
        ClaimKind::MemoryLayout(MemoryLayout {
            type_name: "Record".into(),
            size: 12,
            fields: vec![
                field("magic", 0, Some(FieldKind::Bytes(hex::encode("SAVE")))),
                field("version", 4, version),
                field(
                    "level",
                    8,
                    if typed_after_magic == 2 { level } else { None },
                ),
            ],
        })
    }

    #[test]
    fn a_layout_with_bytes_inserted_is_reported_as_moved() -> Result<(), CoreError> {
        let mut ledger = Ledger::default();
        let both = file(&mut ledger, record_layout(2), true)?;
        let one = file(&mut ledger, record_layout(1), true)?;
        // The new build puts 8 bytes between the magic and the version.
        let mut build = Build::default();
        build.add_snapshot("Record", record(8, 12));
        build.add_snapshot("Record", record(8, 40));
        let rows = rerun(&ledger, &build, Duration::from_secs(5));
        let outcome = |id: &ClaimId| {
            rows.iter()
                .find(|row| row.id == id)
                .map(|row| row.outcome.clone())
        };
        assert_eq!(
            outcome(&both),
            Some(Outcome::Moved {
                to: "the fields from +0x4 on are 8 bytes later, and the type is 20 bytes".into(),
                runs: 2,
            })
        );
        // With a single typed field after the gap, a shift would fit by accident: it stays failed.
        assert!(matches!(outcome(&one), Some(Outcome::Failed { .. })));
        Ok(())
    }

    #[test]
    fn a_renamed_endpoint_is_reported_as_moved() -> Result<(), CoreError> {
        let mut ledger = Ledger::default();
        let ranked = serde_json::json!({"required": ["rank"]});
        let stocked = serde_json::json!({"required": ["items"]});
        let score = file(
            &mut ledger,
            schema("GET game.example/api/v1/score/{player}", ranked),
            true,
        )?;
        let shop = file(
            &mut ledger,
            schema("GET game.example/api/v1/shop", stocked),
            true,
        )?;
        let mut build = Build::default();
        build.add_exchanges([
            exchange(
                "https://game.example/api/v2/score/7",
                200,
                &serde_json::json!({"rank": 3}),
            ),
            exchange(
                "https://game.example/api/v2/score/8",
                200,
                &serde_json::json!({"rank": 9}),
            ),
            exchange(
                "https://game.example/api/v2/news/8",
                200,
                &serde_json::json!({"title": "patch"}),
            ),
        ]);
        let rows = rerun(&ledger, &build, Duration::from_secs(5));
        let outcome = |id: &ClaimId| {
            rows.iter()
                .find(|row| row.id == id)
                .map(|row| row.outcome.clone())
        };
        assert_eq!(
            outcome(&score),
            Some(Outcome::Moved {
                to: "it holds for `GET game.example/api/v2/score/{player}`".into(),
                runs: 2,
            })
        );
        // Nothing in the new build looks like the shop, so there is nothing to suggest.
        assert_eq!(outcome(&shop), Some(Outcome::NoEvidence));
        Ok(())
    }
}
