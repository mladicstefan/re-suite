//! Re-checks what a ledger holds against the captures of a new build of the target.
//!
//! Read-only: it reports what still holds and records nothing, so a new build can
//! never change a claim's status behind anyone's back. A web claim is tied to its
//! endpoint and a claim about snapshots to its type name; that is how the captures
//! of the new build are matched to it.

use std::collections::BTreeMap;
use std::time::Duration;

use ledger_core::{
    Claim, ClaimId, ClaimKind, EvidenceId, EvidenceKind, HttpExchange, Ledger, Status, Verdict,
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
            | ClaimKind::StringTable(_) => {
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
        ClaimKind::RequestSignature(c) => &c.endpoint,
        ClaimKind::RequestHeader(c) => &c.endpoint,
        ClaimKind::RequestBodySchema(c) => &c.endpoint,
        ClaimKind::ResponseSchema(c) => &c.endpoint,
        ClaimKind::StatusSet(c) => &c.endpoint,
    }
}

/// What became of one held claim in the new build.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// It holds on this many captures of the new build.
    Holds { runs: u64 },
    /// A capture of the new build contradicts it.
    Failed { detail: String },
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
            Outcome::NoEvidence
        } else {
            match check_claim(id, &claim.kind, &evidence, limit) {
                Ok(Verdict::Held { runs }) => Outcome::Holds { runs: runs.get() },
                Ok(Verdict::Refuted { counterexample }) => Outcome::Failed {
                    detail: counterexample.detail,
                },
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
        ResponseSchema, admit,
    };
    use std::collections::BTreeSet;
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
}
