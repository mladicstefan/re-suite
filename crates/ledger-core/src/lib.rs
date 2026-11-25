//! Pure, synchronous core of the replay ledger: claims, admission, events,
//! verdicts and derived status. No IO, no async, no clocks.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::num::NonZeroU64;
use std::ops::Bound;

use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("claim rejected: {0}")]
    Inadmissible(String),
    #[error("unknown claim {0}")]
    UnknownClaim(ClaimId),
    #[error("unknown evidence {0}")]
    UnknownEvidence(EvidenceId),
    #[error("duplicate claim {0}")]
    DuplicateClaim(ClaimId),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

macro_rules! hash_id {
    ($name:ident, $domain:literal) => {
        /// blake3 hash of canonical content, hex encoded.
        #[derive(
            Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
        )]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            #[must_use]
            pub fn of(content: &[u8]) -> Self {
                let mut h = blake3::Hasher::new();
                h.update($domain);
                h.update(content);
                Self(hex::encode(h.finalize().as_bytes()))
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        // Lets maps keyed by this id be searched by a plain string, for short ids.
        impl std::borrow::Borrow<str> for $name {
            fn borrow(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

hash_id!(ClaimId, b"ledger.claim.v1\0");
hash_id!(EvidenceId, b"ledger.evidence.v1\0");

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
pub struct FieldLayout {
    pub name: String,
    pub offset: u64,
    pub len: u64,
}

/// A struct's in-memory layout.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct MemoryLayout {
    pub type_name: String,
    pub size: u64,
    pub fields: Vec<FieldLayout>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SigAlgorithm {
    HmacSha256,
    HmacSha1,
    /// md5(key || body), common in game and mobile APIs.
    KeyedMd5,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SigEncoding {
    Hex,
    Base64,
}

/// A request header carries a signature over the request body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RequestSignature {
    pub endpoint: String,
    pub header: String,
    pub algorithm: SigAlgorithm,
    pub encoding: SigEncoding,
    pub key_hex: String,
}

/// Responses from an endpoint conform to a JSON Schema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ResponseSchema {
    pub endpoint: String,
    pub schema: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ClaimKind {
    MemoryLayout(MemoryLayout),
    RequestSignature(RequestSignature),
    ResponseSchema(ResponseSchema),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Claim {
    #[serde(flatten)]
    pub kind: ClaimKind,
    /// Claims this one depends on; it only holds if they hold.
    #[serde(default)]
    pub premises: BTreeSet<ClaimId>,
}

impl Claim {
    /// Hash of the canonical JSON form (sorted maps, declaration-order fields).
    ///
    /// # Errors
    /// Fails only if serialization fails.
    pub fn id(&self) -> Result<ClaimId, CoreError> {
        Ok(ClaimId::of(&serde_json::to_vec(self)?))
    }

    /// What the claim is about: a type name or an endpoint.
    #[must_use]
    pub fn subject(&self) -> &str {
        match &self.kind {
            ClaimKind::MemoryLayout(m) => &m.type_name,
            ClaimKind::RequestSignature(s) => &s.endpoint,
            ClaimKind::ResponseSchema(r) => &r.endpoint,
        }
    }

    /// Plain sentence shown to the human.
    #[must_use]
    pub fn sentence(&self) -> String {
        match &self.kind {
            ClaimKind::MemoryLayout(m) => format!(
                "`{}` is {} bytes with {} fields ({}).",
                m.type_name,
                m.size,
                m.fields.len(),
                m.fields
                    .iter()
                    .map(|f| format!("{} at +{:#x}", f.name, f.offset))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            ClaimKind::RequestSignature(s) => format!(
                "Requests to {} carry a {:?} signature of the body in header `{}`, {:?} encoded.",
                s.endpoint, s.algorithm, s.header, s.encoding
            ),
            ClaimKind::ResponseSchema(r) => {
                format!(
                    "Responses from {} match the recorded JSON Schema.",
                    r.endpoint
                )
            }
        }
    }
}

/// A value that passed admission. Only `admit` constructs one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct WellFormed<T>(T);

impl<T> WellFormed<T> {
    pub fn get(&self) -> &T {
        &self.0
    }
}

impl<'de> Deserialize<'de> for WellFormed<Claim> {
    // Replayed events are re-admitted, so stored data never bypasses `admit`.
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        admit(Claim::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}

/// Structural checks that do not need evidence.
///
/// # Errors
/// `CoreError::Inadmissible` with the reason.
pub fn admit(claim: Claim) -> Result<WellFormed<Claim>, CoreError> {
    let bad = |m: &str| Err(CoreError::Inadmissible(m.to_owned()));
    match &claim.kind {
        ClaimKind::MemoryLayout(m) => {
            if m.type_name.is_empty() || m.size == 0 {
                return bad("memory layout needs a type name and non-zero size");
            }
            let mut fields = m.fields.clone();
            fields.sort();
            let mut end = 0;
            for f in &fields {
                if f.len == 0 || f.offset < end || f.offset.saturating_add(f.len) > m.size {
                    return bad(&format!(
                        "field `{}` is empty, overlaps, or exceeds size",
                        f.name
                    ));
                }
                end = f.offset + f.len;
            }
        }
        ClaimKind::RequestSignature(s) => {
            if s.endpoint.is_empty() || s.header.is_empty() || hex::decode(&s.key_hex).is_err() {
                return bad("signature needs endpoint, header and a hex key");
            }
        }
        ClaimKind::ResponseSchema(r) => {
            if r.endpoint.is_empty() || !(r.schema.is_object() || r.schema.is_boolean()) {
                return bad("response schema needs endpoint and an object or boolean schema");
            }
        }
    }
    Ok(WellFormed(claim))
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    MemorySnapshot,
    CapturedRequest,
    CapturedExchange,
}

/// Evidence format for `EvidenceKind::CapturedRequest`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CapturedRequest {
    pub headers: BTreeMap<String, String>,
    // shortcut: text bodies only, add a base64 variant when binary bodies show up.
    pub body: String,
}

/// Evidence format for `EvidenceKind::CapturedExchange`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CapturedExchange {
    pub response: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Counterexample {
    pub evidence: EvidenceId,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum Verdict {
    Held { runs: NonZeroU64 },
    Refuted { counterexample: Counterexample },
    Inconclusive { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    Proposed {
        claim: WellFormed<Claim>,
    },
    EvidenceAdded {
        id: EvidenceId,
        kind: EvidenceKind,
    },
    Checked {
        claim: ClaimId,
        evidence: BTreeSet<EvidenceId>,
        verdict: Verdict,
    },
    Retracted {
        claim: ClaimId,
        reason: String,
    },
}

impl Event {
    /// # Errors
    /// Fails only if serialization fails.
    pub fn encode(&self) -> Result<String, CoreError> {
        Ok(serde_json::to_string(self)?)
    }

    /// # Errors
    /// Malformed JSON or a claim that fails admission.
    pub fn decode(s: &str) -> Result<Self, CoreError> {
        Ok(serde_json::from_str(s)?)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Unchecked,
    Held,
    Refuted,
    Inconclusive,
    /// Its own checks hold or are pending, but a premise does not hold.
    Blocked,
    Retracted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Entry {
    id: ClaimId,
    claim: Claim,
    /// Positions of the premises in `Ledger::entries`, each smaller than this entry's own.
    premises: Vec<usize>,
    verdicts: Vec<Verdict>,
    retracted: bool,
}

impl Entry {
    /// This claim's status, given the statuses of its premises.
    fn status(&self, premise: impl Fn(usize) -> Status) -> Status {
        let any = |f: fn(&Verdict) -> bool| self.verdicts.iter().any(f);
        if self.retracted {
            Status::Retracted
        } else if any(|v| matches!(v, Verdict::Refuted { .. })) {
            Status::Refuted
        } else if self.premises.iter().any(|&p| premise(p) != Status::Held) {
            Status::Blocked
        } else if any(|v| matches!(v, Verdict::Held { .. })) {
            Status::Held
        } else if self.verdicts.is_empty() {
            Status::Unchecked
        } else {
            Status::Inconclusive
        }
    }
}

/// State rebuilt by folding events. Status is never stored, only derived.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Ledger {
    index: BTreeMap<ClaimId, usize>,
    /// Proposal order. A premise is always proposed before its dependents
    /// (content-addressed), so this is also a dependency order.
    entries: Vec<Entry>,
    evidence: BTreeMap<EvidenceId, EvidenceKind>,
}

impl Ledger {
    /// Validates the event against current state, then applies it. On error the ledger is unchanged.
    ///
    /// # Errors
    /// Unknown claim/evidence references or a duplicate proposal.
    pub fn apply(&mut self, event: Event) -> Result<(), CoreError> {
        match event {
            Event::Proposed { claim } => {
                let claim = claim.0;
                let id = claim.id()?;
                if self.index.contains_key(&id) {
                    return Err(CoreError::DuplicateClaim(id));
                }
                let premises = (claim.premises.iter())
                    .map(|p| self.position(p))
                    .collect::<Result<_, _>>()?;
                self.index.insert(id.clone(), self.entries.len());
                self.entries.push(Entry {
                    id,
                    claim,
                    premises,
                    verdicts: Vec::new(),
                    retracted: false,
                });
            }
            Event::EvidenceAdded { id, kind } => {
                self.evidence.insert(id, kind);
            }
            Event::Checked {
                claim,
                evidence,
                verdict,
            } => {
                let at = self.position(&claim)?;
                if let Some(e) = evidence.iter().find(|e| !self.evidence.contains_key(*e)) {
                    return Err(CoreError::UnknownEvidence(e.clone()));
                }
                self.entries[at].verdicts.push(verdict);
            }
            Event::Retracted { claim, .. } => {
                let at = self.position(&claim)?;
                self.entries[at].retracted = true;
            }
        }
        Ok(())
    }

    fn position(&self, id: &ClaimId) -> Result<usize, CoreError> {
        (self.index.get(id).copied()).ok_or_else(|| CoreError::UnknownClaim(id.clone()))
    }

    fn entry(&self, id: &ClaimId) -> Option<&Entry> {
        self.index.get(id).map(|&at| &self.entries[at])
    }

    /// Claims in the order they were proposed.
    pub fn claims(&self) -> impl Iterator<Item = (&ClaimId, &Claim)> {
        self.entries.iter().map(|e| (&e.id, &e.claim))
    }

    #[must_use]
    pub fn claim(&self, id: &ClaimId) -> Option<&Claim> {
        self.entry(id).map(|e| &e.claim)
    }

    #[must_use]
    pub fn verdicts(&self, id: &ClaimId) -> &[Verdict] {
        self.entry(id).map_or(&[], |e| &e.verdicts)
    }

    #[must_use]
    pub fn evidence_kind(&self, id: &EvidenceId) -> Option<EvidenceKind> {
        self.evidence.get(id).copied()
    }

    /// Claim ids that start with `prefix`, in id order, so callers can accept short ids.
    pub fn claims_starting<'a>(&'a self, prefix: &'a str) -> impl Iterator<Item = &'a ClaimId> {
        let from = (Bound::Included(prefix), Bound::Unbounded);
        let ids = self.index.range::<str, _>(from).map(|(id, _)| id);
        ids.take_while(move |id| id.as_str().starts_with(prefix))
    }

    /// Evidence ids that start with `prefix`, in id order.
    pub fn evidence_starting<'a>(
        &'a self,
        prefix: &'a str,
    ) -> impl Iterator<Item = &'a EvidenceId> {
        let from = (Bound::Included(prefix), Bound::Unbounded);
        let ids = self.evidence.range::<str, _>(from).map(|(id, _)| id);
        ids.take_while(move |id| id.as_str().starts_with(prefix))
    }

    /// Claims that rest on `id`, directly or through other claims, in proposal order.
    /// These are the claims put on hold if `id` stops holding.
    #[must_use]
    pub fn dependents(&self, id: &ClaimId) -> Vec<&ClaimId> {
        let Some(&root) = self.index.get(id) else {
            return Vec::new();
        };
        let mut affected = vec![false; self.entries.len()];
        affected[root] = true;
        let mut dependents = Vec::new();
        for (at, entry) in self.entries.iter().enumerate().skip(root + 1) {
            if entry.premises.iter().any(|&p| affected[p]) {
                affected[at] = true;
                dependents.push(&entry.id);
            }
        }
        dependents
    }

    /// Derived from verdicts and premises. Settles the claim's premise closure
    /// once each, in dependency order, so shared premises cost nothing extra.
    #[must_use]
    pub fn status(&self, id: &ClaimId) -> Option<Status> {
        let target = *self.index.get(id)?;
        let mut closure = BTreeSet::from([target]);
        let mut todo = vec![target];
        while let Some(at) = todo.pop() {
            for &p in &self.entries[at].premises {
                if closure.insert(p) {
                    todo.push(p);
                }
            }
        }
        // Ascending position: every premise is settled before the claims that rest on it.
        let mut settled = BTreeMap::new();
        for at in closure {
            let status = self.entries[at].status(|p| settled[&p]);
            settled.insert(at, status);
        }
        settled.get(&target).copied()
    }

    /// Every claim's status, in one pass in proposal order.
    pub fn statuses(&self) -> impl Iterator<Item = (&ClaimId, Status)> {
        let mut settled: Vec<Status> = Vec::with_capacity(self.entries.len());
        for entry in &self.entries {
            let status = entry.status(|p| settled[p]);
            settled.push(status);
        }
        self.entries.iter().map(|e| &e.id).zip(settled)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use proptest::prelude::*;

    fn layout(size: u64) -> Claim {
        Claim {
            kind: ClaimKind::MemoryLayout(MemoryLayout {
                type_name: "Player".into(),
                size,
                fields: vec![
                    FieldLayout {
                        name: "hp".into(),
                        offset: 0,
                        len: 4,
                    },
                    FieldLayout {
                        name: "pos".into(),
                        offset: 8,
                        len: 12,
                    },
                ],
            }),
            premises: BTreeSet::new(),
        }
    }

    fn signature() -> Claim {
        Claim {
            kind: ClaimKind::RequestSignature(RequestSignature {
                endpoint: "/api/v2/score".into(),
                header: "X-Sig".into(),
                algorithm: SigAlgorithm::HmacSha256,
                encoding: SigEncoding::Hex,
                key_hex: "00ff".into(),
            }),
            premises: BTreeSet::new(),
        }
    }

    fn schema() -> Claim {
        Claim {
            kind: ClaimKind::ResponseSchema(ResponseSchema {
                endpoint: "/api/v2/profile".into(),
                schema: serde_json::json!({"type": "object"}),
            }),
            premises: BTreeSet::new(),
        }
    }

    #[test]
    fn admit_rejects_overlapping_fields() {
        let mut c = layout(32);
        if let ClaimKind::MemoryLayout(m) = &mut c.kind {
            m.fields.push(FieldLayout {
                name: "bad".into(),
                offset: 2,
                len: 4,
            });
        }
        assert!(admit(c).is_err());
        assert!(admit(layout(16)).is_err(), "pos exceeds size");
    }

    #[test]
    fn status_follows_verdicts_and_premises() -> Result<(), CoreError> {
        let mut l = Ledger::default();
        let base = layout(32);
        let base_id = base.id()?;
        l.apply(Event::Proposed {
            claim: admit(base)?,
        })?;
        let mut dep = signature();
        dep.premises.insert(base_id.clone());
        let dep_id = dep.id()?;
        l.apply(Event::Proposed { claim: admit(dep)? })?;
        assert_eq!(l.status(&dep_id), Some(Status::Blocked));

        let ev = EvidenceId::of(b"snapshot");
        l.apply(Event::EvidenceAdded {
            id: ev.clone(),
            kind: EvidenceKind::MemorySnapshot,
        })?;
        let held = Verdict::Held {
            runs: NonZeroU64::MIN,
        };
        l.apply(Event::Checked {
            claim: base_id.clone(),
            evidence: [ev].into(),
            verdict: held,
        })?;
        assert_eq!(l.status(&base_id), Some(Status::Held));
        assert_eq!(l.status(&dep_id), Some(Status::Unchecked));

        l.apply(Event::Retracted {
            claim: base_id,
            reason: "wrong build".into(),
        })?;
        assert_eq!(l.status(&dep_id), Some(Status::Blocked));
        Ok(())
    }

    #[test]
    fn replayed_events_are_readmitted() {
        let bad = r#"{"event":"proposed","claim":{"kind":"memory_layout","type_name":"","size":0,"fields":[]}}"#;
        assert!(Event::decode(bad).is_err());
    }

    #[test]
    fn sentences() {
        insta::assert_snapshot!("memory_layout", layout(32).sentence());
        insta::assert_snapshot!("request_signature", signature().sentence());
        insta::assert_snapshot!("response_schema", schema().sentence());
    }

    /// The definition of status, as plain recursion. Exponential on shared premises.
    fn status_by_recursion(l: &Ledger, id: &ClaimId) -> Status {
        let entry = &l.entries[l.index[id]];
        entry.status(|p| status_by_recursion(l, &l.entries[p].id))
    }

    /// Claim `n` rests on the claims named in `premises` (earlier ones only).
    fn numbered(n: u64, premises: &[ClaimId]) -> Claim {
        let mut c = layout(32 + n);
        c.premises = premises.iter().cloned().collect();
        c
    }

    #[test]
    fn shared_premises_are_settled_once() -> Result<(), CoreError> {
        // Each claim rests on the two before it: plain recursion would take about 2^140 steps.
        let mut l = Ledger::default();
        let mut ids: Vec<ClaimId> = Vec::new();
        for n in 0..200 {
            let c = numbered(n, &ids[ids.len().saturating_sub(2)..]);
            ids.push(c.id()?);
            l.apply(Event::Proposed { claim: admit(c)? })?;
            l.apply(Event::Checked {
                claim: ids[ids.len() - 1].clone(),
                evidence: BTreeSet::new(),
                verdict: Verdict::Held {
                    runs: NonZeroU64::MIN,
                },
            })?;
        }
        assert_eq!(l.status(&ids[199]), Some(Status::Held));
        assert_eq!(l.dependents(&ids[0]).len(), 199);
        assert_eq!(l.dependents(&ids[198]), [&ids[199]]);
        let short = &ids[7].as_str()[..12];
        assert_eq!(l.claims_starting(short).collect::<Vec<_>>(), [&ids[7]]);
        assert_eq!(l.claims_starting("").count(), 200);
        assert_eq!(l.claims_starting("not hex").count(), 0);
        l.apply(Event::Retracted {
            claim: ids[0].clone(),
            reason: String::new(),
        })?;
        assert_eq!(l.status(&ids[199]), Some(Status::Blocked));
        assert!(l.statuses().skip(1).all(|(_, s)| s == Status::Blocked));
        Ok(())
    }

    proptest! {
        #[test]
        fn status_agrees_with_plain_recursion(
            // Per claim: which earlier claims it rests on, and what happens to it (0 = nothing).
            shape in proptest::collection::vec((proptest::collection::vec(any::<prop::sample::Index>(), 0..3), 0..5u8), 1..12),
        ) {
            let mut l = Ledger::default();
            let mut ids: Vec<ClaimId> = Vec::new();
            for (n, (premises, fate)) in shape.iter().enumerate() {
                let premises: Vec<ClaimId> = if ids.is_empty() {
                    Vec::new()
                } else {
                    premises.iter().map(|i| i.get(&ids).clone()).collect()
                };
                let c = numbered(n as u64, &premises);
                let id = c.id()?;
                ids.push(id.clone());
                l.apply(Event::Proposed { claim: admit(c)? })?;
                let verdict = match fate {
                    1 => Some(Verdict::Held { runs: NonZeroU64::MIN }),
                    2 => Some(Verdict::Inconclusive { reason: String::new() }),
                    3 => Some(Verdict::Refuted {
                        counterexample: Counterexample { evidence: EvidenceId::of(b"e"), detail: String::new() },
                    }),
                    _ => None,
                };
                if let Some(verdict) = verdict {
                    l.apply(Event::Checked { claim: id.clone(), evidence: BTreeSet::new(), verdict })?;
                }
                if *fate == 4 {
                    l.apply(Event::Retracted { claim: id, reason: String::new() })?;
                }
            }
            for (id, status) in l.statuses() {
                prop_assert_eq!(status, status_by_recursion(&l, id));
                prop_assert_eq!(l.status(id), Some(status));
            }
        }

        #[test]
        fn id_is_stable_across_roundtrip(size in 20u64..1 << 20) {
            let c = layout(size);
            let back: Claim = serde_json::from_str(&serde_json::to_string(&c)?)?;
            prop_assert_eq!(c.id()?, back.id()?);
        }
    }
}
