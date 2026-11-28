//! Offline checkers. Each replays one claim kind over saved evidence; none touches a live target.

pub mod format;
pub mod rerun;

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU64;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use base64::Engine as _;
use hmac::{Hmac, KeyInit, Mac};
use ledger_core::{
    BinaryFacts, Body, CheckerRef, ClaimId, ClaimKind, Counterexample, Endpoint, EvidenceId,
    EvidenceKind, FieldKind, Function, FunctionRef, HttpExchange, HttpRequest, MemoryLayout,
    RequestSignature, ResponseSchema, SigAlgorithm, SigEncoding, SignedPart, Verdict,
};
use md5::Digest as _;
use rayon::prelude::*;

#[derive(Debug, thiserror::Error)]
pub enum CheckError {
    #[error("{0:?} evidence cannot check this claim kind")]
    WrongEvidence(EvidenceKind),
    #[error("malformed evidence {0}: {1}")]
    Malformed(EvidenceId, String),
    #[error("the claim's key {0} was not given as secret evidence")]
    MissingKey(EvidenceId),
    #[error("evidence {0} is {1}, which the claim says nothing about")]
    NotApplicable(EvidenceId, String),
    #[error("evidence {0} is {1} bytes, over the {2} byte limit for its format")]
    TooLarge(EvidenceId, usize, usize),
    #[error("invalid claim: {0}")]
    InvalidClaim(String),
}

/// A saved piece of evidence, decoded to the checker's type.
pub struct Item<E> {
    pub id: EvidenceId,
    /// Size of the stored evidence in bytes: the smallest capture that disagrees is the one shown.
    pub size: usize,
    pub data: E,
}

/// Parsed evidence formats (JSON) are refused above this size. Snapshots are only sliced, never parsed.
pub const MAX_PARSED_EVIDENCE: usize = 16 << 20;

/// Longest counterexample detail, in characters. Details are stored in the event log
/// and shown to agents, so they must not grow with the evidence.
pub const MAX_DETAIL: usize = 300;

/// A check is a pure function of the claim, the evidence and the checker's
/// version; only whether it finishes before `deadline` depends on the clock.
pub trait Checker<'e> {
    /// Stable name, used in trace spans and as part of a check's cache key.
    const ID: &'static str;
    /// Bumped whenever the checker could answer differently; old verdicts are then re-run.
    const VERSION: u32;
    type Claim;
    type Evidence: Sync;

    /// # Errors
    /// The claim cannot be checked at all (as opposed to being refuted).
    fn check(
        &self,
        claim: &Self::Claim,
        evidence: &[Item<Self::Evidence>],
        deadline: Instant,
    ) -> Result<Verdict, CheckError>;
}

/// Runs `one` over every item in parallel; the first failure (in evidence order) is the
/// counterexample. Items reached after `deadline` are skipped, and the verdict is then
/// inconclusive at best, never held.
fn replay<E: Sync>(
    evidence: &[Item<E>],
    deadline: Instant,
    one: impl Fn(&E) -> Result<(), String> + Sync,
) -> Verdict {
    let Some(runs) = NonZeroU64::new(evidence.len() as u64) else {
        return Verdict::Inconclusive {
            reason: "no evidence".into(),
        };
    };
    let late = AtomicBool::new(false);
    // Every capture is replayed, not just up to the first failure: the reader gets the
    // smallest one that disagrees, and is told how many do.
    let failures: Vec<(usize, usize, String)> = (evidence.par_iter().enumerate())
        .filter_map(|(at, it)| {
            if Instant::now() >= deadline {
                late.store(true, Ordering::Relaxed);
                return None;
            }
            one(&it.data).err().map(|detail| (it.size, at, detail))
        })
        .collect();
    let disagree = failures.len();
    match failures.into_iter().min() {
        Some((_, at, mut detail)) => {
            // A validator can quote a whole response; a counterexample stays a sentence.
            if let Some((cut, _)) = detail.char_indices().nth(MAX_DETAIL) {
                detail.truncate(cut);
                detail.push('…');
            }
            if disagree > 1 {
                detail = format!(
                    "{detail} ({disagree} of {runs} captures disagree; this is the smallest)"
                );
            }
            Verdict::Refuted {
                counterexample: Counterexample {
                    evidence: evidence[at].id.clone(),
                    detail,
                },
            }
        }
        None if late.load(Ordering::Relaxed) => Verdict::Inconclusive {
            reason: "time limit reached before all evidence was replayed".into(),
        },
        None => Verdict::Held { runs },
    }
}

/// A snapshot and, when it was captured from a running process, what a human saw then.
pub struct Snapshot<'e> {
    pub bytes: &'e [u8],
    pub observed: BTreeMap<String, ledger_core::Observed>,
}

pub struct MemoryLayoutChecker;

impl<'e> Checker<'e> for MemoryLayoutChecker {
    const ID: &'static str = "memory_layout";
    const VERSION: u32 = 4;
    type Claim = MemoryLayout;
    type Evidence = Snapshot<'e>;

    fn check(
        &self,
        claim: &MemoryLayout,
        evidence: &[Item<Snapshot<'e>>],
        deadline: Instant,
    ) -> Result<Verdict, CheckError> {
        Ok(replay(evidence, deadline, |snapshot| {
            let bytes = snapshot.bytes;
            if (bytes.len() as u64) < claim.size {
                return Err(format!(
                    "snapshot is {} bytes, `{}` needs {}",
                    bytes.len(),
                    claim.type_name,
                    claim.size
                ));
            }
            fields_hold(&claim.fields, bytes)?;
            seen_holds(&claim.fields, snapshot)
        }))
    }
}

/// `len` bytes at `offset`, if they are all there.
fn slice(bytes: &[u8], offset: u64, len: u64) -> Option<&[u8]> {
    let at = usize::try_from(offset).ok()?;
    bytes.get(at..at.checked_add(usize::try_from(len).ok()?)?)
}

/// Whether every typed field holds in `bytes`, which start where the fields' offsets do.
fn fields_hold(fields: &[ledger_core::FieldLayout], bytes: &[u8]) -> Result<(), String> {
    for field in fields {
        let Some(kind) = &field.is else { continue };
        // The claim may not have been through admission, so nothing is assumed to fit.
        let found = slice(bytes, field.offset, field.len)
            .ok_or_else(|| format!("field `{}` lies outside the snapshot", field.name))?;
        field_holds(kind, found)
            .map_err(|why| format!("field `{}` at +{:#x} {why}", field.name, field.offset))?;
    }
    Ok(())
}

pub struct RecordArrayChecker;

impl<'e> Checker<'e> for RecordArrayChecker {
    const ID: &'static str = "record_array";
    const VERSION: u32 = 1;
    type Claim = ledger_core::RecordArray;
    type Evidence = &'e [u8];

    fn check(
        &self,
        claim: &Self::Claim,
        evidence: &[Item<&'e [u8]>],
        deadline: Instant,
    ) -> Result<Verdict, CheckError> {
        Ok(replay(evidence, deadline, |bytes| {
            let count = slice(bytes, claim.count_offset, claim.count_len)
                .map(uint)
                .ok_or("the count lies outside the snapshot")?;
            let len = bytes.len() as u64;
            // The records must fit before any of them is read, so a wild count costs nothing.
            let end = (count.checked_mul(claim.stride))
                .and_then(|records| records.checked_add(claim.first))
                .filter(|end| *end <= len)
                .ok_or_else(|| {
                    format!(
                        "the count is {count}, which needs more than the snapshot's {len} bytes"
                    )
                })?;
            if claim.exact && end != len {
                return Err(format!(
                    "the count is {count}, so the records end at +{end:#x}, but {} more bytes follow",
                    len - end
                ));
            }
            for index in 0..count {
                let record = slice(bytes, claim.first + index * claim.stride, claim.stride)
                    .ok_or("a record lies outside the snapshot")?;
                fields_hold(&claim.fields, record)
                    .map_err(|why| format!("record {index}: {why}"))?;
            }
            Ok(())
        }))
    }
}

/// Little-endian unsigned value of up to 8 bytes.
/// Whether each field named like something the human saw reads as what they saw.
/// A layout that gives no field that name says nothing about the value.
#[expect(
    clippy::cast_precision_loss,
    reason = "what a human reads off a screen is far below 2^53"
)]
fn seen_holds(fields: &[ledger_core::FieldLayout], snapshot: &Snapshot<'_>) -> Result<(), String> {
    for (name, seen) in &snapshot.observed {
        let Some(field) = fields.iter().find(|f| f.name == *name) else {
            continue;
        };
        let found = slice(snapshot.bytes, field.offset, field.len)
            .ok_or_else(|| format!("field `{name}` lies outside the snapshot"))?;
        let value = match (&field.is, found.len()) {
            (Some(FieldKind::Float { .. }), 4) => {
                f64::from(f32::from_bits(u32::try_from(uint(found)).unwrap_or(0)))
            }
            (Some(FieldKind::Float { .. }), 8) => f64::from_bits(uint(found)),
            (Some(FieldKind::Int { .. }), 1 | 2 | 4 | 8) => int(found) as f64,
            (_, 1 | 2 | 4 | 8) => uint(found) as f64,
            (_, len) => {
                return Err(format!(
                    "field `{name}` is {len} bytes, which reads as no number; {seen} was seen when the capture was taken"
                ));
            }
        };
        if !(seen.min..=seen.max).contains(&value) {
            return Err(format!(
                "field `{name}` at +{:#x} reads {value}, but {seen} was seen when the capture was taken",
                field.offset
            ));
        }
    }
    Ok(())
}

/// A little-endian signed integer of 1, 2, 4 or 8 bytes.
fn int(bytes: &[u8]) -> i64 {
    // Shift the field's top bit up to bit 63 and back down to extend its sign.
    let shift = 64 - 8 * u32::try_from(bytes.len()).unwrap_or(8);
    i64::from_le_bytes((uint(bytes) << shift).to_le_bytes()) >> shift
}

fn uint(bytes: &[u8]) -> u64 {
    (bytes.iter().rev()).fold(0, |value, byte| value << 8 | u64::from(*byte))
}

/// Whether a field's bytes satisfy what the claim says they are. The error
/// finishes the sentence "field `x` at +0x4 ...".
fn field_holds(kind: &FieldKind, bytes: &[u8]) -> Result<(), String> {
    let sized = |ok: bool| {
        let sizes = "is not 1, 2, 4 or 8 bytes long";
        ok.then_some(()).ok_or_else(|| sizes.to_owned())
    };
    let hex = hex::encode(bytes);
    match kind {
        FieldKind::Bytes(want) if hex.eq_ignore_ascii_case(want) => Ok(()),
        FieldKind::Bytes(want) => Err(format!("is {hex}, not {want}")),
        FieldKind::Uint { min, max } => {
            sized(matches!(bytes.len(), 1 | 2 | 4 | 8))?;
            let value = uint(bytes);
            if (*min..=*max).contains(&value) {
                Ok(())
            } else {
                Err(format!("is {value}, outside {min} to {max}"))
            }
        }
        FieldKind::Int { min, max } => {
            sized(matches!(bytes.len(), 1 | 2 | 4 | 8))?;
            let value = int(bytes);
            if (*min..=*max).contains(&value) {
                Ok(())
            } else {
                Err(format!("is {value}, outside {min} to {max}"))
            }
        }
        FieldKind::Float { min, max } => {
            // Normal in its own width: a subnormal f32 would pass as a normal f64.
            let (plain, value) = match bytes.len() {
                4 => {
                    let value = f32::from_bits(u32::try_from(uint(bytes)).unwrap_or(0));
                    (value == 0.0 || value.is_normal(), f64::from(value))
                }
                8 => {
                    let value = f64::from_bits(uint(bytes));
                    (value == 0.0 || value.is_normal(), value)
                }
                _ => return Err("is not 4 or 8 bytes long".into()),
            };
            if plain && (f64::from(*min)..=f64::from(*max)).contains(&value) {
                Ok(())
            } else {
                Err(format!("is {value:e}, not a plain float in {min} to {max}"))
            }
        }
        FieldKind::OneOf(values) => {
            sized(matches!(bytes.len(), 1 | 2 | 4 | 8))?;
            let value = uint(bytes);
            if values.contains(&value) {
                Ok(())
            } else {
                Err(format!("is {value}, not one of the claimed values"))
            }
        }
        FieldKind::Pointer { min, max } => {
            sized(matches!(bytes.len(), 4 | 8))?;
            let value = uint(bytes);
            if value == 0 || (*min..=*max).contains(&value) {
                Ok(())
            } else {
                Err(format!(
                    "is {value:#x}, neither null nor in {min:#x} to {max:#x}"
                ))
            }
        }
        FieldKind::Text { min } => {
            let text = bytes.split(|b| *b == 0).next().unwrap_or_default();
            let shown = String::from_utf8_lossy(&text[..text.len().min(16)]);
            if text.len() == bytes.len() {
                Err("has no terminating NUL".into())
            } else if !text.iter().all(|b| b.is_ascii_graphic() || *b == b' ') {
                Err(format!(
                    "is not printable text (starts {})",
                    &hex[..hex.len().min(16)]
                ))
            } else if (text.len() as u64) < *min || !text.iter().any(u8::is_ascii_graphic) {
                Err(format!("is {shown:?}, not text of {min}+ characters"))
            } else {
                Ok(())
            }
        }
        FieldKind::Zero => match bytes.iter().position(|b| *b != 0) {
            None => Ok(()),
            Some(at) => Err(format!("is not zero (byte {at} is {:#04x})", bytes[at])),
        },
    }
}

/// Replays a signature claim with the key its `key` evidence holds.
pub struct SignatureChecker<'k> {
    pub key: &'k [u8],
}

impl Checker<'_> for SignatureChecker<'_> {
    const ID: &'static str = "request_signature";
    const VERSION: u32 = 6;
    type Claim = RequestSignature;
    type Evidence = HttpExchange;

    fn check(
        &self,
        claim: &RequestSignature,
        evidence: &[Item<HttpExchange>],
        deadline: Instant,
    ) -> Result<Verdict, CheckError> {
        Ok(replay(evidence, deadline, |exchange| {
            let req = &exchange.request;
            // Header names are case-insensitive in HTTP, and HTTP/2 captures have them in lower case.
            let got = (req.headers.iter())
                .find(|h| h.name.eq_ignore_ascii_case(&claim.header))
                .map(|h| &h.value)
                .ok_or_else(|| format!("header `{}` missing", claim.header))?;
            let mac = sign(claim.algorithm, self.key, &signed_input(claim, req)?)?;
            // Hex digits may be in either case; in base64 case is part of the value.
            let (want, same) = match claim.encoding {
                SigEncoding::Hex => {
                    let want = hex::encode(mac);
                    let same = got.eq_ignore_ascii_case(&want);
                    (want, same)
                }
                SigEncoding::Base64 => {
                    let want = base64::engine::general_purpose::STANDARD.encode(mac);
                    let same = *got == want;
                    (want, same)
                }
            };
            if same {
                Ok(())
            } else {
                Err(format!("header has {got}, recomputed {want}"))
            }
        }))
    }
}

fn sign(alg: SigAlgorithm, key: &[u8], body: &[u8]) -> Result<Vec<u8>, String> {
    fn hmac<D: hmac::EagerHash>(key: &[u8], body: &[u8]) -> Result<Vec<u8>, String>
    where
        Hmac<D>: KeyInit + Mac,
    {
        let mut m = <Hmac<D> as KeyInit>::new_from_slice(key).map_err(|e| e.to_string())?;
        m.update(body);
        Ok(m.finalize().into_bytes().to_vec())
    }
    match alg {
        SigAlgorithm::HmacSha256 => hmac::<sha2::Sha256>(key, body),
        SigAlgorithm::HmacSha1 => hmac::<sha1::Sha1>(key, body),
        SigAlgorithm::KeyedMd5 => Ok(md5::Md5::new()
            .chain_update(key)
            .chain_update(body)
            .finalize()
            .to_vec()),
    }
}

pub struct SchemaChecker;

impl Checker<'_> for SchemaChecker {
    const ID: &'static str = "response_schema";
    const VERSION: u32 = 3;
    type Claim = ResponseSchema;
    type Evidence = HttpExchange;

    fn check(
        &self,
        claim: &ResponseSchema,
        evidence: &[Item<HttpExchange>],
        deadline: Instant,
    ) -> Result<Verdict, CheckError> {
        let v = jsonschema::validator_for(&claim.schema)
            .map_err(|e| CheckError::InvalidClaim(e.to_string()))?;
        Ok(replay(evidence, deadline, |exchange| {
            let body = exchange.response.as_ref().and_then(|r| r.body.as_ref());
            json_matches(&v, body, "response")
        }))
    }
}

/// Whether a captured body is JSON that the schema accepts. `whose` names it in the detail.
fn json_matches(
    schema: &jsonschema::Validator,
    body: Option<&Body>,
    whose: &str,
) -> Result<(), String> {
    let body = body.ok_or_else(|| format!("the {whose} has no body"))?;
    let json: serde_json::Value = serde_json::from_slice(&body_bytes(Some(body))?)
        .map_err(|e| format!("the {whose} body is not JSON: {e}"))?;
    schema
        .validate(&json)
        .map_err(|e| match e.instance_path().as_str() {
            "" => format!("{e} at the top level"),
            path => format!("{e} at {path}"),
        })
}

pub struct BodySchemaChecker;

impl Checker<'_> for BodySchemaChecker {
    const ID: &'static str = "request_body_schema";
    const VERSION: u32 = 1;
    type Claim = ledger_core::RequestBodySchema;
    type Evidence = HttpExchange;

    fn check(
        &self,
        claim: &Self::Claim,
        evidence: &[Item<HttpExchange>],
        deadline: Instant,
    ) -> Result<Verdict, CheckError> {
        let v = jsonschema::validator_for(&claim.schema)
            .map_err(|e| CheckError::InvalidClaim(e.to_string()))?;
        Ok(replay(evidence, deadline, |exchange| {
            json_matches(&v, exchange.request.body.as_ref(), "request")
        }))
    }
}

/// The bytes a signature claim says are signed: the body, or its listed parts in order.
fn signed_input(claim: &RequestSignature, req: &HttpRequest) -> Result<Vec<u8>, String> {
    let body = body_bytes(req.body.as_ref())?;
    if claim.signed.is_empty() {
        return Ok(body.into_owned());
    }
    let after_host = req
        .url
        .split_once("://")
        .map_or(req.url.as_str(), |(_, rest)| {
            rest.find('/').map_or("", |slash| &rest[slash..])
        });
    let no_fragment = after_host.split('#').next().unwrap_or_default();
    let (path, query) = no_fragment.split_once('?').unwrap_or((no_fragment, ""));
    let mut input = Vec::new();
    for part in &claim.signed {
        match part {
            SignedPart::Body => input.extend_from_slice(&body),
            SignedPart::Text(text) => input.extend_from_slice(text.as_bytes()),
            SignedPart::Method => input.extend_from_slice(req.method.as_bytes()),
            SignedPart::Path => input.extend_from_slice(path.as_bytes()),
            SignedPart::Query => input.extend_from_slice(query.as_bytes()),
            SignedPart::Header(name) => {
                let header = req
                    .headers
                    .iter()
                    .find(|h| h.name.eq_ignore_ascii_case(name));
                let header = header.ok_or_else(|| format!("signed header `{name}` missing"))?;
                input.extend_from_slice(header.value.as_bytes());
            }
        }
    }
    Ok(input)
}

/// A captured body as bytes; no body is no bytes.
fn body_bytes(body: Option<&Body>) -> Result<std::borrow::Cow<'_, [u8]>, String> {
    match body {
        None => Ok((&[][..]).into()),
        Some(Body::Text(text)) => Ok(text.as_bytes().into()),
        Some(Body::Base64(encoded)) => base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map(Into::into)
            .map_err(|e| format!("body is not valid base64: {e}")),
    }
}

/// Parses one stored HTTP exchange and makes sure its bodies decode.
fn http_exchange(bytes: &[u8]) -> Result<HttpExchange, String> {
    let exchange: HttpExchange = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    body_bytes(exchange.request.body.as_ref())?;
    body_bytes(exchange.response.as_ref().and_then(|r| r.body.as_ref()))?;
    Ok(exchange)
}

/// Refuses captures the claim says nothing about: another endpoint, or for a
/// response claim another status. Unrelated traffic must not be able to refute
/// a claim, or to make it look checked.
fn about(
    endpoint: &str,
    other_status: impl Fn(Option<u16>) -> Option<String>,
    evidence: Vec<Item<HttpExchange>>,
) -> Result<Vec<Item<HttpExchange>>, CheckError> {
    let endpoint = Endpoint::parse(endpoint).map_err(|e| CheckError::InvalidClaim(e.into()))?;
    for item in &evidence {
        let request = &item.data.request;
        let got = item.data.response.as_ref().map(|r| r.status);
        // The query string can hold keys and tokens, so it stays out of the message.
        let line = request.url.split(['?', '#']).next().unwrap_or_default();
        let what = if !endpoint.matches_path(&request.method, &request.url) {
            format!("`{} {line}`", request.method)
        } else if !endpoint.matches(&request.method, &request.url) {
            "a request whose query string does not meet the endpoint's conditions".into()
        } else if let Some(what) = other_status(got) {
            what
        } else {
            continue;
        };
        return Err(CheckError::NotApplicable(item.id.clone(), what));
    }
    Ok(evidence)
}

pub struct HeaderChecker;

impl Checker<'_> for HeaderChecker {
    const ID: &'static str = "request_header";
    const VERSION: u32 = 1;
    type Claim = ledger_core::RequestHeader;
    type Evidence = HttpExchange;

    fn check(
        &self,
        claim: &Self::Claim,
        evidence: &[Item<HttpExchange>],
        deadline: Instant,
    ) -> Result<Verdict, CheckError> {
        let value = jsonschema::validator_for(&claim.value)
            .map_err(|e| CheckError::InvalidClaim(e.to_string()))?;
        Ok(replay(evidence, deadline, |exchange| {
            let found = (exchange.request.headers.iter())
                .find(|h| h.name.eq_ignore_ascii_case(&claim.header))
                .ok_or_else(|| format!("header `{}` missing", claim.header))?;
            // The value can be a key or a token, so the counterexample does not quote it.
            if value.is_valid(&serde_json::Value::String(found.value.clone())) {
                Ok(())
            } else {
                Err(format!(
                    "header `{}` is sent, but its value does not match the schema",
                    claim.header
                ))
            }
        }))
    }
}

pub struct StatusChecker;

impl Checker<'_> for StatusChecker {
    const ID: &'static str = "status_set";
    const VERSION: u32 = 1;
    type Claim = ledger_core::StatusSet;
    type Evidence = HttpExchange;

    fn check(
        &self,
        claim: &Self::Claim,
        evidence: &[Item<HttpExchange>],
        deadline: Instant,
    ) -> Result<Verdict, CheckError> {
        Ok(replay(evidence, deadline, |exchange| {
            match exchange.response.as_ref().map(|r| r.status) {
                Some(status) if claim.statuses.contains(&status) => Ok(()),
                Some(status) => Err(format!("answered {status}")),
                None => Err("was never answered".into()),
            }
        }))
    }
}

pub struct RelationChecker;

impl<'e> Checker<'e> for RelationChecker {
    const ID: &'static str = "field_relation";
    const VERSION: u32 = 1;
    type Claim = ledger_core::FieldRelation;
    type Evidence = &'e [u8];

    fn check(
        &self,
        claim: &Self::Claim,
        evidence: &[Item<&'e [u8]>],
        deadline: Instant,
    ) -> Result<Verdict, CheckError> {
        use ledger_core::Relation;
        Ok(replay(evidence, deadline, |bytes| {
            let read = |f: &ledger_core::IntField| {
                let found = slice(bytes, f.offset, f.len).map(uint).map(i128::from);
                found.ok_or_else(|| {
                    format!("the value at +{:#x} lies outside the snapshot", f.offset)
                })
            };
            let len = bytes.len() as u64;
            let value = read(&claim.field)?;
            let (expected, what) = match &claim.equals {
                Relation::SnapshotLength => (i128::from(len), "the snapshot's length".to_owned()),
                Relation::BytesAfter { from } => {
                    let rest = len.checked_sub(*from);
                    let rest =
                        rest.ok_or_else(|| format!("+{from:#x} lies outside the snapshot"))?;
                    (
                        i128::from(rest),
                        format!("the number of bytes after +{from:#x}"),
                    )
                }
                Relation::Sum { fields, plus } => {
                    let mut sum = i128::from(*plus);
                    for field in fields {
                        sum += read(field)?;
                    }
                    (sum, "the sum".to_owned())
                }
            };
            if value == expected {
                Ok(())
            } else {
                Err(format!(
                    "the value at +{:#x} is {value}, but {what} is {expected}",
                    claim.field.offset
                ))
            }
        }))
    }
}

pub struct TaggedRecordsChecker;

impl<'e> Checker<'e> for TaggedRecordsChecker {
    const ID: &'static str = "tagged_records";
    const VERSION: u32 = 1;
    type Claim = ledger_core::TaggedRecords;
    type Evidence = &'e [u8];

    fn check(
        &self,
        claim: &Self::Claim,
        evidence: &[Item<&'e [u8]>],
        deadline: Instant,
    ) -> Result<Verdict, CheckError> {
        Ok(replay(evidence, deadline, |bytes| {
            let len = bytes.len() as u64;
            let head = claim.size_len + claim.tag_len;
            let (mut at, mut seen) = (claim.start, 0u64);
            // Each record moves `at` forward by at least its head, so the walk ends.
            while claim.count.map_or(at != len, |count| seen < count) {
                let past =
                    || format!("record {seen} at +{at:#x} runs past the end of the snapshot");
                let size = slice(bytes, at, claim.size_len)
                    .map(uint)
                    .ok_or_else(past)?;
                let tag = slice(bytes, at + claim.size_len, claim.tag_len)
                    .map(uint)
                    .ok_or_else(past)?;
                if !claim.tags.is_empty() && !claim.tags.contains(&tag) {
                    return Err(format!(
                        "record {seen} at +{at:#x} has tag {tag}, which is not a claimed tag"
                    ));
                }
                let left = len - at - head;
                if size > left {
                    return Err(format!(
                        "record {seen} at +{at:#x} claims {size} bytes of value, but {left} remain"
                    ));
                }
                at += head + size;
                seen += 1;
            }
            Ok(())
        }))
    }
}

pub struct StringTableChecker;

impl<'e> Checker<'e> for StringTableChecker {
    const ID: &'static str = "string_table";
    const VERSION: u32 = 1;
    type Claim = ledger_core::StringTable;
    type Evidence = &'e [u8];

    fn check(
        &self,
        claim: &Self::Claim,
        evidence: &[Item<&'e [u8]>],
        deadline: Instant,
    ) -> Result<Verdict, CheckError> {
        Ok(replay(evidence, deadline, |bytes| {
            let rest = (bytes.len() as u64).saturating_sub(claim.start);
            let region = slice(bytes, claim.start, claim.len.unwrap_or(rest))
                .ok_or("the region lies outside the snapshot")?;
            let Some((&0, strings)) = region.split_last() else {
                return Err("the region does not end with a NUL".into());
            };
            let mut found = 0u64;
            for (index, text) in strings.split(|b| *b == 0).enumerate() {
                if !text.iter().all(|b| b.is_ascii_graphic() || *b == b' ') {
                    return Err(format!("string {index} is not printable text"));
                }
                if (text.len() as u64) < claim.min_chars {
                    return Err(format!(
                        "string {index} has {} characters, fewer than {}",
                        text.len(),
                        claim.min_chars
                    ));
                }
                found += 1;
            }
            if found == claim.count {
                Ok(())
            } else {
                Err(format!(
                    "the region holds {found} strings, not {}",
                    claim.count
                ))
            }
        }))
    }
}

pub struct ResponseHeaderChecker;

impl Checker<'_> for ResponseHeaderChecker {
    const ID: &'static str = "response_header";
    const VERSION: u32 = 1;
    type Claim = ledger_core::ResponseHeader;
    type Evidence = HttpExchange;

    fn check(
        &self,
        claim: &Self::Claim,
        evidence: &[Item<HttpExchange>],
        deadline: Instant,
    ) -> Result<Verdict, CheckError> {
        let value = jsonschema::validator_for(&claim.value)
            .map_err(|e| CheckError::InvalidClaim(e.to_string()))?;
        Ok(replay(evidence, deadline, |exchange| {
            let headers = exchange.response.as_ref().map_or(&[][..], |r| &r.headers);
            let mut lines = (headers.iter()).filter(|h| h.name.eq_ignore_ascii_case(&claim.header));
            let mut sent = false;
            // A header can be sent several times; one line that matches is enough.
            let matched = lines.any(|h| {
                sent = true;
                value.is_valid(&serde_json::Value::String(h.value.clone()))
            });
            // The value can be a cookie or a token, so the counterexample does not quote it.
            match (matched, sent) {
                (true, _) => Ok(()),
                (false, true) => Err(format!(
                    "header `{}` is sent, but its value does not match the schema",
                    claim.header
                )),
                (false, false) => Err(format!("header `{}` missing", claim.header)),
            }
        }))
    }
}

pub struct FormatChecker;

impl<'e> Checker<'e> for FormatChecker {
    const ID: &'static str = "format";
    const VERSION: u32 = 1;
    type Claim = ledger_core::Format;
    type Evidence = &'e [u8];

    fn check(
        &self,
        claim: &Self::Claim,
        evidence: &[Item<&'e [u8]>],
        deadline: Instant,
    ) -> Result<Verdict, CheckError> {
        let spec =
            ledger_core::format::Spec::parse(&claim.spec).map_err(CheckError::InvalidClaim)?;
        let too_big = AtomicBool::new(false);
        let verdict = replay(evidence, deadline, |bytes| {
            match format::Tree::read(&spec, bytes, claim.exact) {
                Ok(_) => Ok(()),
                Err(format::Failure::Wrong(detail)) => Err(detail),
                // Nothing is known about a file that was not read to its end: it neither
                // refutes the claim nor counts towards it.
                Err(format::Failure::TooBig) => {
                    too_big.store(true, Ordering::Relaxed);
                    Ok(())
                }
            }
        });
        Ok(match verdict {
            Verdict::Held { .. } if too_big.load(Ordering::Relaxed) => Verdict::Inconclusive {
                reason: format!(
                    "a file holds more than {} values under this description and was not read to its end",
                    format::MAX_VALUES
                ),
            },
            verdict => verdict,
        })
    }
}

pub struct CallEdgeChecker;

/// What one analysis says about a claimed call.
enum Edge {
    Calls,
    /// The caller jumps to the callee and nothing calls the callee: a tail call, or a
    /// jump inside one function that the analysis split in two.
    Jumps,
    /// Neither, with what the caller does call.
    Neither(String),
}

fn refers(f: &Function, wanted: &FunctionRef) -> bool {
    match wanted {
        FunctionRef::Address(at) => f.address == *at,
        FunctionRef::Name(name) => f.name == *name,
    }
}

fn call_edge(claim: &ledger_core::CallEdge, facts: &BinaryFacts) -> Edge {
    let functions = facts.functions.iter();
    let Some(caller) = functions.clone().find(|f| refers(f, &claim.caller)) else {
        return Edge::Neither(format!("{} is not in the recovered code", claim.caller));
    };
    // A name can stand for a recovered function or for an imported symbol.
    let mut targets: Vec<u64> = (functions.clone().filter(|f| refers(f, &claim.callee)))
        .map(|f| f.address)
        .collect();
    match &claim.callee {
        FunctionRef::Address(at) => targets.push(*at),
        FunctionRef::Name(name) => {
            let imported = facts.imports.iter().filter(|(_, import)| *import == name);
            targets.extend(imported.map(|(at, _)| *at));
        }
    }
    if targets.is_empty() {
        return Edge::Neither(format!(
            "{} is neither a recovered function nor an import that is called",
            claim.callee
        ));
    }
    if caller.calls.iter().any(|to| targets.contains(to)) {
        return Edge::Calls;
    }
    if caller.jumps.iter().any(|to| targets.contains(to)) {
        return Edge::Jumps;
    }
    let name_of = |to: &u64| {
        let function = || functions.clone().find(|f| f.address == *to);
        let name = (facts.imports.get(to).cloned()).or_else(|| function().map(|f| f.name.clone()));
        name.unwrap_or_else(|| format!("{to:#x}"))
    };
    let calls: Vec<String> = caller.calls.iter().map(name_of).collect();
    let made = if calls.is_empty() {
        String::from("it makes no direct calls")
    } else {
        format!(
            "its {} direct calls go to: {}",
            calls.len(),
            calls.join(", ")
        )
    };
    Edge::Neither(format!(
        "`{}` at {:#x} does not call {} directly; {made}",
        caller.name, caller.address, claim.callee
    ))
}

impl Checker<'_> for CallEdgeChecker {
    const ID: &'static str = "call_edge";
    const VERSION: u32 = 2;
    type Claim = ledger_core::CallEdge;
    type Evidence = BinaryFacts;

    fn check(
        &self,
        claim: &Self::Claim,
        evidence: &[Item<BinaryFacts>],
        deadline: Instant,
    ) -> Result<Verdict, CheckError> {
        // An analysis that did not recover the caller does not know what it calls, so it
        // cannot refute the claim: tools miss functions that are there.
        let recovered =
            |facts: &BinaryFacts| facts.functions.iter().any(|f| refers(f, &claim.caller));
        if let Some(blind) = evidence.iter().find(|it| !recovered(&it.data)) {
            return Err(CheckError::NotApplicable(
                blind.id.clone(),
                format!("an analysis that did not recover {}", claim.caller),
            ));
        }
        let verdict = replay(evidence, deadline, |facts| match call_edge(claim, facts) {
            Edge::Neither(detail) => Err(detail),
            Edge::Calls | Edge::Jumps => Ok(()),
        });
        // A jump is not a counterexample, and it is not a call either.
        let unclear = |facts: &BinaryFacts| matches!(call_edge(claim, facts), Edge::Jumps);
        if matches!(verdict, Verdict::Held { .. }) && evidence.iter().any(|it| unclear(&it.data)) {
            return Ok(Verdict::Inconclusive {
                reason: format!(
                    "{} jumps to {}, which nothing calls: a tail call, or a jump inside one function that the analysis split in two. The export cannot tell which",
                    claim.caller, claim.callee
                ),
            });
        }
        Ok(verdict)
    }
}

/// Every checker with its version. A checker missing here would have its verdicts
/// ignored once the log lists the current checkers, so `run` refuses to run one.
pub const CHECKERS: [(&str, u32); 13] = [
    (FormatChecker::ID, FormatChecker::VERSION),
    (CallEdgeChecker::ID, CallEdgeChecker::VERSION),
    (ResponseHeaderChecker::ID, ResponseHeaderChecker::VERSION),
    (StringTableChecker::ID, StringTableChecker::VERSION),
    (TaggedRecordsChecker::ID, TaggedRecordsChecker::VERSION),
    (RelationChecker::ID, RelationChecker::VERSION),
    (RecordArrayChecker::ID, RecordArrayChecker::VERSION),
    (StatusChecker::ID, StatusChecker::VERSION),
    (BodySchemaChecker::ID, BodySchemaChecker::VERSION),
    (HeaderChecker::ID, HeaderChecker::VERSION),
    (MemoryLayoutChecker::ID, MemoryLayoutChecker::VERSION),
    (SignatureChecker::ID, SignatureChecker::VERSION),
    (SchemaChecker::ID, SchemaChecker::VERSION),
];

/// The checker that `check_claim` runs for a claim, by id and version. With the
/// claim and the evidence, this is what a recorded verdict is cached on.
#[must_use]
pub fn checker_of(claim: &ClaimKind) -> CheckerRef {
    let (id, version) = match claim {
        ClaimKind::Format(_) => (FormatChecker::ID, FormatChecker::VERSION),
        ClaimKind::CallEdge(_) => (CallEdgeChecker::ID, CallEdgeChecker::VERSION),
        ClaimKind::ResponseHeader(_) => (ResponseHeaderChecker::ID, ResponseHeaderChecker::VERSION),
        ClaimKind::StringTable(_) => (StringTableChecker::ID, StringTableChecker::VERSION),
        ClaimKind::TaggedRecords(_) => (TaggedRecordsChecker::ID, TaggedRecordsChecker::VERSION),
        ClaimKind::FieldRelation(_) => (RelationChecker::ID, RelationChecker::VERSION),
        ClaimKind::RecordArray(_) => (RecordArrayChecker::ID, RecordArrayChecker::VERSION),
        ClaimKind::StatusSet(_) => (StatusChecker::ID, StatusChecker::VERSION),
        ClaimKind::RequestBodySchema(_) => (BodySchemaChecker::ID, BodySchemaChecker::VERSION),
        ClaimKind::RequestHeader(_) => (HeaderChecker::ID, HeaderChecker::VERSION),
        ClaimKind::MemoryLayout(_) => (MemoryLayoutChecker::ID, MemoryLayoutChecker::VERSION),
        ClaimKind::RequestSignature(_) => (SignatureChecker::ID, SignatureChecker::VERSION),
        ClaimKind::ResponseSchema(_) => (SchemaChecker::ID, SchemaChecker::VERSION),
    };
    CheckerRef {
        id: id.to_owned(),
        version,
    }
}

/// Saved evidence as stored: its id, its declared kind and its bytes.
pub type Raw<'e> = (EvidenceId, EvidenceKind, &'e [u8]);

fn decode<'e, E>(
    want: EvidenceKind,
    max: usize,
    raw: &[Raw<'e>],
    parse: impl Fn(&'e [u8]) -> Result<E, String>,
) -> Result<Vec<Item<E>>, CheckError> {
    raw.iter()
        .map(|(id, kind, bytes)| {
            if *kind != want {
                return Err(CheckError::WrongEvidence(*kind));
            }
            if bytes.len() > max {
                return Err(CheckError::TooLarge(id.clone(), bytes.len(), max));
            }
            let data = parse(bytes).map_err(|e| CheckError::Malformed(id.clone(), e))?;
            Ok(Item {
                id: id.clone(),
                size: bytes.len(),
                data,
            })
        })
        .collect()
}

/// Which of an endpoint's exchanges a web claim is about.
enum Scope {
    /// Every request, answered or not.
    Any,
    /// Requests that got a response.
    Answered,
    /// Requests the server did not turn down.
    Accepted,
    /// Responses with exactly this status.
    Status(u16),
}

impl Scope {
    /// Why a capture with this response status is not about the claim, if it is not.
    fn excludes(&self, got: Option<u16>) -> Option<String> {
        match (self, got) {
            (Self::Answered | Self::Status(_), None) => Some("a request with no response".into()),
            (Self::Accepted, Some(status)) if status >= 400 => {
                Some(format!("a request the server answered with {status}"))
            }
            (Self::Status(want), Some(status)) if status != *want => {
                Some(format!("a {status} response"))
            }
            _ => None,
        }
    }
}

/// The endpoint a web claim is about and which of its exchanges, or `None` for a
/// claim about snapshots or binaries.
fn scope(claim: &ClaimKind) -> Option<(&str, Scope)> {
    match claim {
        ClaimKind::StatusSet(c) => Some((&c.endpoint, Scope::Answered)),
        ClaimKind::RequestBodySchema(c) => Some((&c.endpoint, Scope::Any)),
        ClaimKind::RequestHeader(c) => Some((&c.endpoint, Scope::Any)),
        ClaimKind::RequestSignature(c) => Some((&c.endpoint, Scope::Accepted)),
        ClaimKind::ResponseSchema(c) => Some((&c.endpoint, Scope::Status(c.status))),
        ClaimKind::ResponseHeader(c) => Some((&c.endpoint, Scope::Status(c.status))),
        ClaimKind::MemoryLayout(_)
        | ClaimKind::RecordArray(_)
        | ClaimKind::FieldRelation(_)
        | ClaimKind::TaggedRecords(_)
        | ClaimKind::StringTable(_)
        | ClaimKind::Format(_)
        | ClaimKind::CallEdge(_) => None,
    }
}

/// Whether a captured exchange is one a claim speaks about: its endpoint, and the
/// kind of response the claim covers. Never true for a claim about snapshots.
#[must_use]
pub fn is_about(claim: &ClaimKind, exchange: &HttpExchange) -> bool {
    let request = &exchange.request;
    let status = exchange.response.as_ref().map(|r| r.status);
    scope(claim).is_some_and(|(endpoint, scope)| {
        Endpoint::parse(endpoint).is_ok_and(|e| e.matches(&request.method, &request.url))
            && scope.excludes(status).is_none()
    })
}

/// The evidence as captures of the claim's endpoint: each must be an HTTP exchange
/// the claim is about.
fn exchanges(
    evidence: &[Raw<'_>],
    claim: &ClaimKind,
) -> Result<Vec<Item<HttpExchange>>, CheckError> {
    let (endpoint, scope) =
        scope(claim).ok_or_else(|| CheckError::InvalidClaim("not a web claim".into()))?;
    let decoded = decode(
        EvidenceKind::HttpExchange,
        MAX_PARSED_EVIDENCE,
        evidence,
        http_exchange,
    );
    decoded.and_then(|items| about(endpoint, |got| scope.excludes(got), items))
}

/// The parts of a HAR file that become evidence. Everything else in the file is ignored.
#[derive(serde::Deserialize)]
struct Har {
    log: HarLog,
}

#[derive(serde::Deserialize)]
struct HarLog {
    entries: Vec<HarEntry>,
}

#[derive(serde::Deserialize)]
struct HarEntry {
    request: HarRequest,
    response: Option<HarResponse>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct HarRequest {
    method: String,
    url: String,
    #[serde(default)]
    headers: Vec<ledger_core::Header>,
    post_data: Option<HarContent>,
}

#[derive(serde::Deserialize)]
struct HarResponse {
    status: u16,
    #[serde(default)]
    headers: Vec<ledger_core::Header>,
    content: Option<HarContent>,
}

#[derive(serde::Deserialize)]
struct HarContent {
    text: Option<String>,
    encoding: Option<String>,
}

impl HarContent {
    fn body(self) -> Option<Body> {
        let base64 = self.encoding.as_deref() == Some("base64");
        self.text.map(|text| {
            if base64 {
                Body::Base64(text)
            } else {
                Body::Text(text)
            }
        })
    }
}

/// The exchanges recorded in a HAR file, one per entry, or `None` if the bytes
/// are not a HAR file.
#[must_use]
pub fn har_exchanges(bytes: &[u8]) -> Option<Vec<HttpExchange>> {
    let har: Har = serde_json::from_slice(bytes).ok()?;
    let exchange = |entry: HarEntry| HttpExchange {
        request: HttpRequest {
            method: entry.request.method,
            url: entry.request.url,
            headers: entry.request.headers,
            body: entry.request.post_data.and_then(HarContent::body),
        },
        // HAR writes status 0 for a request that was never answered.
        response: entry
            .response
            .filter(|r| r.status != 0)
            .map(|r| ledger_core::HttpResponse {
                status: r.status,
                headers: r.headers,
                body: r.content.and_then(HarContent::body),
            }),
    };
    Some(har.log.entries.into_iter().map(exchange).collect())
}

/// The commands Rizin is run with, in the order [`rizin_facts`] reads their output:
/// the file's format, its hashes, its imports, its relocations, then the analysis
/// and the functions it found.
///
/// The plain `aaa` analysis left 7% to 59% of the code ranges in four programs' unwind
/// tables in no function. Looking for a function after the end of each one found
/// (`analysis.hasnext`) and scanning for function preludes (`aap`) brings that down to
/// 0% to 12%, and Rizin's calls still agree with a second disassembler in over 99.7%
/// of the functions that can be compared (`docs/trials/rzil-coverage.md`).
pub const RIZIN_COMMANDS: &str = "iIj; iTj; iij; irj; e analysis.hasnext=true; aaa; aap; aflj";

/// What Rizin printed, one value per command.
struct RizinExport {
    hashes: RizinHashes,
    imports: Vec<RizinImport>,
    relocs: Vec<RizinReloc>,
    functions: Vec<RizinFunction>,
}

#[derive(serde::Deserialize)]
struct RizinFormat {
    /// `elf`, `pe`, `mach0` and so on; absent for a file Rizin does not recognise.
    bintype: Option<String>,
}

#[derive(serde::Deserialize)]
struct RizinHashes {
    sha256: String,
}

#[derive(serde::Deserialize)]
struct RizinFunction {
    offset: u64,
    name: String,
    #[serde(default)]
    callrefs: Vec<RizinRef>,
}

#[derive(serde::Deserialize)]
struct RizinRef {
    to: u64,
    #[serde(rename = "type")]
    kind: String,
}

#[derive(serde::Deserialize)]
struct RizinImport {
    name: String,
    /// The stub or table slot calls to the import go through, where the format has one.
    plt: Option<u64>,
}

#[derive(serde::Deserialize)]
struct RizinReloc {
    name: Option<String>,
    vaddr: u64,
}

/// The functions and direct calls in what Rizin printed for [`RIZIN_COMMANDS`]. A jump
/// to an import, or to another function that something calls, is a tail call and
/// counts as a call; any other jump does not. `tool` names the Rizin that ran.
///
/// # Errors
/// The output is not the four JSON values the commands print, or holds no function.
pub fn rizin_facts(tool: &str, output: &[u8]) -> Result<BinaryFacts, String> {
    use serde::Deserialize as _;
    let mut values = serde_json::Deserializer::from_slice(output);
    let next = |what: &str| format!("{what} are missing or malformed");
    let format = RizinFormat::deserialize(&mut values).map_err(|_| next("the file's format"))?;
    // Rizin will disassemble any bytes; only a format it recognises says where the code is.
    if format.bintype.is_none() {
        return Err(String::from("the file is not a program format Rizin knows"));
    }
    let hashes = RizinHashes::deserialize(&mut values).map_err(|_| next("the file's hashes"))?;
    let imports = Vec::<RizinImport>::deserialize(&mut values).map_err(|_| next("the imports"))?;
    let relocs =
        Vec::<RizinReloc>::deserialize(&mut values).map_err(|_| next("the relocations"))?;
    let functions =
        Vec::<RizinFunction>::deserialize(&mut values).map_err(|_| next("the functions"))?;
    if functions.is_empty() {
        return Err(String::from("no function was recovered"));
    }
    let export = RizinExport {
        hashes,
        imports,
        relocs,
        functions,
    };
    let imported: BTreeSet<&str> = export.imports.iter().map(|i| i.name.as_str()).collect();
    // A call reaches an import through a stub function, a table slot or a relocated
    // pointer, depending on the file format and how the binary was linked.
    let stubs = (export.functions.iter())
        .filter_map(|f| Some((f.offset, f.name.strip_prefix("sym.imp.")?.to_owned())));
    let slots = (export.imports.iter()).filter_map(|i| Some((i.plt?, i.name.clone())));
    let relocs = export.relocs.iter().filter_map(|r| {
        let name = r.name.as_deref().filter(|name| imported.contains(name))?;
        Some((r.vaddr, name.to_owned()))
    });
    let mut imports: BTreeMap<u64, String> = stubs.chain(slots).chain(relocs).collect();
    let starts: BTreeSet<u64> = export.functions.iter().map(|f| f.offset).collect();
    // Rizin also splits pieces of a function off as functions of their own, so only a
    // function something calls is one a jump can leave for.
    let entries: BTreeSet<u64> = (export.functions.iter().flat_map(|f| &f.callrefs))
        .filter(|r| r.kind == "CALL" && starts.contains(&r.to))
        .map(|r| r.to)
        .collect();
    let function = |f: RizinFunction| {
        let leaves =
            |to: u64| to != f.offset && (entries.contains(&to) || imports.contains_key(&to));
        let called = |r: &RizinRef| r.kind == "CALL" || (r.kind == "CODE" && leaves(r.to));
        // A jump to a function nothing calls is kept apart: it may be a tail call.
        let jumped = |r: &RizinRef| {
            r.kind == "CODE" && r.to != f.offset && starts.contains(&r.to) && !leaves(r.to)
        };
        Function {
            address: f.offset,
            name: f.name,
            calls: (f.callrefs.iter().filter(|r| called(r)))
                .map(|r| r.to)
                .collect(),
            jumps: (f.callrefs.iter().filter(|r| jumped(r)))
                .map(|r| r.to)
                .collect(),
        }
    };
    let functions: Vec<Function> = export.functions.into_iter().map(function).collect();
    // Only imports something calls are kept: the rest cannot be the callee of a claim that holds.
    let called: BTreeSet<u64> = functions.iter().flat_map(|f| &f.calls).copied().collect();
    imports.retain(|at, _| called.contains(at));
    Ok(BinaryFacts {
        tool: format!("{tool} ({RIZIN_COMMANDS})"),
        sha256: export.hashes.sha256,
        functions,
        imports,
    })
}

/// The evidence as what a tool recovered from a binary.
fn facts(evidence: &[Raw<'_>]) -> Result<Vec<Item<BinaryFacts>>, CheckError> {
    let parse = |bytes| serde_json::from_slice(bytes).map_err(|e| e.to_string());
    decode(
        EvidenceKind::BinaryFacts,
        MAX_PARSED_EVIDENCE,
        evidence,
        parse,
    )
}

/// The evidence as snapshots: files given as they are, and live captures with what
/// was seen when they were taken. The bytes are only sliced, never parsed.
fn captures<'e>(evidence: &[Raw<'e>]) -> Result<Vec<Item<Snapshot<'e>>>, CheckError> {
    (evidence.iter())
        .map(|(id, kind, bytes)| {
            let data = match kind {
                EvidenceKind::MemorySnapshot => Snapshot {
                    bytes,
                    observed: BTreeMap::new(),
                },
                EvidenceKind::LiveSnapshot => {
                    let (capture, memory) = ledger_core::Capture::split(bytes)
                        .map_err(|why| CheckError::Malformed(id.clone(), why))?;
                    Snapshot {
                        bytes: memory,
                        observed: capture.observed,
                    }
                }
                other => return Err(CheckError::WrongEvidence(*other)),
            };
            Ok(Item {
                id: id.clone(),
                size: bytes.len(),
                data,
            })
        })
        .collect()
}

/// The evidence as the bytes of snapshots, for the claims that take no account of
/// what was seen at a capture.
fn snapshots<'e>(evidence: &[Raw<'e>]) -> Result<Vec<Item<&'e [u8]>>, CheckError> {
    let bytes = |it: Item<Snapshot<'e>>| Item {
        id: it.id,
        size: it.size,
        data: it.data.bytes,
    };
    Ok(captures(evidence)?.into_iter().map(bytes).collect())
}

/// Runs one checker inside a trace span, giving it `limit` to finish.
fn run<'e, C: Checker<'e>>(
    checker: &C,
    id: &ClaimId,
    claim: &C::Claim,
    evidence: Result<Vec<Item<C::Evidence>>, CheckError>,
    limit: Duration,
) -> Result<Verdict, CheckError> {
    if !CHECKERS.contains(&(C::ID, C::VERSION)) {
        return Err(CheckError::InvalidClaim(format!(
            "checker `{}` is not listed in CHECKERS",
            C::ID
        )));
    }
    let span = tracing::info_span!("check", claim = %id, checker = C::ID, version = C::VERSION);
    let _entered = span.enter();
    let start = Instant::now();
    let verdict = checker.check(claim, &evidence?, start + limit);
    // Only the outcome is logged: details can quote evidence.
    let outcome = match &verdict {
        Ok(Verdict::Held { .. }) => "held",
        Ok(Verdict::Refuted { .. }) => "refuted",
        Ok(Verdict::Inconclusive { .. }) => "inconclusive",
        Err(_) => "error",
    };
    tracing::info!(elapsed = ?start.elapsed(), outcome, "checked");
    verdict
}

/// Decodes raw evidence for the claim's kind and runs the matching checker
/// inside a trace span, giving it `limit` to finish.
///
/// # Errors
/// Evidence of the wrong kind, oversized or undecodable evidence, evidence that
/// is not about the claim, or an uncheckable claim.
pub fn check_claim(
    id: &ClaimId,
    claim: &ClaimKind,
    evidence: &[Raw<'_>],
    limit: Duration,
) -> Result<Verdict, CheckError> {
    match claim {
        ClaimKind::Format(c) => run(&FormatChecker, id, c, snapshots(evidence), limit),
        ClaimKind::CallEdge(c) => run(&CallEdgeChecker, id, c, facts(evidence), limit),
        ClaimKind::ResponseHeader(c) => run(
            &ResponseHeaderChecker,
            id,
            c,
            exchanges(evidence, claim),
            limit,
        ),
        ClaimKind::StringTable(c) => run(&StringTableChecker, id, c, snapshots(evidence), limit),
        ClaimKind::TaggedRecords(c) => {
            run(&TaggedRecordsChecker, id, c, snapshots(evidence), limit)
        }
        ClaimKind::FieldRelation(c) => run(&RelationChecker, id, c, snapshots(evidence), limit),
        ClaimKind::RecordArray(c) => run(&RecordArrayChecker, id, c, snapshots(evidence), limit),
        ClaimKind::MemoryLayout(c) => run(&MemoryLayoutChecker, id, c, captures(evidence), limit),
        ClaimKind::StatusSet(c) => run(&StatusChecker, id, c, exchanges(evidence, claim), limit),
        ClaimKind::RequestBodySchema(c) => {
            run(&BodySchemaChecker, id, c, exchanges(evidence, claim), limit)
        }
        ClaimKind::RequestHeader(c) => {
            run(&HeaderChecker, id, c, exchanges(evidence, claim), limit)
        }
        ClaimKind::ResponseSchema(c) => {
            run(&SchemaChecker, id, c, exchanges(evidence, claim), limit)
        }
        ClaimKind::RequestSignature(c) => {
            // The key travels with the captures as secret evidence; it is not a capture.
            let captures: Vec<Raw<'_>> = (evidence.iter())
                .filter(|(_, kind, _)| *kind != EvidenceKind::Secret)
                .cloned()
                .collect();
            let key = (evidence.iter())
                .find(|(e, kind, _)| *e == c.key && *kind == EvidenceKind::Secret)
                .map(|(_, _, bytes)| *bytes)
                .ok_or_else(|| CheckError::MissingKey(c.key.clone()))?;
            run(
                &SignatureChecker { key },
                id,
                c,
                exchanges(&captures, claim),
                limit,
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ledger_core::{FieldLayout, Header, HttpRequest, HttpResponse};

    /// A captured exchange: a POST with one header and a text body, answered with JSON.
    fn exchange(
        url: &str,
        header: (&str, &str),
        body: &str,
        status: u16,
        response: &serde_json::Value,
    ) -> HttpExchange {
        HttpExchange {
            request: HttpRequest {
                method: "POST".into(),
                url: url.into(),
                headers: vec![Header {
                    name: header.0.into(),
                    value: header.1.into(),
                }],
                body: Some(Body::Text(body.into())),
            },
            response: Some(HttpResponse {
                status,
                headers: vec![],
                body: Some(Body::Text(response.to_string())),
            }),
        }
    }

    fn stored(exchange: &HttpExchange) -> Result<Vec<u8>, CheckError> {
        serde_json::to_vec(exchange).map_err(|e| CheckError::InvalidClaim(e.to_string()))
    }

    fn item<E>(name: &[u8], data: E) -> Item<E> {
        Item {
            id: EvidenceId::of(name),
            size: name.len(),
            data,
        }
    }

    fn soon() -> Instant {
        Instant::now() + Duration::from_secs(5)
    }

    /// Both were seen in trial 2: a true claim refuted by lower-case header names, and
    /// a damaged base64 signature accepted.
    #[test]
    fn header_names_ignore_case_and_base64_does_not() -> Result<(), CheckError> {
        let claim = RequestSignature {
            endpoint: "POST /purchase".into(),
            header: "X-Sig".into(),
            algorithm: SigAlgorithm::HmacSha1,
            encoding: SigEncoding::Base64,
            key: EvidenceId::of(KEY),
            signed: vec![],
        };
        let mac = sign(claim.algorithm, &[0x00, 0xff, 0x10], b"item=1")
            .map_err(CheckError::InvalidClaim)?;
        let good = base64::engine::general_purpose::STANDARD.encode(mac);
        assert_ne!(
            good,
            good.to_lowercase(),
            "the test needs a signature with capitals"
        );
        let request = |header: &str, value: &str| {
            exchange(
                "/purchase",
                (header, value),
                "item=1",
                200,
                &serde_json::json!({}),
            )
        };
        let held = |request| -> Result<bool, CheckError> {
            let checker = SignatureChecker { key: KEY };
            let verdict = checker.check(&claim, &[item(b"r", request)], soon())?;
            Ok(matches!(verdict, Verdict::Held { .. }))
        };
        assert!(held(request("x-sig", &good))?);
        assert!(!held(request("X-Sig", &good.to_lowercase()))?);
        Ok(())
    }

    const KEY: &[u8] = &[0x00, 0xff, 0x10];
    const OTHER_KEY: &[u8] = &[0x00, 0xff, 0x11];

    fn signed(claim: &RequestSignature, body: &str) -> Result<Vec<u8>, CheckError> {
        let mac = sign(claim.algorithm, KEY, body.as_bytes()).map_err(CheckError::InvalidClaim)?;
        let header = (claim.header.as_str(), hex::encode(mac));
        let url = "https://game.example/score?session=abc";
        stored(&exchange(
            url,
            (header.0, &header.1),
            body,
            200,
            &serde_json::json!({}),
        ))
    }

    /// Runs every claim over the same evidence and returns how many were refuted.
    fn refuted(
        claims: &[ClaimKind],
        kind: EvidenceKind,
        evidence: &[Vec<u8>],
    ) -> Result<usize, CheckError> {
        let mut raw: Vec<Raw<'_>> = (evidence.iter())
            .map(|bytes| (EvidenceId::of(bytes), kind, &bytes[..]))
            .collect();
        // Signature claims cite their key as evidence; both keys are on hand.
        if claims
            .iter()
            .all(|c| matches!(c, ClaimKind::RequestSignature(_)))
        {
            raw.extend([KEY, OTHER_KEY].map(|k| (EvidenceId::of(k), EvidenceKind::Secret, k)));
        }
        let mut caught = 0;
        for claim in claims {
            let verdict = check_claim(&ClaimId::of(b"c"), claim, &raw, Duration::from_secs(5))?;
            caught += usize::from(matches!(verdict, Verdict::Refuted { .. }));
        }
        Ok(caught)
    }

    /// Seeded errors: each kind's true claim holds and every deliberately wrong variant is refuted.
    #[test]
    fn seeded_wrong_claims_are_refuted() -> Result<(), CheckError> {
        let truth = RequestSignature {
            endpoint: "POST game.example/score".into(),
            header: "X-Sig".into(),
            algorithm: SigAlgorithm::HmacSha256,
            encoding: SigEncoding::Hex,
            key: EvidenceId::of(KEY),
            signed: vec![],
        };
        let requests = [signed(&truth, "score=10")?, signed(&truth, "score=9000")?];
        let wrong = |edit: fn(&mut RequestSignature)| {
            let mut claim = truth.clone();
            edit(&mut claim);
            ClaimKind::RequestSignature(claim)
        };
        let seeded = [
            wrong(|c| c.key = EvidenceId::of(OTHER_KEY)),
            wrong(|c| c.algorithm = SigAlgorithm::HmacSha1),
            wrong(|c| c.algorithm = SigAlgorithm::KeyedMd5),
            wrong(|c| c.encoding = SigEncoding::Base64),
            wrong(|c| c.header = "X-Signature".into()),
        ];
        let kind = EvidenceKind::HttpExchange;
        assert_eq!(
            refuted(
                &[ClaimKind::RequestSignature(truth.clone())],
                kind,
                &requests
            )?,
            0
        );
        assert_eq!(refuted(&seeded, kind, &requests)?, seeded.len());

        let profile = |json| stored(&exchange("/profile", ("a", "b"), "", 200, &json));
        let responses = [
            profile(serde_json::json!({"level": 3, "name": "ann"}))?,
            profile(serde_json::json!({"level": 70, "name": "bo"}))?,
        ];
        let schema = |schema: serde_json::Value| {
            ClaimKind::ResponseSchema(ResponseSchema {
                endpoint: "POST /profile".into(),
                status: 200,
                schema,
            })
        };
        let level = |v: serde_json::Value| schema(serde_json::json!({"properties": {"level": v}}));
        let seeded = [
            level(serde_json::json!({"type": "string"})),
            level(serde_json::json!({"maximum": 50})),
            level(serde_json::json!({"enum": [1, 2, 3]})),
            schema(serde_json::json!({"required": ["guild"]})),
            schema(
                serde_json::json!({"properties": {"level": true}, "additionalProperties": false}),
            ),
        ];
        let kind = EvidenceKind::HttpExchange;
        assert_eq!(
            refuted(
                &[level(serde_json::json!({"type": "integer"}))],
                kind,
                &responses
            )?,
            0
        );
        assert_eq!(refuted(&seeded, kind, &responses)?, seeded.len());

        Ok(())
    }

    #[test]
    fn a_lone_space_is_not_text() {
        // The miss of trial 1: a record header `20 00 ..` read as the string " ".
        let field = [0x20, 0x00, 0x80, 0x07, b'c', b'1', b'a', b'0'];
        assert!(field_holds(&FieldKind::Text { min: 1 }, &field).is_err());
        assert!(field_holds(&FieldKind::Text { min: 3 }, b"c1a0\0\xff\xff\xff").is_ok());
        assert!(field_holds(&FieldKind::Text { min: 5 }, b"c1a0\0\xff\xff\xff").is_err());
    }

    /// Trial 2: a claim filed under a made-up endpoint held, and requests to another
    /// endpoint refuted a true claim. Captures that are not about the claim are refused.
    #[test]
    fn captures_of_another_endpoint_or_status_are_refused() -> Result<(), CheckError> {
        let id = ClaimId::of(b"c");
        let limit = Duration::from_secs(5);
        let raw = |e: &HttpExchange| {
            Ok::<_, CheckError>((EvidenceId::of(b"e"), EvidenceKind::HttpExchange, stored(e)?))
        };
        let about = |claim: &ClaimKind,
                     e: &HttpExchange|
         -> Result<Result<Verdict, CheckError>, CheckError> {
            let (id_e, kind, bytes) = raw(e)?;
            Ok(check_claim(&id, claim, &[(id_e, kind, &bytes[..])], limit))
        };
        let schema = |endpoint: &str| {
            ClaimKind::ResponseSchema(ResponseSchema {
                endpoint: endpoint.into(),
                status: 200,
                schema: serde_json::json!({"required": ["id"]}),
            })
        };
        let ok = serde_json::json!({"id": 1});
        let serde = exchange(
            "https://crates.io/api/v1/crates/serde?include=x",
            ("a", "b"),
            "",
            200,
            &ok,
        );
        let claim = schema("POST crates.io/api/v1/crates/{name}");
        assert!(matches!(about(&claim, &serde)?, Ok(Verdict::Held { .. })));
        // Another path, another host, another status: none of them is evidence for this claim.
        let owners = exchange(
            "https://crates.io/api/v1/crates/serde/owners",
            ("a", "b"),
            "",
            200,
            &ok,
        );
        let other_host = exchange(
            "https://docs.rs/api/v1/crates/serde",
            ("a", "b"),
            "",
            200,
            &ok,
        );
        let not_found = exchange(
            "https://crates.io/api/v1/crates/nope",
            ("a", "b"),
            "",
            404,
            &serde_json::json!({"errors": []}),
        );
        for capture in [&owners, &other_host, &not_found] {
            assert!(matches!(
                about(&claim, capture)?,
                Err(CheckError::NotApplicable(..))
            ));
        }
        assert!(matches!(
            about(&schema("POST /api/v9/nowhere"), &serde)?,
            Err(CheckError::NotApplicable(..))
        ));
        // An endpoint with query conditions takes only the requests that meet them.
        let narrowed = schema("POST crates.io/api/v1/crates/{name}?include=x");
        assert!(matches!(
            about(&narrowed, &serde)?,
            Ok(Verdict::Held { .. })
        ));
        let other = schema("POST crates.io/api/v1/crates/{name}?!include");
        assert!(matches!(
            about(&other, &serde)?,
            Err(CheckError::NotApplicable(..))
        ));
        // The query string, which can hold keys, is not echoed.
        if let Err(e) = about(&schema("POST /nowhere"), &serde)? {
            assert!(!e.to_string().contains("include"), "{e}");
        }
        Ok(())
    }

    #[test]
    fn the_smallest_capture_that_disagrees_is_shown() -> Result<(), CheckError> {
        let claim = MemoryLayout {
            type_name: "T".into(),
            size: 64,
            fields: vec![],
        };
        // Sizes 40, 80, 8 and 20: three are too short, and the 8-byte one is the smallest.
        let snapshots = [vec![0u8; 40], vec![0; 80], vec![0; 8], vec![0; 20]];
        let items: Vec<Item<Snapshot<'_>>> = (snapshots.iter())
            .map(|bytes| Item {
                id: EvidenceId::of(bytes),
                size: bytes.len(),
                data: plain(&bytes[..]),
            })
            .collect();
        let Verdict::Refuted { counterexample } =
            MemoryLayoutChecker.check(&claim, &items, soon())?
        else {
            return Err(CheckError::InvalidClaim("expected a refutation".into()));
        };
        assert_eq!(counterexample.evidence, EvidenceId::of(&[0u8; 8]));
        assert!(
            counterexample
                .detail
                .ends_with("(3 of 4 captures disagree; this is the smallest)"),
            "{}",
            counterexample.detail
        );
        Ok(())
    }

    #[test]
    fn counterexample_details_are_bounded() -> Result<(), CheckError> {
        // Seen in trial 3: the schema validator quoted a 3,000 character array.
        let claim = ResponseSchema {
            endpoint: "POST /p".into(),
            status: 200,
            schema: serde_json::json!({"properties": {"items": {"maxItems": 0}}}),
        };
        let long = serde_json::json!({"items": vec!["oran-berry"; 500]});
        let capture = exchange("/p", ("a", "b"), "", 200, &long);
        let verdict = SchemaChecker.check(&claim, &[item(b"e", capture)], soon())?;
        let Verdict::Refuted { counterexample } = verdict else {
            return Err(CheckError::InvalidClaim("expected a refutation".into()));
        };
        assert_eq!(counterexample.detail.chars().count(), MAX_DETAIL + 1);
        Ok(())
    }

    /// Trial 2's session endpoint signs a timestamp header, a dot and the body; and a
    /// request the server rejected is not evidence about accepted ones.
    #[test]
    fn signatures_over_several_parts_and_only_accepted_requests() -> Result<(), CheckError> {
        let mut claim = RequestSignature {
            endpoint: "POST /session".into(),
            header: "X-Auth".into(),
            algorithm: SigAlgorithm::HmacSha256,
            encoding: SigEncoding::Hex,
            key: EvidenceId::of(KEY),
            signed: vec![
                SignedPart::Header("x-timestamp".into()),
                SignedPart::Text(".".into()),
                SignedPart::Body,
                SignedPart::Method,
                SignedPart::Path,
                SignedPart::Query,
            ],
        };
        let mac = sign(
            claim.algorithm,
            &[0x00, 0xff, 0x10],
            b"1795000000.{}POST/sessiona=1",
        )
        .map_err(CheckError::InvalidClaim)?;
        let capture = |status: u16| {
            let url = "https://game.example/session?a=1#top";
            let mut e = exchange(
                url,
                ("X-Auth", &hex::encode(&mac)),
                "{}",
                status,
                &serde_json::json!({}),
            );
            e.request.headers.push(Header {
                name: "X-Timestamp".into(),
                value: "1795000000".into(),
            });
            stored(&e)
        };
        let id = ClaimId::of(b"c");
        let run = |claim: &RequestSignature,
                   status: u16|
         -> Result<Result<Verdict, CheckError>, CheckError> {
            let bytes = capture(status)?;
            let raw = (EvidenceId::of(b"e"), EvidenceKind::HttpExchange, &bytes[..]);
            let claim = ClaimKind::RequestSignature(claim.clone());
            let key = (EvidenceId::of(KEY), EvidenceKind::Secret, KEY);
            Ok(check_claim(
                &id,
                &claim,
                &[raw, key],
                Duration::from_secs(5),
            ))
        };
        assert!(matches!(run(&claim, 200)?, Ok(Verdict::Held { .. })));
        assert!(matches!(
            run(&claim, 401)?,
            Err(CheckError::NotApplicable(..))
        ));
        // The body alone is not what this endpoint signs.
        claim.signed.clear();
        assert!(matches!(run(&claim, 200)?, Ok(Verdict::Refuted { .. })));
        Ok(())
    }

    #[test]
    fn header_claims_hold_refute_and_keep_the_value_out() -> Result<(), CheckError> {
        let claim = |header: &str, value: serde_json::Value| ledger_core::RequestHeader {
            endpoint: "POST /query".into(),
            header: header.into(),
            value,
        };
        let capture = exchange(
            "/query",
            ("X-Api-Key", "s3cret-token-0123456789"),
            "{}",
            200,
            &serde_json::json!({}),
        );
        let verdict = |claim| HeaderChecker.check(&claim, &[item(b"e", capture.clone())], soon());
        // Names are matched without regard to case, as everywhere.
        assert!(matches!(
            verdict(claim("x-api-key", serde_json::json!({"minLength": 20})))?,
            Verdict::Held { .. }
        ));
        assert!(matches!(
            verdict(claim("x-api-key", serde_json::json!(true)))?,
            Verdict::Held { .. }
        ));
        let Verdict::Refuted { counterexample } = verdict(claim(
            "x-api-key",
            serde_json::json!({"pattern": "^Bearer "}),
        ))?
        else {
            return Err(CheckError::InvalidClaim("expected a refutation".into()));
        };
        assert!(
            !counterexample.detail.contains("s3cret"),
            "{}",
            counterexample.detail
        );
        assert!(matches!(
            verdict(claim("authorization", serde_json::json!(true)))?,
            Verdict::Refuted { .. }
        ));
        Ok(())
    }

    #[test]
    fn request_body_claims_hold_and_refute() -> Result<(), CheckError> {
        let claim = |schema| ledger_core::RequestBodySchema {
            endpoint: "POST /query".into(),
            schema,
        };
        let search = exchange(
            "/query",
            ("a", "b"),
            r#"{"query": "rust", "page": 0}"#,
            200,
            &serde_json::json!({}),
        );
        let form = exchange(
            "/query",
            ("a", "b"),
            "query=rust&page=0",
            200,
            &serde_json::json!({}),
        );
        let run = |schema, capture: &HttpExchange| {
            BodySchemaChecker.check(&claim(schema), &[item(b"e", capture.clone())], soon())
        };
        let asks =
            serde_json::json!({"required": ["query"], "properties": {"page": {"type": "integer"}}});
        assert!(matches!(run(asks.clone(), &search)?, Verdict::Held { .. }));
        let wrong = serde_json::json!({"properties": {"page": {"type": "string"}}});
        assert!(
            matches!(run(wrong, &search)?, Verdict::Refuted { counterexample } if counterexample.detail.contains("/page"))
        );
        assert!(
            matches!(run(asks, &form)?, Verdict::Refuted { counterexample } if counterexample.detail.contains("not JSON"))
        );
        Ok(())
    }

    #[test]
    fn status_claims_hold_refute_and_skip_unanswered_requests() -> Result<(), CheckError> {
        let claim = |statuses: &[u16]| {
            ClaimKind::StatusSet(ledger_core::StatusSet {
                endpoint: "POST /crates/{name}".into(),
                statuses: statuses.iter().copied().collect(),
            })
        };
        let found = stored(&exchange(
            "/crates/serde",
            ("a", "b"),
            "",
            200,
            &serde_json::json!({}),
        ))?;
        let missing = stored(&exchange(
            "/crates/nope",
            ("a", "b"),
            "",
            404,
            &serde_json::json!({}),
        ))?;
        let mut unanswered = exchange("/crates/slow", ("a", "b"), "", 200, &serde_json::json!({}));
        unanswered.response = None;
        let unanswered = stored(&unanswered)?;
        let run = |claim: &ClaimKind, captures: &[&Vec<u8>]| {
            let raw: Vec<Raw<'_>> = (captures.iter())
                .map(|bytes| {
                    (
                        EvidenceId::of(bytes),
                        EvidenceKind::HttpExchange,
                        &bytes[..],
                    )
                })
                .collect();
            check_claim(&ClaimId::of(b"c"), claim, &raw, Duration::from_secs(5))
        };
        assert!(matches!(
            run(&claim(&[200, 404]), &[&found, &missing])?,
            Verdict::Held { .. }
        ));
        assert!(matches!(
            run(&claim(&[200]), &[&found, &missing])?,
            Verdict::Refuted { counterexample } if counterexample.detail == "answered 404"
        ));
        assert!(matches!(
            run(&claim(&[200]), &[&unanswered]),
            Err(CheckError::NotApplicable(..))
        ));
        Ok(())
    }

    /// Trial 1's `.HL3` files: a count, then that many 4-byte entity indices, and nothing else.
    #[test]
    fn record_arrays_follow_their_count() -> Result<(), CheckError> {
        let claim = ledger_core::RecordArray {
            type_name: "EntityList".into(),
            count_offset: 0,
            count_len: 4,
            first: 4,
            stride: 4,
            fields: vec![FieldLayout {
                name: "index".into(),
                offset: 0,
                len: 4,
                is: Some(FieldKind::Uint { min: 1, max: 4095 }),
            }],
            exact: true,
        };
        let file = |count: u32, values: &[u32]| {
            let mut bytes = count.to_le_bytes().to_vec();
            for v in values {
                bytes.extend(v.to_le_bytes());
            }
            bytes
        };
        let verdict =
            |bytes: Vec<u8>| RecordArrayChecker.check(&claim, &[item(b"e", &bytes[..])], soon());
        let detail = |bytes: Vec<u8>| match verdict(bytes) {
            Ok(Verdict::Refuted { counterexample }) => counterexample.detail,
            other => format!("{other:?}"),
        };
        assert!(matches!(
            verdict(file(3, &[1, 183, 320]))?,
            Verdict::Held { .. }
        ));
        assert!(
            matches!(verdict(file(0, &[]))?, Verdict::Held { .. }),
            "an empty list is a list"
        );
        assert!(detail(file(4, &[1, 183, 320])).starts_with("the count is 4, which needs more"));
        assert!(detail(file(2, &[1, 183, 320])).contains("4 more bytes follow"));
        assert!(detail(file(3, &[1, 183, 9000])).starts_with("record 2: field `index`"));
        assert!(detail(file(u32::MAX, &[1])).starts_with("the count is 4294967295"));
        Ok(())
    }

    /// Trial 1's directory entries: a name, a size, then exactly that many bytes of data.
    #[test]
    fn field_relations_hold_and_refute() {
        use ledger_core::{FieldRelation, IntField, Relation};
        // 8 bytes of name, a 4-byte size, a 4-byte header length, then the data.
        let entry = |size: u32, data: usize| {
            let mut bytes = b"c1a0.HL1".to_vec();
            bytes.extend(size.to_le_bytes());
            bytes.extend(16u32.to_le_bytes());
            bytes.extend(vec![0xAB; data]);
            bytes
        };
        let claim = |offset, equals| FieldRelation {
            type_name: "Entry".into(),
            field: IntField { offset, len: 4 },
            equals,
        };
        let detail = |claim: &FieldRelation, bytes: &[u8]| match RelationChecker.check(
            claim,
            &[item(b"e", bytes)],
            soon(),
        ) {
            Ok(Verdict::Refuted { counterexample }) => counterexample.detail,
            Ok(Verdict::Held { .. }) => "held".to_owned(),
            other => format!("{other:?}"),
        };
        let size_is_rest = claim(8, Relation::BytesAfter { from: 16 });
        assert_eq!(detail(&size_is_rest, &entry(40, 40)), "held");
        assert_eq!(
            detail(&size_is_rest, &entry(40, 39)),
            "the value at +0x8 is 40, but the number of bytes after +0x10 is 39"
        );
        assert_eq!(
            detail(&claim(8, Relation::BytesAfter { from: 99 }), &entry(40, 40)),
            "+0x63 lies outside the snapshot"
        );
        // size + header length = the whole entry
        let whole = Relation::Sum {
            fields: vec![IntField { offset: 8, len: 4 }],
            plus: 0,
        };
        assert_eq!(detail(&claim(12, whole), &entry(16, 5)), "held");
        let sum = Relation::Sum {
            fields: vec![
                IntField { offset: 8, len: 4 },
                IntField { offset: 12, len: 4 },
            ],
            plus: 0,
        };
        let mut total = entry(40, 40);
        total.extend(56u32.to_le_bytes());
        assert_eq!(detail(&claim(56, sum), &total), "held");
        assert_eq!(
            detail(&claim(56, Relation::SnapshotLength), &total),
            "the value at +0x38 is 56, but the snapshot's length is 60"
        );
    }

    /// Trial 1's save body: (size, token, value) records, as in `04 00 21 0b 03 00 00 00`.
    #[test]
    fn tagged_records_are_walked_to_their_end() {
        let record = |tag: u16, value: &[u8]| {
            let mut bytes = u16::try_from(value.len())
                .unwrap_or(0)
                .to_le_bytes()
                .to_vec();
            bytes.extend(tag.to_le_bytes());
            bytes.extend(value);
            bytes
        };
        let body = [
            record(2849, &[3, 0, 0, 0]),
            record(892, &[12, 0, 0, 0]),
            record(1920, b"c1a1f\0\0\0"),
        ]
        .concat();
        let claim = |count, tags: &[u64]| ledger_core::TaggedRecords {
            type_name: "GameHeader".into(),
            start: 0,
            size_len: 2,
            tag_len: 2,
            count,
            tags: tags.iter().copied().collect(),
        };
        let detail = |claim: &ledger_core::TaggedRecords, bytes: &[u8]| match TaggedRecordsChecker
            .check(claim, &[item(b"e", bytes)], soon())
        {
            Ok(Verdict::Refuted { counterexample }) => counterexample.detail,
            Ok(Verdict::Held { .. }) => "held".to_owned(),
            other => format!("{other:?}"),
        };
        assert_eq!(detail(&claim(None, &[]), &body), "held");
        assert_eq!(detail(&claim(Some(3), &[2849, 892, 1920]), &body), "held");
        assert_eq!(
            detail(&claim(Some(2), &[2849, 892]), &body),
            "held",
            "a count stops the walk early"
        );
        assert_eq!(
            detail(&claim(None, &[2849, 892]), &body),
            "record 2 at +0x10 has tag 1920, which is not a claimed tag"
        );
        assert_eq!(
            detail(&claim(Some(4), &[]), &body),
            "record 3 at +0x1c runs past the end of the snapshot"
        );
        // One byte short: the last record claims more than is left, and a stray byte is not a record.
        assert_eq!(
            detail(&claim(None, &[]), &body[..body.len() - 1]),
            "record 2 at +0x10 claims 8 bytes of value, but 7 remain"
        );
        let stray = [body.clone(), vec![0xFF]].concat();
        assert_eq!(
            detail(&claim(None, &[]), &stray),
            "record 3 at +0x1c runs past the end of the snapshot"
        );
    }

    /// Trial 1's token table: a fixed number of strings, most of them empty, in a fixed region.
    #[test]
    fn string_tables_are_counted_and_read() {
        let claim = |len, count, min_chars| ledger_core::StringTable {
            type_name: "TokenTable".into(),
            start: 4,
            len,
            count,
            min_chars,
        };
        let detail = |claim: &ledger_core::StringTable, bytes: &[u8]| match StringTableChecker
            .check(claim, &[item(b"e", bytes)], soon())
        {
            Ok(Verdict::Refuted { counterexample }) => counterexample.detail,
            Ok(Verdict::Held { .. }) => "held".to_owned(),
            other => format!("{other:?}"),
        };
        // Four header bytes, then "", "mapName", "", "GENT", then two bytes of something else.
        let file = b"JSAV\0mapName\0\0GENT\0\x07\x08";
        assert_eq!(detail(&claim(Some(15), 4, 0), file), "held");
        assert_eq!(
            detail(&claim(Some(15), 5, 0), file),
            "the region holds 4 strings, not 5"
        );
        assert_eq!(
            detail(&claim(Some(15), 4, 1), file),
            "string 0 has 0 characters, fewer than 1"
        );
        assert_eq!(
            detail(&claim(Some(14), 4, 0), file),
            "the region does not end with a NUL"
        );
        assert_eq!(
            detail(&claim(None, 4, 0), file),
            "the region does not end with a NUL"
        );
        assert_eq!(
            detail(&claim(Some(99), 4, 0), file),
            "the region lies outside the snapshot"
        );
        let binary = b"JSAV\0map\xffName\0";
        assert_eq!(
            detail(&claim(None, 2, 0), binary),
            "string 1 is not printable text"
        );
    }

    /// A snapshot nobody was watching when it was taken.
    fn plain(bytes: &[u8]) -> Snapshot<'_> {
        Snapshot {
            bytes,
            observed: BTreeMap::new(),
        }
    }

    /// A capture of 12 bytes: hp 73 as a u32, armor 21.25 as an f32, then a signed -1
    /// nobody watched. The human saw 73 HP, armor between 20.5 and 21.5, and 12 rounds.
    fn live_capture() -> Result<(Vec<u8>, Vec<u8>), CheckError> {
        let seen =
            |name: &str, min: f64, max: f64| (name.to_owned(), ledger_core::Observed { min, max });
        let capture = ledger_core::Capture {
            process: "game".into(),
            pid: 4242,
            address: 0x7f00_1000,
            observed: BTreeMap::from([
                seen("hp", 73.0, 73.0),
                seen("armor", 20.5, 21.5),
                seen("ammo", 12.0, 12.0),
            ]),
        };
        let mut memory = 73u32.to_le_bytes().to_vec();
        memory.extend_from_slice(&21.25f32.to_le_bytes());
        memory.extend_from_slice(&(-1i32).to_le_bytes());
        let stored =
            (capture.encode(&memory)).map_err(|e| CheckError::InvalidClaim(e.to_string()))?;
        Ok((stored, memory))
    }

    #[test]
    fn a_layout_must_read_what_was_seen_at_a_live_capture() -> Result<(), CheckError> {
        let (stored, _) = live_capture()?;
        let field = |name: &str, offset, len, is| ledger_core::FieldLayout {
            name: name.into(),
            offset,
            len,
            is,
        };
        let float = Some(FieldKind::Float {
            min: -1000,
            max: 1000,
        });
        let detail = |fields: Vec<ledger_core::FieldLayout>| {
            let claim = ClaimKind::MemoryLayout(MemoryLayout {
                type_name: "Player".into(),
                size: 12,
                fields,
            });
            let evidence = [(
                EvidenceId::of(&stored),
                EvidenceKind::LiveSnapshot,
                &stored[..],
            )];
            match check_claim(
                &ClaimId::of(b"c"),
                &claim,
                &evidence,
                Duration::from_secs(5),
            ) {
                Ok(Verdict::Refuted { counterexample }) => counterexample.detail,
                Ok(Verdict::Held { .. }) => "held".to_owned(),
                other => format!("{other:?}"),
            }
        };
        // The layout that is right, and one that names nothing that was seen.
        let right = vec![field("hp", 0, 4, None), field("armor", 4, 4, float)];
        assert_eq!(detail(right), "held");
        assert_eq!(detail(vec![field("health", 4, 4, None)]), "held");
        // hp placed where the armor is, and where the signed number is.
        assert_eq!(
            detail(vec![field("hp", 4, 4, None)]),
            "field `hp` at +0x4 reads 1101660160, but 73 was seen when the capture was taken"
        );
        let signed = Some(FieldKind::Int { min: -5, max: 5 });
        assert_eq!(
            detail(vec![field("hp", 8, 4, signed)]),
            "field `hp` at +0x8 reads -1, but 73 was seen when the capture was taken"
        );
        assert_eq!(
            detail(vec![field("ammo", 0, 3, None)]),
            "field `ammo` is 3 bytes, which reads as no number; 12 was seen when the capture was taken"
        );
        Ok(())
    }

    #[test]
    fn other_snapshot_claims_read_the_bytes_of_a_live_capture() -> Result<(), CheckError> {
        let (stored, memory) = live_capture()?;
        let format = ClaimKind::Format(ledger_core::Format {
            type_name: "Player".into(),
            spec: serde_json::json!({"seq": [{"id": "hp", "type": "u4le", "valid": 73}]}),
            exact: false,
        });
        let check = |bytes: &[u8]| {
            let evidence = [(EvidenceId::of(bytes), EvidenceKind::LiveSnapshot, bytes)];
            check_claim(
                &ClaimId::of(b"f"),
                &format,
                &evidence,
                Duration::from_secs(5),
            )
        };
        assert!(matches!(check(&stored)?, Verdict::Held { .. }));
        // The bytes without the line that says what they are do not count as a capture.
        assert!(matches!(check(&memory), Err(CheckError::Malformed(..))));
        Ok(())
    }

    fn format_detail(claim: &ledger_core::Format, bytes: &[u8]) -> String {
        match FormatChecker.check(claim, &[item(b"e", bytes)], soon()) {
            Ok(Verdict::Refuted { counterexample }) => counterexample.detail,
            Ok(Verdict::Held { .. }) => "held".to_owned(),
            other => format!("{other:?}"),
        }
    }

    #[test]
    fn formats_are_read_to_the_first_disagreement() {
        let claim = |exact| ledger_core::Format {
            type_name: "TokenTable".into(),
            spec: serde_json::json!({
                "meta": {"endian": "le", "encoding": "ASCII"},
                "seq": [
                    {"id": "magic", "contents": "JSAV"},
                    {"id": "count", "type": "u2", "valid": {"max": 4}},
                    {"id": "records", "type": "record", "repeat": "expr", "repeat-expr": "count"},
                    {"id": "names", "type": "strz", "repeat": "expr", "repeat-expr": "count"}
                ],
                "types": {"record": {"seq": [
                    {"id": "kind", "type": "u1", "valid": {"any-of": [1, 2]}},
                    {"id": "len", "type": "u1"}
                ]}}
            }),
            exact,
        };
        let detail = format_detail;
        // The names start where the records end, which the count decides.
        let file = b"JSAV\x02\x00\x01\x05\x02\x03alpha\0map\0";
        assert_eq!(detail(&claim(true), file), "held");
        assert_eq!(
            detail(&claim(false), b"JSAW\x02\x00"),
            "at +0x0, `magic` is 4a534157, not 4a534156"
        );
        assert_eq!(
            detail(&claim(false), b"JSAV\x09\x00"),
            "at +0x4, `count` is 9, over the most allowed, 4"
        );
        assert_eq!(
            detail(&claim(false), b"JSAV\x02\x00\x01\x05\x07\x03alpha\0map\0"),
            "at +0x8, `records[1].kind` is 7, not one of 1, 2"
        );
        assert_eq!(
            detail(&claim(false), b"JSAV\x02\x00\x01\x05\x02\x03alpha\0map"),
            "at +0x10, `names[1]` has no NUL before the end"
        );
        assert_eq!(
            detail(&claim(false), b"JSAV\x02\x00\x01"),
            "at +0x7, `records[0].len` needs 1 bytes, 0 are left"
        );
        assert_eq!(detail(&claim(false), b"JSAV\x00\x00more"), "held");
        assert_eq!(
            detail(&claim(true), b"JSAV\x00\x00more"),
            "the top-level fields end at +0x6, the file at +0xa"
        );
    }

    #[test]
    fn a_check_survives_a_hostile_description_or_file() {
        let detail = format_detail;
        let file = b"JSAV\x02\x00\x01\x05\x02\x03alpha\0map\0";
        // What a hostile file or description could use to crash a check is refused instead.
        let hostile = |instances: serde_json::Value| ledger_core::Format {
            type_name: "TokenTable".into(),
            spec: serde_json::json!({
                "seq": [
                    {"id": "count", "type": "u1"},
                    {"id": "items", "type": "item", "repeat": "expr", "repeat-expr": "count"}
                ],
                "instances": instances,
                "types": {"item": {
                    "seq": [{"id": "next", "type": "u1"}],
                    "instances": {"depth": {
                        "value": "next == 255 ? 0 : _parent.items[next].depth + 1"
                    }}
                }}
            }),
            exact: false,
        };
        // Each item names the next one, so the first rests on all the others.
        let chain = |len: u8| {
            let mut file = vec![len];
            file.extend(1..len);
            file.push(255);
            file
        };
        let plain = hostile(serde_json::json!({}));
        assert_eq!(detail(&plain, &chain(50)), "held");
        assert_eq!(
            detail(&plain, &chain(100)),
            "`items[64].depth` rests on more than 64 other instances"
        );
        let least = "(0 - 170141183460469231731687303715884105727 - 1)";
        let overflow = hostile(serde_json::json!({
            "rem": {"value": format!("{least} % (0 - 1)")}
        }));
        assert_eq!(
            detail(&overflow, &chain(1)),
            "a number too large to compute with"
        );

        // A description that never moves forward is stopped, and the file then says nothing.
        let stuck = ledger_core::Format {
            type_name: "TokenTable".into(),
            spec: serde_json::json!({"seq": [
                {"id": "magic", "contents": "J"},
                {"id": "pad", "size": 0, "repeat": "eos"}
            ]}),
            exact: false,
        };
        assert!(
            detail(&stuck, file).starts_with("Ok(Inconclusive { reason: \"a file holds more than")
        );
        assert_eq!(detail(&stuck, b"J"), "held");
    }

    #[test]
    fn response_header_claims_hold_refute_and_keep_the_value_out() -> Result<(), CheckError> {
        let claim = |header: &str, value: serde_json::Value| ledger_core::ResponseHeader {
            endpoint: "POST /login".into(),
            status: 200,
            header: header.into(),
            value,
        };
        let mut capture = exchange("/login", ("a", "b"), "", 200, &serde_json::json!({}));
        if let Some(response) = &mut capture.response {
            let line = |name: &str, value: &str| Header {
                name: name.into(),
                value: value.into(),
            };
            response.headers = vec![
                line("Set-Cookie", "theme=dark"),
                line("set-cookie", "session=s3cret; HttpOnly"),
                line("Strict-Transport-Security", "max-age=63072000"),
            ];
        }
        let verdict =
            |claim| ResponseHeaderChecker.check(&claim, &[item(b"e", capture.clone())], soon());
        assert!(matches!(
            verdict(claim(
                "strict-transport-security",
                serde_json::json!({"pattern": "^max-age="})
            ))?,
            Verdict::Held { .. }
        ));
        // Two cookies are set; the claim holds if one of them matches.
        assert!(matches!(
            verdict(claim(
                "set-cookie",
                serde_json::json!({"pattern": "HttpOnly"})
            ))?,
            Verdict::Held { .. }
        ));
        let Verdict::Refuted { counterexample } = verdict(claim(
            "set-cookie",
            serde_json::json!({"pattern": "Secure"}),
        ))?
        else {
            return Err(CheckError::InvalidClaim("expected a refutation".into()));
        };
        assert!(
            !counterexample.detail.contains("s3cret"),
            "{}",
            counterexample.detail
        );
        assert!(
            matches!(verdict(claim("x-frame-options", serde_json::json!(true)))?, Verdict::Refuted { counterexample } if counterexample.detail.ends_with("missing"))
        );
        Ok(())
    }

    /// A made-up save header: magic, version 113, a size, a float time, a map name,
    /// padding and a pointer.
    fn save_header(size: u32, time: f32, map: [u8; 8]) -> Vec<u8> {
        let mut bytes = b"JSAV".to_vec();
        bytes.extend(113u32.to_le_bytes());
        bytes.extend(size.to_le_bytes());
        bytes.extend(time.to_le_bytes());
        bytes.extend(map);
        bytes.extend([0; 4]);
        bytes.extend(0x0804_9000_u32.to_le_bytes());
        bytes
    }

    /// Seeded errors for layouts: one field of the true claim moved or retyped at a time.
    #[test]
    fn seeded_wrong_layouts_are_refuted() -> Result<(), CheckError> {
        let headers = [
            save_header(8544, 12.5, *b"c1a0\0\0\0\0"),
            save_header(512, 903.0, *b"c2a4e\0zz"),
        ];
        let field = |name: &str, offset, len, is| FieldLayout {
            name: name.into(),
            offset,
            len,
            is: Some(is),
        };
        let truth = vec![
            field("magic", 0, 4, FieldKind::Bytes("4a534156".into())),
            field("version", 4, 4, FieldKind::Uint { min: 113, max: 113 }),
            field(
                "size",
                8,
                4,
                FieldKind::Int {
                    min: 1,
                    max: 1 << 20,
                },
            ),
            field(
                "time",
                12,
                4,
                FieldKind::Float {
                    min: 0,
                    max: 100_000,
                },
            ),
            field("map", 16, 8, FieldKind::Text { min: 3 }),
            field("pad", 24, 4, FieldKind::Zero),
            field(
                "next",
                28,
                4,
                FieldKind::Pointer {
                    min: 0x0804_8000,
                    max: 0x0805_0000,
                },
            ),
        ];
        let layout = |fields: Vec<FieldLayout>| {
            ClaimKind::MemoryLayout(MemoryLayout {
                type_name: "SaveHeader".into(),
                size: 32,
                fields,
            })
        };
        // Each wrong claim changes one field of the true one.
        let wrong = |at: usize, offset, is| {
            let mut fields = truth.clone();
            fields[at].offset = offset;
            fields[at].is = Some(is);
            layout(fields)
        };
        let seeded = [
            wrong(0, 0, FieldKind::Bytes("56415356".into())),
            wrong(1, 4, FieldKind::Uint { min: 112, max: 112 }),
            wrong(1, 8, FieldKind::Uint { min: 113, max: 113 }),
            wrong(2, 8, FieldKind::Int { min: 1, max: 1000 }),
            wrong(2, 8, FieldKind::OneOf([8544].into())),
            wrong(
                3,
                8,
                FieldKind::Float {
                    min: 0,
                    max: 100_000,
                },
            ),
            wrong(4, 12, FieldKind::Text { min: 1 }),
            wrong(4, 16, FieldKind::Text { min: 6 }),
            wrong(5, 20, FieldKind::Zero),
            wrong(
                6,
                28,
                FieldKind::Pointer {
                    min: 0x4000_0000,
                    max: 0x5000_0000,
                },
            ),
            ClaimKind::MemoryLayout(MemoryLayout {
                type_name: "SaveHeader".into(),
                size: 33,
                fields: truth.clone(),
            }),
        ];
        let kind = EvidenceKind::MemorySnapshot;
        assert_eq!(refuted(&[layout(truth.clone())], kind, &headers)?, 0);
        assert_eq!(refuted(&seeded, kind, &headers)?, seeded.len());
        // A claim that only places fields asserts nothing a snapshot can contradict.
        let mut placed = truth.clone();
        for f in &mut placed {
            f.is = None;
        }
        placed[1].offset = 5;
        placed[1].len = 3;
        assert_eq!(refuted(&[layout(placed)], kind, &headers)?, 0);
        Ok(())
    }

    #[test]
    fn call_edges_replay_on_a_rizin_export() -> Result<(), Box<dyn std::error::Error>> {
        // What Rizin prints, one line per command, cut down to three functions. `main`
        // calls an import through its relocation, calls a function, jumps inside itself,
        // jumps into a piece of itself that Rizin split off as a function, and ends by
        // jumping to another import. The piece ends by jumping to the function `main` calls.
        let output = br#"{"bintype":"elf","arch":"x86"}
            {"md5":"b6","sha256":"31"}
            [{"ordinal":1,"name":"setlocale"},{"ordinal":2,"name":"free"},{"name":"exit"}]
            [{"name":"setlocale","vaddr":40864},{"name":"free","vaddr":40568},
                {"name":"exit","vaddr":40900}]
            [{"offset":9344,"name":"main","size":262,"callrefs":[
                {"from":9350,"to":40864,"type":"CALL"},
                {"from":9360,"to":9616,"type":"CALL"},
                {"from":9370,"to":9400,"type":"CODE"},
                {"from":9380,"to":40900,"type":"CODE"},
                {"from":9390,"to":9408,"type":"CODE"}]},
            {"offset":9408,"name":"fcn.000024c0","callrefs":[
                {"from":9412,"to":9616,"type":"CODE"}]},
            {"offset":9616,"name":"fcn.00002590","callrefs":[]}]"#;
        let facts = rizin_facts("rizin 0.9.1", output)?;
        assert_eq!(facts.tool, format!("rizin 0.9.1 ({RIZIN_COMMANDS})"));
        // Only imports that are called are kept.
        assert_eq!(
            facts.imports.iter().collect::<Vec<_>>(),
            [
                (&40864, &"setlocale".to_owned()),
                (&40900, &"exit".to_owned())
            ]
        );
        let stored = serde_json::to_vec(&facts)?;
        // Output cut short, or of a file with no code, is refused, not stored as empty facts.
        assert!(rizin_facts("rizin", &output[..90]).is_err());
        assert!(rizin_facts("rizin", br#"{"bintype":"elf"} {"sha256":"31"} [] [] []"#).is_err());
        // Rizin finds "functions" in any bytes; a file of no known format is refused.
        let text = br#"{"bintype":null} {"sha256":"31"} [] [] [{"offset":0,"name":"fcn.0"}]"#;
        assert!(rizin_facts("rizin", text).is_err());
        let check = |caller, callee, kind| {
            let claim = ClaimKind::CallEdge(ledger_core::CallEdge {
                binary: "true".into(),
                caller,
                callee,
            });
            let evidence = (EvidenceId::of(&stored), kind, &stored[..]);
            check_claim(
                &ClaimId::of(b"c"),
                &claim,
                &[evidence],
                Duration::from_secs(5),
            )
        };
        let detail = |caller, callee| match check(caller, callee, EvidenceKind::BinaryFacts) {
            Ok(Verdict::Held { .. }) => Ok(String::from("held")),
            Ok(Verdict::Refuted { counterexample }) => Ok(counterexample.detail),
            Ok(Verdict::Inconclusive { reason }) => Ok(format!("inconclusive: {reason}")),
            Err(e) => Err(e.to_string()),
        };
        let named = |name: &str| FunctionRef::Name(name.into());
        let at = FunctionRef::Address;
        assert_eq!(detail(named("main"), named("setlocale"))?, "held");
        assert_eq!(detail(at(9344), at(9616))?, "held");
        assert_eq!(detail(at(9344), named("fcn.00002590"))?, "held");
        // A jump out to an import is a tail call. A jump inside the function is not a
        // call, and an import nothing calls is not a callee.
        assert_eq!(detail(named("main"), named("exit"))?, "held");
        assert_eq!(
            detail(named("main"), at(9400))?,
            "`main` at 0x2480 does not call the function at 0x24b8 directly; its 3 direct calls go to: fcn.00002590, setlocale, exit"
        );
        // A jump into a piece Rizin split off is not a call either; a jump to a
        // function something calls is a tail call.
        // A jump to a function nothing calls is a tail call or a jump inside one function
        // that Rizin split in two. The export cannot tell, so the answer is neither.
        assert_eq!(
            detail(named("main"), named("fcn.000024c0"))?,
            "inconclusive: `main` jumps to `fcn.000024c0`, which nothing calls: a tail call, or a jump inside one function that the analysis split in two. The export cannot tell which"
        );
        assert_eq!(detail(at(9408), named("fcn.00002590"))?, "held");
        assert_eq!(
            detail(named("main"), named("free"))?,
            "`free` is neither a recovered function nor an import that is called"
        );
        assert_eq!(
            detail(named("fcn.00002590"), named("main"))?,
            "`fcn.00002590` at 0x2590 does not call `main` directly; it makes no direct calls"
        );
        // A function the tool did not recover is not evidence against a call from it.
        assert!(matches!(
            check(at(9345), named("main"), EvidenceKind::BinaryFacts),
            Err(CheckError::NotApplicable(..))
        ));
        assert!(matches!(
            check(
                named("main"),
                named("setlocale"),
                EvidenceKind::MemorySnapshot
            ),
            Err(CheckError::WrongEvidence(EvidenceKind::MemorySnapshot))
        ));
        Ok(())
    }

    #[test]
    fn limits_never_yield_held() -> Result<(), CheckError> {
        let claim = ClaimKind::MemoryLayout(MemoryLayout {
            type_name: "Player".into(),
            size: 8,
            fields: vec![],
        });
        let id = ClaimId::of(b"c");
        let snapshot = (
            EvidenceId::of(b"s"),
            EvidenceKind::MemorySnapshot,
            &[0u8; 8][..],
        );
        let out_of_time =
            check_claim(&id, &claim, std::slice::from_ref(&snapshot), Duration::ZERO)?;
        assert!(matches!(out_of_time, Verdict::Inconclusive { .. }));

        let schema = ClaimKind::ResponseSchema(ResponseSchema {
            endpoint: "POST /p".into(),
            status: 200,
            schema: serde_json::json!({}),
        });
        let huge = vec![b' '; MAX_PARSED_EVIDENCE + 1];
        let oversized = (EvidenceId::of(b"h"), EvidenceKind::HttpExchange, &huge[..]);
        let limit = Duration::from_secs(5);
        assert!(matches!(
            check_claim(&id, &schema, &[oversized], limit),
            Err(CheckError::TooLarge(..))
        ));
        let garbage = (
            EvidenceId::of(b"g"),
            EvidenceKind::HttpExchange,
            &b"\xff{["[..],
        );
        assert!(matches!(
            check_claim(&id, &schema, &[garbage], limit),
            Err(CheckError::Malformed(..))
        ));
        assert!(matches!(
            check_claim(&id, &schema, &[snapshot], limit),
            Err(CheckError::WrongEvidence(EvidenceKind::MemorySnapshot))
        ));
        Ok(())
    }

    #[test]
    fn memory_layout_refutes_short_snapshot() -> Result<(), CheckError> {
        let claim = MemoryLayout {
            type_name: "Player".into(),
            size: 8,
            fields: vec![FieldLayout {
                name: "hp".into(),
                offset: 0,
                len: 4,
                is: None,
            }],
        };
        let v = MemoryLayoutChecker.check(
            &claim,
            &[item(b"a", plain(&[0; 8])), item(b"b", plain(&[0; 4]))],
            soon(),
        )?;
        assert!(
            matches!(v, Verdict::Refuted { counterexample } if counterexample.evidence == EvidenceId::of(b"b"))
        );
        Ok(())
    }

    #[test]
    fn signature_replay_holds_for_rfc4231_case_2() -> Result<(), CheckError> {
        let claim = RequestSignature {
            endpoint: "POST /x".into(),
            header: "X-Sig".into(),
            algorithm: SigAlgorithm::HmacSha256,
            encoding: SigEncoding::Hex,
            key: EvidenceId::of(b"Jefe"),
            signed: vec![],
        };
        let sig = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";
        let body = "what do ya want for nothing?";
        let req = exchange("/x", ("X-Sig", sig), body, 200, &serde_json::json!({}));
        assert_eq!(
            SignatureChecker { key: b"Jefe" }.check(&claim, &[item(b"r", req)], soon())?,
            Verdict::Held {
                runs: NonZeroU64::MIN
            }
        );
        Ok(())
    }

    #[test]
    fn schema_refutes_wrong_type() -> Result<(), CheckError> {
        let claim = ResponseSchema {
            endpoint: "POST /p".into(),
            status: 200,
            schema: serde_json::json!({"type": "object", "properties": {"level": {"type": "integer"}}}),
        };
        let ok = exchange("/p", ("a", "b"), "", 200, &serde_json::json!({"level": 3}));
        let bad = exchange(
            "/p",
            ("a", "b"),
            "",
            200,
            &serde_json::json!({"level": "3"}),
        );
        let v = SchemaChecker.check(&claim, &[item(b"ok", ok), item(b"bad", bad)], soon())?;
        assert!(
            matches!(v, Verdict::Refuted { counterexample } if counterexample.detail.contains("/level"))
        );
        Ok(())
    }
}
