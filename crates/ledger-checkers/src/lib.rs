//! Offline checkers. Each replays one claim kind over saved evidence; none touches a live target.

use std::num::NonZeroU64;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use base64::Engine as _;
use hmac::{Hmac, KeyInit, Mac};
use ledger_core::{
    CapturedExchange, CapturedRequest, ClaimId, ClaimKind, Counterexample, EvidenceId,
    EvidenceKind, FieldKind, MemoryLayout, RequestSignature, ResponseSchema, SigAlgorithm,
    SigEncoding, Verdict,
};
use md5::Digest as _;
use rayon::prelude::*;

#[derive(Debug, thiserror::Error)]
pub enum CheckError {
    #[error("{0:?} evidence cannot check this claim kind")]
    WrongEvidence(EvidenceKind),
    #[error("malformed evidence {0}: {1}")]
    Malformed(EvidenceId, String),
    #[error("evidence {0} is {1} bytes, over the {2} byte limit for its format")]
    TooLarge(EvidenceId, usize, usize),
    #[error("invalid claim: {0}")]
    InvalidClaim(String),
}

/// A saved piece of evidence, decoded to the checker's type.
pub struct Item<E> {
    pub id: EvidenceId,
    pub data: E,
}

/// Parsed evidence formats (JSON) are refused above this size. Snapshots are only sliced, never parsed.
pub const MAX_PARSED_EVIDENCE: usize = 16 << 20;

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
    let failure = evidence.par_iter().find_map_first(|it| {
        if Instant::now() >= deadline {
            late.store(true, Ordering::Relaxed);
            return None;
        }
        one(&it.data).err().map(|d| (it.id.clone(), d))
    });
    match failure {
        Some((evidence, detail)) => Verdict::Refuted {
            counterexample: Counterexample { evidence, detail },
        },
        None if late.load(Ordering::Relaxed) => Verdict::Inconclusive {
            reason: "time limit reached before all evidence was replayed".into(),
        },
        None => Verdict::Held { runs },
    }
}

pub struct MemoryLayoutChecker;

impl<'e> Checker<'e> for MemoryLayoutChecker {
    const ID: &'static str = "memory_layout";
    const VERSION: u32 = 3;
    type Claim = MemoryLayout;
    type Evidence = &'e [u8];

    fn check(
        &self,
        claim: &MemoryLayout,
        evidence: &[Item<&'e [u8]>],
        deadline: Instant,
    ) -> Result<Verdict, CheckError> {
        Ok(replay(evidence, deadline, |bytes| {
            if (bytes.len() as u64) < claim.size {
                return Err(format!(
                    "snapshot is {} bytes, `{}` needs {}",
                    bytes.len(),
                    claim.type_name,
                    claim.size
                ));
            }
            for field in &claim.fields {
                let Some(kind) = &field.is else { continue };
                // The claim may not have been through admission, so nothing is assumed to fit.
                let found = usize::try_from(field.offset)
                    .ok()
                    .zip(usize::try_from(field.len).ok())
                    .and_then(|(at, len)| bytes.get(at..at.checked_add(len)?))
                    .ok_or_else(|| format!("field `{}` lies outside the snapshot", field.name))?;
                field_holds(kind, found).map_err(|why| {
                    format!("field `{}` at +{:#x} {why}", field.name, field.offset)
                })?;
            }
            Ok(())
        }))
    }
}

/// Little-endian unsigned value of up to 8 bytes.
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
            // Shift the field's top bit up to bit 63 and back down to extend its sign.
            let shift = 64 - 8 * u32::try_from(bytes.len()).unwrap_or(8);
            let value = i64::from_le_bytes((uint(bytes) << shift).to_le_bytes()) >> shift;
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

pub struct SignatureChecker;

impl Checker<'_> for SignatureChecker {
    const ID: &'static str = "request_signature";
    const VERSION: u32 = 1;
    type Claim = RequestSignature;
    type Evidence = CapturedRequest;

    fn check(
        &self,
        claim: &RequestSignature,
        evidence: &[Item<CapturedRequest>],
        deadline: Instant,
    ) -> Result<Verdict, CheckError> {
        let key =
            hex::decode(&claim.key_hex).map_err(|e| CheckError::InvalidClaim(e.to_string()))?;
        Ok(replay(evidence, deadline, |req| {
            let got = req
                .headers
                .get(&claim.header)
                .ok_or_else(|| format!("header `{}` missing", claim.header))?;
            let mac = sign(claim.algorithm, &key, req.body.as_bytes())?;
            let want = match claim.encoding {
                SigEncoding::Hex => hex::encode(mac),
                SigEncoding::Base64 => base64::engine::general_purpose::STANDARD.encode(mac),
            };
            if got.eq_ignore_ascii_case(&want) {
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
    const VERSION: u32 = 1;
    type Claim = ResponseSchema;
    type Evidence = CapturedExchange;

    fn check(
        &self,
        claim: &ResponseSchema,
        evidence: &[Item<CapturedExchange>],
        deadline: Instant,
    ) -> Result<Verdict, CheckError> {
        let v = jsonschema::validator_for(&claim.schema)
            .map_err(|e| CheckError::InvalidClaim(e.to_string()))?;
        Ok(replay(evidence, deadline, |ex| {
            v.validate(&ex.response)
                .map_err(|e| format!("{e} at {}", e.instance_path()))
        }))
    }
}

/// Saved evidence as stored: its id, its declared kind and its bytes.
pub type Raw<'e> = (EvidenceId, EvidenceKind, &'e [u8]);

/// Decodes raw evidence for the claim's kind and runs the matching checker
/// inside a trace span, giving it `limit` to finish.
///
/// # Errors
/// Evidence of the wrong kind, oversized or undecodable evidence, or an uncheckable claim.
pub fn check_claim(
    id: &ClaimId,
    claim: &ClaimKind,
    evidence: &[Raw<'_>],
    limit: Duration,
) -> Result<Verdict, CheckError> {
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
                    data,
                })
            })
            .collect()
    }
    fn run<'e, C: Checker<'e>>(
        checker: &C,
        id: &ClaimId,
        claim: &C::Claim,
        evidence: Result<Vec<Item<C::Evidence>>, CheckError>,
        limit: Duration,
    ) -> Result<Verdict, CheckError> {
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
    let json = MAX_PARSED_EVIDENCE;
    match claim {
        ClaimKind::MemoryLayout(c) => {
            let items = decode(EvidenceKind::MemorySnapshot, usize::MAX, evidence, Ok);
            run(&MemoryLayoutChecker, id, c, items, limit)
        }
        ClaimKind::RequestSignature(c) => {
            let items = decode(EvidenceKind::CapturedRequest, json, evidence, |b| {
                serde_json::from_slice(b).map_err(|e| e.to_string())
            });
            run(&SignatureChecker, id, c, items, limit)
        }
        ClaimKind::ResponseSchema(c) => {
            let items = decode(EvidenceKind::CapturedExchange, json, evidence, |b| {
                serde_json::from_slice(b).map_err(|e| e.to_string())
            });
            run(&SchemaChecker, id, c, items, limit)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ledger_core::FieldLayout;
    use std::collections::BTreeMap;

    fn item<E>(name: &[u8], data: E) -> Item<E> {
        Item {
            id: EvidenceId::of(name),
            data,
        }
    }

    fn soon() -> Instant {
        Instant::now() + Duration::from_secs(5)
    }

    fn signed(claim: &RequestSignature, body: &str) -> Result<Vec<u8>, CheckError> {
        let key =
            hex::decode(&claim.key_hex).map_err(|e| CheckError::InvalidClaim(e.to_string()))?;
        let mac = sign(claim.algorithm, &key, body.as_bytes()).map_err(CheckError::InvalidClaim)?;
        let request =
            serde_json::json!({"headers": {&claim.header: hex::encode(mac)}, "body": body});
        Ok(request.to_string().into_bytes())
    }

    /// Runs every claim over the same evidence and returns how many were refuted.
    fn refuted(
        claims: &[ClaimKind],
        kind: EvidenceKind,
        evidence: &[Vec<u8>],
    ) -> Result<usize, CheckError> {
        let raw: Vec<Raw<'_>> = (evidence.iter())
            .map(|bytes| (EvidenceId::of(bytes), kind, &bytes[..]))
            .collect();
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
            endpoint: "/score".into(),
            header: "X-Sig".into(),
            algorithm: SigAlgorithm::HmacSha256,
            encoding: SigEncoding::Hex,
            key_hex: "00ff10".into(),
        };
        let requests = [signed(&truth, "score=10")?, signed(&truth, "score=9000")?];
        let wrong = |edit: fn(&mut RequestSignature)| {
            let mut claim = truth.clone();
            edit(&mut claim);
            ClaimKind::RequestSignature(claim)
        };
        let seeded = [
            wrong(|c| c.key_hex = "00ff11".into()),
            wrong(|c| c.algorithm = SigAlgorithm::HmacSha1),
            wrong(|c| c.algorithm = SigAlgorithm::KeyedMd5),
            wrong(|c| c.encoding = SigEncoding::Base64),
            wrong(|c| c.header = "X-Signature".into()),
        ];
        let kind = EvidenceKind::CapturedRequest;
        assert_eq!(
            refuted(
                &[ClaimKind::RequestSignature(truth.clone())],
                kind,
                &requests
            )?,
            0
        );
        assert_eq!(refuted(&seeded, kind, &requests)?, seeded.len());

        let responses = [
            br#"{"response": {"level": 3, "name": "ann"}}"#.to_vec(),
            br#"{"response": {"level": 70, "name": "bo"}}"#.to_vec(),
        ];
        let schema = |schema: serde_json::Value| {
            ClaimKind::ResponseSchema(ResponseSchema {
                endpoint: "/profile".into(),
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
        let kind = EvidenceKind::CapturedExchange;
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
            endpoint: "/p".into(),
            schema: serde_json::json!({}),
        });
        let huge = vec![b' '; MAX_PARSED_EVIDENCE + 1];
        let oversized = (
            EvidenceId::of(b"h"),
            EvidenceKind::CapturedExchange,
            &huge[..],
        );
        let limit = Duration::from_secs(5);
        assert!(matches!(
            check_claim(&id, &schema, &[oversized], limit),
            Err(CheckError::TooLarge(..))
        ));
        let garbage = (
            EvidenceId::of(b"g"),
            EvidenceKind::CapturedExchange,
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
            &[item(b"a", &[0; 8][..]), item(b"b", &[0; 4][..])],
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
            endpoint: "/x".into(),
            header: "X-Sig".into(),
            algorithm: SigAlgorithm::HmacSha256,
            encoding: SigEncoding::Hex,
            key_hex: hex::encode("Jefe"),
        };
        let sig = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";
        let req = CapturedRequest {
            headers: BTreeMap::from([("X-Sig".into(), sig.into())]),
            body: "what do ya want for nothing?".into(),
        };
        assert_eq!(
            SignatureChecker.check(&claim, &[item(b"r", req)], soon())?,
            Verdict::Held {
                runs: NonZeroU64::MIN
            }
        );
        Ok(())
    }

    #[test]
    fn schema_refutes_wrong_type() -> Result<(), CheckError> {
        let claim = ResponseSchema {
            endpoint: "/p".into(),
            schema: serde_json::json!({"type": "object", "properties": {"level": {"type": "integer"}}}),
        };
        let ok = CapturedExchange {
            response: serde_json::json!({"level": 3}),
        };
        let bad = CapturedExchange {
            response: serde_json::json!({"level": "3"}),
        };
        let v = SchemaChecker.check(&claim, &[item(b"ok", ok), item(b"bad", bad)], soon())?;
        assert!(
            matches!(v, Verdict::Refuted { counterexample } if counterexample.detail.contains("/level"))
        );
        Ok(())
    }
}
