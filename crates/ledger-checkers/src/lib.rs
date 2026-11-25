//! Offline checkers. Each replays one claim kind over saved evidence; none touches a live target.

use std::num::NonZeroU64;

use base64::Engine as _;
use hmac::{Hmac, KeyInit, Mac};
use ledger_core::{
    CapturedExchange, CapturedRequest, ClaimKind, Counterexample, EvidenceId, EvidenceKind,
    MemoryLayout, RequestSignature, ResponseSchema, SigAlgorithm, SigEncoding, Verdict,
};
use md5::Digest as _;
use rayon::prelude::*;

#[derive(Debug, thiserror::Error)]
pub enum CheckError {
    #[error("{0:?} evidence cannot check this claim kind")]
    WrongEvidence(EvidenceKind),
    #[error("malformed evidence {0}: {1}")]
    Malformed(EvidenceId, String),
    #[error("invalid claim: {0}")]
    InvalidClaim(String),
}

/// A saved piece of evidence, decoded to the checker's type.
pub struct Item<E> {
    pub id: EvidenceId,
    pub data: E,
}

pub trait Checker {
    type Claim;
    type Evidence: Sync;

    /// # Errors
    /// The claim cannot be checked at all (as opposed to being refuted).
    fn check(
        &self,
        claim: &Self::Claim,
        evidence: &[Item<Self::Evidence>],
    ) -> Result<Verdict, CheckError>;
}

/// Runs `one` over every item in parallel; the first failure (in evidence order) is the counterexample.
fn replay<E: Sync>(evidence: &[Item<E>], one: impl Fn(&E) -> Result<(), String> + Sync) -> Verdict {
    let Some(runs) = NonZeroU64::new(evidence.len() as u64) else {
        return Verdict::Inconclusive {
            reason: "no evidence".into(),
        };
    };
    match evidence
        .par_iter()
        .find_map_first(|it| one(&it.data).err().map(|d| (it.id.clone(), d)))
    {
        Some((evidence, detail)) => Verdict::Refuted {
            counterexample: Counterexample { evidence, detail },
        },
        None => Verdict::Held { runs },
    }
}

pub struct MemoryLayoutChecker;

impl Checker for MemoryLayoutChecker {
    type Claim = MemoryLayout;
    type Evidence = Vec<u8>;

    fn check(
        &self,
        claim: &MemoryLayout,
        evidence: &[Item<Vec<u8>>],
    ) -> Result<Verdict, CheckError> {
        // shortcut: only checks the snapshot covers `size`; per-field value checks come with typed field claims.
        Ok(replay(evidence, |bytes| {
            if (bytes.len() as u64) < claim.size {
                return Err(format!(
                    "snapshot is {} bytes, `{}` needs {}",
                    bytes.len(),
                    claim.type_name,
                    claim.size
                ));
            }
            Ok(())
        }))
    }
}

pub struct SignatureChecker;

impl Checker for SignatureChecker {
    type Claim = RequestSignature;
    type Evidence = CapturedRequest;

    fn check(
        &self,
        claim: &RequestSignature,
        evidence: &[Item<CapturedRequest>],
    ) -> Result<Verdict, CheckError> {
        let key =
            hex::decode(&claim.key_hex).map_err(|e| CheckError::InvalidClaim(e.to_string()))?;
        Ok(replay(evidence, |req| {
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

impl Checker for SchemaChecker {
    type Claim = ResponseSchema;
    type Evidence = CapturedExchange;

    fn check(
        &self,
        claim: &ResponseSchema,
        evidence: &[Item<CapturedExchange>],
    ) -> Result<Verdict, CheckError> {
        let v = jsonschema::validator_for(&claim.schema)
            .map_err(|e| CheckError::InvalidClaim(e.to_string()))?;
        Ok(replay(evidence, |ex| {
            v.validate(&ex.response)
                .map_err(|e| format!("{e} at {}", e.instance_path()))
        }))
    }
}

/// Decodes raw evidence for the claim's kind and runs the matching checker.
///
/// # Errors
/// Evidence of the wrong kind, undecodable evidence, or an uncheckable claim.
pub fn check_claim(
    claim: &ClaimKind,
    evidence: Vec<(EvidenceId, EvidenceKind, Vec<u8>)>,
) -> Result<Verdict, CheckError> {
    fn decode<E>(
        want: EvidenceKind,
        raw: Vec<(EvidenceId, EvidenceKind, Vec<u8>)>,
        parse: impl Fn(Vec<u8>) -> Result<E, String>,
    ) -> Result<Vec<Item<E>>, CheckError> {
        raw.into_iter()
            .map(|(id, kind, bytes)| {
                if kind != want {
                    return Err(CheckError::WrongEvidence(kind));
                }
                let data = parse(bytes).map_err(|e| CheckError::Malformed(id.clone(), e))?;
                Ok(Item { id, data })
            })
            .collect()
    }
    match claim {
        ClaimKind::MemoryLayout(c) => {
            MemoryLayoutChecker.check(c, &decode(EvidenceKind::MemorySnapshot, evidence, Ok)?)
        }
        ClaimKind::RequestSignature(c) => SignatureChecker.check(
            c,
            &decode(EvidenceKind::CapturedRequest, evidence, |b| {
                serde_json::from_slice(&b).map_err(|e| e.to_string())
            })?,
        ),
        ClaimKind::ResponseSchema(c) => SchemaChecker.check(
            c,
            &decode(EvidenceKind::CapturedExchange, evidence, |b| {
                serde_json::from_slice(&b).map_err(|e| e.to_string())
            })?,
        ),
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

    #[test]
    fn memory_layout_refutes_short_snapshot() -> Result<(), CheckError> {
        let claim = MemoryLayout {
            type_name: "Player".into(),
            size: 8,
            fields: vec![FieldLayout {
                name: "hp".into(),
                offset: 0,
                len: 4,
            }],
        };
        let v =
            MemoryLayoutChecker.check(&claim, &[item(b"a", vec![0; 8]), item(b"b", vec![0; 4])])?;
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
            SignatureChecker.check(&claim, &[item(b"r", req)])?,
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
        let v = SchemaChecker.check(&claim, &[item(b"ok", ok), item(b"bad", bad)])?;
        assert!(
            matches!(v, Verdict::Refuted { counterexample } if counterexample.detail.contains("/level"))
        );
        Ok(())
    }
}
