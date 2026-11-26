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
            pub const fn as_str(&self) -> &str {
                self.0.as_str()
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

/// What a field's bytes must look like in every snapshot. Integers, floats and
/// pointers are little-endian.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FieldKind {
    /// Exactly these bytes, as hex: a magic number or a fixed tag.
    Bytes(String),
    /// Unsigned integer of 1, 2, 4 or 8 bytes within `min..=max`.
    Uint { min: u64, max: u64 },
    /// Signed integer of 1, 2, 4 or 8 bytes within `min..=max`.
    Int { min: i64, max: i64 },
    /// Float of 4 or 8 bytes within `min..=max` that is zero or normal: a subnormal
    /// value is what a small integer looks like when read as a float.
    Float { min: i32, max: i32 },
    /// Unsigned integer of 1, 2, 4 or 8 bytes equal to one of these values.
    OneOf(BTreeSet<u64>),
    /// Null, or an address of 4 or 8 bytes within `min..=max`.
    Pointer { min: u64, max: u64 },
    /// At least `min` printable ASCII characters, not all spaces, then a NUL
    /// inside the field.
    Text { min: u64 },
    /// Every byte zero: padding or a reserved field.
    Zero,
}

impl FieldKind {
    /// Whether the constraint suits a field of `len` bytes and rules anything out.
    fn fits(&self, len: u64) -> Result<(), &'static str> {
        let integer = matches!(len, 1 | 2 | 4 | 8);
        let top = match len {
            1 => 0xff,
            2 => 0xffff,
            4 => 0xffff_ffff,
            _ => u64::MAX,
        };
        let (low, high) = match len {
            1 => (i64::from(i8::MIN), i64::from(i8::MAX)),
            2 => (i64::from(i16::MIN), i64::from(i16::MAX)),
            4 => (i64::from(i32::MIN), i64::from(i32::MAX)),
            _ => (i64::MIN, i64::MAX),
        };
        let vacuous = "its range allows every value; drop `is` instead";
        let empty = "its range is empty or does not fit the field";
        match self {
            Self::Bytes(hex) => match hex::decode(hex) {
                Ok(bytes) if bytes.len() as u64 == len => Ok(()),
                _ => Err("`bytes` must be hex of exactly the field's length"),
            },
            Self::Uint { min, max } | Self::Pointer { min, max } => match () {
                () if !integer => Err("integers and pointers are 1, 2, 4 or 8 bytes"),
                () if min > max || *max > top => Err(empty),
                () if *min == 0 && *max == top => Err(vacuous),
                () => Ok(()),
            },
            Self::Int { min, max } => match () {
                () if !integer => Err("integers and pointers are 1, 2, 4 or 8 bytes"),
                () if min > max || *min < low || *max > high => Err(empty),
                () if *min == low && *max == high => Err(vacuous),
                () => Ok(()),
            },
            Self::Float { min, max } => match () {
                () if !matches!(len, 4 | 8) => Err("floats are 4 or 8 bytes"),
                () if min > max => Err(empty),
                () => Ok(()),
            },
            Self::OneOf(values) => match () {
                () if !integer => Err("integers and pointers are 1, 2, 4 or 8 bytes"),
                () if values.is_empty() || values.iter().any(|v| *v > top) => Err(empty),
                () => Ok(()),
            },
            Self::Text { min } if *min == 0 || *min >= len => {
                Err("`text` needs a `min` of at least 1 that leaves room for the NUL")
            }
            Self::Text { .. } | Self::Zero => Ok(()),
        }
    }
}

impl fmt::Display for FieldKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bytes(hex) => write!(f, "bytes {hex}"),
            Self::Uint { min, max } if min == max => write!(f, "{min}"),
            Self::Uint { min, max } => write!(f, "{min} to {max}"),
            Self::Int { min, max } if min == max => write!(f, "{min}"),
            Self::Int { min, max } => write!(f, "{min} to {max}"),
            Self::Float { min, max } => write!(f, "float {min} to {max}"),
            Self::OneOf(values) => {
                let values: Vec<String> = values.iter().map(u64::to_string).collect();
                write!(f, "one of {}", values.join(", "))
            }
            Self::Pointer { min, max } => write!(f, "null or address {min:#x} to {max:#x}"),
            Self::Text { min } => write!(f, "text of {min}+ characters"),
            Self::Zero => f.write_str("zero"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
pub struct FieldLayout {
    pub name: String,
    pub offset: u64,
    pub len: u64,
    /// What the bytes must look like in every snapshot. Without it the claim
    /// only places the field, and no snapshot can contradict that.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is: Option<FieldKind>,
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

/// One piece of what a request signature is computed over.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SignedPart {
    /// The request body.
    Body,
    /// The value of a request header, such as a timestamp or a nonce.
    Header(String),
    /// These exact characters, such as a separator.
    Text(String),
    /// The request method.
    Method,
    /// The URL's path, without the query string.
    Path,
    /// The URL's query string, without the `?`.
    Query,
}

/// A request header carries a signature over the request body, or over the
/// parts listed in `signed`. It is a claim about requests the server accepted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RequestSignature {
    /// `METHOD [host]/path`, see [`Endpoint`].
    pub endpoint: String,
    pub header: String,
    pub algorithm: SigAlgorithm,
    pub encoding: SigEncoding,
    /// Evidence of kind `secret` that holds the key's raw bytes. The key itself
    /// is never part of a claim, the event log or a response.
    pub key: EvidenceId,
    /// What is signed, in order, joined with nothing in between. Empty means the body alone.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signed: Vec<SignedPart>,
}

impl RequestSignature {
    /// What is signed, in words.
    fn signed_input(&self) -> String {
        let part = |p: &SignedPart| match p {
            SignedPart::Body => "the body".to_owned(),
            SignedPart::Header(name) => format!("header `{name}`"),
            SignedPart::Text(text) => format!("{text:?}"),
            SignedPart::Method => "the method".to_owned(),
            SignedPart::Path => "the path".to_owned(),
            SignedPart::Query => "the query string".to_owned(),
        };
        if self.signed.is_empty() {
            return "the body".to_owned();
        }
        self.signed.iter().map(part).collect::<Vec<_>>().join(" + ")
    }
}

/// Responses with one status from an endpoint conform to a JSON Schema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ResponseSchema {
    /// `METHOD [host]/path`, see [`Endpoint`].
    pub endpoint: String,
    /// The response status the schema describes. Other statuses are other claims.
    pub status: u16,
    pub schema: serde_json::Value,
}

/// Requests to an endpoint carry a header whose value matches a JSON Schema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RequestHeader {
    /// `METHOD [host]/path`, see [`Endpoint`].
    pub endpoint: String,
    pub header: String,
    /// A JSON Schema for the header's value, which is a string: `{"const": "application/json"}`,
    /// `{"pattern": "^Bearer "}`, `{"minLength": 32}`. `true` claims only that the header is sent.
    pub value: serde_json::Value,
}

/// Request bodies sent to an endpoint conform to a JSON Schema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RequestBodySchema {
    /// `METHOD [host]/path`, see [`Endpoint`].
    pub endpoint: String,
    pub schema: serde_json::Value,
}

/// An endpoint only ever answers with these statuses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct StatusSet {
    /// `METHOD [host]/path`, see [`Endpoint`].
    pub endpoint: String,
    pub statuses: BTreeSet<u16>,
}

/// A count, followed by that many records of one fixed size.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RecordArray {
    pub type_name: String,
    /// Where the little-endian count is.
    pub count_offset: u64,
    /// Bytes in the count: 1, 2, 4 or 8.
    pub count_len: u64,
    /// Where the first record starts.
    pub first: u64,
    /// Bytes per record.
    pub stride: u64,
    /// What each record holds, with offsets from the start of the record.
    #[serde(default)]
    pub fields: Vec<FieldLayout>,
    /// Whether the snapshot ends right after the last record.
    #[serde(default)]
    pub exact: bool,
}

/// A little-endian unsigned integer somewhere in a snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct IntField {
    pub offset: u64,
    /// Bytes in the integer: 1, 2, 4 or 8.
    pub len: u64,
}

/// What a field's value is determined by.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Relation {
    /// The number of bytes from `from` to the end of the snapshot.
    BytesAfter { from: u64 },
    /// The length of the whole snapshot.
    SnapshotLength,
    /// The sum of other integer fields, plus a constant.
    Sum {
        fields: Vec<IntField>,
        #[serde(default)]
        plus: i64,
    },
}

/// One integer field equals a length or a sum taken from the rest of the snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct FieldRelation {
    pub type_name: String,
    pub field: IntField,
    pub equals: Relation,
}

/// A run of records, each a size, a tag and that many bytes of value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TaggedRecords {
    pub type_name: String,
    /// Where the first record starts.
    pub start: u64,
    /// Bytes in a record's size field, which comes first: 1, 2 or 4.
    pub size_len: u64,
    /// Bytes in a record's tag field, which follows the size: 1, 2 or 4.
    pub tag_len: u64,
    /// How many records there are. Without it the run goes to the end of the
    /// snapshot and must end exactly there.
    #[serde(default)]
    pub count: Option<u64>,
    /// The tags that may appear. Empty means any tag.
    #[serde(default)]
    pub tags: BTreeSet<u64>,
}

/// A region holding a stated number of NUL-terminated strings and nothing else.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct StringTable {
    pub type_name: String,
    /// Where the first string starts.
    pub start: u64,
    /// Bytes in the region. Without it the region goes to the end of the snapshot.
    #[serde(default)]
    pub len: Option<u64>,
    /// How many strings the region holds, each ended by one NUL.
    pub count: u64,
    /// The fewest characters a string may have. 0 allows empty strings.
    #[serde(default)]
    pub min_chars: u64,
}

impl StringTable {
    /// Plain sentence shown to the human.
    fn sentence(&self) -> String {
        let region = match self.len {
            Some(len) => format!("in the {len} bytes from +{:#x}", self.start),
            None => format!("from +{:#x} to the end of the snapshot", self.start),
        };
        let each = match self.min_chars {
            0 => String::new(),
            min => format!(", each of {min}+ characters"),
        };
        format!(
            "`{}` holds {} NUL-terminated strings {region}{each}.",
            self.type_name, self.count
        )
    }

    /// What admission asks of this kind.
    fn admissible(&self) -> Result<(), String> {
        if self.type_name.is_empty() || self.count == 0 {
            return Err(String::from(
                "a string table needs a type name and at least one string",
            ));
        }
        // Every string takes its characters and one NUL.
        let least = self.count.saturating_mul(self.min_chars.saturating_add(1));
        if self.len.is_some_and(|len| len < least) {
            return Err(format!(
                "{} strings need at least {least} bytes",
                self.count
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ClaimKind {
    StringTable(StringTable),
    TaggedRecords(TaggedRecords),
    FieldRelation(FieldRelation),
    RecordArray(RecordArray),
    StatusSet(StatusSet),
    RequestBodySchema(RequestBodySchema),
    RequestHeader(RequestHeader),
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
    pub const fn subject(&self) -> &str {
        match &self.kind {
            ClaimKind::StringTable(t) => t.type_name.as_str(),
            ClaimKind::TaggedRecords(t) => t.type_name.as_str(),
            ClaimKind::FieldRelation(r) => r.type_name.as_str(),
            ClaimKind::RecordArray(r) => r.type_name.as_str(),
            ClaimKind::StatusSet(s) => s.endpoint.as_str(),
            ClaimKind::RequestBodySchema(b) => b.endpoint.as_str(),
            ClaimKind::RequestHeader(h) => h.endpoint.as_str(),
            ClaimKind::MemoryLayout(m) => m.type_name.as_str(),
            ClaimKind::RequestSignature(s) => s.endpoint.as_str(),
            ClaimKind::ResponseSchema(r) => r.endpoint.as_str(),
        }
    }

    /// Plain sentence shown to the human.
    #[must_use]
    pub fn sentence(&self) -> String {
        match &self.kind {
            ClaimKind::StringTable(c) => c.sentence(),
            ClaimKind::TaggedRecords(c) => c.sentence(),
            ClaimKind::FieldRelation(c) => c.sentence(),
            ClaimKind::RecordArray(c) => c.sentence(),
            ClaimKind::StatusSet(c) => c.sentence(),
            ClaimKind::RequestBodySchema(c) => c.sentence(),
            ClaimKind::RequestHeader(c) => c.sentence(),
            ClaimKind::MemoryLayout(c) => c.sentence(),
            ClaimKind::RequestSignature(c) => c.sentence(),
            ClaimKind::ResponseSchema(c) => c.sentence(),
        }
    }
}

/// A value that passed admission. Only `admit` constructs one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct WellFormed<T>(T);

impl<T> WellFormed<T> {
    pub const fn get(&self) -> &T {
        &self.0
    }
}

impl<'de> Deserialize<'de> for WellFormed<Claim> {
    // Replayed events are re-admitted, so stored data never bypasses `admit`.
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        admit(Claim::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}

/// The first eight characters of a schema's hash: enough to tell two schemas apart in a sentence.
fn schema_print(schema: &serde_json::Value) -> String {
    let hash = blake3::hash(schema.to_string().as_bytes()).to_hex();
    hash[..8].to_owned()
}

/// A schema in a sentence: its print and how much it asks for.
fn schema_summary(schema: &serde_json::Value) -> String {
    let count = |key: &str| match schema.get(key) {
        Some(serde_json::Value::Object(map)) => map.len(),
        Some(serde_json::Value::Array(list)) => list.len(),
        _ => 0,
    };
    format!(
        "JSON Schema {}: {} properties, {} required",
        schema_print(schema),
        count("properties"),
        count("required")
    )
}

/// Whether a JSON Schema accepts every value, so that no response could refute it:
/// `true`, or an object with nothing but annotations and properties that
/// themselves accept everything.
fn accepts_everything(schema: &serde_json::Value) -> bool {
    const ANNOTATIONS: [&str; 8] = [
        "$schema",
        "$id",
        "$comment",
        "title",
        "description",
        "default",
        "examples",
        "deprecated",
    ];
    match schema {
        serde_json::Value::Bool(accepts) => *accepts,
        serde_json::Value::Object(keywords) => keywords.iter().all(|(key, value)| match value {
            serde_json::Value::Object(properties) if key == "properties" => {
                properties.values().all(accepts_everything)
            }
            _ => ANNOTATIONS.contains(&key.as_str()),
        }),
        _ => false,
    }
}

/// Whether fields lie inside `size` bytes without overlapping, each with a kind that fits it.
fn fields_fit(fields: &[FieldLayout], size: u64) -> Result<(), String> {
    // By position, not by the derived order, which would compare names first.
    let mut fields: Vec<&FieldLayout> = fields.iter().collect();
    fields.sort_by_key(|f| f.offset);
    let mut end = 0;
    for f in fields {
        if f.len == 0 || f.offset < end || f.offset.saturating_add(f.len) > size {
            return Err(format!(
                "field `{}` is empty, overlaps, or exceeds size",
                f.name
            ));
        }
        if let Some(Err(why)) = f.is.as_ref().map(|kind| kind.fits(f.len)) {
            return Err(format!("field `{}`: {why}", f.name));
        }
        end = f.offset + f.len;
    }
    Ok(())
}

impl TaggedRecords {
    /// Plain sentence shown to the human.
    fn sentence(&self) -> String {
        let t = self;
        let extent = match t.count {
            Some(count) => format!("{count} of them"),
            None => "up to the end of the snapshot".to_owned(),
        };
        let listed: Vec<String> = t.tags.iter().take(6).map(u64::to_string).collect();
        let tags = match t.tags.len() {
            0 => String::new(),
            all if all > 6 => {
                format!(", with tags {} and {} more", listed.join(", "), all - 6)
            }
            _ => format!(", with tags {}", listed.join(", ")),
        };
        format!(
            "`{}` is a run of records from +{:#x}, each a {}-byte size, a {}-byte tag and that many bytes of value: {extent}{tags}.",
            t.type_name, t.start, t.size_len, t.tag_len
        )
    }

    /// What admission asks of this kind.
    fn admissible(&self) -> Result<(), String> {
        let t = self;
        let width = |len: u64| matches!(len, 1 | 2 | 4);
        if t.type_name.is_empty() || !width(t.size_len) || !width(t.tag_len) || t.count == Some(0) {
            return Err(String::from(
                "tagged records need a type name, size and tag fields of 1, 2 or 4 bytes, and a count above zero if one is given",
            ));
        }
        if t.tags.iter().any(|tag| tag >> (t.tag_len * 8) != 0) {
            return Err(String::from("a claimed tag does not fit the tag field"));
        }

        Ok(())
    }
}

impl FieldRelation {
    /// Plain sentence shown to the human.
    fn sentence(&self) -> String {
        let r = self;
        let equals = match &r.equals {
            Relation::BytesAfter { from } => {
                format!("the number of bytes after +{from:#x}")
            }
            Relation::SnapshotLength => "the length of the whole snapshot".to_owned(),
            Relation::Sum { fields, plus } => {
                let at: Vec<String> = fields.iter().map(|f| format!("+{:#x}", f.offset)).collect();
                let constant = match plus {
                    0 => String::new(),
                    n if *n > 0 => format!(" plus {n}"),
                    n => format!(" minus {}", n.unsigned_abs()),
                };
                format!("the sum of the values at {}{constant}", at.join(", "))
            }
        };
        format!(
            "In `{}`, the {}-byte value at +{:#x} equals {equals}.",
            r.type_name, r.field.len, r.field.offset
        )
    }

    /// What admission asks of this kind.
    fn admissible(&self) -> Result<(), String> {
        let r = self;
        let integer = |f: &IntField| matches!(f.len, 1 | 2 | 4 | 8);
        let summed = match &r.equals {
            Relation::Sum { fields, .. } => !fields.is_empty() && fields.iter().all(integer),
            Relation::BytesAfter { .. } | Relation::SnapshotLength => true,
        };
        if r.type_name.is_empty() || !integer(&r.field) || !summed {
            return Err(String::from(
                "a field relation needs a type name, integers of 1, 2, 4 or 8 bytes, and at least one field to sum",
            ));
        }

        Ok(())
    }
}

impl RecordArray {
    /// Plain sentence shown to the human.
    fn sentence(&self) -> String {
        let r = self;
        let end = if r.exact {
            ", and nothing after them"
        } else {
            ""
        };
        let checked = r.fields.iter().filter(|f| f.is.is_some()).count();
        let fields = match r.fields.len() {
            0 => String::new(),
            all => format!(" Contents checked for {checked} of {all} fields per record."),
        };
        format!(
            "`{}` has a {}-byte count at +{:#x}, then that many {}-byte records from +{:#x}{end}.{fields}",
            r.type_name, r.count_len, r.count_offset, r.stride, r.first
        )
    }

    /// What admission asks of this kind.
    fn admissible(&self) -> Result<(), String> {
        let r = self;
        if r.type_name.is_empty() || r.stride == 0 || !matches!(r.count_len, 1 | 2 | 4 | 8) {
            return Err(String::from(
                "a record array needs a type name, a count of 1, 2, 4 or 8 bytes and a record size",
            ));
        }
        if r.count_offset.saturating_add(r.count_len) > r.first {
            return Err(String::from(
                "the count must end before the first record starts",
            ));
        }
        if let Err(why) = fields_fit(&r.fields, r.stride) {
            return Err(String::from(&why));
        }

        Ok(())
    }
}

impl StatusSet {
    /// Plain sentence shown to the human.
    fn sentence(&self) -> String {
        let s = self;
        let statuses: Vec<String> = s.statuses.iter().map(u16::to_string).collect();
        format!(
            "`{}` only answers with {}.",
            s.endpoint,
            statuses.join(", ")
        )
    }

    /// What admission asks of this kind.
    fn admissible(&self) -> Result<(), String> {
        let s = self;
        if let Err(why) = Endpoint::parse(&s.endpoint) {
            return Err(String::from(why));
        }
        if s.statuses.is_empty() || !s.statuses.iter().all(|status| (100..600).contains(status)) {
            return Err(String::from(
                "a status claim needs at least one status, each from 100 to 599",
            ));
        }

        Ok(())
    }
}

impl RequestBodySchema {
    /// Plain sentence shown to the human.
    fn sentence(&self) -> String {
        let b = self;
        format!(
            "`{}` request bodies match {}.",
            b.endpoint,
            schema_summary(&b.schema)
        )
    }

    /// What admission asks of this kind.
    fn admissible(&self) -> Result<(), String> {
        let b = self;
        if let Err(why) = Endpoint::parse(&b.endpoint) {
            return Err(String::from(why));
        }
        if !(b.schema.is_object() || b.schema.is_boolean()) {
            return Err(String::from(
                "a request body claim needs an object or boolean schema",
            ));
        }
        if accepts_everything(&b.schema) {
            return Err(String::from(
                "this schema accepts every body, so nothing could refute it; say what a body must have",
            ));
        }

        Ok(())
    }
}

impl RequestHeader {
    /// Plain sentence shown to the human.
    fn sentence(&self) -> String {
        match self {
            h if h.value == serde_json::Value::Bool(true) => {
                format!("`{}` requests carry header `{}`.", h.endpoint, h.header)
            }
            h => format!(
                "`{}` requests carry header `{}` with a value matching JSON Schema {}.",
                h.endpoint,
                h.header,
                schema_print(&h.value)
            ),
        }
    }

    /// What admission asks of this kind.
    fn admissible(&self) -> Result<(), String> {
        let h = self;
        if let Err(why) = Endpoint::parse(&h.endpoint) {
            return Err(String::from(why));
        }
        if h.header.is_empty() || !(h.value.is_object() || h.value.is_boolean()) {
            return Err(String::from(
                "a header claim needs a header name and an object or boolean schema for its value",
            ));
        }

        Ok(())
    }
}

impl MemoryLayout {
    /// Plain sentence shown to the human.
    fn sentence(&self) -> String {
        match self {
            m if m.fields.is_empty() => {
                format!("`{}` is {} bytes.", m.type_name, m.size)
            }
            m => {
                let field = |f: &FieldLayout| match &f.is {
                    Some(kind) => format!("{} at +{:#x} ({kind})", f.name, f.offset),
                    None => format!("{} at +{:#x}", f.name, f.offset),
                };
                // The count comes first: lists cut long sentences, and it must survive the cut.
                format!(
                    "`{}` is {} bytes, contents checked for {} of {} fields: {}.",
                    m.type_name,
                    m.size,
                    m.fields.iter().filter(|f| f.is.is_some()).count(),
                    m.fields.len(),
                    m.fields.iter().map(field).collect::<Vec<_>>().join(", ")
                )
            }
        }
    }

    /// What admission asks of this kind.
    fn admissible(&self) -> Result<(), String> {
        let m = self;
        if m.type_name.is_empty() || m.size == 0 {
            return Err(String::from(
                "memory layout needs a type name and non-zero size",
            ));
        }
        if let Err(why) = fields_fit(&m.fields, m.size) {
            return Err(String::from(&why));
        }

        Ok(())
    }
}

impl RequestSignature {
    /// Plain sentence shown to the human.
    fn sentence(&self) -> String {
        let s = self;
        format!(
            "`{}` requests carry a {:?} signature of {} in header `{}`, {:?} encoded.",
            s.endpoint,
            s.algorithm,
            s.signed_input(),
            s.header,
            s.encoding
        )
    }

    /// What admission asks of this kind.
    fn admissible(&self) -> Result<(), String> {
        let s = self;
        if let Err(why) = Endpoint::parse(&s.endpoint) {
            return Err(String::from(why));
        }
        if s.header.is_empty() {
            return Err(String::from("signature needs a header name"));
        }
        let empty = |p: &SignedPart| matches!(p, SignedPart::Header(t) | SignedPart::Text(t) if t.is_empty());
        if s.signed.iter().any(empty) {
            return Err(String::from("a signed header or text must not be empty"));
        }

        Ok(())
    }
}

impl ResponseSchema {
    /// Plain sentence shown to the human.
    fn sentence(&self) -> String {
        let r = self;
        format!(
            "{} responses to `{}` match {}.",
            r.status,
            r.endpoint,
            schema_summary(&r.schema)
        )
    }

    /// What admission asks of this kind.
    fn admissible(&self) -> Result<(), String> {
        let r = self;
        if let Err(why) = Endpoint::parse(&r.endpoint) {
            return Err(String::from(why));
        }
        if !(100..600).contains(&r.status) || !(r.schema.is_object() || r.schema.is_boolean()) {
            return Err(String::from(
                "response schema needs a status of 100 to 599 and an object or boolean schema",
            ));
        }
        if accepts_everything(&r.schema) {
            return Err(String::from(
                "this schema accepts every response, so nothing could refute it; say what a response must have",
            ));
        }

        Ok(())
    }
}

/// Structural checks that do not need evidence.
///
/// # Errors
/// `CoreError::Inadmissible` with the reason.
pub fn admit(claim: Claim) -> Result<WellFormed<Claim>, CoreError> {
    let admissible = match &claim.kind {
        ClaimKind::StringTable(c) => c.admissible(),
        ClaimKind::TaggedRecords(c) => c.admissible(),
        ClaimKind::FieldRelation(c) => c.admissible(),
        ClaimKind::RecordArray(c) => c.admissible(),
        ClaimKind::StatusSet(c) => c.admissible(),
        ClaimKind::RequestBodySchema(c) => c.admissible(),
        ClaimKind::RequestHeader(c) => c.admissible(),
        ClaimKind::MemoryLayout(c) => c.admissible(),
        ClaimKind::RequestSignature(c) => c.admissible(),
        ClaimKind::ResponseSchema(c) => c.admissible(),
    };
    admissible.map_err(CoreError::Inadmissible)?;
    Ok(WellFormed(claim))
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    MemorySnapshot,
    /// Retired: headers and a body with no request line. Kept so old events decode.
    CapturedRequest,
    /// Retired: a response body alone. Kept so old events decode.
    CapturedExchange,
    /// One request and its response, as [`HttpExchange`].
    HttpExchange,
    /// A signing key or other secret, as raw bytes. Cited by claims, never shown.
    Secret,
}

/// One header line. A list of these, not a map: names repeat, and HTTP/2 captures
/// spell them in lower case and add pseudo-headers such as `:path`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Header {
    pub name: String,
    pub value: String,
}

/// A captured body: text as it is, anything else as base64.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Body {
    Text(String),
    Base64(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct HttpRequest {
    pub method: String,
    /// Absolute (`https://host/path?query`) or, in a server-side capture, just the path.
    pub url: String,
    #[serde(default)]
    pub headers: Vec<Header>,
    #[serde(default)]
    pub body: Option<Body>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct HttpResponse {
    pub status: u16,
    #[serde(default)]
    pub headers: Vec<Header>,
    #[serde(default)]
    pub body: Option<Body>,
}

/// Evidence format for `EvidenceKind::HttpExchange`: one request and, if it was
/// answered, its response. Shaped like a HAR entry; fields a capture tool adds
/// beyond these are ignored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct HttpExchange {
    pub request: HttpRequest,
    #[serde(default)]
    pub response: Option<HttpResponse>,
}

/// What a web claim is about: `METHOD [host]/path[?conditions]`, where a path
/// segment written `{name}` stands for any one segment.
/// `GET crates.io/api/v1/crates/{name}`, `POST /api/v1/score`.
///
/// Without conditions the query string is ignored. Conditions, joined by `&`,
/// narrow the endpoint to requests whose query meets all of them: `name` (the
/// parameter is present), `name=value` (it has this value) and `!name` (it is
/// absent). `GET api.example.com/forecast?current&!hourly`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Endpoint<'a> {
    method: &'a str,
    host: Option<&'a str>,
    path: &'a str,
    conditions: &'a str,
}

/// Decodes `%XX` escapes; anything else, including a lone `%`, is kept as it is.
fn percent_decode(text: &str) -> String {
    let hex = |b: u8| {
        char::from(b)
            .to_digit(16)
            .and_then(|d| u8::try_from(d).ok())
    };
    let (bytes, mut out, mut at) = (text.as_bytes(), Vec::with_capacity(text.len()), 0);
    while at < bytes.len() {
        let high = bytes.get(at + 1).copied().and_then(hex);
        let low = bytes.get(at + 2).copied().and_then(hex);
        match (bytes[at], high, low) {
            (b'%', Some(high), Some(low)) => {
                out.push(high << 4 | low);
                at += 3;
            }
            (byte, _, _) => {
                out.push(byte);
                at += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

impl<'a> Endpoint<'a> {
    /// # Errors
    /// The text is not a method, a space, and a path with an optional host in
    /// front and optional query conditions behind.
    pub fn parse(text: &'a str) -> Result<Self, &'static str> {
        let shape =
            "an endpoint is written `METHOD [host]/path`, like `GET api.example.com/users/{id}`";
        let (method, rest) = text.split_once(' ').ok_or(shape)?;
        let (rest, conditions) = match rest.split_once('?') {
            Some((rest, conditions)) => (rest, Some(conditions)),
            None => (rest, None),
        };
        let slash = rest.find('/').ok_or(shape)?;
        let (host, path) = rest.split_at(slash);
        if method.is_empty() || !method.bytes().all(|b| b.is_ascii_uppercase()) {
            return Err(shape);
        }
        if text.contains('#')
            || rest.contains(' ')
            || conditions.is_some_and(|c| c.contains([' ', '?']))
        {
            return Err("an endpoint has no spaces and no fragment");
        }
        let named = |condition: &str| {
            let name = condition.trim_start_matches('!').split('=').next();
            !name.unwrap_or_default().is_empty()
        };
        if conditions.is_some_and(|c| !c.split('&').all(named)) {
            return Err("query conditions are `name`, `name=value` or `!name`, joined by `&`");
        }
        Ok(Self {
            method,
            host: (!host.is_empty()).then_some(host),
            path,
            conditions: conditions.unwrap_or_default(),
        })
    }

    /// Whether a captured request has this endpoint's method, host and path,
    /// whatever its query string.
    #[must_use]
    pub fn matches_path(&self, method: &str, url: &str) -> bool {
        let (host, path) = match url.split_once("://") {
            Some((_, rest)) => rest.split_at(rest.find(['/', '?', '#']).unwrap_or(rest.len())),
            None => ("", url),
        };
        let path = path.split(['?', '#']).next().unwrap_or_default();
        let path = if path.is_empty() { "/" } else { path };
        let segments = |p: &'a str| p.split('/');
        method.eq_ignore_ascii_case(self.method)
            && self.host.is_none_or(|h| h.eq_ignore_ascii_case(host))
            && path.split('/').count() == segments(self.path).count()
            && path.split('/').zip(segments(self.path)).all(|(got, want)| {
                got == want || (want.starts_with('{') && want.ends_with('}') && !got.is_empty())
            })
    }

    /// Whether a captured request belongs to this endpoint: [`Endpoint::matches_path`]
    /// and every query condition.
    #[must_use]
    pub fn matches(&self, method: &str, url: &str) -> bool {
        let query = url.split('#').next().unwrap_or_default();
        let query = query.split_once('?').map_or("", |(_, q)| q);
        let pairs: Vec<(String, String)> = (query.split('&').filter(|p| !p.is_empty()))
            .map(|pair| pair.split_once('=').unwrap_or((pair, "")))
            .map(|(name, value)| (percent_decode(name), percent_decode(value)))
            .collect();
        let has = |name: &str| pairs.iter().any(|(n, _)| *n == percent_decode(name));
        let met = |condition: &str| match (condition.strip_prefix('!'), condition.split_once('=')) {
            (Some(name), _) => !has(name),
            (None, Some((name, value))) => {
                let (name, value) = (percent_decode(name), percent_decode(value));
                pairs.iter().any(|(n, v)| *n == name && *v == value)
            }
            (None, None) => has(condition),
        };
        let conditions = self.conditions.split('&').filter(|c| !c.is_empty());
        self.matches_path(method, url) && conditions.into_iter().all(met)
    }
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

/// Which checker produced a verdict. Together with the claim and the evidence
/// the check read, this identifies the check: the same three give the same verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CheckerRef {
    pub id: String,
    pub version: u32,
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
        /// Which checker ran. Absent in events written before checks were cached.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        checker: Option<CheckerRef>,
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
    /// For each verdict, in step with `verdicts`: the evidence its check read and the checker.
    checks: Vec<(BTreeSet<EvidenceId>, Option<CheckerRef>)>,
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
                    checks: Vec::new(),
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
                checker,
            } => {
                let at = self.position(&claim)?;
                if let Some(e) = evidence.iter().find(|e| !self.evidence.contains_key(*e)) {
                    return Err(CoreError::UnknownEvidence(e.clone()));
                }
                self.entries[at].verdicts.push(verdict);
                self.entries[at].checks.push((evidence, checker));
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

    /// The verdict already recorded for exactly this check, if there is one: the same
    /// claim, the same evidence and the same checker at the same version. The latest wins.
    #[must_use]
    pub fn checked(
        &self,
        claim: &ClaimId,
        evidence: &BTreeSet<EvidenceId>,
        checker: &CheckerRef,
    ) -> Option<&Verdict> {
        let entry = self.entry(claim)?;
        let same = |(read, by): &&(BTreeSet<EvidenceId>, Option<CheckerRef>)| {
            read == evidence && by.as_ref() == Some(checker)
        };
        let at = entry.checks.iter().rposition(|check| same(&check))?;
        entry.verdicts.get(at)
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
                        is: None,
                    },
                    FieldLayout {
                        name: "pos".into(),
                        offset: 8,
                        len: 12,
                        is: None,
                    },
                ],
            }),
            premises: BTreeSet::new(),
        }
    }

    fn signature() -> Claim {
        Claim {
            kind: ClaimKind::RequestSignature(RequestSignature {
                endpoint: "POST /api/v2/score".into(),
                header: "X-Sig".into(),
                algorithm: SigAlgorithm::HmacSha256,
                encoding: SigEncoding::Hex,
                key: EvidenceId::of(b"key"),
                signed: vec![],
            }),
            premises: BTreeSet::new(),
        }
    }

    fn schema() -> Claim {
        Claim {
            kind: ClaimKind::ResponseSchema(ResponseSchema {
                endpoint: "GET game.example/api/v2/profile/{id}".into(),
                status: 200,
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
                is: None,
            });
        }
        assert!(admit(c).is_err());
        assert!(admit(layout(16)).is_err(), "pos exceeds size");

        // Regression: fields are ordered by offset, whatever their names.
        let mut c = layout(32);
        if let ClaimKind::MemoryLayout(m) = &mut c.kind {
            m.fields[0].name = "zz_first_by_offset".into();
        }
        assert!(admit(c).is_ok());
    }

    /// A layout with one typed field of `len` bytes.
    fn typed(len: u64, kind: FieldKind) -> Claim {
        Claim {
            kind: ClaimKind::MemoryLayout(MemoryLayout {
                type_name: "SaveHeader".into(),
                size: 16,
                fields: vec![FieldLayout {
                    name: "f".into(),
                    offset: 4,
                    len,
                    is: Some(kind),
                }],
            }),
            premises: BTreeSet::new(),
        }
    }

    #[test]
    fn endpoints_match_request_lines() -> Result<(), &'static str> {
        let crates = Endpoint::parse("GET crates.io/api/v1/crates/{name}")?;
        assert!(crates.matches("GET", "https://crates.io/api/v1/crates/serde?include=x"));
        assert!(crates.matches("get", "https://CRATES.IO/api/v1/crates/tokio#top"));
        assert!(!crates.matches("POST", "https://crates.io/api/v1/crates/serde"));
        assert!(!crates.matches("GET", "https://docs.rs/api/v1/crates/serde"));
        assert!(!crates.matches("GET", "https://crates.io/api/v1/crates/serde/owners"));
        assert!(!crates.matches("GET", "https://crates.io/api/v1/crates/"));
        // Without a host the endpoint matches any host, and a server-side capture has only a path.
        let score = Endpoint::parse("POST /api/v1/score")?;
        assert!(score.matches("POST", "/api/v1/score"));
        assert!(score.matches("POST", "http://127.0.0.1:41943/api/v1/score"));
        assert!(!score.matches("POST", "/api/v1/purchase"));
        assert!(Endpoint::parse("GET example.com/")?.matches("GET", "https://example.com"));
        // Query conditions narrow an endpoint; without them the query is ignored.
        let asked =
            "https://api.example.com/v1/forecast?latitude=52.52&current=temperature_2m%2Cwind";
        let plain = "https://api.example.com/v1/forecast?latitude=52.52&hourly=rain";
        let met =
            |endpoint: &'static str, url| Endpoint::parse(endpoint).map(|e| e.matches("GET", url));
        assert_eq!(met("GET /v1/forecast", asked), Ok(true));
        assert_eq!(met("GET /v1/forecast?current", asked), Ok(true));
        assert_eq!(met("GET /v1/forecast?current", plain), Ok(false));
        assert_eq!(
            met("GET /v1/forecast?!current&hourly=rain", plain),
            Ok(true)
        );
        assert_eq!(met("GET /v1/forecast?!current", asked), Ok(false));
        assert_eq!(
            met("GET /v1/forecast?current=temperature_2m,wind", asked),
            Ok(true)
        );
        assert_eq!(
            met(
                "GET /v1/forecast?current=temperature_2m%2Cwind&latitude=52.52",
                asked
            ),
            Ok(true)
        );
        assert_eq!(met("GET /v1/forecast?current=wind", asked), Ok(false));
        assert_eq!(met("GET /v1/other?current", asked), Ok(false));
        assert!(Endpoint::parse("GET /v1/forecast?current")?.matches_path("GET", plain));
        for bad in [
            "/api/v1/score",
            "get /x",
            "GET",
            "GET /x?",
            "GET /x?a&&b",
            "GET /x?=1",
            "GET /x?!",
            "GET /x#f",
            "GET  /x",
            " /x",
        ] {
            assert!(Endpoint::parse(bad).is_err(), "{bad}");
        }
        Ok(())
    }

    #[test]
    fn admit_refuses_schemas_that_say_nothing() {
        let claim = |schema: serde_json::Value| Claim {
            kind: ClaimKind::ResponseSchema(ResponseSchema {
                endpoint: "GET /profile".into(),
                status: 200,
                schema,
            }),
            premises: BTreeSet::new(),
        };
        let nothing = [
            serde_json::json!(true),
            serde_json::json!({}),
            serde_json::json!({"title": "Profile", "description": "a profile"}),
            serde_json::json!({"properties": {"id": {}, "name": true}}),
        ];
        for schema in nothing {
            assert!(admit(claim(schema.clone())).is_err(), "{schema}");
        }
        let something = [
            serde_json::json!(false),
            serde_json::json!({"type": "object"}),
            serde_json::json!({"required": ["id"]}),
            serde_json::json!({"properties": {"id": {"type": "integer"}}}),
            serde_json::json!({"properties": {"id": true}, "additionalProperties": false}),
        ];
        for schema in something {
            assert!(admit(claim(schema.clone())).is_ok(), "{schema}");
        }
    }

    #[test]
    fn tagged_records_sentence_and_admission() {
        let run = |count, tags: &[u64]| Claim {
            kind: ClaimKind::TaggedRecords(TaggedRecords {
                type_name: "GameHeader".into(),
                start: 0,
                size_len: 2,
                tag_len: 2,
                count,
                tags: tags.iter().copied().collect(),
            }),
            premises: BTreeSet::new(),
        };
        insta::assert_snapshot!(
            "tagged_records",
            run(Some(3), &[2849, 892, 1920]).sentence()
        );
        insta::assert_snapshot!("tagged_records_open", run(None, &[]).sentence());
        assert!(admit(run(None, &[])).is_ok());
        assert!(admit(run(Some(0), &[])).is_err());
        assert!(
            admit(run(None, &[70_000])).is_err(),
            "a tag wider than two bytes"
        );
    }

    #[test]
    fn string_table_sentence_and_admission() {
        let table = |len, count, min_chars| Claim {
            kind: ClaimKind::StringTable(StringTable {
                type_name: "TokenTable".into(),
                start: 20,
                len,
                count,
                min_chars,
            }),
            premises: BTreeSet::new(),
        };
        insta::assert_snapshot!("string_table", table(Some(4166), 4095, 0).sentence());
        insta::assert_snapshot!("string_table_open", table(None, 3, 2).sentence());
        assert!(admit(table(Some(4166), 4095, 0)).is_ok());
        assert!(admit(table(None, 0, 0)).is_err());
        assert!(
            admit(table(Some(8), 3, 2)).is_err(),
            "three strings of two characters need nine bytes"
        );
    }

    #[test]
    fn admit_checks_field_kinds() -> Result<(), CoreError> {
        let good = [
            typed(4, FieldKind::Bytes("4a534156".into())),
            typed(4, FieldKind::Uint { min: 113, max: 113 }),
            typed(2, FieldKind::Int { min: -5, max: 5 }),
            typed(4, FieldKind::Float { min: 0, max: 100 }),
            typed(1, FieldKind::OneOf([0, 1].into())),
            typed(
                8,
                FieldKind::Pointer {
                    min: 0x1000,
                    max: 0x7fff_ffff_ffff,
                },
            ),
            typed(12, FieldKind::Text { min: 3 }),
            typed(3, FieldKind::Zero),
        ];
        for claim in good {
            admit(claim)?;
        }
        let bad = [
            typed(4, FieldKind::Bytes("4a53".into())),
            typed(4, FieldKind::Bytes("not hex!".into())),
            typed(3, FieldKind::Uint { min: 1, max: 2 }),
            typed(1, FieldKind::Uint { min: 0, max: 256 }),
            typed(2, FieldKind::Uint { min: 9, max: 3 }),
            typed(
                2,
                FieldKind::Uint {
                    min: 0,
                    max: 0xffff,
                },
            ),
            typed(
                1,
                FieldKind::Int {
                    min: -128,
                    max: 127,
                },
            ),
            typed(1, FieldKind::Int { min: -129, max: 0 }),
            typed(2, FieldKind::Float { min: 0, max: 1 }),
            typed(1, FieldKind::OneOf(BTreeSet::new())),
            typed(1, FieldKind::OneOf([300].into())),
            typed(
                8,
                FieldKind::Pointer {
                    min: 0,
                    max: u64::MAX,
                },
            ),
            typed(12, FieldKind::Text { min: 0 }),
            typed(12, FieldKind::Text { min: 12 }),
        ];
        for claim in bad {
            assert!(admit(claim.clone()).is_err(), "{claim:?}");
        }
        Ok(())
    }

    #[test]
    fn untyped_claims_keep_their_identity() -> Result<(), CoreError> {
        // Old events must replay to the same ids: an absent `is` is not serialized.
        let json = serde_json::to_string(&layout(32))?;
        assert!(!json.contains("\"is\""), "{json}");
        let old = r#"{"kind":"memory_layout","type_name":"Player","size":32,"fields":[{"name":"hp","offset":0,"len":4},{"name":"pos","offset":8,"len":12}],"premises":[]}"#;
        assert_eq!(json, old);
        Ok(())
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
            checker: None,
        })?;
        assert_eq!(l.status(&base_id), Some(Status::Held));
        assert_eq!(l.status(&dep_id), Some(Status::Unchecked));

        // A check is found again by its claim, its evidence and its checker at that version.
        let by = |version| CheckerRef {
            id: "memory_layout".into(),
            version,
        };
        let read: BTreeSet<EvidenceId> = [EvidenceId::of(b"snapshot")].into();
        assert_eq!(
            l.checked(&base_id, &read, &by(1)),
            None,
            "recorded without a checker"
        );
        let second = Verdict::Inconclusive {
            reason: "second look".into(),
        };
        l.apply(Event::Checked {
            claim: base_id.clone(),
            evidence: read.clone(),
            verdict: second.clone(),
            checker: Some(by(1)),
        })?;
        assert_eq!(l.checked(&base_id, &read, &by(1)), Some(&second));
        assert_eq!(
            l.checked(&base_id, &read, &by(2)),
            None,
            "another version is another check"
        );
        assert_eq!(
            l.checked(&base_id, &BTreeSet::new(), &by(1)),
            None,
            "other evidence"
        );
        assert_eq!(l.checked(&dep_id, &read, &by(1)), None, "another claim");

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
        let mut header = typed(4, FieldKind::Bytes("4a534156".into()));
        if let ClaimKind::MemoryLayout(m) = &mut header.kind {
            m.fields.push(FieldLayout {
                name: "version".into(),
                offset: 8,
                len: 4,
                is: Some(FieldKind::Uint { min: 113, max: 113 }),
            });
            m.fields.push(FieldLayout {
                name: "rest".into(),
                offset: 12,
                len: 4,
                is: None,
            });
        }
        insta::assert_snapshot!("memory_layout_typed", header.sentence());
        let bare = MemoryLayout {
            type_name: "Blob".into(),
            size: 16,
            fields: vec![],
        };
        let bare = Claim {
            kind: ClaimKind::MemoryLayout(bare),
            premises: BTreeSet::new(),
        };
        insta::assert_snapshot!("memory_layout_bare", bare.sentence());
        insta::assert_snapshot!("request_signature", signature().sentence());
        let mut stamped = signature();
        if let ClaimKind::RequestSignature(s) = &mut stamped.kind {
            s.signed = vec![
                SignedPart::Header("X-Timestamp".into()),
                SignedPart::Text(".".into()),
                SignedPart::Body,
            ];
        }
        insta::assert_snapshot!("request_signature_parts", stamped.sentence());
        // A claim that signs the body alone is written, and hashed, as before.
        assert!(
            !serde_json::to_string(&signature())
                .unwrap_or_default()
                .contains("signed")
        );
        insta::assert_snapshot!("response_schema", schema().sentence());
    }

    #[test]
    fn sentences_of_newer_kinds() {
        let relation = |equals| Claim {
            kind: ClaimKind::FieldRelation(FieldRelation {
                type_name: "SaveDirEntry".into(),
                field: IntField {
                    offset: 260,
                    len: 4,
                },
                equals,
            }),
            premises: BTreeSet::new(),
        };
        let parts = vec![
            IntField { offset: 8, len: 4 },
            IntField { offset: 16, len: 4 },
        ];
        insta::assert_snapshot!(
            "field_relation_bytes_after",
            relation(Relation::BytesAfter { from: 264 }).sentence()
        );
        insta::assert_snapshot!(
            "field_relation_length",
            relation(Relation::SnapshotLength).sentence()
        );
        insta::assert_snapshot!(
            "field_relation_sum",
            relation(Relation::Sum {
                fields: parts,
                plus: -20
            })
            .sentence()
        );
        assert!(admit(relation(Relation::SnapshotLength)).is_ok());
        assert!(
            admit(relation(Relation::Sum {
                fields: vec![],
                plus: 4
            }))
            .is_err()
        );
        assert!(
            admit(relation(Relation::Sum {
                fields: vec![IntField { offset: 0, len: 3 }],
                plus: 0
            }))
            .is_err()
        );
        let array = |stride, fields: Vec<FieldLayout>, exact| Claim {
            kind: ClaimKind::RecordArray(RecordArray {
                type_name: "EntityList".into(),
                count_offset: 0,
                count_len: 4,
                first: 4,
                stride,
                fields,
                exact,
            }),
            premises: BTreeSet::new(),
        };
        let index = FieldLayout {
            name: "index".into(),
            offset: 0,
            len: 4,
            is: Some(FieldKind::Uint { min: 1, max: 4095 }),
        };
        insta::assert_snapshot!(
            "record_array",
            array(4, vec![index.clone()], true).sentence()
        );
        insta::assert_snapshot!("record_array_bare", array(16, vec![], false).sentence());
        assert!(admit(array(4, vec![index.clone()], true)).is_ok());
        assert!(
            admit(array(2, vec![index], true)).is_err(),
            "a field longer than the record"
        );
        assert!(admit(array(0, vec![], true)).is_err());
    }

    #[test]
    fn sentences_of_web_kinds() {
        let statuses = |statuses: &[u16]| Claim {
            kind: ClaimKind::StatusSet(StatusSet {
                endpoint: "GET crates.io/api/v1/crates/{name}".into(),
                statuses: statuses.iter().copied().collect(),
            }),
            premises: BTreeSet::new(),
        };
        insta::assert_snapshot!("status_set", statuses(&[404, 200]).sentence());
        assert!(admit(statuses(&[])).is_err());
        assert!(admit(statuses(&[200, 99])).is_err());
        let body = |schema| Claim {
            kind: ClaimKind::RequestBodySchema(RequestBodySchema {
                endpoint: "POST search.example/1/indexes/{index}/query".into(),
                schema,
            }),
            premises: BTreeSet::new(),
        };
        let asks = serde_json::json!({"required": ["query"], "properties": {"query": {"type": "string"}, "page": {"type": "integer"}}});
        insta::assert_snapshot!("request_body_schema", body(asks).sentence());
        assert!(
            admit(body(serde_json::json!({}))).is_err(),
            "an empty schema says nothing"
        );
        let header = |value| Claim {
            kind: ClaimKind::RequestHeader(RequestHeader {
                endpoint: "POST search.example/1/indexes/{index}/query".into(),
                header: "x-api-key".into(),
                value,
            }),
            premises: BTreeSet::new(),
        };
        insta::assert_snapshot!(
            "request_header",
            header(serde_json::json!({"minLength": 32})).sentence()
        );
        insta::assert_snapshot!(
            "request_header_present",
            header(serde_json::json!(true)).sentence()
        );
        assert!(admit(header(serde_json::json!(true))).is_ok());
        assert!(admit(header(serde_json::json!("a string is not a schema"))).is_err());
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
                checker: None,
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
                    l.apply(Event::Checked { claim: id.clone(), evidence: BTreeSet::new(), verdict, checker: None, })?;
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
