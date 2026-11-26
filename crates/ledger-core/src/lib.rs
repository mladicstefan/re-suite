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

/// Responses with one status from an endpoint carry a header whose value matches a JSON Schema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ResponseHeader {
    /// `METHOD [host]/path`, see [`Endpoint`].
    pub endpoint: String,
    /// The response status the claim is about.
    pub status: u16,
    pub header: String,
    /// A JSON Schema for the header's value, which is a string. `true` claims only
    /// that the header is sent. If the header is sent more than once, one matching line is enough.
    pub value: serde_json::Value,
}

impl ResponseHeader {
    /// Plain sentence shown to the human.
    fn sentence(&self) -> String {
        let value = match &self.value {
            serde_json::Value::Bool(true) => String::new(),
            schema => format!(
                " with a value matching JSON Schema {}",
                schema_print(schema)
            ),
        };
        format!(
            "{} responses to `{}` carry header `{}`{value}.",
            self.status, self.endpoint, self.header
        )
    }

    /// What admission asks of this kind.
    fn admissible(&self) -> Result<(), String> {
        Endpoint::parse(&self.endpoint).map_err(String::from)?;
        let schema = self.value.is_object() || self.value.is_boolean();
        if self.header.is_empty() || !schema || !(100..600).contains(&self.status) {
            return Err(String::from(
                "a response header claim needs a header name, a status of 100 to 599 and an object or boolean schema for the value",
            ));
        }
        Ok(())
    }
}

/// A function in a binary, named by the address it starts at or by the name the
/// analysis tool gives it. Addresses change from build to build; names mostly do not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FunctionRef {
    Address(u64),
    Name(String),
}

impl fmt::Display for FunctionRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Address(at) => write!(f, "the function at {at:#x}"),
            Self::Name(name) => write!(f, "`{name}`"),
        }
    }
}

/// One function calls another directly, within the code a tool recovered from a
/// binary. A jump to another function counts (a tail call). Says nothing about
/// calls through a pointer the tool could not resolve.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CallEdge {
    /// A name for the binary, such as its file name.
    pub binary: String,
    pub caller: FunctionRef,
    /// A function, or by name an imported symbol such as `malloc`.
    pub callee: FunctionRef,
}

impl CallEdge {
    /// Plain sentence shown to the human.
    fn sentence(&self) -> String {
        format!(
            "Within the code recovered from `{}`, {} calls {} directly (assumes the tool's analysis is right).",
            self.binary, self.caller, self.callee
        )
    }

    /// What admission asks of this kind.
    fn admissible(&self) -> Result<(), String> {
        let unnamed = |f: &FunctionRef| matches!(f, FunctionRef::Name(name) if name.is_empty());
        if self.binary.is_empty() || unnamed(&self.caller) || unnamed(&self.callee) {
            return Err(String::from(
                "a call edge needs a binary name and no empty function name",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ClaimKind {
    CallEdge(CallEdge),
    ResponseHeader(ResponseHeader),
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
            ClaimKind::CallEdge(c) => c.binary.as_str(),
            ClaimKind::ResponseHeader(h) => h.endpoint.as_str(),
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

    /// How this claim differs from `earlier`, if both are of one kind and about one
    /// subject and do differ. Premises are not compared.
    #[must_use]
    pub fn revision_of(&self, earlier: &Self) -> Option<Revision> {
        // The cheap tests first: this runs against every refuted claim in the ledger.
        if std::mem::discriminant(&self.kind) != std::mem::discriminant(&earlier.kind)
            || self.subject() != earlier.subject()
        {
            return None;
        }
        let (now, was) = (
            serde_json::to_value(&self.kind).ok()?,
            serde_json::to_value(&earlier.kind).ok()?,
        );
        // Two claims about one subject are still about different things if they name
        // different headers, statuses or functions; one does not replace the other.
        let topic = |kind: &serde_json::Value| {
            ["header", "status", "caller", "callee"].map(|part| kind.get(part).cloned())
        };
        if topic(&now) != topic(&was) {
            return None;
        }
        let mut revision = Revision::default();
        revision.compare("", "", &was, &now);
        (revision != Revision::default()).then_some(revision)
    }

    /// Plain sentence shown to the human.
    #[must_use]
    pub fn sentence(&self) -> String {
        match &self.kind {
            ClaimKind::CallEdge(c) => c.sentence(),
            ClaimKind::ResponseHeader(c) => c.sentence(),
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
/// `true`, or an object whose every keyword is an annotation or a constraint
/// nothing can fail, such as `"required": []`. It errs towards "says something":
/// a schema it does not see through is admitted.
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
    // Every JSON type; `number` covers `integer`.
    const TYPES: [&str; 6] = ["null", "boolean", "object", "array", "number", "string"];
    use serde_json::Value as V;
    // A keyword says nothing when it is an annotation, or a constraint written so
    // that nothing can fail it.
    let says_nothing = |(key, value): (&String, &V)| match (key.as_str(), value) {
        ("properties" | "patternProperties", V::Object(named)) => {
            named.values().all(accepts_everything)
        }
        ("items" | "additionalProperties" | "additionalItems" | "propertyNames", _) => {
            accepts_everything(value)
        }
        ("required", V::Array(names)) => names.is_empty(),
        ("minItems" | "minLength" | "minProperties", V::Number(least)) => least.as_u64() == Some(0),
        ("uniqueItems", V::Bool(unique)) => !unique,
        ("type", V::Array(types)) => TYPES.iter().all(|t| types.iter().any(|named| named == t)),
        ("anyOf", V::Array(options)) => options.iter().any(accepts_everything),
        ("allOf", V::Array(parts)) => parts.iter().all(accepts_everything),
        ("not", V::Bool(false)) => true,
        _ => ANNOTATIONS.contains(&key.as_str()),
    };
    match schema {
        V::Bool(accepts) => *accepts,
        V::Object(keywords) => keywords.iter().all(says_nothing),
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
        ClaimKind::CallEdge(c) => c.admissible(),
        ClaimKind::ResponseHeader(c) => c.admissible(),
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
    /// What an analysis tool recovered from one binary, as [`BinaryFacts`].
    BinaryFacts,
}

/// One function an analysis tool recovered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Function {
    /// Where the function starts.
    pub address: u64,
    pub name: String,
    /// The addresses it calls directly, or ends by jumping to (a tail call).
    #[serde(default)]
    pub calls: BTreeSet<u64>,
}

/// Evidence format for `EvidenceKind::BinaryFacts`: the functions and direct calls a
/// tool recovered from one binary. A claim checked against it holds within this
/// recovered code, which is only as right as the tool's analysis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BinaryFacts {
    /// The tool, its version and the analysis it ran.
    pub tool: String,
    /// SHA-256 of the binary the facts came from, in hex.
    pub sha256: String,
    pub functions: Vec<Function>,
    /// Called addresses that stand for an imported symbol, with the symbol's name.
    #[serde(default)]
    pub imports: BTreeMap<u64, String>,
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

/// A request URL's host and path, without scheme, query or fragment. A URL with
/// no scheme, as a server-side capture has, has no host; an empty path is `/`.
#[must_use]
pub fn url_host_and_path(url: &str) -> (&str, &str) {
    // Only a scheme at the very start makes a URL absolute: a path-only capture can
    // carry another URL in its query.
    let scheme = |text: &str| {
        text.starts_with(|c: char| c.is_ascii_alphabetic())
            && text
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"+.-".contains(&b))
    };
    let (host, path) = match url.split_once("://") {
        Some((before, rest)) if scheme(before) => {
            rest.split_at(rest.find(['/', '?', '#']).unwrap_or(rest.len()))
        }
        _ => ("", url),
    };
    let path = path.split(['?', '#']).next().unwrap_or_default();
    (host, if path.is_empty() { "/" } else { path })
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
        // `!name=value` is refused: "absent" is about a name, not about one of its values.
        let named = |condition: &str| match condition.strip_prefix('!') {
            Some(name) => !name.is_empty() && !name.contains(['=', '!']),
            None => !condition.is_empty() && !condition.starts_with('='),
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

    /// The endpoint as written: its method, its host if it names one, its path and
    /// its query conditions.
    #[must_use]
    pub const fn parts(&self) -> (&'a str, Option<&'a str>, &'a str, &'a str) {
        (self.method, self.host, self.path, self.conditions)
    }

    /// Whether a captured request has this endpoint's method, host and path,
    /// whatever its query string.
    #[must_use]
    pub fn matches_path(&self, method: &str, url: &str) -> bool {
        let (host, path) = url_host_and_path(url);
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
    /// A stored proposal that today's admission rules refuse: it was admitted under
    /// earlier ones. Only [`Event::decode`] builds it and it is never written, so the
    /// log keeps the proposal as it was filed. The claim stays in the ledger, withdrawn.
    #[serde(skip)]
    Lapsed {
        claim: Claim,
        reason: String,
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
    /// The checkers of the program that writes this log, each with its version. From
    /// here on a verdict counts only if it came from a checker listed here, at the
    /// version listed. Written again whenever the set changes, so a verdict from a
    /// checker that has since been fixed stops deciding a claim's status.
    CheckersSet {
        current: BTreeMap<String, u32>,
    },
}

impl Event {
    /// # Errors
    /// Fails only if serialization fails.
    pub fn encode(&self) -> Result<String, CoreError> {
        Ok(serde_json::to_string(self)?)
    }

    /// A proposal that fails admission is not an error: see [`Event::Lapsed`].
    /// Tightening a rule must not make a ledger unreadable.
    ///
    /// # Errors
    /// Malformed JSON, or an event or claim of a kind this version does not know.
    pub fn decode(s: &str) -> Result<Self, CoreError> {
        #[derive(Deserialize)]
        #[serde(tag = "event", rename_all = "snake_case")]
        enum Stored {
            Proposed {
                claim: Claim,
            },
            #[serde(other)]
            Other,
        }
        let refused = match serde_json::from_str(s) {
            Ok(event) => return Ok(event),
            Err(refused) => refused,
        };
        if let Ok(Stored::Proposed { claim }) = serde_json::from_str(s)
            && let Err(CoreError::Inadmissible(reason)) = admit(claim.clone())
        {
            return Ok(Self::Lapsed { claim, reason });
        }
        Err(refused.into())
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

/// How a claim differs from an earlier claim of the same kind about the same subject.
/// After a refutation the tempting fix is to say less until the check passes;
/// this makes what was given up visible.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Revision {
    /// What the earlier claim asked for that this one dropped or loosened.
    pub weaker: Vec<String>,
    /// Every other difference: something added, tightened or replaced.
    pub other: Vec<String>,
}

impl Revision {
    /// Walks two claims' JSON side by side. Which direction is "weaker" depends on what
    /// a value means, and that is read off its key: a `required` list asks for more with
    /// every entry, an allow-list (`statuses`, `enum`, `type`) permits more with every entry.
    fn compare(&mut self, path: &str, key: &str, old: &serde_json::Value, new: &serde_json::Value) {
        use serde_json::Value as V;
        const NOTES: [&str; 4] = ["title", "description", "$comment", "examples"];
        const FLOORS: [&str; 6] = [
            "min",
            "minimum",
            "minLength",
            "minItems",
            "min_chars",
            "exclusiveMinimum",
        ];
        const CEILINGS: [&str; 5] = [
            "max",
            "maximum",
            "maxLength",
            "maxItems",
            "exclusiveMaximum",
        ];
        let plain = |values: &[V]| values.iter().all(|v| !v.is_object() && !v.is_array());
        match (old, new) {
            _ if old == new => {}
            (V::Object(a), V::Object(b)) => {
                for (k, was) in a.iter().filter(|(k, _)| !NOTES.contains(&k.as_str())) {
                    match b.get(k) {
                        Some(now) => self.compare(&format!("{path}/{k}"), k, was, now),
                        None => self.weaker.push(format!("{path}/{k} dropped")),
                    }
                }
                let added = b
                    .keys()
                    .filter(|k| !a.contains_key(*k) && !NOTES.contains(&k.as_str()));
                self.other
                    .extend(added.map(|k| format!("{path}/{k} added")));
            }
            (V::Array(a), V::Array(b)) if plain(a) && plain(b) => {
                self.compare_sets(path, key, a, b);
            }
            (V::Array(a), V::Array(b)) => {
                for at in 0..a.len().max(b.len()) {
                    match (a.get(at), b.get(at)) {
                        (Some(was), Some(now)) => {
                            self.compare(&format!("{path}/{at}"), key, was, now);
                        }
                        (Some(_), None) => self.weaker.push(format!("{path}/{at} dropped")),
                        _ => self.other.push(format!("{path}/{at} added")),
                    }
                }
            }
            (V::String(_), V::Array(b)) if key == "type" && b.contains(old) => {
                self.compare_sets(path, key, std::slice::from_ref(old), b);
            }
            (V::Number(a), V::Number(b)) if FLOORS.contains(&key) || CEILINGS.contains(&key) => {
                let (was, now) = (a.as_f64().unwrap_or(0.0), b.as_f64().unwrap_or(0.0));
                let looser = if FLOORS.contains(&key) {
                    now < was
                } else {
                    now > was
                };
                let side = if looser {
                    &mut self.weaker
                } else {
                    &mut self.other
                };
                side.push(format!("{path} was {a}, now {b}"));
            }
            (V::Bool(true), V::Bool(false)) if key == "exact" => {
                self.weaker.push(format!("{path} no longer holds"));
            }
            _ => self.other.push(format!("{path} was {old}, now {new}")),
        }
    }

    /// Two lists of plain values, compared as sets.
    fn compare_sets(
        &mut self,
        path: &str,
        key: &str,
        old: &[serde_json::Value],
        new: &[serde_json::Value],
    ) {
        let allows = matches!(key, "statuses" | "tags" | "one_of" | "enum" | "type");
        let only_in = |these: &[serde_json::Value], those: &[serde_json::Value]| {
            let missing = these.iter().filter(|v| !those.contains(v));
            missing
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        };
        let (gone, came) = (only_in(old, new), only_in(new, old));
        // Entries leaving a list of requirements loosen the claim; entries joining an allow-list do.
        let (loosened, tightened) = if allows { (came, gone) } else { (gone, came) };
        let (loosening, tightening) = if allows {
            ("now also allows", "no longer allows")
        } else {
            ("no longer asks for", "now also asks for")
        };
        if !loosened.is_empty() {
            self.weaker.push(format!("{path} {loosening} {loosened}"));
        }
        if !tightened.is_empty() {
            self.other.push(format!("{path} {tightening} {tightened}"));
        }
    }
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
    /// Why today's admission rules refuse this claim, if it was admitted under earlier ones.
    lapsed: Option<String>,
}

impl Entry {
    /// This claim's status, given the statuses of its premises.
    fn status(&self, current: &BTreeMap<String, u32>, premise: impl Fn(usize) -> Status) -> Status {
        let any = |f: fn(&Verdict) -> bool| self.counted(current).any(|(v, counts)| counts && f(v));
        if self.retracted || self.lapsed.is_some() {
            Status::Retracted
        } else if any(|v| matches!(v, Verdict::Refuted { .. })) {
            Status::Refuted
        } else if self.premises.iter().any(|&p| premise(p) != Status::Held) {
            Status::Blocked
        } else if any(|v| matches!(v, Verdict::Held { .. })) {
            Status::Held
        } else if !self.counted(current).any(|(_, counts)| counts) {
            Status::Unchecked
        } else {
            Status::Inconclusive
        }
    }
}

impl Entry {
    /// Each verdict with whether it counts towards the status. Before the log lists
    /// its checkers every verdict does; after that, only one from a listed checker
    /// at the listed version.
    fn counted<'a>(
        &'a self,
        current: &'a BTreeMap<String, u32>,
    ) -> impl Iterator<Item = (&'a Verdict, bool)> {
        let counts = move |checker: &Option<CheckerRef>| {
            let listed = |c: &CheckerRef| current.get(&c.id) == Some(&c.version);
            current.is_empty() || checker.as_ref().is_some_and(listed)
        };
        let checkers = self.checks.iter().map(|(_, checker)| checker);
        self.verdicts.iter().zip(checkers.map(counts))
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
    /// The checkers whose verdicts count, as the log last listed them.
    checkers: BTreeMap<String, u32>,
}

impl Ledger {
    /// Validates the event against current state, then applies it. On error the ledger is unchanged.
    ///
    /// # Errors
    /// Unknown claim/evidence references or a duplicate proposal.
    pub fn apply(&mut self, event: Event) -> Result<(), CoreError> {
        match event {
            Event::Proposed { claim } => self.enter(claim.0, None)?,
            Event::Lapsed { claim, reason } => self.enter(claim, Some(reason))?,
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
            Event::CheckersSet { current } => self.checkers = current,
        }
        Ok(())
    }

    /// Adds a claim. `lapsed` says why today's rules refuse it, if they do.
    fn enter(&mut self, claim: Claim, lapsed: Option<String>) -> Result<(), CoreError> {
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
            lapsed,
        });
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

    /// A claim's verdicts, oldest first, each with whether it still counts towards
    /// the status: one from a checker version that is no longer current does not.
    pub fn current_verdicts(&self, id: &ClaimId) -> impl Iterator<Item = (&Verdict, bool)> {
        let entry = self.entry(id).into_iter();
        entry.flat_map(|e| e.counted(&self.checkers))
    }

    /// The checkers whose verdicts count, by id, as the log last listed them. Empty
    /// until the log lists any.
    #[must_use]
    pub const fn checkers(&self) -> &BTreeMap<String, u32> {
        &self.checkers
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

    /// Why a claim that was admitted under earlier rules is refused by today's. Such a
    /// claim counts as withdrawn.
    #[must_use]
    pub fn lapsed(&self, id: &ClaimId) -> Option<&str> {
        self.entry(id)?.lapsed.as_deref()
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

    /// The refuted claim, proposed earlier, of the same kind and subject that this
    /// claim differs least from: the one it most likely replaces.
    #[must_use]
    pub fn revised_from(&self, id: &ClaimId) -> Option<(&ClaimId, Revision)> {
        let at = *self.index.get(id)?;
        let claim = &self.entries[at].claim;
        let statuses: Vec<Status> = self.statuses().map(|(_, status)| status).collect();
        (self.entries[..at].iter().zip(statuses))
            .filter(|(_, status)| *status == Status::Refuted)
            .filter_map(|(earlier, _)| Some((&earlier.id, claim.revision_of(&earlier.claim)?)))
            .min_by_key(|(_, revision)| revision.weaker.len() + revision.other.len())
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
            let status = self.entries[at].status(&self.checkers, |p| settled[&p]);
            settled.insert(at, status);
        }
        settled.get(&target).copied()
    }

    /// Every claim's status, in one pass in proposal order.
    pub fn statuses(&self) -> impl Iterator<Item = (&ClaimId, Status)> {
        let mut settled: Vec<Status> = Vec::with_capacity(self.entries.len());
        for entry in &self.entries {
            let status = entry.status(&self.checkers, |p| settled[p]);
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
    fn a_stored_claim_the_rules_now_refuse_stays_in_the_ledger_withdrawn() -> Result<(), CoreError>
    {
        // A field outside its type: refused today, and standing in for any claim that
        // was admitted before a rule was tightened.
        let claim = r#"{"kind":"memory_layout","type_name":"Player","size":4,"fields":[{"name":"hp","offset":8,"len":4}],"premises":[]}"#;
        let event = Event::decode(&format!(r#"{{"event":"proposed","claim":{claim}}}"#))?;
        let mut ledger = Ledger::default();
        ledger.apply(event.clone())?;
        let id = ledger.claims().map(|(id, _)| id.clone()).next();
        let id = id.ok_or_else(|| CoreError::Inadmissible("the claim was not loaded".into()))?;
        assert_eq!(ledger.status(&id), Some(Status::Retracted));
        assert!(ledger.lapsed(&id).is_some_and(|why| why.contains("hp")));
        // The log already holds the proposal; the loaded form is never written again.
        assert!(event.encode().is_err());
        // Events that name the claim still apply, so the rest of the log replays.
        ledger.apply(Event::Retracted {
            claim: id,
            reason: "second look".into(),
        })?;
        // A new proposal still has to pass admission, and other bad events are still errors.
        assert!(serde_json::from_str::<WellFormed<Claim>>(claim).is_err());
        assert!(Event::decode(r#"{"event":"proposed","claim":{"kind":"no_such_kind"}}"#).is_err());
        assert!(Event::decode(r#"{"event":"no_such_event"}"#).is_err());
        Ok(())
    }

    #[test]
    fn a_condition_cannot_negate_a_value() {
        // `!a=1` used to be accepted and then looked for a parameter named `a=1`,
        // so it matched requests with and without `a=1` alike.
        assert!(Endpoint::parse("GET /x?!a=1").is_err());
        assert!(Endpoint::parse("GET /x?a=1&!b").is_ok());
    }

    #[test]
    fn schemas_that_say_nothing_are_refused_however_they_are_written() {
        let admitted = |schema: serde_json::Value| {
            admit(Claim {
                kind: ClaimKind::ResponseSchema(ResponseSchema {
                    endpoint: "GET /x".into(),
                    status: 200,
                    schema,
                }),
                premises: BTreeSet::new(),
            })
            .is_ok()
        };
        let all_types = [
            "null", "boolean", "object", "array", "number", "string", "integer",
        ];
        for nothing in [
            serde_json::json!({"required": []}),
            serde_json::json!({"additionalProperties": true}),
            serde_json::json!({"minItems": 0, "minLength": 0}),
            serde_json::json!({"type": all_types}),
            serde_json::json!({"anyOf": [{"required": ["id"]}, {}]}),
            serde_json::json!({"allOf": [{}, true]}),
            serde_json::json!({"not": false}),
            serde_json::json!({"items": {}, "properties": {"id": {"required": []}}}),
        ] {
            assert!(!admitted(nothing.clone()), "{nothing} was admitted");
        }
        for something in [
            serde_json::json!({"required": ["id"]}),
            serde_json::json!({"additionalProperties": false}),
            serde_json::json!({"minItems": 1}),
            serde_json::json!({"type": ["object", "null"]}),
            serde_json::json!({"anyOf": [{"required": ["id"]}, {"type": "null"}]}),
            serde_json::json!({"not": {}}),
            serde_json::json!({"items": {"type": "string"}}),
        ] {
            assert!(admitted(something.clone()), "{something} was refused");
        }
    }

    #[test]
    fn a_url_inside_a_query_is_not_the_request_url() -> Result<(), &'static str> {
        // A server-side capture has no scheme or host; its query can still hold a URL.
        let callback = "/api/score?redirect=https://app.example/cb";
        assert_eq!(url_host_and_path(callback), ("", "/api/score"));
        let score = Endpoint::parse("POST /api/score")?;
        assert!(score.matches("POST", callback));
        assert!(!score.matches("POST", "/other?x=://a/api/score"));
        // A real scheme still gives a host.
        assert_eq!(
            url_host_and_path("https://app.example/cb?next=http://x/y"),
            ("app.example", "/cb")
        );
        Ok(())
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
    fn a_revision_shows_what_was_given_up() -> Result<(), CoreError> {
        let record = |schema| Claim {
            kind: ClaimKind::ResponseSchema(ResponseSchema {
                endpoint: "GET /repos/{owner}/{repo}".into(),
                status: 200,
                schema,
            }),
            premises: BTreeSet::new(),
        };
        let first = record(serde_json::json!({
            "required": ["id", "organization"],
            "properties": {"homepage": {"type": "string"}, "stars": {"minimum": 10}},
        }));
        let looser = record(serde_json::json!({
            "required": ["id"],
            "properties": {"homepage": {"type": ["string", "null"]}, "stars": {"minimum": 0}},
        }));
        let revision = looser.revision_of(&first).unwrap_or_default();
        assert_eq!(revision.other, Vec::<String>::new());
        assert_eq!(
            revision.weaker,
            [
                "/schema/properties/homepage/type now also allows \"null\"",
                "/schema/properties/stars/minimum was 10, now 0",
                "/schema/required no longer asks for \"organization\"",
            ]
        );
        // The other way round nothing was given up, and a claim about another endpoint is no revision.
        let back = first.revision_of(&looser).unwrap_or_default();
        assert!(back.weaker.is_empty() && back.other.len() == 3, "{back:?}");
        assert_eq!(first.revision_of(&first), None);
        // Claims about different headers of one endpoint, or different statuses, are not revisions.
        let sends = |status, header: &str| Claim {
            kind: ClaimKind::ResponseHeader(ResponseHeader {
                endpoint: "GET /{page}".into(),
                status,
                header: header.into(),
                value: serde_json::json!({"minLength": 1}),
            }),
            premises: BTreeSet::new(),
        };
        assert_eq!(sends(200, "server").revision_of(&sends(200, "etag")), None);
        assert_eq!(
            sends(404, "server").revision_of(&sends(200, "server")),
            None
        );
        assert_eq!(schema().revision_of(&first), None);

        // In a ledger: the looser claim is traced to the refuted one it replaces.
        let mut l = Ledger::default();
        let (first_id, looser_id) = (first.id()?, looser.id()?);
        l.apply(Event::Proposed {
            claim: admit(first)?,
        })?;
        l.apply(Event::Proposed {
            claim: admit(looser)?,
        })?;
        assert_eq!(l.revised_from(&looser_id), None, "nothing is refuted yet");
        l.apply(Event::Checked {
            claim: first_id.clone(),
            evidence: BTreeSet::new(),
            verdict: Verdict::Refuted {
                counterexample: Counterexample {
                    evidence: EvidenceId::of(b"e"),
                    detail: String::new(),
                },
            },
            checker: None,
        })?;
        assert_eq!(
            l.revised_from(&looser_id)
                .map(|(id, r)| (id.clone(), r.weaker.len())),
            Some((first_id.clone(), 3))
        );
        assert_eq!(l.revised_from(&first_id), None, "only earlier claims count");
        Ok(())
    }

    #[test]
    fn response_header_sentence_and_admission() {
        let header = |status, value| Claim {
            kind: ClaimKind::ResponseHeader(ResponseHeader {
                endpoint: "GET /{page}".into(),
                status,
                header: "strict-transport-security".into(),
                value,
            }),
            premises: BTreeSet::new(),
        };
        insta::assert_snapshot!(
            "response_header",
            header(200, serde_json::json!({"pattern": "max-age="})).sentence()
        );
        insta::assert_snapshot!(
            "response_header_present",
            header(404, serde_json::json!(true)).sentence()
        );
        assert!(admit(header(200, serde_json::json!(true))).is_ok());
        assert!(admit(header(99, serde_json::json!(true))).is_err());
        assert!(admit(header(200, serde_json::json!("not a schema"))).is_err());
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
    fn a_verdict_from_another_checker_version_stops_counting() -> Result<(), CoreError> {
        let set = |version: u32| {
            let current = format!(r#"{{"memory_layout":{version}}}"#);
            Event::decode(&format!(
                r#"{{"event":"checkers_set","current":{current}}}"#
            ))
        };
        let mut l = Ledger::default();
        let (held, wrong) = (layout(32), layout(40));
        let (held_id, wrong_id) = (held.id()?, wrong.id()?);
        let mut dep = signature();
        dep.premises.insert(held_id.clone());
        let dep_id = dep.id()?;
        for claim in [held, wrong, dep] {
            l.apply(Event::Proposed {
                claim: admit(claim)?,
            })?;
        }
        let ev = EvidenceId::of(b"snapshot");
        l.apply(Event::EvidenceAdded {
            id: ev.clone(),
            kind: EvidenceKind::MemorySnapshot,
        })?;
        let check = |claim: &ClaimId, verdict, checker: &str, version| Event::Checked {
            claim: claim.clone(),
            evidence: [ev.clone()].into(),
            verdict,
            checker: Some(CheckerRef {
                id: checker.into(),
                version,
            }),
        };
        let yes = || Verdict::Held {
            runs: NonZeroU64::MIN,
        };
        let no = Verdict::Refuted {
            counterexample: Counterexample {
                evidence: ev.clone(),
                detail: "a bug in version 1".into(),
            },
        };
        l.apply(check(&held_id, yes(), "memory_layout", 1))?;
        l.apply(check(&wrong_id, no, "memory_layout", 1))?;
        l.apply(check(&dep_id, yes(), "request_signature", 1))?;
        // Until the log says which checkers are current, every verdict counts.
        let status = |l: &Ledger| [&held_id, &wrong_id, &dep_id].map(|id| l.status(id));
        let (held, refuted) = (Some(Status::Held), Some(Status::Refuted));
        assert_eq!(status(&l), [held, refuted, held]);
        l.apply(set(1)?)?;
        // The signature checker is not listed, so its verdict no longer counts.
        assert_eq!(status(&l), [held, refuted, Some(Status::Unchecked)]);
        // The checker is fixed and its version bumped: its old verdicts lapse, the
        // wrong refutation with them, and what rested on them goes on hold.
        l.apply(set(2)?)?;
        let unchecked = Some(Status::Unchecked);
        assert_eq!(status(&l), [unchecked, unchecked, Some(Status::Blocked)]);
        assert_eq!(
            l.statuses().map(|(_, s)| Some(s)).collect::<Vec<_>>(),
            status(&l)
        );
        // A fresh check by the current version counts again.
        l.apply(check(&held_id, yes(), "memory_layout", 2))?;
        assert_eq!(l.status(&held_id), held);
        let counted: Vec<bool> = l
            .current_verdicts(&held_id)
            .map(|(_, counts)| counts)
            .collect();
        assert_eq!(counted, [false, true]);
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
        // It is admitted again on the way in, and a failure never yields a live proposal.
        assert!(matches!(Event::decode(bad), Ok(Event::Lapsed { .. })));
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
        let calls = |caller, callee| Claim {
            kind: ClaimKind::CallEdge(CallEdge {
                binary: "true".into(),
                caller,
                callee,
            }),
            premises: BTreeSet::new(),
        };
        let named = |name: &str| FunctionRef::Name(name.into());
        insta::assert_snapshot!(
            "call_edge",
            calls(FunctionRef::Address(0x2480), named("setlocale")).sentence()
        );
        assert!(admit(calls(named("main"), named("main"))).is_ok());
        assert!(admit(calls(named("main"), named(""))).is_err());
        // Two call edges in one binary are two findings, not one revised.
        assert_eq!(
            calls(named("main"), named("exit")).revision_of(&calls(named("main"), named("abort"))),
            None
        );
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
        entry.status(&l.checkers, |p| status_by_recursion(l, &l.entries[p].id))
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
