//! File and message layouts written in Kaitai Struct, read from JSON.
//!
//! A description is the JSON form of a `.ksy` file. Only part of the language is
//! read, and a key or a type outside that part is refused by name, never skipped:
//! a description that was half understood could hold for the wrong reason.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::de::IgnoredAny;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// How deep an expression or a type may nest. Descriptions come from agents.
pub const MAX_NESTING: usize = 64;

/// The most numbers, names and signs in one expression. `1 + 1 + 1 ...` nests as deep
/// as it is long, and whatever walks an expression recurses that deep.
pub const MAX_TOKENS: usize = 256;

/// Every file of one kind parses under a Kaitai Struct description.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Format {
    pub type_name: String,
    /// A Kaitai Struct description (the content of a `.ksy` file) as JSON. Read:
    /// `meta` (`endian`, `encoding`), `seq`, `instances` (`value`, or `pos` with
    /// an optional `io`), `types`; per field `id`, `type`, `size`, `size-eos`,
    /// `contents`, `repeat` with `repeat-expr` or `repeat-until`, `if`, `valid`,
    /// `encoding`. Types: `u1`, `u2`, `u4`, `u8`, the same with `s`, `f4`, `f8`
    /// (with `le` or `be`), `str`, `strz`, a name from `types`, or `switch-on` with `cases`.
    /// Not read: `enums`, `params`, `process`, bit fields, `terminator`, calls.
    pub spec: Value,
    /// Whether the top-level fields end exactly where the file ends.
    #[serde(default)]
    pub exact: bool,
}

impl Format {
    /// Plain sentence shown to the human.
    pub(crate) fn sentence(&self) -> String {
        let (types, fields, checked) = Spec::parse(&self.spec).map_or((0, 0, 0), |spec| {
            let fields = || {
                spec.types
                    .iter()
                    .flat_map(|t| t.seq.iter().chain(&t.instances))
            };
            let checked = fields().filter(|a| a.checks()).count();
            (spec.types.len(), fields().count(), checked)
        });
        let end = if self.exact {
            ", and ends where its top-level fields end"
        } else {
            ""
        };
        format!(
            "Every `{}` parses as format description {}: {fields} fields in {types} types, {checked} checked against fixed bytes or a rule{end}.",
            self.type_name,
            crate::schema_print(&self.spec),
        )
    }

    /// What admission asks of this kind.
    pub(crate) fn admissible(&self) -> Result<(), String> {
        if self.type_name.is_empty() {
            return Err(String::from("a format needs a type name"));
        }
        let spec = Spec::parse(&self.spec)?;
        let reads = |a: &Attr| a.value.is_none() && (a.checks() || a.size != Some(Size::ToEnd));
        if !self.exact
            && !spec
                .types
                .iter()
                .any(|t| t.seq.iter().chain(&t.instances).any(reads))
        {
            return Err(String::from(
                "this description reads nothing that a file could lack, so nothing could refute it; give a field a type, a size, `contents` or `valid`",
            ));
        }
        Ok(())
    }
}

/// A description with every name resolved and every expression parsed.
#[derive(Debug, Clone, PartialEq)]
pub struct Spec {
    /// The first type is the whole file.
    pub types: Vec<Type>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Type {
    /// Its name with the types around it, for messages: `file.header`.
    pub name: String,
    pub seq: Vec<Attr>,
    pub instances: Vec<Attr>,
}

/// One field: read from the bytes, or computed from other fields.
#[derive(Debug, Clone, PartialEq)]
pub struct Attr {
    pub id: String,
    /// The field exists only when this holds.
    pub cond: Option<Expr>,
    pub repeat: Option<Repeat>,
    /// A computed field. It reads no bytes, and the rest but `valid` is unused.
    pub value: Option<Expr>,
    /// Where to read, from the start of the stream. Without it the field follows the one before.
    pub pos: Option<Expr>,
    /// The stream `pos` counts in, when not the one the field's type is read from.
    pub io: Option<Expr>,
    pub size: Option<Size>,
    pub read: Read,
    pub valid: Option<Valid>,
}

impl Attr {
    /// Whether a file's bytes can contradict this field beyond being too short.
    #[must_use]
    pub const fn checks(&self) -> bool {
        self.valid.is_some() || matches!(self.read, Read::Fixed(_))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Size {
    Bytes(Expr),
    ToEnd,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Repeat {
    Times(Expr),
    ToEnd,
    /// Until this holds of the element just read, which the expression calls `_`.
    Until(Expr),
}

#[derive(Debug, Clone, PartialEq)]
pub enum Read {
    /// Raw bytes; the field gives a size.
    Bytes,
    /// Exactly these bytes.
    Fixed(Vec<u8>),
    Int {
        len: usize,
        signed: bool,
        big: bool,
    },
    Float {
        len: usize,
        big: bool,
    },
    /// Text of the field's size, or up to a NUL.
    Text {
        utf8: bool,
        nul: bool,
    },
    /// An index into [`Spec::types`].
    Type(usize),
    Switch {
        on: Expr,
        cases: Vec<(Expr, Self)>,
        default: Option<Box<Self>>,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum Valid {
    Eq(Expr),
    Range {
        min: Option<Expr>,
        max: Option<Expr>,
    },
    AnyOf(Vec<Expr>),
    /// Holds of the value, which the expression calls `_`.
    Expr(Expr),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Mul,
    Div,
    Rem,
    Add,
    Sub,
    Shl,
    Shr,
    BitAnd,
    BitXor,
    BitOr,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    And,
    Or,
}

/// A Kaitai Struct expression.
#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    Int(i128),
    Float(f64),
    Bool(bool),
    Text(String),
    /// A field of the type being read, or `_`, `_index`, `_io`, `_parent`, `_root`.
    Name(String),
    Not(Box<Self>),
    Neg(Box<Self>),
    Invert(Box<Self>),
    Binary(Op, Box<Self>, Box<Self>),
    If(Box<Self>, Box<Self>, Box<Self>),
    Member(Box<Self>, String),
    Index(Box<Self>, Box<Self>),
}

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Int(i128),
    Float(f64),
    Text(String),
    Word(String),
    Sign(&'static str),
}

const SIGNS: [&str; 25] = [
    "::", "<<", ">>", "==", "!=", "<=", ">=", "+", "-", "*", "/", "%", "&", "|", "^", "~", "<",
    ">", "?", ":", ".", "[", "]", "(", ")",
];

fn tokens(source: &str) -> Result<Vec<Token>, String> {
    let mut out = Vec::new();
    let mut rest = source.trim_start();
    while let Some(first) = rest.chars().next() {
        let taken = if first.is_ascii_digit() {
            let (found, len) = number(rest)?;
            out.push(found);
            len
        } else if first.is_ascii_alphabetic() || first == '_' {
            let end = rest
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .unwrap_or(rest.len());
            out.push(Token::Word(rest[..end].to_owned()));
            end
        } else if first == '\'' || first == '"' {
            let (text, taken) = quoted(rest, first)?;
            out.push(Token::Text(text));
            taken
        } else {
            let sign = SIGNS
                .iter()
                .find(|sign| rest.starts_with(**sign))
                .ok_or_else(|| format!("`{first}` is not part of an expression"))?;
            out.push(Token::Sign(sign));
            sign.len()
        };
        rest = rest[taken..].trim_start();
        if out.len() > MAX_TOKENS {
            return Err(format!("an expression has more than {MAX_TOKENS} parts"));
        }
    }
    Ok(out)
}

fn number(rest: &str) -> Result<(Token, usize), String> {
    let digits = |text: &str, radix: u32| {
        let end = text
            .find(|c: char| !(c.is_digit(radix) || c == '_'))
            .unwrap_or(text.len());
        (text[..end].replace('_', ""), end)
    };
    let radix = match rest.get(..2) {
        Some("0x") => Some(16),
        Some("0b") => Some(2),
        Some("0o") => Some(8),
        _ => None,
    };
    if let Some(radix) = radix {
        let (text, end) = digits(&rest[2..], radix);
        let value = i128::from_str_radix(&text, radix)
            .map_err(|_| format!("`{}` is not a number", &rest[..2 + end]))?;
        return Ok((Token::Int(value), 2 + end));
    }
    let (whole, end) = digits(rest, 10);
    let fraction = rest[end..]
        .strip_prefix('.')
        .filter(|after| after.starts_with(|c: char| c.is_ascii_digit()));
    if let Some(after) = fraction {
        let (part, more) = digits(after, 10);
        let value = format!("{whole}.{part}")
            .parse()
            .map_err(|_| format!("`{whole}.{part}` is not a number"))?;
        return Ok((Token::Float(value), end + 1 + more));
    }
    let value = whole
        .parse()
        .map_err(|_| format!("`{whole}` is not a number"))?;
    Ok((Token::Int(value), end))
}

fn quoted(rest: &str, quote: char) -> Result<(String, usize), String> {
    let mut text = String::new();
    let mut chars = rest.char_indices().skip(1);
    while let Some((at, c)) = chars.next() {
        match c {
            c if c == quote => return Ok((text, at + 1)),
            // Only double quotes take escapes, as in Kaitai Struct.
            '\\' if quote == '"' => match chars.next() {
                Some((_, 'n')) => text.push('\n'),
                Some((_, 'r')) => text.push('\r'),
                Some((_, 't')) => text.push('\t'),
                Some((_, '0')) => text.push('\0'),
                Some((_, c @ ('\\' | '"'))) => text.push(c),
                _ => {
                    return Err(String::from(
                        "only \\n \\r \\t \\0 \\\\ and \\\" are read as escapes",
                    ));
                }
            },
            c => text.push(c),
        }
    }
    Err(format!("the text starting at {rest} has no closing quote"))
}

struct Parser {
    tokens: Vec<Token>,
    at: usize,
    depth: usize,
}

impl Parser {
    fn sign(&mut self, wanted: &str) -> bool {
        let found = matches!(self.tokens.get(self.at), Some(Token::Sign(s)) if *s == wanted);
        self.at += usize::from(found);
        found
    }

    fn word(&mut self, wanted: &str) -> bool {
        let found = matches!(self.tokens.get(self.at), Some(Token::Word(w)) if w == wanted);
        self.at += usize::from(found);
        found
    }

    /// One level of left-associative binary operators over `next`.
    fn level(
        &mut self,
        ops: &[(&str, Op)],
        next: fn(&mut Self) -> Result<Expr, String>,
    ) -> Result<Expr, String> {
        let mut left = next(self)?;
        while let Some((_, op)) = ops
            .iter()
            .find(|(sign, _)| self.sign(sign) || self.word(sign))
        {
            left = Expr::Binary(*op, Box::new(left), Box::new(next(self)?));
        }
        Ok(left)
    }

    // Loosest first, in Kaitai Struct's order: bit operators bind tighter than comparisons.
    fn ternary(&mut self) -> Result<Expr, String> {
        self.depth += 1;
        if self.depth > MAX_NESTING {
            return Err(format!("an expression nests deeper than {MAX_NESTING}"));
        }
        let test = self.level(&[("or", Op::Or)], Self::and)?;
        let out = if self.sign("?") {
            let then = self.ternary()?;
            if !self.sign(":") {
                return Err(String::from("`?` needs a `:`"));
            }
            Expr::If(Box::new(test), Box::new(then), Box::new(self.ternary()?))
        } else {
            test
        };
        self.depth -= 1;
        Ok(out)
    }

    fn and(&mut self) -> Result<Expr, String> {
        self.level(&[("and", Op::And)], Self::not)
    }

    fn not(&mut self) -> Result<Expr, String> {
        if self.word("not") {
            return Ok(Expr::Not(Box::new(self.not()?)));
        }
        let left = self.bit_or()?;
        let ops = [
            ("==", Op::Eq),
            ("!=", Op::Ne),
            ("<=", Op::Le),
            (">=", Op::Ge),
            ("<", Op::Lt),
            (">", Op::Gt),
        ];
        match ops.iter().find(|(sign, _)| self.sign(sign)) {
            Some((_, op)) => Ok(Expr::Binary(*op, Box::new(left), Box::new(self.bit_or()?))),
            None => Ok(left),
        }
    }

    fn bit_or(&mut self) -> Result<Expr, String> {
        self.level(&[("|", Op::BitOr)], Self::bit_xor)
    }

    fn bit_xor(&mut self) -> Result<Expr, String> {
        self.level(&[("^", Op::BitXor)], Self::bit_and)
    }

    fn bit_and(&mut self) -> Result<Expr, String> {
        self.level(&[("&", Op::BitAnd)], Self::shift)
    }

    fn shift(&mut self) -> Result<Expr, String> {
        self.level(&[("<<", Op::Shl), (">>", Op::Shr)], Self::sum)
    }

    fn sum(&mut self) -> Result<Expr, String> {
        self.level(&[("+", Op::Add), ("-", Op::Sub)], Self::product)
    }

    fn product(&mut self) -> Result<Expr, String> {
        self.level(
            &[("*", Op::Mul), ("/", Op::Div), ("%", Op::Rem)],
            Self::unary,
        )
    }

    fn unary(&mut self) -> Result<Expr, String> {
        self.depth += 1;
        if self.depth > MAX_NESTING {
            return Err(format!("an expression nests deeper than {MAX_NESTING}"));
        }
        let out = if self.sign("-") {
            Expr::Neg(Box::new(self.unary()?))
        } else if self.sign("~") {
            Expr::Invert(Box::new(self.unary()?))
        } else if self.sign("+") {
            self.unary()?
        } else {
            self.postfix()?
        };
        self.depth -= 1;
        Ok(out)
    }

    fn postfix(&mut self) -> Result<Expr, String> {
        let mut out = self.atom()?;
        loop {
            if self.sign(".") {
                let Some(Token::Word(name)) = self.tokens.get(self.at).cloned() else {
                    return Err(String::from("`.` needs a name after it"));
                };
                self.at += 1;
                out = Expr::Member(Box::new(out), name);
            } else if self.sign("[") {
                let index = self.ternary()?;
                if !self.sign("]") {
                    return Err(String::from("`[` needs a `]`"));
                }
                out = Expr::Index(Box::new(out), Box::new(index));
            } else if self.sign("(") {
                return Err(String::from("calls with `(...)` are not read"));
            } else if self.sign("::") {
                return Err(String::from(
                    "enums (`a::b`) are not read; compare with the number",
                ));
            } else {
                return Ok(out);
            }
        }
    }

    fn atom(&mut self) -> Result<Expr, String> {
        let token = self.tokens.get(self.at).cloned();
        self.at += 1;
        match token {
            Some(Token::Int(n)) => Ok(Expr::Int(n)),
            Some(Token::Float(n)) => Ok(Expr::Float(n)),
            Some(Token::Text(text)) => Ok(Expr::Text(text)),
            Some(Token::Word(word)) => Ok(match word.as_str() {
                "true" => Expr::Bool(true),
                "false" => Expr::Bool(false),
                "and" | "or" | "not" => return Err(format!("`{word}` is not a value")),
                _ => Expr::Name(word),
            }),
            Some(Token::Sign("(")) => {
                let inner = self.ternary()?;
                if self.sign(")") {
                    Ok(inner)
                } else {
                    Err(String::from("`(` needs a `)`"))
                }
            }
            Some(Token::Sign("[")) => Err(String::from("array literals are not read")),
            Some(Token::Sign(sign)) => Err(format!("`{sign}` is not a value")),
            None => Err(String::from("the expression ends where a value should be")),
        }
    }
}

impl Expr {
    /// Reads an expression as Kaitai Struct writes it.
    ///
    /// # Errors
    /// What in the text is not an expression, or is one this subset does not read.
    pub fn parse(source: &str) -> Result<Self, String> {
        let read = || {
            let mut parser = Parser {
                tokens: tokens(source)?,
                at: 0,
                depth: 0,
            };
            let out = parser.ternary()?;
            match parser.tokens.get(parser.at) {
                None => Ok(out),
                Some(extra) => Err(format!("unexpected {extra:?} after the expression")),
            }
        };
        read().map_err(|why: String| format!("in `{source}`: {why}"))
    }

    /// A value from the description: a JSON number or boolean is itself, a string is an expression.
    fn of(value: &Value) -> Result<Self, String> {
        match value {
            Value::Bool(b) => Ok(Self::Bool(*b)),
            Value::Number(n) => (n.as_i128().map(Self::Int))
                .or_else(|| n.as_f64().map(Self::Float))
                .ok_or_else(|| format!("{n} is not a number an expression can hold")),
            Value::String(source) => Self::parse(source),
            other => Err(format!("{other} is not an expression")),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct RawMeta {
    #[serde(default)]
    endian: Option<String>,
    #[serde(default)]
    encoding: Option<String>,
    // Says nothing about the bytes.
    #[serde(default, rename = "id")]
    _id: IgnoredAny,
    #[serde(default, rename = "title")]
    _title: IgnoredAny,
    #[serde(default, rename = "file-extension")]
    _file_extension: IgnoredAny,
    #[serde(default, rename = "application")]
    _application: IgnoredAny,
    #[serde(default, rename = "license")]
    _license: IgnoredAny,
    #[serde(default, rename = "ks-version")]
    _ks_version: IgnoredAny,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct RawType {
    #[serde(default)]
    meta: Option<RawMeta>,
    #[serde(default)]
    seq: Vec<RawAttr>,
    #[serde(default)]
    instances: BTreeMap<String, RawAttr>,
    #[serde(default)]
    types: BTreeMap<String, Self>,
    #[serde(default, rename = "doc")]
    _doc: IgnoredAny,
    #[serde(default, rename = "doc-ref")]
    _doc_ref: IgnoredAny,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct RawAttr {
    #[serde(default)]
    id: Option<String>,
    #[serde(default, rename = "type")]
    read: Option<Value>,
    #[serde(default)]
    size: Option<Value>,
    #[serde(default)]
    size_eos: bool,
    #[serde(default)]
    contents: Option<Value>,
    #[serde(default)]
    repeat: Option<String>,
    #[serde(default)]
    repeat_expr: Option<Value>,
    #[serde(default)]
    repeat_until: Option<Value>,
    #[serde(default, rename = "if")]
    cond: Option<Value>,
    #[serde(default)]
    valid: Option<Value>,
    #[serde(default)]
    encoding: Option<String>,
    #[serde(default)]
    pos: Option<Value>,
    #[serde(default)]
    io: Option<Value>,
    #[serde(default)]
    value: Option<Value>,
    #[serde(default, rename = "doc")]
    _doc: IgnoredAny,
    #[serde(default, rename = "doc-ref")]
    _doc_ref: IgnoredAny,
}

/// What a type's fields inherit from the types around it.
#[derive(Clone, Copy)]
struct Scope<'a> {
    /// Whether multi-byte numbers are big-endian, when `meta` says.
    big: Option<bool>,
    encoding: Option<&'a str>,
}

fn name_ok(name: &str) -> bool {
    name.starts_with(|c: char| c.is_ascii_lowercase())
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// The bytes of a `contents` value: text, or a list of bytes and text.
fn fixed(contents: &Value) -> Result<Vec<u8>, String> {
    let wrong = || String::from("`contents` is text, or a list of bytes (0 to 255) and text");
    match contents {
        Value::String(text) => Ok(text.clone().into_bytes()),
        Value::Array(parts) if !parts.is_empty() => {
            let mut out = Vec::new();
            for part in parts {
                match part {
                    Value::String(text) => out.extend_from_slice(text.as_bytes()),
                    Value::Number(n) => {
                        out.push(
                            n.as_u64()
                                .and_then(|n| u8::try_from(n).ok())
                                .ok_or_else(wrong)?,
                        );
                    }
                    _ => return Err(wrong()),
                }
            }
            Ok(out)
        }
        _ => Err(wrong()),
    }
}

fn valid(rule: &Value) -> Result<Valid, String> {
    let Value::Object(map) = rule else {
        return Expr::of(rule).map(Valid::Eq);
    };
    let part = |key: &str| map.get(key).map(Expr::of).transpose();
    let keys: Vec<&str> = map.keys().map(String::as_str).collect();
    match keys.as_slice() {
        ["eq"] => Ok(Valid::Eq(Expr::of(&map["eq"])?)),
        ["expr"] => Ok(Valid::Expr(Expr::of(&map["expr"])?)),
        ["min" | "max"] | ["max", "min"] => Ok(Valid::Range {
            min: part("min")?,
            max: part("max")?,
        }),
        ["any-of"] => match &map["any-of"] {
            Value::Array(list) if !list.is_empty() => Ok(Valid::AnyOf(
                list.iter().map(Expr::of).collect::<Result<_, _>>()?,
            )),
            _ => Err(String::from("`any-of` is a list of at least one value")),
        },
        _ => Err(String::from(
            "`valid` is a value, or one of `eq`, `min` and `max`, `any-of`, `expr`",
        )),
    }
}

struct Compiler<'a> {
    /// Each type's own nested types by name, and the type around it.
    nested: Vec<(BTreeMap<&'a str, usize>, Option<usize>)>,
    out: Vec<Type>,
}

impl<'a> Compiler<'a> {
    /// Gives every type its index, outer types first, so that a name can be resolved before its type is read.
    fn number(
        &mut self,
        raw: &'a RawType,
        name: &str,
        around: Option<usize>,
        depth: usize,
    ) -> Result<usize, String> {
        if depth > MAX_NESTING {
            return Err(format!("types nest deeper than {MAX_NESTING}"));
        }
        let at = self.out.len();
        self.out.push(Type {
            name: name.to_owned(),
            seq: Vec::new(),
            instances: Vec::new(),
        });
        self.nested.push((BTreeMap::new(), around));
        for (child, inner) in &raw.types {
            if !name_ok(child) {
                return Err(format!(
                    "type name `{child}` must be lower case letters, digits and `_`"
                ));
            }
            let index = self.number(inner, &format!("{name}.{child}"), Some(at), depth + 1)?;
            self.nested[at].0.insert(child, index);
        }
        Ok(at)
    }

    /// Finds a type by name from inside type `from`: its own types first, then those around it.
    fn find(&self, from: usize, name: &str) -> Option<usize> {
        let (own, around) = &self.nested[from];
        own.get(name)
            .copied()
            .or_else(|| self.find((*around)?, name))
    }

    fn read(
        &self,
        from: usize,
        raw: &Value,
        scope: Scope<'_>,
        encoding: Option<&str>,
    ) -> Result<Read, String> {
        let name = match raw {
            Value::String(name) => name.as_str(),
            Value::Object(switch) => {
                let (Some(on), Some(Value::Object(cases)), 2) =
                    (switch.get("switch-on"), switch.get("cases"), switch.len())
                else {
                    return Err(String::from(
                        "a `type` object needs `switch-on` and `cases`, and nothing else",
                    ));
                };
                let mut out = Vec::new();
                let mut default = None;
                for (case, target) in cases {
                    let target = self.read(from, target, scope, encoding)?;
                    if case == "_" {
                        default = Some(Box::new(target));
                    } else {
                        out.push((Expr::parse(case)?, target));
                    }
                }
                return Ok(Read::Switch {
                    on: Expr::of(on)?,
                    cases: out,
                    default,
                });
            }
            other => return Err(format!("`type` is a name or a `switch-on`, not {other}")),
        };
        let endian = |rest: &str| {
            match rest {
            "le" => Ok(false),
            "be" => Ok(true),
            "" => scope.big.ok_or_else(|| {
                format!("`{name}` needs a byte order: write `{name}le` or `{name}be`, or set `meta.endian`")
            }),
            _ => Err(format!("`{name}` is not a type")),
        }
        };
        let text = |nul| match encoding
            .or(scope.encoding)
            .map(str::to_ascii_lowercase)
            .as_deref()
        {
            Some("ascii") => Ok(Read::Text { utf8: false, nul }),
            Some("utf-8" | "utf8") => Ok(Read::Text { utf8: true, nul }),
            Some(other) => Err(format!(
                "encoding `{other}` is not read; use ASCII or UTF-8"
            )),
            None => Err(format!("`{name}` needs an `encoding`: ASCII or UTF-8")),
        };
        let width = |digit: &str| {
            digit
                .parse()
                .ok()
                .filter(|len| matches!(len, 1 | 2 | 4 | 8))
        };
        match name {
            "u1" | "s1" => Ok(Read::Int {
                len: 1,
                signed: name == "s1",
                big: false,
            }),
            "str" => text(false),
            "strz" => text(true),
            _ if let Some(index) = self.find(from, name) => Ok(Read::Type(index)),
            _ => match (name.get(..1), name.get(1..2).and_then(width), name.get(2..)) {
                (Some(kind @ ("u" | "s")), Some(len), Some(rest)) if len > 1 => Ok(Read::Int {
                    len,
                    signed: kind == "s",
                    big: endian(rest)?,
                }),
                (Some("f"), Some(len @ (4 | 8)), Some(rest)) => Ok(Read::Float {
                    len,
                    big: endian(rest)?,
                }),
                (Some("b"), _, _)
                    if name[1..].chars().all(|c| c.is_ascii_digit()) && name.len() > 1 =>
                {
                    Err(format!("bit fields (`{name}`) are not read"))
                }
                _ => Err(format!(
                    "`{name}` is neither a built-in type nor a name in `types`"
                )),
            },
        }
    }

    fn attr(
        &self,
        from: usize,
        id: &str,
        raw: &RawAttr,
        scope: Scope<'_>,
        instance: bool,
    ) -> Result<Attr, String> {
        let expr = |value: &Option<Value>| value.as_ref().map(Expr::of).transpose();
        let repeat = match (raw.repeat.as_deref(), &raw.repeat_expr, &raw.repeat_until) {
            (None, None, None) => None,
            (Some("expr"), Some(times), None) => Some(Repeat::Times(Expr::of(times)?)),
            (Some("until"), None, Some(until)) => Some(Repeat::Until(Expr::of(until)?)),
            (Some("eos"), None, None) => Some(Repeat::ToEnd),
            _ => {
                return Err(String::from(
                    "`repeat` is `expr` with `repeat-expr`, `until` with `repeat-until`, or `eos`",
                ));
            }
        };
        let size = match (&raw.size, raw.size_eos) {
            (Some(_), true) => {
                return Err(String::from("`size` and `size-eos` cannot both be given"));
            }
            (Some(size), false) => Some(Size::Bytes(Expr::of(size)?)),
            (None, true) => Some(Size::ToEnd),
            (None, false) => None,
        };
        let value = expr(&raw.value)?;
        let reads =
            raw.read.is_some() || size.is_some() || raw.contents.is_some() || raw.pos.is_some();
        if value.is_some() && (reads || !instance) {
            return Err(String::from(
                "`value` goes in `instances`, with no `type`, `size`, `contents` or `pos`",
            ));
        }
        if !instance && (raw.pos.is_some() || raw.io.is_some()) {
            return Err(String::from("`pos` and `io` go in `instances`"));
        }
        if raw.io.is_some() && raw.pos.is_none() {
            return Err(String::from("`io` needs a `pos`"));
        }
        let read = match (&raw.contents, &raw.read) {
            _ if value.is_some() => Read::Bytes,
            (Some(_), Some(_)) => return Err(String::from("`contents` cannot have a `type`")),
            (Some(_), None) if size.is_some() => {
                return Err(String::from("`contents` gives its own size"));
            }
            (Some(contents), None) => Read::Fixed(fixed(contents)?),
            (None, Some(read)) => self.read(from, read, scope, raw.encoding.as_deref())?,
            (None, None) => Read::Bytes,
        };
        let sized = |read: &Read| match read {
            Read::Bytes => "needs a `size`, `size-eos`, `contents` or a `type`",
            Read::Text { nul: false, .. } => "is `str`, which needs a `size` or `size-eos`",
            _ => "",
        };
        if value.is_none() && size.is_none() && !sized(&read).is_empty() {
            return Err(format!("it {}", sized(&read)));
        }
        if size.is_some() && matches!(read, Read::Int { .. } | Read::Float { .. }) {
            return Err(String::from(
                "a number's size comes from its type; drop `size`",
            ));
        }
        Ok(Attr {
            id: id.to_owned(),
            cond: expr(&raw.cond)?,
            repeat,
            value,
            pos: expr(&raw.pos)?,
            io: expr(&raw.io)?,
            size,
            read,
            valid: raw.valid.as_ref().map(valid).transpose()?,
        })
    }

    fn fill(&mut self, raw: &'a RawType, at: usize, around: Scope<'a>) -> Result<(), String> {
        let meta = raw.meta.as_ref();
        let big = match meta.and_then(|m| m.endian.as_deref()) {
            Some("le") => Some(false),
            Some("be") => Some(true),
            Some(other) => return Err(format!("`meta.endian` is `le` or `be`, not `{other}`")),
            None => around.big,
        };
        let scope = Scope {
            big,
            encoding: meta.and_then(|m| m.encoding.as_deref()).or(around.encoding),
        };
        let place = |id: &str| format!("field `{id}` of `{}`", self.out[at].name);
        let mut seen = std::collections::BTreeSet::new();
        let mut seq = Vec::new();
        for (index, field) in raw.seq.iter().enumerate() {
            let id = (field.id.as_deref())
                .ok_or_else(|| format!("field {index} of `{}` needs an `id`", self.out[at].name))?;
            if !name_ok(id) || !seen.insert(id) {
                return Err(format!(
                    "{}: an `id` is lower case letters, digits and `_`, used once",
                    place(id)
                ));
            }
            seq.push(
                self.attr(at, id, field, scope, false)
                    .map_err(|why| format!("{}: {why}", place(id)))?,
            );
        }
        let mut instances = Vec::new();
        for (id, field) in &raw.instances {
            if !name_ok(id) || !seen.insert(id) || field.id.is_some() {
                return Err(format!(
                    "{}: an instance is named by its key, in lower case letters, digits and `_`, used once",
                    place(id)
                ));
            }
            instances.push(
                self.attr(at, id, field, scope, true)
                    .map_err(|why| format!("{}: {why}", place(id)))?,
            );
        }
        self.out[at].seq = seq;
        self.out[at].instances = instances;
        for (child, inner) in &raw.types {
            let index = self.nested[at].0[child.as_str()];
            self.fill(inner, index, scope)?;
        }
        Ok(())
    }
}

impl Spec {
    /// Reads a description, resolving every type name and parsing every expression.
    ///
    /// # Errors
    /// The first thing in the description that is wrong or that this subset does not read.
    pub fn parse(spec: &Value) -> Result<Self, String> {
        let raw = RawType::deserialize(spec).map_err(|why| format!("in the description: {why}"))?;
        let mut compiler = Compiler {
            nested: Vec::new(),
            out: Vec::new(),
        };
        compiler.number(&raw, "file", None, 0)?;
        let top = Scope {
            big: None,
            encoding: None,
        };
        compiler.fill(&raw, 0, top)?;
        Ok(Self {
            types: compiler.out,
        })
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use serde_json::json;

    use super::*;

    fn claim(spec: Value) -> Format {
        Format {
            type_name: "ShaderCache".into(),
            spec,
            exact: false,
        }
    }

    #[test]
    fn a_description_is_admitted_or_refused_by_what_is_wrong() {
        let good = json!({
            "meta": {"id": "cache", "endian": "le"},
            "doc": "Says nothing about the bytes.",
            "seq": [
                {"id": "magic", "contents": "CACH"},
                {"id": "count", "type": "u4", "valid": {"max": 64}},
                {"id": "entries", "type": "entry", "repeat": "expr", "repeat-expr": "count"}
            ],
            "types": {"entry": {"seq": [{"id": "len", "type": "u2"}, {"id": "body", "size": "len"}]}}
        });
        assert_eq!(claim(good.clone()).admissible(), Ok(()));
        insta::assert_snapshot!("format", claim(good.clone()).sentence());
        let exact = Format {
            exact: true,
            ..claim(good)
        };
        insta::assert_snapshot!("format_exact", exact.sentence());

        let refused = |spec: Value| claim(spec).admissible().err().unwrap_or_default();
        let field = |field: Value| refused(json!({"seq": [field]}));
        for (why, wanted) in [
            (
                field(json!({"id": "a", "type": "u4"})),
                "needs a byte order",
            ),
            (
                field(json!({"id": "a", "type": "u1", "process": "zlib"})),
                "unknown field `process`",
            ),
            (
                refused(json!({"seq": [], "enums": {}})),
                "unknown field `enums`",
            ),
            (
                field(json!({"id": "a", "type": "b3"})),
                "bit fields (`b3`) are not read",
            ),
            (
                field(json!({"id": "a", "type": "entry"})),
                "neither a built-in type nor a name in `types`",
            ),
            (
                field(json!({"id": "a", "size": "n +"})),
                "in `n +`: the expression ends where a value should be",
            ),
            (
                field(json!({"id": "a", "size": "kind::big"})),
                "enums (`a::b`) are not read",
            ),
            (
                field(json!({"id": "a", "size": "f(1)"})),
                "calls with `(...)` are not read",
            ),
            (
                field(json!({"id": "a"})),
                "field `a` of `file`: it needs a `size`",
            ),
            (
                field(json!({"id": "a", "type": "str", "size": 4})),
                "needs an `encoding`",
            ),
            (
                field(json!({"type": "u1"})),
                "field 0 of `file` needs an `id`",
            ),
            (
                field(json!({"id": "a", "type": "u1", "repeat": "expr"})),
                "`repeat` is `expr` with `repeat-expr`",
            ),
            (
                field(json!({"id": "a", "type": "u1", "valid": {"minimum": 1}})),
                "`valid` is a value, or one of",
            ),
            (
                field(json!({"id": "rest", "size-eos": true})),
                "nothing could refute it",
            ),
            (
                refused(json!({"instances": {"n": {"value": 1}}})),
                "nothing could refute it",
            ),
            (refused(json!([1])), "in the description: invalid type"),
        ] {
            assert!(why.contains(wanted), "{why:?} does not say {wanted:?}");
        }
        // A description that only reads to the end still says something when the file must end there.
        let rest = Format {
            exact: true,
            ..claim(json!({"seq": [{"id": "a", "type": "u1"}, {"id": "rest", "size-eos": true}]}))
        };
        assert_eq!(rest.admissible(), Ok(()));
    }

    #[test]
    fn expressions_bind_as_kaitai_struct_binds_them() {
        let name = |name: &str| Box::new(Expr::Name(name.into()));
        assert_eq!(
            Expr::parse("b & 3 == 1 or not a.size > 0x10"),
            Ok(Expr::Binary(
                Op::Or,
                Box::new(Expr::Binary(
                    Op::Eq,
                    Box::new(Expr::Binary(Op::BitAnd, name("b"), Box::new(Expr::Int(3)))),
                    Box::new(Expr::Int(1)),
                )),
                Box::new(Expr::Not(Box::new(Expr::Binary(
                    Op::Gt,
                    Box::new(Expr::Member(name("a"), "size".into())),
                    Box::new(Expr::Int(16)),
                )))),
            ))
        );
        assert_eq!(
            Expr::parse("1 - 2 - x[0] ? 'a' : \"b\\n\""),
            Ok(Expr::If(
                Box::new(Expr::Binary(
                    Op::Sub,
                    Box::new(Expr::Binary(
                        Op::Sub,
                        Box::new(Expr::Int(1)),
                        Box::new(Expr::Int(2))
                    )),
                    Box::new(Expr::Index(name("x"), Box::new(Expr::Int(0)))),
                )),
                Box::new(Expr::Text("a".into())),
                Box::new(Expr::Text("b\n".into())),
            ))
        );
        let deep = format!("{}1{}", "(".repeat(100), ")".repeat(100));
        assert!(Expr::parse(&deep).is_err_and(|why| why.contains("nests deeper")));
        let long = "1 + ".repeat(100_000) + "1";
        assert!(Expr::parse(&long).is_err_and(|why| why.contains("more than 256 parts")));
    }

    proptest! {
        #[test]
        fn no_text_makes_the_expression_parser_panic(source in "[ -~]{0,40}") {
            let _ = Expr::parse(&source);
        }
    }
}
