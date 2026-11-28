//! Reads a file as a Kaitai Struct description says, without generated code:
//! the description is walked directly, so a check runs nothing but this crate.

use std::rc::Rc;

use ledger_core::format::{Attr, Expr, MAX_NESTING, Op, Read, Repeat, Size, Spec, Type, Valid};

/// The most values one file may hold under a description. A description that loops
/// on a hostile file stops here instead of filling memory.
pub const MAX_VALUES: usize = 1 << 20;

/// Why a file was not read to its end.
#[derive(Debug, PartialEq, Eq)]
pub enum Failure {
    /// The file contradicts the description: where and how.
    Wrong(String),
    /// The file holds more than [`MAX_VALUES`] values. Nothing is known about it.
    TooBig,
}

type Parsed<T> = Result<T, Failure>;

fn wrong<T>(why: impl Into<String>) -> Parsed<T> {
    Err(Failure::Wrong(why.into()))
}

/// What a field or an expression comes to.
#[derive(Debug, Clone, PartialEq)]
pub enum Value<'b> {
    Int(i128),
    Float(f64),
    Bool(bool),
    Text(Rc<str>),
    Bytes(&'b [u8]),
    List(Rc<[Self]>),
    /// An index into the file's objects.
    Object(usize),
    /// An index into the file's streams: what `_io` names.
    Stream(usize),
    /// A field whose `if` did not hold.
    Null,
}

impl Value<'_> {
    const fn kind(&self) -> &'static str {
        match self {
            Self::Int(_) => "an integer",
            Self::Float(_) => "a float",
            Self::Bool(_) => "true or false",
            Self::Text(_) => "text",
            Self::Bytes(_) => "bytes",
            Self::List(_) => "a list",
            Self::Object(_) => "a structure",
            Self::Stream(_) => "a stream",
            Self::Null => "absent",
        }
    }

    /// How a value reads in a counterexample.
    fn show(&self) -> String {
        match self {
            Self::Int(n) => n.to_string(),
            Self::Float(n) => n.to_string(),
            Self::Bool(b) => b.to_string(),
            Self::Text(text) => format!("{text:?}"),
            Self::Bytes(bytes) => hex::encode(bytes),
            other => String::from(other.kind()),
        }
    }
}

/// A run of bytes being read: the file, or the sized part of it one field takes.
struct Stream {
    start: usize,
    end: usize,
    at: usize,
}

enum Slot<'b> {
    Empty,
    /// Being computed: a second request means the instance depends on itself.
    Busy,
    Done(Value<'b>),
}

struct Object<'s, 'b> {
    ty: &'s Type,
    parent: Option<usize>,
    /// The field of the parent that holds this object, and its place in a repeat.
    held: (&'s str, Option<usize>),
    stream: usize,
    seq: Vec<Value<'b>>,
    instances: Vec<Slot<'b>>,
}

/// What an expression may name besides fields.
#[derive(Clone, Copy)]
struct Scope<'v, 'b> {
    object: usize,
    index: Option<usize>,
    /// The value `_` names in `repeat-until` and `valid`.
    it: Option<&'v Value<'b>>,
}

/// A file read under a description.
pub struct Tree<'s, 'b> {
    spec: &'s Spec,
    bytes: &'b [u8],
    streams: Vec<Stream>,
    objects: Vec<Object<'s, 'b>>,
    values: usize,
    /// How many instances are being computed, each for the one before it.
    waiting: usize,
}

fn int(value: &Value<'_>, what: &str) -> Parsed<i128> {
    match value {
        Value::Int(n) => Ok(*n),
        other => wrong(format!("{what} is {}, not an integer", other.kind())),
    }
}

fn length(value: &Value<'_>, what: &str) -> Parsed<usize> {
    let n = int(value, what)?;
    usize::try_from(n).or_else(|_| wrong(format!("{what} is {n}, not a length")))
}

fn truth(value: &Value<'_>, what: &str) -> Parsed<bool> {
    match value {
        Value::Bool(b) => Ok(*b),
        other => wrong(format!("{what} is {}, not true or false", other.kind())),
    }
}

fn number(bytes: &[u8], signed: bool, big: bool) -> i128 {
    let top = if big { bytes.first() } else { bytes.last() };
    let negative = signed && top.is_some_and(|b| b & 0x80 != 0);
    let mut raw = [0u8; 16];
    let fill = if negative { 0xff } else { 0 };
    raw.fill(fill);
    for (at, byte) in bytes.iter().enumerate() {
        let place = if big { bytes.len() - 1 - at } else { at };
        raw[place] = *byte;
    }
    i128::from_le_bytes(raw)
}

fn float(bytes: &[u8], big: bool) -> f64 {
    let mut raw: Vec<u8> = bytes.to_vec();
    if big {
        raw.reverse();
    }
    match <[u8; 4]>::try_from(raw.as_slice()) {
        Ok(four) => f64::from(f32::from_le_bytes(four)),
        Err(_) => <[u8; 8]>::try_from(raw.as_slice()).map_or(f64::NAN, f64::from_le_bytes),
    }
}

const fn compare(op: Op, order: Option<std::cmp::Ordering>) -> bool {
    use std::cmp::Ordering::{Equal, Greater, Less};
    matches!(
        (op, order),
        (Op::Eq, Some(Equal))
            | (Op::Ne, Some(Less | Greater) | None)
            | (Op::Lt, Some(Less))
            | (Op::Gt, Some(Greater))
            | (Op::Le, Some(Less | Equal))
            | (Op::Ge, Some(Greater | Equal))
    )
}

/// Integers as Kaitai Struct's Python code computes them: division rounds down and
/// a remainder takes the sign of the divisor.
fn integers(op: Op, a: i128, b: i128) -> Parsed<Value<'static>> {
    let shift = u32::try_from(b).ok().filter(|by| *by < 127);
    let out = match op {
        Op::Add => a.checked_add(b),
        Op::Sub => a.checked_sub(b),
        Op::Mul => a.checked_mul(b),
        Op::Div | Op::Rem if b == 0 => return wrong("a division by zero"),
        Op::Div => a.checked_div_euclid(b).map(|q| {
            if b < 0 && a.rem_euclid(b) != 0 {
                q - 1
            } else {
                q
            }
        }),
        Op::Rem => (a.checked_rem_euclid(b)).map(|r| if b < 0 && r != 0 { r + b } else { r }),
        Op::Shl => shift.and_then(|by| a.checked_mul(1i128 << by)),
        Op::Shr => shift.map(|by| a >> by),
        Op::BitAnd => Some(a & b),
        Op::BitOr => Some(a | b),
        Op::BitXor => Some(a ^ b),
        _ => return Ok(Value::Bool(compare(op, Some(a.cmp(&b))))),
    };
    out.map_or_else(
        || wrong("a number too large to compute with"),
        |n| Ok(Value::Int(n)),
    )
}

#[expect(
    clippy::cast_precision_loss,
    reason = "an integer next to a float is read as a float, as Kaitai Struct does"
)]
fn floats(op: Op, a: &Value<'_>, b: &Value<'_>) -> Option<Value<'static>> {
    let as_float = |v: &Value<'_>| match v {
        Value::Int(n) => Some(*n as f64),
        Value::Float(n) => Some(*n),
        _ => None,
    };
    let (a, b) = (as_float(a)?, as_float(b)?);
    Some(match op {
        Op::Add => Value::Float(a + b),
        Op::Sub => Value::Float(a - b),
        Op::Mul => Value::Float(a * b),
        Op::Div => Value::Float(a / b),
        Op::Eq | Op::Ne | Op::Lt | Op::Le | Op::Gt | Op::Ge => {
            Value::Bool(compare(op, a.partial_cmp(&b)))
        }
        _ => return None,
    })
}

fn binary<'b>(op: Op, a: &Value<'b>, b: &Value<'b>) -> Parsed<Value<'b>> {
    let ordered = matches!(op, Op::Eq | Op::Ne | Op::Lt | Op::Le | Op::Gt | Op::Ge);
    match (a, b) {
        (Value::Int(a), Value::Int(b)) => integers(op, *a, *b),
        (Value::Text(a), Value::Text(b)) if op == Op::Add => {
            Ok(Value::Text(format!("{a}{b}").into()))
        }
        (Value::Text(a), Value::Text(b)) if ordered => Ok(Value::Bool(compare(op, Some(a.cmp(b))))),
        (Value::Bytes(a), Value::Bytes(b)) if ordered => {
            Ok(Value::Bool(compare(op, Some(a.cmp(b)))))
        }
        (Value::Bool(a), Value::Bool(b)) if matches!(op, Op::Eq | Op::Ne) => {
            Ok(Value::Bool((a == b) == (op == Op::Eq)))
        }
        _ => floats(op, a, b).map_or_else(
            || {
                wrong(format!(
                    "{op:?} does not apply to {} and {}",
                    a.kind(),
                    b.kind()
                ))
            },
            Ok,
        ),
    }
}

impl<'s, 'b> Tree<'s, 'b> {
    /// Reads `bytes` as `spec` describes: every field in order, then every instance.
    ///
    /// # Errors
    /// Where the bytes contradict the description, or that the file is too large to tell.
    pub fn read(spec: &'s Spec, bytes: &'b [u8], exact: bool) -> Parsed<Self> {
        let mut tree = Self {
            spec,
            bytes,
            streams: vec![Stream {
                start: 0,
                end: bytes.len(),
                at: 0,
            }],
            objects: Vec::new(),
            values: 0,
            waiting: 0,
        };
        let Some(root) = spec.types.first() else {
            return wrong("the description has no type");
        };
        tree.object(root, None, ("", None), 0)?;
        let Stream { at, end, .. } = tree.streams[0];
        if exact && at != end {
            return wrong(format!(
                "the top-level fields end at +{at:#x}, the file at +{end:#x}"
            ));
        }
        // An instance may name a field read long after its own object, so instances wait
        // until every field is read. Computing one can add objects, which are reached in turn.
        let mut object = 0;
        while object < tree.objects.len() {
            for instance in 0..tree.objects[object].ty.instances.len() {
                tree.instance(object, instance)?;
            }
            object += 1;
        }
        Ok(tree)
    }

    /// The field's name from the top of the file, for a counterexample.
    fn path(&self, object: usize, id: &str, index: Option<usize>) -> String {
        let mut parts = vec![(id, index)];
        let mut at = Some(object);
        while let Some(object) = at {
            let Object { held, parent, .. } = &self.objects[object];
            if parent.is_some() {
                parts.push(*held);
            }
            at = *parent;
        }
        let part = |(id, index): &(&str, Option<usize>)| match index {
            Some(index) => format!("{id}[{index}]"),
            None => (*id).to_owned(),
        };
        parts.iter().rev().map(part).collect::<Vec<_>>().join(".")
    }

    fn object(
        &mut self,
        ty: &'s Type,
        parent: Option<usize>,
        held: (&'s str, Option<usize>),
        stream: usize,
    ) -> Parsed<usize> {
        let mut depth = 0;
        let mut above = parent;
        while let Some(object) = above {
            depth += 1;
            above = self.objects[object].parent;
        }
        if depth > MAX_NESTING {
            return wrong(format!("structures nest deeper than {MAX_NESTING}"));
        }
        let object = self.objects.len();
        self.objects.push(Object {
            ty,
            parent,
            held,
            stream,
            seq: Vec::with_capacity(ty.seq.len()),
            instances: ty.instances.iter().map(|_| Slot::Empty).collect(),
        });
        for attr in &ty.seq {
            let value = self.attr(object, attr)?;
            self.objects[object].seq.push(value);
        }
        Ok(object)
    }

    fn instance(&mut self, object: usize, instance: usize) -> Parsed<Value<'b>> {
        let ty = self.objects[object].ty;
        let attr = &ty.instances[instance];
        match &self.objects[object].instances[instance] {
            Slot::Done(value) => return Ok(value.clone()),
            Slot::Busy => {
                return wrong(format!(
                    "`{}` depends on itself",
                    self.path(object, &attr.id, None)
                ));
            }
            Slot::Empty => {}
        }
        // A file can chain instances as long as it likes; the stack cannot follow.
        self.waiting += 1;
        if self.waiting > MAX_NESTING {
            return wrong(format!(
                "`{}` rests on more than {MAX_NESTING} other instances",
                self.path(object, &attr.id, None)
            ));
        }
        self.objects[object].instances[instance] = Slot::Busy;
        let value = self.attr(object, attr)?;
        self.waiting -= 1;
        self.objects[object].instances[instance] = Slot::Done(value.clone());
        Ok(value)
    }

    fn field(&mut self, object: usize, name: &str) -> Parsed<Value<'b>> {
        let Object { ty, seq, .. } = &self.objects[object];
        if let Some(at) = ty.seq.iter().position(|a| a.id == name) {
            return seq
                .get(at)
                .cloned()
                .map_or_else(|| wrong(format!("`{name}` is used before it is read")), Ok);
        }
        match ty.instances.iter().position(|a| a.id == name) {
            Some(at) => self.instance(object, at),
            None => wrong(format!("`{}` has no field `{name}`", ty.name)),
        }
    }

    fn member(&mut self, of: &Value<'b>, name: &str) -> Parsed<Value<'b>> {
        let count = |n: usize| Ok(Value::Int(n as i128));
        match (of, name) {
            (Value::Object(_), "_root") => Ok(Value::Object(0)),
            (Value::Object(object), "_io") => Ok(Value::Stream(self.objects[*object].stream)),
            (Value::Object(object), "_parent") => self.objects[*object].parent.map_or_else(
                || wrong("the whole file has no `_parent`"),
                |parent| Ok(Value::Object(parent)),
            ),
            (Value::Object(object), _) => self.field(*object, name),
            (Value::Stream(stream), "size" | "pos" | "eof") => {
                let Stream { start, end, at } = self.streams[*stream];
                match name {
                    "size" => count(end - start),
                    "pos" => count(at - start),
                    _ => Ok(Value::Bool(at >= end)),
                }
            }
            (Value::List(list), "size") => count(list.len()),
            (Value::Bytes(bytes), "size" | "length") => count(bytes.len()),
            (Value::Text(text), "length") => count(text.chars().count()),
            (Value::List(list), "first" | "last") => {
                let item = if name == "first" {
                    list.first()
                } else {
                    list.last()
                };
                item.cloned()
                    .map_or_else(|| wrong(format!("`{name}` of an empty list")), Ok)
            }
            (Value::Bytes(bytes), "first" | "last") => {
                let item = if name == "first" {
                    bytes.first()
                } else {
                    bytes.last()
                };
                item.map_or_else(
                    || wrong(format!("`{name}` of no bytes")),
                    |byte| Ok(Value::Int(i128::from(*byte))),
                )
            }
            (other, _) => wrong(format!("{} has no `{name}`", other.kind())),
        }
    }

    fn eval(&mut self, expr: &Expr, scope: Scope<'_, 'b>) -> Parsed<Value<'b>> {
        match expr {
            Expr::Int(n) => Ok(Value::Int(*n)),
            Expr::Float(n) => Ok(Value::Float(*n)),
            Expr::Bool(b) => Ok(Value::Bool(*b)),
            Expr::Text(text) => Ok(Value::Text(text.as_str().into())),
            Expr::Name(name) => match name.as_str() {
                "_" => scope
                    .it
                    .cloned()
                    .map_or_else(|| wrong("`_` names nothing here"), Ok),
                "_index" => scope.index.map_or_else(
                    || wrong("`_index` is used outside a repeat"),
                    |index| Ok(Value::Int(index as i128)),
                ),
                "_root" | "_io" | "_parent" => self.member(&Value::Object(scope.object), name),
                _ => self.field(scope.object, name),
            },
            Expr::Not(inner) => {
                let value = self.eval(inner, scope)?;
                Ok(Value::Bool(!truth(&value, "the operand of `not`")?))
            }
            Expr::Neg(inner) => match self.eval(inner, scope)? {
                Value::Float(n) => Ok(Value::Float(-n)),
                other => integers(Op::Sub, 0, int(&other, "the operand of `-`")?),
            },
            Expr::Invert(inner) => {
                let value = self.eval(inner, scope)?;
                Ok(Value::Int(!int(&value, "the operand of `~`")?))
            }
            Expr::Binary(op @ (Op::And | Op::Or), left, right) => {
                let left = self.eval(left, scope)?;
                // The right side is not computed when the left decides, as in Kaitai Struct.
                if truth(&left, "an operand of `and` or `or`")? == (*op == Op::Or) {
                    return Ok(left);
                }
                let right = self.eval(right, scope)?;
                truth(&right, "an operand of `and` or `or`").map(Value::Bool)
            }
            Expr::Binary(op, left, right) => {
                let left = self.eval(left, scope)?;
                let right = self.eval(right, scope)?;
                binary(*op, &left, &right)
            }
            Expr::If(test, then, otherwise) => {
                let test = self.eval(test, scope)?;
                let taken = if truth(&test, "the test of `?`")? {
                    then
                } else {
                    otherwise
                };
                self.eval(taken, scope)
            }
            Expr::Member(of, name) => {
                let of = self.eval(of, scope)?;
                self.member(&of, name)
            }
            Expr::Index(of, index) => {
                let of = self.eval(of, scope)?;
                let index = self.eval(index, scope)?;
                let at = length(&index, "an index")?;
                let item = match &of {
                    Value::List(list) => list.get(at).cloned(),
                    Value::Bytes(bytes) => bytes.get(at).map(|byte| Value::Int(i128::from(*byte))),
                    other => return wrong(format!("{} cannot be indexed", other.kind())),
                };
                item.map_or_else(|| wrong(format!("index {at} is past the end")), Ok)
            }
        }
    }

    /// Takes the next `len` bytes of a stream.
    fn take(&mut self, stream: usize, len: usize) -> Result<&'b [u8], String> {
        let Stream { at, end, .. } = self.streams[stream];
        let left = end - at;
        if len > left {
            return Err(format!("needs {len} bytes, {left} are left"));
        }
        self.streams[stream].at = at + len;
        Ok(&self.bytes[at..at + len])
    }

    fn attr(&mut self, object: usize, attr: &'s Attr) -> Parsed<Value<'b>> {
        let scope = Scope {
            object,
            index: None,
            it: None,
        };
        let named = |tree: &Self, what: &str| {
            format!("`{what}` of `{}`", tree.path(object, &attr.id, None))
        };
        if let Some(cond) = &attr.cond {
            let value = self.eval(cond, scope)?;
            if !truth(&value, &named(self, "if"))? {
                return Ok(Value::Null);
            }
        }
        if let Some(value) = &attr.value {
            let value = self.eval(value, scope)?;
            self.rule(object, attr, None, &value, None)?;
            return Ok(value);
        }
        let mut stream = self.objects[object].stream;
        let mut back = None;
        if let Some(pos) = &attr.pos {
            if let Some(io) = &attr.io {
                stream = match self.eval(io, scope)? {
                    Value::Stream(stream) => stream,
                    other => {
                        return wrong(format!(
                            "{} is {}, not a stream",
                            named(self, "io"),
                            other.kind()
                        ));
                    }
                };
            }
            let value = self.eval(pos, scope)?;
            let pos = length(&value, &named(self, "pos"))?;
            let Stream { start, end, at } = self.streams[stream];
            if pos > end - start {
                return wrong(format!(
                    "{} is {pos:#x}, past the {:#x} bytes it counts in",
                    named(self, "pos"),
                    end - start
                ));
            }
            back = Some(at);
            self.streams[stream].at = start + pos;
        }
        let value = self.repeated(object, attr, stream);
        if let Some(at) = back {
            self.streams[stream].at = at;
        }
        value
    }

    fn repeated(&mut self, object: usize, attr: &'s Attr, stream: usize) -> Parsed<Value<'b>> {
        let Some(repeat) = &attr.repeat else {
            return self.one(object, attr, stream, None);
        };
        let scope = Scope {
            object,
            index: None,
            it: None,
        };
        let times = match repeat {
            Repeat::Times(times) => {
                let value = self.eval(times, scope)?;
                let what = format!("`repeat-expr` of `{}`", self.path(object, &attr.id, None));
                Some(length(&value, &what)?)
            }
            Repeat::ToEnd | Repeat::Until(_) => None,
        };
        let mut items = Vec::new();
        loop {
            let done = match (repeat, times) {
                (_, Some(times)) => items.len() >= times,
                (Repeat::ToEnd, _) => self.streams[stream].at >= self.streams[stream].end,
                _ => false,
            };
            if done {
                break;
            }
            let index = Some(items.len());
            let item = self.one(object, attr, stream, index)?;
            let last = if let Repeat::Until(until) = repeat {
                let scope = Scope {
                    object,
                    index,
                    it: Some(&item),
                };
                let value = self.eval(until, scope)?;
                let what = format!("`repeat-until` of `{}`", self.path(object, &attr.id, index));
                truth(&value, &what)?
            } else {
                false
            };
            items.push(item);
            if last {
                break;
            }
        }
        Ok(Value::List(items.into()))
    }

    /// Picks the type a `switch-on` names for this file.
    fn chosen(&mut self, read: &'s Read, scope: Scope<'_, 'b>) -> Parsed<Option<&'s Read>> {
        let Read::Switch { on, cases, default } = read else {
            return Ok(Some(read));
        };
        let on = self.eval(on, scope)?;
        for (case, target) in cases {
            let case = self.eval(case, scope)?;
            if binary(Op::Eq, &on, &case)? == Value::Bool(true) {
                return self.chosen(target, scope);
            }
        }
        match default {
            Some(target) => self.chosen(target, scope),
            None => Ok(None),
        }
    }

    /// Reads text of `size` bytes, or up to a NUL.
    fn text(
        &mut self,
        stream: usize,
        size: Option<usize>,
        utf8: bool,
        nul: bool,
    ) -> Result<Value<'b>, String> {
        let found = if let Some(size) = size {
            let found = self.take(stream, size)?;
            let end = found.iter().position(|b| *b == 0).filter(|_| nul);
            &found[..end.unwrap_or(found.len())]
        } else {
            let Stream { at, end, .. } = self.streams[stream];
            let rest = &self.bytes[at..end];
            let len = (rest.iter().position(|b| *b == 0)).ok_or("has no NUL before the end")?;
            self.streams[stream].at = at + len + 1;
            &rest[..len]
        };
        match std::str::from_utf8(found) {
            Ok(text) if utf8 || text.is_ascii() => Ok(Value::Text(text.into())),
            _ => Err(format!(
                "is not text in its encoding: {}",
                hex::encode(found)
            )),
        }
    }

    /// Reads one value of a field: the field itself, or one element of its repeat.
    fn one(
        &mut self,
        object: usize,
        attr: &'s Attr,
        stream: usize,
        index: Option<usize>,
    ) -> Parsed<Value<'b>> {
        self.values += 1;
        if self.values > MAX_VALUES {
            return Err(Failure::TooBig);
        }
        let scope = Scope {
            object,
            index,
            it: None,
        };
        let start = self.streams[stream].at;
        let size = match &attr.size {
            Some(Size::Bytes(size)) => {
                let value = self.eval(size, scope)?;
                let what = format!("`size` of `{}`", self.path(object, &attr.id, index));
                Some(length(&value, &what)?)
            }
            Some(Size::ToEnd) => Some(self.streams[stream].end - start),
            None => None,
        };
        // Only now, so that a failure above is reported as the expression's and not the field's.
        let here = |tree: &Self, why: String| {
            Failure::Wrong(format!(
                "at +{start:#x}, `{}` {why}",
                tree.path(object, &attr.id, index)
            ))
        };
        let value = match (self.chosen(&attr.read, scope)?, size) {
            (Some(Read::Fixed(wanted)), _) => {
                let found = self
                    .take(stream, wanted.len())
                    .map_err(|why| here(self, why))?;
                if found != wanted.as_slice() {
                    let why = format!("is {}, not {}", hex::encode(found), hex::encode(wanted));
                    return Err(here(self, why));
                }
                Value::Bytes(found)
            }
            (Some(Read::Int { len, signed, big }), _) => {
                let found = self.take(stream, *len).map_err(|why| here(self, why))?;
                Value::Int(number(found, *signed, *big))
            }
            (Some(Read::Float { len, big }), _) => {
                let found = self.take(stream, *len).map_err(|why| here(self, why))?;
                Value::Float(float(found, *big))
            }
            (Some(Read::Text { utf8, nul }), size) => {
                (self.text(stream, size, *utf8, *nul)).map_err(|why| here(self, why))?
            }
            (Some(Read::Type(ty)), size) => {
                let inner = match size {
                    Some(size) => {
                        self.take(stream, size).map_err(|why| here(self, why))?;
                        self.streams.push(Stream {
                            start,
                            end: start + size,
                            at: start,
                        });
                        self.streams.len() - 1
                    }
                    None => stream,
                };
                let ty = &self.spec.types[*ty];
                Value::Object(self.object(ty, Some(object), (attr.id.as_str(), index), inner)?)
            }
            // A value no case names is left as raw bytes when the field has a size.
            (Some(Read::Bytes | Read::Switch { .. }) | None, Some(size)) => {
                Value::Bytes(self.take(stream, size).map_err(|why| here(self, why))?)
            }
            (None, None) => {
                return Err(here(
                    self,
                    String::from("has a value its `switch-on` gives no type for"),
                ));
            }
            (Some(Read::Bytes | Read::Switch { .. }), None) => {
                return Err(here(self, String::from("has no size")));
            }
        };
        self.rule(object, attr, index, &value, Some(start))?;
        Ok(value)
    }

    /// Holds a value against the field's `valid`.
    fn rule(
        &mut self,
        object: usize,
        attr: &'s Attr,
        index: Option<usize>,
        value: &Value<'b>,
        start: Option<usize>,
    ) -> Parsed<()> {
        let Some(valid) = &attr.valid else {
            return Ok(());
        };
        let scope = Scope {
            object,
            index,
            it: Some(value),
        };
        let holds = |tree: &mut Self, op: Op, bound: &Expr| -> Parsed<Option<String>> {
            let bound = tree.eval(bound, scope)?;
            let ok = binary(op, value, &bound)? == Value::Bool(true);
            Ok((!ok).then(|| bound.show()))
        };
        let why = match valid {
            Valid::Eq(wanted) => holds(self, Op::Eq, wanted)?.map(|wanted| format!("not {wanted}")),
            Valid::Range { min, max } => {
                let low = match min {
                    Some(min) => holds(self, Op::Ge, min)?
                        .map(|min| format!("under the least allowed, {min}")),
                    None => None,
                };
                match (low, max) {
                    (None, Some(max)) => {
                        holds(self, Op::Le, max)?.map(|max| format!("over the most allowed, {max}"))
                    }
                    (low, _) => low,
                }
            }
            Valid::AnyOf(allowed) => {
                let mut missed = Vec::new();
                for wanted in allowed {
                    match holds(self, Op::Eq, wanted)? {
                        Some(wanted) => missed.push(wanted),
                        None => return Ok(()),
                    }
                }
                Some(format!("not one of {}", missed.join(", ")))
            }
            Valid::Expr(rule) => {
                let rule = self.eval(rule, scope)?;
                (!truth(&rule, "a `valid` expression")?)
                    .then(|| String::from("against its `valid` expression"))
            }
        };
        let Some(why) = why else {
            return Ok(());
        };
        let place = start.map_or_else(String::new, |start| format!("at +{start:#x}, "));
        wrong(format!(
            "{place}`{}` is {}, {why}",
            self.path(object, &attr.id, index),
            value.show()
        ))
    }

    /// The file as JSON: structures as objects, bytes as hex. The whole file is object 0.
    #[must_use]
    pub fn json(&self, value: &Value<'_>) -> serde_json::Value {
        use serde_json::Value as Json;
        match value {
            Value::Int(n) => (i64::try_from(*n).map(Json::from))
                .or_else(|_| u64::try_from(*n).map(Json::from))
                .unwrap_or_else(|_| Json::from(n.to_string())),
            Value::Float(n) => Json::from(*n),
            Value::Bool(b) => Json::from(*b),
            Value::Text(text) => Json::from(&**text),
            Value::Bytes(bytes) => Json::from(hex::encode(bytes)),
            Value::List(list) => list.iter().map(|item| self.json(item)).collect(),
            Value::Stream(_) | Value::Null => Json::Null,
            Value::Object(object) => {
                let Object {
                    ty, seq, instances, ..
                } = &self.objects[*object];
                let seq = ty
                    .seq
                    .iter()
                    .zip(seq)
                    .map(|(attr, value)| (attr.id.clone(), self.json(value)));
                let instances = ty
                    .instances
                    .iter()
                    .zip(instances)
                    .filter_map(|(attr, slot)| match slot {
                        Slot::Done(value) => Some((attr.id.clone(), self.json(value))),
                        Slot::Empty | Slot::Busy => None,
                    });
                Json::Object(seq.chain(instances).collect())
            }
        }
    }
}
