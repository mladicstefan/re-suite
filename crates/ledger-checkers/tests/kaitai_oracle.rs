//! The format reader against the Kaitai Struct compiler: on every file, the two
//! must accept or refuse together and read the same values.
//!
//! Needs `kaitai-struct-compiler` and `uv`, which the flake's shell provides.

use std::path::Path;
use std::process::Command;

use ledger_checkers::format::{Tree, Value};
use ledger_core::format::Spec;
use serde_json::{Value as Json, json};

type Outcome = Result<(), Box<dyn std::error::Error>>;

/// A count, a table of fixed records, then parts whose place depends on the count.
fn records() -> (Json, Vec<u8>) {
    let spec = json!({
        "meta": {"id": "records", "endian": "le", "encoding": "ASCII"},
        "seq": [
            {"id": "magic", "contents": [82, 69, "LG"]},
            {"id": "version", "type": "u2", "valid": {"min": 1, "max": 3}},
            {"id": "count", "type": "u2"},
            {"id": "records", "type": "record", "repeat": "expr", "repeat-expr": "count"},
            {"id": "names", "type": "strz", "repeat": "expr", "repeat-expr": "count"},
            {"id": "tail", "type": "chunk", "repeat": "eos"}
        ],
        "instances": {
            "table_end": {"value": "records.size * 8 + 8"},
            "first_name": {"value": "names[0].length", "if": "count > 0"}
        },
        "types": {
            "record": {
                "seq": [
                    {"id": "kind", "type": "u1", "valid": {"any-of": [1, 2, 7]}},
                    {"id": "flags", "type": "u1"},
                    {"id": "offset", "type": "u2"},
                    {"id": "value", "type": "s4be"}
                ],
                "instances": {
                    "scaled": {"value": "value * 2 + _parent.version"},
                    "target": {"pos": "offset", "io": "_root._io", "type": "u1", "if": "offset != 0"}
                }
            },
            "chunk": {
                "seq": [
                    {"id": "tag", "type": "u1"},
                    {"id": "len", "type": "u1"},
                    {"id": "body", "size": "len", "type": {
                        "switch-on": "tag",
                        "cases": {"1": "pair", "2": "text", "_": "raw"}
                    }}
                ],
                "types": {
                    "pair": {"seq": [{"id": "a", "type": "u2be"}, {"id": "b", "type": "u2be"}]},
                    "text": {"seq": [{"id": "s", "type": "str", "size-eos": true, "encoding": "UTF-8"}]},
                    "raw": {"seq": [{"id": "data", "size-eos": true}]}
                }
            }
        }
    });
    let mut file = b"RELG\x02\x00\x02\x00".to_vec();
    file.extend_from_slice(&[1, 0x80, 0x04, 0x00, 0xff, 0xff, 0xff, 0xfe]);
    file.extend_from_slice(&[7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00]);
    file.extend_from_slice(b"alpha\0b\0");
    file.extend_from_slice(&[1, 4, 0x12, 0x34, 0x56, 0x78]);
    file.extend_from_slice(&[2, 3, b'h', 0xc3, 0xa9]);
    file.extend_from_slice(&[9, 2, 0xde, 0xad]);
    (spec, file)
}

/// Arithmetic, precedence and the names an expression may use.
fn expressions() -> (Json, Vec<u8>) {
    let spec = json!({
        "meta": {"id": "expressions", "endian": "be"},
        "seq": [
            {"id": "a", "type": "s1"},
            {"id": "b", "type": "u1"},
            {"id": "c", "type": "u4"},
            {"id": "wide", "type": "u8le"},
            {"id": "ratio", "type": "f4le", "valid": {"min": 0.5, "max": 2.0}},
            {"id": "exact", "type": "f8"},
            {"id": "word", "type": "str", "size": 2, "encoding": "ASCII", "valid": "\"OK\""},
            {"id": "list", "type": "u1", "repeat": "until", "repeat-until": "_ == 0"},
            {"id": "even", "type": "u1", "valid": {"expr": "_ % 2 == 0"}},
            {"id": "rest", "type": "u2", "repeat": "eos", "valid": {"max": 0x7fff}}
        ],
        "instances": {
            "div": {"value": "a / 3"},
            "rem": {"value": "a % 3"},
            "div_down": {"value": "(0 - 7) / 2"},
            "bits": {"value": "(c >> 4) & 0xff | 1"},
            "tight": {"value": "b & 3 == 1"},
            "choice": {"value": "a < 0 ? b : c"},
            "logic": {"value": "a < 0 and not (b == 2) or c == 5"},
            "text": {"value": "word + 'ay'"},
            "sizes": {"value": "list.size + list.first + list.last + _io.size"},
            "big": {"value": "wide - 1"},
            // Python's integers have no limit and ours stop at 128 bits, so the shift stays small.
            "shifted": {"value": "1 << (b & 63)"},
            "is_ok": {"value": "word == 'OK' and ratio < exact"}
        }
    });
    let mut file = vec![0xf9, 5, 0x00, 0x00, 0x12, 0x34];
    file.extend_from_slice(&0xffff_ffff_ffff_fffe_u64.to_le_bytes());
    file.extend_from_slice(&1.5f32.to_le_bytes());
    file.extend_from_slice(&2.25f64.to_be_bytes());
    file.extend_from_slice(b"OK");
    file.extend_from_slice(&[3, 9, 0, 4, 0x12, 0x34, 0x00, 0x01]);
    (spec, file)
}

/// The base file, every shorter version of it, and every byte changed two ways.
fn variants(base: &[u8]) -> Vec<Vec<u8>> {
    let mut out = vec![base.to_vec()];
    out.extend((0..base.len()).map(|len| base[..len].to_vec()));
    for (at, flip) in (0..base.len()).flat_map(|at| [(at, 0xff), (at, 0x01)]) {
        let mut changed = base.to_vec();
        changed[at] ^= flip;
        out.push(changed);
    }
    out
}

/// A field under an `if` that does not hold is missing from Python's object and null in ours.
fn without_nulls(value: Json) -> Json {
    match value {
        Json::Object(map) => (map.into_iter())
            .filter(|(_, v)| !v.is_null())
            .map(|(k, v)| (k, without_nulls(v)))
            .collect(),
        Json::Array(list) => list.into_iter().map(without_nulls).collect(),
        other => other,
    }
}

fn agrees(spec: &Json, base: &[u8]) -> Outcome {
    let name = spec["meta"]["id"]
        .as_str()
        .ok_or("the test description has no id")?;
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let dir = tempfile::tempdir()?;
    let ksy = dir.path().join(format!("{name}.ksy"));
    // JSON is YAML, so the description goes to the compiler as it is.
    std::fs::write(&ksy, serde_json::to_vec(spec)?)?;
    let compiled = Command::new("kaitai-struct-compiler")
        .args(["--target", "python", "--outdir"])
        .arg(dir.path())
        .arg(&ksy)
        .output()?;
    assert!(
        compiled.status.success(),
        "the compiler refused {name}: {compiled:?}"
    );

    let files = variants(base);
    let mut python = Command::new("uv");
    python.args(["run", "--locked", "--project"]).arg(&root);
    python
        .args(["python", "-I"])
        .arg(root.join("crates/ledger-checkers/tests/kaitai_oracle.py"));
    python.arg(dir.path()).arg(name);
    for (at, file) in files.iter().enumerate() {
        let path = dir.path().join(format!("{at}.bin"));
        std::fs::write(&path, file)?;
        python.arg(path);
    }
    let ran = python.output()?;
    assert!(
        ran.status.success(),
        "the generated parser did not run: {ran:?}"
    );
    let theirs: Vec<Json> = (String::from_utf8(ran.stdout)?.lines())
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()?;
    assert_eq!(theirs.len(), files.len());

    let parsed = Spec::parse(spec)?;
    let mut accepted = 0;
    for (file, theirs) in files.iter().zip(theirs) {
        let ours = Tree::read(&parsed, file, false);
        match (&ours, theirs.get("error")) {
            (Ok(tree), None) => {
                accepted += 1;
                let ours = without_nulls(tree.json(&Value::Object(0)));
                assert_eq!(ours, without_nulls(theirs), "{name}: {}", hex::encode(file));
            }
            (Err(_), Some(_)) => {}
            (ours, theirs) => panic!(
                "{name}: we say {:?}, the compiler's parser says {theirs:?}, on {}",
                ours.as_ref().map(|_| "accepted"),
                hex::encode(file)
            ),
        }
    }
    // A test that only ever compared refusals would prove nothing.
    assert!(
        accepted > 1,
        "{name}: only {accepted} of {} files were accepted",
        files.len()
    );
    Ok(())
}

#[test]
fn a_table_and_what_follows_it_reads_as_the_compiler_reads_it() -> Outcome {
    let (spec, file) = records();
    agrees(&spec, &file)
}

#[test]
fn expressions_come_to_what_the_compiler_computes() -> Outcome {
    let (spec, file) = expressions();
    agrees(&spec, &file)
}
