//! Readable source a tool recovered from one script: the modules it split the script
//! into, each kept as evidence of its own, and the bytes of the script each came from.
//!
//! The record answers where a byte of the script went: [`SourceTree::module_at`]. A
//! stack frame names a line and a column instead, which [`Frame::offset_in`] turns
//! into that byte.
//!
//! [`Frame::offset_in`]: crate::session::Frame::offset_in

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

use serde::{Deserialize, Serialize};

use crate::{EvidenceId, ToolRef};

/// A module's name as the tool gave it, kept as a relative path: names joined by `/`,
/// none of them empty, `.` or `..`, and none holding `\`, `:` or a control character.
/// Laid out under any directory, it names a file inside that directory.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct ModulePath(String);

impl ModulePath {
    /// Longest path, in bytes.
    pub const MAX: usize = 1024;
    /// Most names in one path.
    pub const DEPTH: usize = 32;

    /// # Errors
    /// The text is not a relative path of plain names within the limits.
    pub fn new(text: impl Into<String>) -> Result<Self, String> {
        let text = text.into();
        let plain = |name: &str| {
            !matches!(name, "" | "." | "..")
                && !name
                    .chars()
                    .any(|c| c == '\\' || c == ':' || c.is_control())
        };
        if text.len() > Self::MAX {
            return Err(format!(
                "a module path is {} bytes, limit {}",
                text.len(),
                Self::MAX
            ));
        }
        if text.split('/').count() > Self::DEPTH || !text.split('/').all(plain) {
            return Err(format!("{text:?} is not a relative path of plain names"));
        }
        Ok(Self(text))
    }

    #[must_use]
    pub const fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// The directories it is in, outermost first: `a` and `a/b` for `a/b/c.js`.
    fn directories(&self) -> impl Iterator<Item = &str> {
        let ends = self.0.match_indices('/').map(|(at, _)| at);
        ends.map(|at| &self.0[..at])
    }
}

impl TryFrom<String> for ModulePath {
    type Error = String;
    fn try_from(text: String) -> Result<Self, String> {
        Self::new(text)
    }
}

// Lets maps keyed by a path be searched by a plain string.
impl std::borrow::Borrow<str> for ModulePath {
    fn borrow(&self) -> &str {
        &self.0
    }
}

/// How the tool told the modules of a bundle apart, as it reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Split {
    /// By the module table the bundler wrote, or a script that is one module.
    Structural,
    /// By guessing where each module's code is in a bundle that merged them into one
    /// scope, as Vite and Rollup do.
    Heuristic,
}

/// One recovered module.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Module {
    /// Its readable text, as `artifact` evidence. The same text recovered from another
    /// script or another version of it is the same evidence.
    pub source: EvidenceId,
    /// The bytes of the script it came from, each counted from 0 with its end left out,
    /// in the order they start.
    pub ranges: Vec<Range<u64>>,
}

/// Evidence format for `EvidenceKind::SourceTree`: the modules one tool recovered from
/// one script. Names inside the modules are the tool's guesses, not the author's.
/// Only [`SourceTree::new`] makes one, and reading one back checks what it checked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "Parts")]
pub struct SourceTree {
    tool: ToolRef,
    script: EvidenceId,
    format: String,
    split: Split,
    modules: BTreeMap<ModulePath, Module>,
}

#[derive(Deserialize)]
struct Parts {
    tool: ToolRef,
    script: EvidenceId,
    format: String,
    split: Split,
    modules: BTreeMap<ModulePath, Module>,
}

impl TryFrom<Parts> for SourceTree {
    type Error = String;
    fn try_from(parts: Parts) -> Result<Self, String> {
        let Parts {
            tool,
            script,
            format,
            split,
            mut modules,
        } = parts;
        if format.is_empty()
            || format.len() > SourceTree::FORMAT
            || format.contains(char::is_control)
        {
            return Err(format!("{format:?} does not name a bundle format"));
        }
        let directories: BTreeSet<&str> =
            modules.keys().flat_map(ModulePath::directories).collect();
        if let Some(both) = modules
            .keys()
            .find(|path| directories.contains(path.as_str()))
        {
            return Err(format!(
                "{} is both a module and a directory",
                both.as_str()
            ));
        }
        for (path, module) in &mut modules {
            if module.ranges.iter().any(|range| range.start > range.end) {
                return Err(format!(
                    "{} has a range that ends before it starts",
                    path.as_str()
                ));
            }
            module.ranges.sort_by_key(|range| (range.start, range.end));
        }
        Ok(Self {
            tool,
            script,
            format,
            split,
            modules,
        })
    }
}

impl SourceTree {
    /// The largest record read.
    pub const MAX: usize = 16 << 20;
    /// Longest name of a bundle format, in bytes.
    pub const FORMAT: usize = 64;

    /// # Errors
    /// The format is empty or too long, a path is both a module and a directory, or a
    /// range ends before it starts.
    pub fn new(
        tool: ToolRef,
        script: EvidenceId,
        format: String,
        split: Split,
        modules: BTreeMap<ModulePath, Module>,
    ) -> Result<Self, String> {
        Self::try_from(Parts {
            tool,
            script,
            format,
            split,
            modules,
        })
    }

    /// A stored record.
    ///
    /// # Errors
    /// The bytes are over [`SourceTree::MAX`] or are not a record.
    pub fn read(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > Self::MAX {
            let size = bytes.len();
            return Err(format!(
                "a source tree is {size} bytes, limit {}",
                Self::MAX
            ));
        }
        serde_json::from_slice(bytes).map_err(|why| format!("the source tree does not read: {why}"))
    }

    /// The tool and the version it reported.
    #[must_use]
    pub const fn tool(&self) -> &ToolRef {
        &self.tool
    }

    /// The script it was recovered from, as `artifact` evidence.
    #[must_use]
    pub const fn script(&self) -> &EvidenceId {
        &self.script
    }

    /// The bundle format the tool read, by its name for it: `webpack5`, `scope-hoisted`,
    /// or `unknown` for a script that is not a bundle.
    #[must_use]
    pub const fn format(&self) -> &str {
        self.format.as_str()
    }

    #[must_use]
    pub const fn split(&self) -> Split {
        self.split
    }

    /// Every module, by path.
    #[must_use]
    pub const fn modules(&self) -> &BTreeMap<ModulePath, Module> {
        &self.modules
    }

    /// The module that byte `offset` of the script went into. Of the ranges that hold
    /// it, the one that starts last wins, so code nested in another module's range is
    /// found in the inner module. `None` when no range holds it.
    #[must_use]
    pub fn module_at(&self, offset: u64) -> Option<(&ModulePath, &Module)> {
        let ranges = (self.modules.iter())
            .flat_map(|(path, module)| module.ranges.iter().map(move |r| (r, path, module)));
        let holding = ranges.filter(|(range, ..)| range.contains(&offset));
        let inner = holding.max_by_key(|(range, ..)| range.start);
        inner.map(|(_, path, module)| (path, module))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ranges as `(start, end)`, which clippy does not take for a range written by mistake.
    fn module(name: &str, ranges: &[(u64, u64)]) -> Result<(ModulePath, Module), String> {
        let source = EvidenceId::of(name.as_bytes());
        let ranges = ranges.iter().map(|&(start, end)| start..end).collect();
        Ok((ModulePath::new(name)?, Module { source, ranges }))
    }

    fn built(modules: &[(&str, &[(u64, u64)])]) -> Result<SourceTree, String> {
        let modules = (modules.iter())
            .map(|(name, ranges)| module(name, ranges))
            .collect::<Result<_, _>>()?;
        let tool = ToolRef {
            id: "wakaru".into(),
            version: "1.17.0".into(),
        };
        let script = EvidenceId::of(b"script");
        SourceTree::new(tool, script, "webpack5".into(), Split::Structural, modules)
    }

    #[test]
    fn a_byte_of_the_script_is_found_in_the_module_it_went_into() -> Result<(), String> {
        // Two pieces of `a`, then `b`, with `inner` nested inside `b` and a gap at 30..40.
        let tree = built(&[
            ("src/a.js", &[(20, 30), (0, 10)]),
            ("b.js", &[(40, 60)]),
            ("inner.js", &[(45, 50)]),
            ("empty.js", &[(60, 60)]),
        ])?;
        let at = |offset| tree.module_at(offset).map(|(path, _)| path.as_str());
        let found: Vec<(u64, Option<&str>)> = [
            0,
            9,
            10,
            19,
            20,
            29,
            30,
            39,
            40,
            44,
            45,
            49,
            50,
            59,
            60,
            u64::MAX,
        ]
        .into_iter()
        .map(|offset| (offset, at(offset)))
        .collect();
        assert_eq!(
            found,
            [
                (0, Some("src/a.js")),
                (9, Some("src/a.js")),
                (10, None),
                (19, None),
                (20, Some("src/a.js")),
                (29, Some("src/a.js")),
                (30, None),
                (39, None),
                (40, Some("b.js")),
                (44, Some("b.js")),
                (45, Some("inner.js")),
                (49, Some("inner.js")),
                (50, Some("b.js")),
                (59, Some("b.js")),
                (60, None),
                (u64::MAX, None),
            ]
        );
        // Ranges are kept in the order they start, whatever order the tool gave them in.
        assert_eq!(tree.modules()["src/a.js"].ranges, [0..10, 20..30]);
        Ok(())
    }

    #[test]
    fn a_record_reads_back_as_written_and_refuses_what_new_refuses() -> Result<(), String> {
        let tree = built(&[("module-318.js", &[(27, 178)]), ("entry.js", &[(873, 879)])])?;
        let bytes = serde_json::to_vec(&tree).map_err(|e| e.to_string())?;
        assert_eq!(SourceTree::read(&bytes)?, tree);
        let refused = [
            built(&[("a.js", &[(5, 4)])]),
            built(&[("a", &[]), ("a/b.js", &[])]),
            built(&[("x/a", &[]), ("x/a/b/c.js", &[])]),
        ];
        assert!(refused.iter().all(Result::is_err), "{refused:?}");
        let stored = String::from_utf8(bytes).map_err(|e| e.to_string())?;
        let climbing = stored.replace("module-318.js", "../module-318.js");
        assert!(SourceTree::read(climbing.as_bytes()).is_err());
        let long = stored.replace("webpack5", &"w".repeat(SourceTree::FORMAT + 1));
        assert!(SourceTree::read(long.as_bytes()).is_err());
        assert!(SourceTree::read(&vec![b' '; SourceTree::MAX + 1]).is_err());
        Ok(())
    }

    #[test]
    fn a_module_path_names_a_file_inside_any_directory() {
        let kept = ["entry.js", "chunk_$T.js", "shop/src/api.js", "a b/ü.js"];
        assert!(kept.iter().all(|path| ModulePath::new(*path).is_ok()));
        let deep = vec!["d"; ModulePath::DEPTH + 1].join("/");
        let long = "a".repeat(ModulePath::MAX + 1);
        let refused = [
            "",
            "/etc/passwd",
            "../up.js",
            "a/../../up.js",
            "a/./b.js",
            "a//b.js",
            "a/",
            r"a\b.js",
            "C:x.js",
            "a\nb.js",
            "a\0b.js",
            &deep,
            &long,
        ];
        let kept_anyway: Vec<&&str> = (refused.iter())
            .filter(|path| ModulePath::new(**path).is_ok())
            .collect();
        assert!(kept_anyway.is_empty(), "{kept_anyway:?}");
    }
}
