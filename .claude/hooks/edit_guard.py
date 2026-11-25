#!/usr/bin/env python3
"""PreToolUse guard for Edit/Write. One check per invocation: protect | versions | allows.

Exit 0 lets the edit through; exit 2 blocks it and stderr is shown to the agent.
"""

import collections
import json
import os
import re
import sys
import tomllib

PROTECTED = {"clippy.toml", ".clippy.toml", "deny.toml", "rust-toolchain.toml"}
DEP_TABLES = ("dependencies", "dev-dependencies", "build-dependencies")
ALLOW = re.compile(r"^\s*#!?\[\s*(?:cfg_attr\(.*,\s*)?allow\(")


def before_after(inp):
    """Full file text before and after the edit, so checks see the result, not a fragment."""
    ti = inp.get("tool_input", {})
    path = ti.get("file_path", "")
    try:
        with open(path, encoding="utf-8") as f:
            old = f.read()
    except OSError:
        old = ""
    if inp.get("tool_name") == "Write":
        new = ti.get("content", "")
    else:
        o, n = ti.get("old_string", ""), ti.get("new_string", "")
        new = old.replace(o, n) if ti.get("replace_all") else old.replace(o, n, 1)
    return path, old, new


def user_asked(inp, words):
    """True if a message the user typed this session mentions any of `words`.

    shortcut: a mention counts as asking; tighten to an explicit marker phrase if that proves too loose.
    """
    try:
        lines = open(inp.get("transcript_path", ""), encoding="utf-8")
    except OSError:
        return False
    with lines:
        for line in lines:
            try:
                d = json.loads(line)
            except ValueError:
                continue
            if d.get("type") != "user" or d.get("isMeta"):
                continue
            c = (d.get("message") or {}).get("content")
            if isinstance(c, list):  # tool results are not the user's words
                c = " ".join(b.get("text", "") for b in c if isinstance(b, dict) and b.get("type") == "text")
            if not isinstance(c, str):
                continue
            c = re.sub(r"<system-reminder>.*?</system-reminder>", "", c, flags=re.S)
            if any(w in c for w in words):
                return True
    return False


def toml(text):
    try:
        return tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return None


def dep_tables(doc):
    """Yield (name, table) for every dependency table, including target-specific and workspace ones."""
    for t in DEP_TABLES:
        yield t, doc.get(t, {})
    for target, body in doc.get("target", {}).items():
        for t in DEP_TABLES:
            yield f"target.{target}.{t}", body.get(t, {})
    yield "workspace.dependencies", doc.get("workspace", {}).get("dependencies", {})


def check_protect(inp):
    path, old, new = before_after(inp)
    name = os.path.basename(path)
    if name in PROTECTED:
        if user_asked(inp, [name]):
            return None
        return f"{name} is protected. Ask the user to request this change in this session first."
    if name == "Cargo.toml":
        a, b = toml(old) or {}, toml(new) or {}
        if a.get("workspace", {}).get("lints") != b.get("workspace", {}).get("lints"):
            if user_asked(inp, ["workspace.lints", "workspace lints"]):
                return None
            return "[workspace.lints] is protected. Ask the user to request this change in this session first."
    return None


def check_versions(inp):
    path, old, new = before_after(inp)
    if os.path.basename(path) != "Cargo.toml":
        return None
    b = toml(new)
    if b is None:
        return None  # cargo reports the syntax error itself
    a = dict(dep_tables(toml(old) or {}))
    bad = []
    for table, deps in dep_tables(b):
        for dep, spec in deps.items():
            if a.get(table, {}).get(dep) == spec:
                continue
            if isinstance(spec, str) or (isinstance(spec, dict) and "version" in spec):
                bad.append(f"[{table}] {dep}")
    if bad:
        return ("Hand-written dependency version: " + ", ".join(bad)
                + ". Use `cargo add -p <crate> <dep>` so Cargo resolves it.")
    return None


def uncommented_allows(text):
    lines = text.splitlines()
    found = collections.Counter()
    for i, line in enumerate(lines):
        if not ALLOW.match(line) or "//" in line:
            continue
        j = i - 1  # walk up through the item's other attributes looking for a comment
        while j >= 0 and lines[j].strip().startswith("#"):
            j -= 1
        if j < 0 or not lines[j].strip().startswith("//"):
            found[line.strip()] += 1
    return found


def check_allows(inp):
    path, old, new = before_after(inp)
    if not path.endswith(".rs"):
        return None
    added = uncommented_allows(new) - uncommented_allows(old)
    if added:
        return ("New #[allow(...)] without a comment explaining why: " + "; ".join(added)
                + ". Put a `//` comment on the same item (line above or same line).")
    return None


def main():
    check = {"protect": check_protect, "versions": check_versions, "allows": check_allows}[sys.argv[1]]
    reason = check(json.load(sys.stdin))
    if reason:
        print(reason, file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
