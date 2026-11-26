#!/usr/bin/env python3
"""How much of a program does Rizin recover, and how much of that does RzIL lift?

usage: rzil-coverage.py <program>...

For each program and each analysis setting it prints:
- recovery: the code ranges in the file's unwind table (the exception table of a
  Windows program, .eh_frame of a Linux one) whose first instruction lies in a
  function Rizin recovered. The table is written by the compiler, so it is a list
  of where code is that does not depend on Rizin.
- lifting: the instructions in recovered functions that RzIL gives a meaning to,
  the ones it lifts as "no effect", and the ones it does not lift.

The programs are read, never run. Needs rizin, objdump, readelf and, for a foreign architecture, llvm-objdump.
"""
import bisect
import collections
import json
import re
import subprocess
import sys
import time

# What to run before listing functions. The first is what the ledger runs.
# `aaaa` was tried too and recovered exactly what `aaa; aap` does on all four programs.
ANALYSES = [
    "e analysis.hasnext=true; aaa; aap",
    "aaa",
    "aaa; aap",
    "e analysis.hasnext=true; aaa",
]
# Instructions that really have no effect on registers or memory.
NO_EFFECT = {"nop", "endbr64", "endbr32", "bti", "hint", "fnop", "pause", "data16"}


def unwind_starts(program, bintype):
    """Where each code range in the unwind table starts."""
    if bintype == "pe":
        out = subprocess.run(["objdump", "-p", program], capture_output=True, text=True).stdout
        return {int(a, 16) for a in re.findall(r"^ [0-9a-f]+:\t([0-9a-f]+) [0-9a-f]+ ", out, re.M)}
    out = subprocess.run(
        ["readelf", "--debug-dump=frames", "-W", program], capture_output=True, text=True
    ).stdout
    return {int(a, 16) for a in re.findall(r" FDE .*pc=([0-9a-f]+)\.\.", out)}


def second_reading(program):
    """Every call and jump another disassembler sees, as (address, target or None, is a call)."""
    # GNU objdump reads a file with no symbols but only its own architecture;
    # llvm-objdump reads any architecture but prints nothing without symbols.
    line = r"^\s*([0-9a-f]+):\s+(?:addr32\s+|data16\s+|rex\S*\s+|bnd\s+)*(callq?|bl|jmpq?|b)\s+(.*)$"
    for tool in ("objdump", "llvm-objdump"):
        out = subprocess.run([tool, "-d", "--no-show-raw-insn", program], capture_output=True, text=True).stdout
        found = []
        for at, mnemonic, operand in re.findall(line, out, re.M):
            # A transfer through a pointer the disassembler can place is written as a comment.
            target = re.search(r"# (?:0x)?([0-9a-f]+)", operand) or re.match(r"(?:0x)?([0-9a-f]+)\b", operand)
            call = mnemonic.startswith("call") or mnemonic == "bl"
            found.append((int(at, 16), int(target.group(1), 16) if target else None, call))
        if any(call for _, _, call in found):
            return tool, sorted(found)
    return "no disassembler", []


def measure(program, analysis):
    commands = f"iIj; {analysis}; aflj; aoj 1 @@i @@b @@F"
    start = time.monotonic()
    run = subprocess.Popen(
        ["rizin", "-N", "-q", "-e", "scr.color=0", "-e", "cfg.sandbox=true", "-c", commands, program],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    info = json.loads(run.stdout.readline() or "{}")
    functions = json.loads(run.stdout.readline() or "[]")
    lifted = {}  # address -> (mnemonic, "lifted" | "no effect" | "not lifted")
    for line in run.stdout:
        op = json.loads(line)[0]
        mnemonic = op.get("mnemonic") or op.get("opcode", "?").split()[0]
        il = op.get("rzil")
        kind = "not lifted" if il is None else "no effect" if il.get("opcode") == "empty" else "lifted"
        lifted[op["addr"]] = (mnemonic, kind)
    run.wait()
    return info, functions, lifted, time.monotonic() - start


def top(counter, n):
    return ", ".join(f"{name} {count}" for name, count in counter.most_common(n)) or "none"


def report(program):
    name = program.rsplit("/", 1)[-1]
    for at, analysis in enumerate(ANALYSES):
        info, functions, lifted, seconds = measure(program, analysis)
        if not functions:
            print(f"{name}: `{analysis}` gave no functions")
            continue
        if at == 0:
            print(f"\n## {name}: {info.get('bintype')} {info.get('arch')}-{info.get('bits')}")
        starts = unwind_starts(program, info.get("bintype"))
        found = sum(start in lifted for start in starts)
        share = f"{100 * found / len(starts):.1f}%" if starts else "no table"
        # A function the table does not list can be real (a stub needs no unwinding) or
        # a false start; a jump in this number from one analysis to the next is a warning.
        unlisted = sum(f["offset"] not in starts for f in functions)
        # A function that starts in the middle of another one's bytes is likely a false start.
        ranges = sorted((f["offset"], f["offset"] + f["size"]) for f in functions)
        inside = sum(lo < ranges[at - 1][1] for at, (lo, _) in enumerate(ranges) if at)
        print(
            f"`{analysis}`: {seconds:.1f} s, {len(functions)} functions ({unlisted} not in the table, "
            f"{inside} starting inside the one before), "
            f"{len(lifted)} instructions, unwind ranges recovered {found} of {len(starts)} ({share})"
        )
        # Do the calls Rizin lists match what a second disassembler sees in the same bytes?
        # They agree when Rizin lists every call instruction's target and nothing else,
        # except that Rizin may call a jump a call: a tail call. Only functions that are
        # one byte range can be compared.
        tool, transfers = second_reading(program)
        sites = [site for site, _, _ in transfers]
        whole = [f for f in functions if f.get("realsz", f["size"]) == f["size"]]
        agree = 0
        for f in whole:
            seen = transfers[bisect.bisect_left(sites, f["offset"]) : bisect.bisect_left(sites, f["offset"] + f["size"])]
            called = {target for _, target, call in seen if call and target is not None}
            jumped = {target for _, target, call in seen if not call and target is not None}
            ours = {r["to"] for r in f.get("callrefs", []) if r["type"] == "CALL"}
            agree += called <= ours and ours - called <= jumped
        print(f"  calls agree with {tool} in {agree} of {len(whole)} single-range functions ({100 * agree / len(whole):.2f}%)")
        if at:
            continue
        kinds = collections.Counter(kind for _, kind in lifted.values())
        total = len(lifted)
        # "No effect" is right for a nop and wrong for anything else.
        wrong = collections.Counter(m for m, k in lifted.values() if k == "no effect" and m not in NO_EFFECT)
        missing = collections.Counter(m for m, k in lifted.values() if k == "not lifted")
        unusable = sum(wrong.values()) + sum(missing.values())
        print(
            f"  lifting: {kinds['lifted']} lifted, {kinds['no effect']} as no effect "
            f"({sum(wrong.values())} of them not nops), {kinds['not lifted']} not lifted; "
            f"{100 * (total - unusable) / total:.2f}% of instructions have a usable meaning"
        )
        print(f"  not lifted: {top(missing, 12)}")
        print(f"  no effect but not a nop: {top(wrong, 12)}")
        # A function is only usable for a proof if every instruction in it is. A function
        # is taken as one byte range here, which is not exact for the few that are split.
        bad = sorted(a for a, (m, k) in lifted.items() if k == "not lifted" or (k == "no effect" and m not in NO_EFFECT))
        clean = sum(
            bisect.bisect_left(bad, f["offset"]) == bisect.bisect_left(bad, f["offset"] + f["size"])
            for f in functions
        )
        print(f"  functions lifted in full: {clean} of {len(functions)} ({100 * clean / len(functions):.1f}%)")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    for program in sys.argv[1:]:
        report(program)
