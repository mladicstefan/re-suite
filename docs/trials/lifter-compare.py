#!/usr/bin/env python3
"""How often do two lifters disagree about an instruction? RzIL (Rizin) against P-code (pypcode).

usage: lifter-compare.py <program>...

For every instruction in a function Rizin recovers (with the analysis the ledger runs)
both lifters are asked what the instruction does, and the answers are compared by
their effects: which registers are written, whether memory is written, and whether
control leaves the instruction. Two lifters that agree here can still compute
different values; that needs concrete execution and is not measured.

RzIL's `empty` counts as not lifted unless the instruction truly does nothing.
P-code that calls a user-defined operation (CALLOTHER) counts as not lifted: it
names the instruction instead of giving it a meaning.

The programs are read, never run. Needs rizin and the pypcode Python package.
"""
import bisect
import collections
import json
import subprocess
import sys

import pypcode

ANALYSIS = "e analysis.hasnext=true; aaa; aap"  # what the ledger runs
NO_EFFECT = {"nop", "endbr64", "endbr32", "bti", "hint", "fnop", "pause", "data16"}
LANGUAGES = {("x86", 64): "x86:LE:64:default", ("arm", 64): "AARCH64:LE:64:v8A"}
# RzIL's names for registers that P-code names differently.
ALIASES = {
    "x86:LE:64:default": {"swd": "fpustatusword", "cwd": "fpucontrolword"},
    "AARCH64:LE:64:v8A": {"nf": "ng", "zf": "zr", "cf": "cy", "vf": "ov"},
}
PREFIXES = {"rep", "repe", "repne", "repz", "repnz", "lock", "bnd", "notrack"}
PROGRAM_COUNTER = {"rip", "pc"}
P = pypcode.OpCode
LEAVES = {P.BRANCH, P.CBRANCH, P.BRANCHIND, P.CALL, P.CALLIND, P.RETURN}


class Lifters:
    def __init__(self, language):
        self.pcode = pypcode.Context(language)
        self.aliases = ALIASES[language]
        self.registers = {name.lower(): (v.offset, v.size) for name, v in self.pcode.registers.items()}
        # The widest register over each byte: a write to eax and one to rax are the same write.
        self.widest = {}
        for name, (at, size) in sorted(self.registers.items(), key=lambda r: -r[1][1]):
            for byte in range(at, at + size):
                self.widest.setdefault(byte, name)
        self.unknown = collections.Counter()

    def rzil(self, il):
        """(registers written, memory written, control leaves), from an RzIL tree."""
        written, effect = set(), {"memory": False, "leaves": False}

        def walk(node):
            if isinstance(node, list):
                for item in node:
                    walk(item)
            elif isinstance(node, dict):
                opcode = node.get("opcode")
                if opcode == "set":
                    name = self.aliases.get(node["dst"], node["dst"]).lower()
                    if name in self.registers:
                        written.add(self.widest[self.registers[name][0]])
                    elif not name.startswith("_"):
                        self.unknown[name] += 1  # a local of the lifter, or a register P-code lacks
                elif opcode in ("store", "storew"):
                    effect["memory"] = True
                elif opcode in ("jmp", "goto"):
                    effect["leaves"] = True
                for value in node.values():
                    walk(value)

        walk(il)
        return written - PROGRAM_COUNTER, effect["memory"], effect["leaves"]

    def p_code(self, raw, address):
        """The same from P-code, or the reason there is none."""
        try:
            ops = self.pcode.translate(raw, address, max_instructions=1).ops
        except Exception as why:  # pypcode raises its own errors for bytes it cannot decode or lift
            return None, type(why).__name__
        written, memory, leaves = set(), False, False
        for op in ops:
            if op.opcode == P.CALLOTHER:
                # LOCK and UNLOCK only bracket the meaning of a lock-prefixed instruction.
                if "LOCK()" in pypcode.PcodePrettyPrinter.fmt_op(op):
                    continue
                return None, "user-defined operation"
            if op.opcode == P.STORE:
                memory = True
            elif op.opcode in LEAVES:
                # P-code writes a conditional move or a loop as a branch inside the
                # instruction or to the next one: control does not leave.
                target = op.inputs[0]
                inside = op.opcode in (P.BRANCH, P.CBRANCH) and (
                    target.space.name == "const" or target.offset in (address, address + len(raw))
                )
                leaves = leaves or not inside
            if op.output is not None:
                # AArch64 P-code computes flags into scratch registers named tmp*: not machine state.
                if op.output.space.name == "register" and not self.widest[op.output.offset].startswith("tmp"):
                    written.add(self.widest[op.output.offset])
                memory = memory or op.output.space.name == "ram"
        return (written - PROGRAM_COUNTER, memory, leaves), "lifted"


def top(counter, n=10):
    return ", ".join(f"{name} {count}" for name, count in counter.most_common(n)) or "none"


def report(program):
    commands = f"iIj; {ANALYSIS}; aflj; aoj 1 @@i @@b @@F"
    run = subprocess.Popen(
        ["rizin", "-N", "-q", "-e", "scr.color=0", "-e", "cfg.sandbox=true", "-c", commands, program],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
    )
    info = json.loads(run.stdout.readline() or "{}")
    language = LANGUAGES.get((info.get("arch"), info.get("bits")))
    if language is None:
        print(f"{program}: no P-code language for {info.get('arch')}-{info.get('bits')}")
        run.kill()
        return
    functions = json.loads(run.stdout.readline() or "[]")
    lifters = Lifters(language)
    flag_only, other = [], []  # addresses where the lifters differ: in the AF flag alone, or otherwise
    outcome, by = collections.Counter(), collections.defaultdict(collections.Counter)
    registers, where, seen = collections.Counter(), collections.defaultdict(collections.Counter), set()
    for line in run.stdout:
        op = json.loads(line)[0]
        if op["addr"] in seen or "bytes" not in op:
            continue
        seen.add(op["addr"])
        # Rizin's own `mnemonic` field is an operand for some SSE instructions (`xmm0,`).
        words = [w for w in op.get("disasm", "?").split() if w not in PREFIXES] or ["?"]
        mnemonic = words[0]
        il = op.get("rzil")
        ours = il is not None and (il.get("opcode") != "empty" or mnemonic in NO_EFFECT)
        theirs, _ = lifters.p_code(bytes.fromhex(op["bytes"]), op["addr"])
        if not ours or theirs is None:
            what = ("neither lifts" if not ours else "only RzIL lifts") if theirs is None else "only P-code lifts"
        else:
            mine = lifters.rzil(il)
            if mine == theirs:
                what = "same effects"
            elif mine[0] != theirs[0]:
                what = "registers written differ"
                only = lambda a, b, who: f"{who} alone writes {','.join(sorted(a - b))}" if a - b else ""
                which = "; ".join(filter(None, [only(mine[0], theirs[0], "RzIL"), only(theirs[0], mine[0], "P-code")]))
                registers[which] += 1
                where[which][mnemonic] += 1
            elif mine[1] != theirs[1]:
                what = "memory write differs"
            else:
                what = "control flow differs"
        outcome[what] += 1
        by[what][mnemonic] += 1
        if what == "registers written differ" and which == "RzIL alone writes af":
            flag_only.append(op["addr"])
        elif what != "same effects":
            other.append(op["addr"])
    run.wait()
    total = sum(outcome.values())
    both = total - outcome["neither lifts"] - outcome["only RzIL lifts"] - outcome["only P-code lifts"]
    differ = both - outcome["same effects"]
    print(f"\n## {program.rsplit('/', 1)[-1]}: {info.get('bintype')} {info.get('arch')}-{info.get('bits')}, {total} instructions")
    for what in ("same effects", "registers written differ", "memory write differs", "control flow differs",
                 "only P-code lifts", "only RzIL lifts", "neither lifts"):
        if outcome[what]:
            print(f"{what}: {outcome[what]} ({100 * outcome[what] / total:.2f}%): {top(by[what])}")
    print(f"both lift {both} ({100 * both / total:.2f}%); of those, effects differ in {differ} ({100 * differ / both:.2f}%)")
    for which, count in registers.most_common(8):
        print(f"  {count}: {which} ({top(where[which], 5)})")
    # What a proof over a function needs: every instruction lifted by both, with the same
    # effects. A function is taken as one byte range, which is not exact for the few that are split.
    flag_only.sort()
    other.sort()
    none_in = lambda found, f: bisect.bisect_left(found, f["offset"]) == bisect.bisect_left(found, f["offset"] + f["size"])
    clean = sum(none_in(other, f) for f in functions)
    same = sum(none_in(other, f) and none_in(flag_only, f) for f in functions)
    print(f"functions where both lift every instruction with the same effects: {same} of {len(functions)} "
          f"({100 * same / len(functions):.1f}%); setting the AF flag aside: {clean} ({100 * clean / len(functions):.1f}%)")
    print(f"names RzIL sets that P-code has no register for: {top(lifters.unknown, 8)}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    for program in sys.argv[1:]:
        report(program)
