#!/usr/bin/env python3
"""Trial 8: format claims on files whose later parts sit at offsets a count decides.

    LEDGER_MCP=<server binary> format-claims.py <dir of target files> <work dir>

Two statements about the files are first measured by hand, in plain Python that
shares nothing with the ledger. The same statements are then filed as format
claims, with every file as evidence, and the ledger's answers are compared with
the hand count. Last, the true statement is changed in one place at a time and
every changed version must be refuted.

The files are read, never run. The calls go through ledger-call.py."""
import copy, importlib.util, json, os, struct, sys, time

sys.dont_write_bytecode = True  # ledger-call.py is loaded from the repository; leave no cache there
here = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("ledger_call", os.path.join(here, "ledger-call.py"))
ledger_call = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ledger_call)

HEADER, RECORDS, STRIDE = 0xBC, 0x18F4, 216

UNIFORM = {"seq": [
    {"id": "name_len", "type": "u4", "valid": {"min": 1, "max": 255}},
    {"id": "name_offset", "type": "u4"},
    {"id": "rest", "size": STRIDE - 8},
]}

# A first guess, made from three files: after the records come a zero, a count of
# 32-byte blocks, the blocks, and then the names the records point into.
GUESS = {
    "meta": {"endian": "le"},
    "seq": [
        {"id": "header", "size": HEADER},
        {"id": "uniform_count", "type": "u4"},
        {"id": "tables", "size": RECORDS - HEADER - 4},
        {"id": "uniforms", "type": "uniform", "repeat": "expr", "repeat-expr": "uniform_count"},
        {"id": "zero", "type": "u4", "valid": 0},
        {"id": "block_count", "type": "u4"},
    ],
    "instances": {
        "names_start": {"value": f"{RECORDS} + {STRIDE} * uniform_count + 8 + 32 * block_count"},
    },
    "types": {"uniform": {
        "seq": UNIFORM["seq"],
        "instances": {
            "name": {"pos": "_root.names_start + name_offset", "io": "_root._io",
                     "type": "str", "size": "name_len", "encoding": "ASCII"},
            "name_end": {"pos": "_root.names_start + name_offset + name_len", "io": "_root._io",
                         "type": "u1", "valid": 0},
        },
    }},
}

# What every file does have after the records: one table of slot numbers and one
# of uniform indexes, both as long as a second count in the header says.
TRUTH = {
    "meta": {"endian": "le"},
    "seq": [
        {"id": "header", "size": HEADER},
        {"id": "uniform_count", "type": "u4", "valid": {"min": 1, "max": 1024}},
        {"id": "uniform_count_2", "type": "u4", "valid": {"expr": "_ == uniform_count"}},
        {"id": "uniform_count_3", "type": "u4", "valid": {"expr": "_ == uniform_count"}},
        {"id": "sampler_count", "type": "u4", "valid": {"max": 64}},
        {"id": "tables", "size": RECORDS - HEADER - 16},
        {"id": "uniforms", "type": "uniform", "repeat": "expr", "repeat-expr": "uniform_count"},
        {"id": "sampler_slots", "type": "u4", "repeat": "expr", "repeat-expr": "sampler_count",
         "valid": {"expr": "_ == _index"}},
        {"id": "sampler_uniforms", "type": "u4", "repeat": "expr", "repeat-expr": "sampler_count",
         "valid": {"expr": "_ < uniform_count"}},
    ],
    "types": {"uniform": UNIFORM},
}


def guess_by_hand(b):
    count = struct.unpack_from("<I", b, HEADER)[0]
    end = RECORDS + STRIDE * count
    zero, blocks = struct.unpack_from("<II", b, end)
    names = end + 8 + 32 * blocks
    if zero != 0:
        return False
    for i in range(count):
        length, offset = struct.unpack_from("<II", b, RECORDS + STRIDE * i)
        text = b[names + offset: names + offset + length]
        if not 1 <= length <= 255 or len(text) != length or any(c > 127 for c in text):
            return False
        if b[names + offset + length: names + offset + length + 1] != b"\0":
            return False
    return True


def truth_by_hand(b):
    count, second, third, samplers = struct.unpack_from("<4I", b, HEADER)
    end = RECORDS + STRIDE * count
    if not (1 <= count <= 1024 and count == second == third and samplers <= 64):
        return False
    lengths = [struct.unpack_from("<I", b, RECORDS + STRIDE * i)[0] for i in range(count)]
    slots = struct.unpack_from(f"<{samplers}I", b, end)
    indexes = struct.unpack_from(f"<{samplers}I", b, end + 4 * samplers)
    return (all(1 <= n <= 255 for n in lengths) and list(slots) == list(range(samplers))
            and all(i < count for i in indexes))


def by_hand(check, files):
    def holds(path):
        try:
            return check(open(path, "rb").read())
        except struct.error:  # the file ends before a field
            return False
    return sum(not holds(path) for path in files)


def edited(change):
    claim = copy.deepcopy(TRUTH)
    change(claim)
    return claim


def field(claim, name):
    return next(f for f in claim["seq"] + claim["types"]["uniform"]["seq"] if f["id"] == name)


# The true description with one thing changed. Each must be refuted.
SEEDED = {
    "records of 212 bytes": lambda c: field(c, "rest").update(size=STRIDE - 12),
    "at most 30 uniforms": lambda c: field(c, "uniform_count").update(valid={"min": 1, "max": 30}),
    "at most 8 samplers": lambda c: field(c, "sampler_count").update(valid={"max": 8}),
    "big-endian numbers": lambda c: c["meta"].update(endian="be"),
    "slots count from 1": lambda c: field(c, "sampler_slots").update(valid={"expr": "_ == _index + 1"}),
    "sampler indexes under 10": lambda c: field(c, "sampler_uniforms").update(valid={"expr": "_ < 10"}),
    "names of at most 12 characters": lambda c: field(c, "name_len").update(valid={"min": 1, "max": 12}),
    "the second count is twice the first": lambda c: field(c, "uniform_count_2").update(
        valid={"expr": "_ == uniform_count * 2"}),
}


def propose(db, spec, ids, exact=False):
    claim = {"kind": "format", "type_name": "ShaderCache", "spec": spec, "exact": exact}
    start = time.monotonic()
    answer = ledger_call.call(db, "propose", {"claim": claim, "evidence": ids})
    return answer, time.monotonic() - start


def main(target, work):
    files = sorted(os.path.join(root, f) for root, _, names in os.walk(target) for f in names)
    print(f"{len(files)} files, {sum(map(os.path.getsize, files))} bytes")
    wrong = {"guess": by_hand(guess_by_hand, files), "truth": by_hand(truth_by_hand, files)}
    print(f"by hand: the guess is contradicted by {wrong['guess']} files, the truth by {wrong['truth']}")

    os.makedirs(work, exist_ok=True)
    db = os.path.join(work, "ledger.db")
    start, ids = time.monotonic(), []
    for path in files:
        answer = ledger_call.call(db, "add_evidence", {"kind": "memory_snapshot", "path": path})
        assert "\nevidence " in answer, answer
        ids.append(answer.rsplit(" ", 1)[1])
    print(f"loaded as evidence in {time.monotonic() - start:.0f} s")

    for name, claim in (("guess", GUESS), ("truth", TRUTH)):
        answer, seconds = propose(db, claim, ids)
        print(f"\n## the {name}, {seconds:.1f} s for the call\n{answer}")

    caught = 0
    print("\n## the truth with one thing changed")
    variants = [(name, edited(change), False) for name, change in SEEDED.items()]
    variants.append(("the file ends after the two tables", TRUTH, True))
    for name, claim, exact in variants:
        answer, _ = propose(db, claim, ids, exact)
        lines = answer.splitlines()
        refuted = any(line.startswith("refuted") for line in lines)
        caught += refuted
        print(f"{name}: " + " | ".join(line[:230] for line in lines[1:4]))
    print(f"\ncaught {caught} of {len(variants)} changed descriptions")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])
