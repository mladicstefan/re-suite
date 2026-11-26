#!/usr/bin/env python3
"""The experiment in ledger-loop.md: one task, done with the ledger and without it.

    ledger-loop.py prepare <dir of target files> <out dir> [seed] [working files]
        draws the working set, copies it to <out>/working/001.bin ..., and loads two
        scoring ledgers: one with the working files, one with every file held out
    ledger-loop.py arm <out dir> <run dir> ledger|control
        makes <run dir> with the working files, the task and the claim format; for
        `ledger`, also a ledger that holds the files and a `ledger` command
    ledger-loop.py score <out dir> <run dir>...
        replays every claim in <run dir>/report.json on both scoring ledgers

The server binary is $LEDGER_MCP; the calls go through ledger-call.py."""
import importlib.util, json, os, random, shutil, sys

sys.dont_write_bytecode = True  # ledger-call.py is loaded from the repository; leave no cache there
here = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("ledger_call", os.path.join(here, "ledger-call.py"))
ledger_call = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ledger_call)


def load(db, files):
    """Adds each file as a memory snapshot; returns the short evidence ids in order."""
    ids = []
    for path in files:
        answer = ledger_call.call(db, "add_evidence", {"kind": "memory_snapshot", "path": path})
        assert "\nevidence " in answer, answer
        ids.append(answer.rsplit(" ", 1)[1])
    return ids


def prepare(source, out, seed=1, count=40):
    files = sorted(os.path.join(d, f) for d, _, fs in os.walk(source) for f in fs)
    working = sorted(random.Random(seed).sample(files, count))
    held_out = [f for f in files if f not in set(working)]
    os.makedirs(os.path.join(out, "working"))
    copies = []
    for n, path in enumerate(working, 1):
        copies.append(os.path.join(out, "working", f"{n:03}.bin"))
        shutil.copy(path, copies[-1])
    ids = {"working": load(os.path.join(out, "score-working.db"), copies),
           "held_out": load(os.path.join(out, "score-held-out.db"), held_out)}
    json.dump(ids, open(os.path.join(out, "score-ids.json"), "w"))
    print(f"{len(files)} files: {len(working)} working, {len(held_out)} held out, seed {seed}")


def arm(out, home, kind):
    home = os.path.abspath(home)
    shutil.copytree(os.path.join(out, "working"), os.path.join(home, "files"))
    shutil.copy(os.path.join(here, "ledger-loop.claim-format.md"), os.path.join(home, "claim-format.md"))
    task = open(os.path.join(here, "ledger-loop.task.md")).read().replace("DIR", home)
    start, end = task.index("<!-- ledger arm only"), task.index("<!-- end of the ledger arm's part -->")
    # The two arms read the same task; only the ledger arm reads the part about the ledger.
    task = task[:start] + (task[task.index("\n", start) + 1:end] if kind == "ledger" else "") \
        + task[task.index("\n", end) + 2:]
    open(os.path.join(home, "task.md"), "w").write(task)
    if kind == "ledger":
        shutil.copy(os.path.join(here, "ledger-call.py"), os.path.join(home, ".ledger-call.py"))
        command = os.path.join(home, "ledger")
        with open(command, "w") as script:
            script.write(f"#!/bin/sh\nLEDGER_MCP='{os.environ['LEDGER_MCP']}' exec python3 "
                         f"'{home}/.ledger-call.py' '{home}/ledger.db' \"$@\"\n")
        os.chmod(command, 0o755)
        files = sorted(os.listdir(os.path.join(home, "files")))
        ids = load(os.path.join(home, "ledger.db"), [os.path.join(home, "files", f) for f in files])
        json.dump(ids, open(os.path.join(home, "evidence-ids.json"), "w"))
        with open(os.path.join(home, "evidence.txt"), "w") as listing:
            listing.writelines(f"{f} {i}\n" for f, i in zip(files, ids))


def verdict(db, claim, ids):
    """`held`, `refuted`, `inconclusive`, or the code of a rejection, with the detail."""
    answer = ledger_call.call(db, "propose", {"claim": claim, "evidence": ids})
    if answer.startswith("REJECTED"):
        return answer.split()[1], answer
    rows = answer.splitlines()
    return rows[1].split()[0], "\n".join(rows[2:])


def score(out, homes):
    ids = json.load(open(os.path.join(out, "score-ids.json")))
    for home in homes:
        name = os.path.basename(os.path.normpath(home))
        try:
            report = json.load(open(os.path.join(home, "report.json")))
        except (OSError, ValueError) as why:
            print(f"{name}: no usable report.json ({why})")
            continue
        rows, seen = [], set()
        for entry in report:
            claim = entry.get("claim") if isinstance(entry, dict) else None
            key = json.dumps(claim, sort_keys=True)
            if not isinstance(claim, dict) or key in seen:
                rows.append({"entry": entry, "result": "not a claim" if key not in seen else "repeated"})
                continue
            seen.add(key)
            claim = {**claim, "premises": []}  # each statement is scored on its own
            on_working, why_working = verdict(os.path.join(out, "score-working.db"), claim, ids["working"])
            on_held_out, why_held_out = verdict(os.path.join(out, "score-held-out.db"), claim, ids["held_out"])
            if "refuted" in (on_working, on_held_out):
                result = "wrong"
            elif (on_working, on_held_out) == ("held", "held"):
                result = "holds"
            else:
                result = "not checkable"
            rows.append({"sentence": entry.get("sentence"), "claim": claim, "result": result,
                         "working": on_working, "held_out": on_held_out,
                         "detail": why_working if on_working == "refuted" else why_held_out})
        json.dump(rows, open(os.path.join(home, "score.json"), "w"), indent=1)
        count = lambda **want: sum(all(r.get(k) == v for k, v in want.items()) for r in rows)
        # Bytes a held layout claim says something about: a statement count alone rewards splitting.
        typed = {(f["offset"] + i) for r in rows if r["result"] == "holds"
                 and r["claim"].get("kind") == "memory_layout"
                 for f in r["claim"].get("fields", []) if f.get("is") is not None
                 for i in range(f["len"])}
        print(f"{name}: statements {len(rows)}, hold {count(result='holds')}, "
              f"wrong {count(result='wrong')} (on the working files {count(working='refuted')}, "
              f"only on held-out files {count(result='wrong') - count(working='refuted')}), "
              f"not checkable {count(result='not checkable')}, repeated or not a claim "
              f"{count(result='repeated') + count(result='not a claim')}, "
              f"bytes typed by layouts that hold {len(typed)}")


if __name__ == "__main__":
    command, args = (sys.argv[1], sys.argv[2:]) if len(sys.argv) > 2 else ("", [])
    if command == "prepare":
        prepare(args[0], args[1], *map(int, args[2:]))
    elif command == "arm":
        arm(*args)
    elif command == "score":
        score(args[0], args[1:])
    else:
        sys.exit(__doc__)
