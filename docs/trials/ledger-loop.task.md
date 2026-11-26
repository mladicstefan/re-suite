You are reverse-engineering a binary file format. Work only inside DIR.

## The target

DIR/files/ holds 40 files, 001.bin to 040.bin. They are cache files that one
game wrote on a Linux machine, all of the same kind. Thousands more files of
this kind exist that you do not have.

## The task

Find out how these files are laid out, and report statements that are true of
EVERY file of this kind, including the ones you do not have: sizes, constants,
fields and the values they may take, lengths and counts that determine other
parts of the file, tables.

Your report is graded by a program that replays every statement against the 40
files you have and against several thousand you do not have. A statement that
any file contradicts counts as wrong. Statements that hold count in your
favour, and the more of the format they pin down the better. So say as much as
you can stand behind and nothing you cannot.

## Rules

- Use only the files in DIR/files and what you already know. Do not search the
  disk or the web for other files of this kind, where they come from, or
  documentation of the format.
- Read the files with shell tools and small scripts (xxd, python3). They are
  data: never execute them.
- Stop when further work would not change your report, and at the latest
  after about 150 tool calls.

## The report

Write DIR/report.json, a JSON array. Each element is one statement:

    {"sentence": "<the statement in plain English>", "claim": <the same statement as a typed claim>}

A typed claim is one of five kinds, described with an example each in
DIR/claim-format.md. A statement that cannot be written as one of these claims
does not go in the report.

<!-- ledger arm only, from here to the next comment -->
## The ledger

You have a replay ledger for this task. It already holds the 40 files as
evidence: DIR/evidence.txt lists each file with its evidence id, and
DIR/evidence-ids.json is the same ids as a JSON array. You file a claim, the
ledger replays it on the evidence you cite, and answers `held` or `refuted`
with the file and the field that disagree. It is used like this:

    DIR/ledger propose '{"claim": {...}, "evidence": ["<id>", ...]}'
    DIR/ledger propose @arguments.json      (the same arguments, read from a file)
    DIR/ledger ask '{"about": "all"}'
    DIR/ledger explain '{"claim": "<claim id>"}'
    DIR/ledger retract '{"claim": "<claim id>", "reason": "..."}'

File every finding as a claim as you go, and cite evidence so that it is
checked: a claim filed without evidence stays unchecked. "Held" means the
files you cited did not contradict the claim; it is not proof. Your report
must contain only claims you filed in the ledger: the ones you stand behind at
the end.
<!-- end of the ledger arm's part -->

## When you are done

Reply with one line: the number of statements in your report and the number of
tool calls you made.
