# Trial 8: format claims on parts of a file that a count places

28 November 2026. Trial 7 ended with an open question: no claim kind could
place a field at an offset that depends on a count, so six agents out of six
left out everything after the first table of a file. This trial files such
statements as `format` claims, written in Kaitai Struct, on the same files.

**Result: it works, and it agrees with a count made by hand.** A wrong
description was refuted with the number of files that contradict it, 3,943
of 6,594, which is the number plain Python finds. A true one held on all
6,594. Nine versions of the true one, each changed in one place, were all
refuted.

## Setup

- **Target:** the 6,594 files (105 MB) of the OpenGL shader cache of
  trial 7. They were read, never run, and nothing was sent anywhere.
- **Two statements,** both about what follows a table of 216-byte records
  whose length is a count in the header:
  - *the guess*, made from three files: after the records come a zero, a
    count of 32-byte blocks and the blocks, and then the names the
    records point into, each at `names + its offset` and ended by a NUL;
  - *the truth*: the header holds the record count three times and a
    second count; after the records come two tables of that second
    length, one of slot numbers 0, 1, 2 and one of record indexes.
- **By hand:** each statement as a few lines of Python (`struct`), run on
  every file. It shares no code with the ledger.
- **In the ledger:** every file as evidence in the real `ledger-mcp`
  binary, and each statement proposed once as a `format` claim with all
  6,594 files cited.
- **Seeded errors:** the true description with one thing changed (the
  record size, a bound, the byte order, a rule, the end of the file).
- The whole trial is `format-claims.py`; its output is `format-claims.txt`.

## Result

| Statement | By hand | Ledger |
| --- | --- | --- |
| The guess | 3,943 files contradict it | refuted, "3943 of 6594 captures disagree", with the smallest such file and the field: `at +0x2824, zero is 1162690883, not 0` |
| The truth | 0 files contradict it | held on 6,594 |
| The truth, changed in one place (9 versions) | wrong by construction | 9 of 9 refuted, each naming the field and the value |

One proposal took 0.2 seconds, the start of the server and the replay of
its log included. Loading the files as evidence took about 50 seconds, one
server start per file.

The three numbers of section 11:

1. **Wrong claims caught: 10 of 10** (the guess and the nine seeded ones).
2. **Attempts per accepted claim: 2.0** in the sense of the earlier
   trials: one refuted guess, one accepted description. A proposal is
   about 1,500 characters of description; the 6,594 evidence ids it has
   to list are 86,000 more (still open, see below).
3. **Passed, later failed:** none staged.

## Findings

- **A description places what a fixed layout cannot.** The two tables of
  the true statement start at `0x18f4 + 216 * count`, and the guess reads
  names through an offset computed from two counts. Both were checked on
  every file.
- **The refutation says where.** "`uniforms[1].name_len` is 0, under the
  least allowed, 1" for records of the wrong size; "`uniform_count` is
  301989888" for the wrong byte order. A changed description is found in
  one call.
- **The reader is ours, the language is not.** Descriptions are walked
  directly by the checker; no code is generated or run, so a check stays
  a function of the claim and the files. A test compares the reader with
  the Kaitai Struct compiler's own Python parser on about 300 files made
  from two descriptions (each truncation, each byte changed): the two
  accept, refuse and read the same values on all of them.
- **Only part of the language is read.** `enums`, `params`, `process`,
  bit fields and `terminator` are refused at admission by name. Numbers
  are computed in 128 bits, where the compiler's Python has no limit.
- **Open: a failed `valid` expression is not quoted.** The counterexample
  says "against its `valid` expression" and gives the value, not the
  rule.
- **Open, as before: every proposal lists every file.** A format claim
  is a snapshot claim and cannot say "all files of this type".
- **Not measured:** an agent writing descriptions. Both were written by
  the same hand that measured them, and I did not work out the rest of
  the file (the names start after more tables than the two found here).
