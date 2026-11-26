# Trial 7: the same task with the ledger and without it

27 November 2026. The experiment the roadmap asked for: does the loop cut
tokens and false claims on a real task? One task was given to six agents
that share no context, three with the ledger and three without, and every
statement in their reports was replayed on files none of them had seen.

**Result: no difference.** The ledger arm made 21, 21 and 18 wrong
statements and the control arm 22, 22 and 20, for 100,000 and 106,000
tokens a run on average. Three runs an arm cannot tell those apart. The
ledger refuted none of the 302 claims proposed to it.

## Setup

- **Target:** the 6,594 files of the OpenGL shader cache one game
  (Dying Light) wrote on this machine, 11 to 30 KB each: the driver's
  compiled program inside a wrapper nobody documents. No earlier trial
  used it. The files were read, never run, and nothing was sent anywhere.
- **Working set:** 40 files drawn with a fixed seed and renamed
  `001.bin` to `040.bin`. The other 6,554 were held out.
- **Task:** `ledger-loop.task.md`, the same text for both arms: state what
  is true of every file of this kind, including the ones you do not
  have; a statement that any file contradicts counts as wrong.
- **Report, both arms:** a list of statements, each a sentence and the
  same statement as a typed claim (`ledger-loop.claim-format.md`).
- **Ledger arm:** also the real `ledger-mcp` binary with the 40 files
  loaded, reached through `ledger-call.py`, and the instruction to file
  every finding as it goes.
- **Control arm:** no ledger. It had a shell and Python, as the ledger
  arm did.
- **Agents:** six subagents on Claude Opus, started together, each with
  only its task file. Runs 1, 3 and 5 had the ledger.
- **Scoring:** `ledger-loop.py score` proposes every reported claim to
  two scoring ledgers, one holding the 40 working files and one holding
  the 6,554 held-out files. Wrong means refuted on either. The same
  program scored both arms. It was first run on six claims whose truth
  had been measured by hand and classified all six correctly.
- **Tokens:** the total the harness reports when a subagent finishes,
  and the split from its transcript.

## Result

| Run | Arm | Statements | Hold | Wrong | Wrong on the 40 files it had | Bytes typed by layouts that hold | Tokens | Tool calls | Seconds |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | ledger | 208 | 187 | 21 | 0 | 6,192 | 104,866 | 21 | 265 |
| 3 | ledger | 52 | 31 | 21 | 0 | 5,212 | 89,827 | 21 | 216 |
| 5 | ledger | 38 | 20 | 18 | 0 | 4,628 | 105,044 | 23 | 282 |
| 2 | control | 152 | 130 | 22 | 0 | 6,228 | 106,197 | 20 | 293 |
| 4 | control | 40 | 18 | 22 | 0 | 4,568 | 100,695 | 16 | 232 |
| 6 | control | 59 | 39 | 20 | 0 | 5,540 | 111,033 | 24 | 290 |

| Mean of three runs | Ledger | Control |
| --- | --- | --- |
| Wrong statements | 20.0 | 21.3 |
| Statements that hold | 79 | 62 |
| Bytes typed by layouts that hold | 5,344 | 5,445 |
| Tokens the harness reports | 99,912 | 105,975 |
| New input tokens / output tokens | 80,002 / 21,226 | 85,615 / 24,187 |

"Tokens" is the harness's total for the subagent. The transcripts split
it into new input and output; each run also re-read 1.0 to 1.7 million
cached input tokens over its 17 to 25 turns. The full numbers and every
wrong statement with its counterexample are in `ledger-loop.results.json`.

## Why the ledger made no difference

- **Both arms checked their statements on all 40 files before
  reporting.** No statement of either arm was wrong on a file its agent
  had. The control agents wrote a checker script of their own; the
  ledger agents did too, and then filed what had passed.
- **So the ledger was a stamp.** 211, 53 and 38 proposals, all held at
  the first attempt: 0 refuted and 0 rejected in 302. Nothing came back
  that the agent did not know.
- **Every wrong statement was wrong only on files nobody had.** Of the
  124 wrong statements, 70 are contradicted by one or two of the 6,554
  held-out files: two files are of a third kind of shader program (the
  first field is 5, where the working set shows only 0 and 1), and one
  file has zero where every other has `0x7f75`. A sample of 40 contains
  one of two such files about once in 80 draws. Another 48 are
  contradicted by 3 to 99 files and 6 by 100 or more.
- **The arms made the same mistakes.** Those two rare cases alone
  account for 9 to 15 wrong statements a run, in both arms.

The ledger checks a claim on the evidence it holds. Here it held exactly
what the agent had already read with a script, so it could not know more
than the agent. In the earlier trials the agent guessed from one capture
and the ledger answered from all of them; that gap is what the loop
feeds on, and this design closed it.

## Metrics

1. **Wrong claims caught: 0.** None of the 302 proposals was wrong on the
   evidence the ledger held, so there was nothing for it to catch.
2. **Attempts per accepted claim: 302 proposals for 302 accepted claims
   (1.0)**, about 310 tokens of tool traffic per claim, most of it the
   40 evidence ids each proposal has to list.
3. **Claims that passed and later failed: 60 of the 298 reported by the
   ledger arm (20%)** held on the 40 files and were refuted by the
   held-out ones.

## Findings

- **"Held on 40" was wrong one time in five.** That is the measured
  answer, for this target, to how much "held on N" is worth: 60 of 298
  claims that held on 40 files do not hold on 6,554.
- **The ledger needs evidence the agent has not read.** An agent with a
  shell replays its own guesses on whatever it can loop over. The loop
  can only add something when the ledger holds more captures than the
  agent looks at, or captures taken later. That arm was not run.
- **Open: no claim kind can place a field at a computed offset.** All six
  agents said, unprompted, that everything after the table of uniform
  records (the names, the attribute table, the program text) starts at
  an offset that depends on a count, and left it out. The five snapshot
  kinds only take fixed offsets. A format description language places
  such fields; this is the case for the Kaitai Struct work.
- **Open: a verdict lists every piece of evidence it read.** One verdict
  on the 6,554 held-out files is a 430 KB event. Scoring 549 claims grew
  that ledger's log to 227 MB, and the server replays the log each time
  it starts: scoring took 10.5 minutes, against 0.14 seconds a claim
  when the log was empty.
- **Open: a snapshot claim cannot say "all snapshots of this type".**
  Web claims have `all_captures`; a snapshot claim must list its
  evidence ids, 40 of them in every proposal here.
- **A count of statements can be gamed.** Told that one contradicted
  statement costs one statement, run 1 cut the constant regions into
  64-byte pieces and reported 208 statements; run 2 did the same in
  256-byte pieces. The number of wrong statements barely moved (18 to
  22), the share went from 10% to 55%. Counts of wrong statements and
  bytes covered compare runs better than shares do.

## Limits

- **Three runs an arm, one target, one model.** The spread inside an arm
  (89,827 to 105,044 tokens; 18 to 21 wrong) is as large as the gap
  between the arms.
- **The control arm reported in the ledger's claim language.** That made
  the scoring mechanical and the same for both arms, and it means the
  trial measures the checking loop only, not what typed claims are worth
  against free prose.
- **Held-out files can refute a statement and never prove one.**
  "Holds" means 6,594 files did not contradict it.
- **The task rewarded what the ledger does not check.** Coverage was
  rewarded, and the claim language cannot reach the variable part of
  the format, so every agent described the same fixed 6,388 bytes.
- **The agents were told to stay in their directory; that was checked
  only by searching their tool calls** for paths outside it and for web
  tools. None were found.
- **The tool-call cap of 150 never bound.** Every run stopped by itself
  after 16 to 24 calls.
