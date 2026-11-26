# Trial 6: a binary

26 November 2026. The first trial on a program instead of its data or
its traffic. The binary was read from disk and never run.

## Setup

- **Target:** `UnityCrashHandler64.exe`, the crash reporter a Unity game
  ships with: a 1.6 MB Windows program for x86-64, with no symbols.
- **Export:** a shell script ran Rizin 0.9.1 with its `aaa` analysis
  and wrote one JSON document. It took 4 seconds and produced 3.2 MB.
  Two runs give the same bytes. Since this trial the server runs Rizin
  itself: `add_evidence kind=binary_facts` takes the program's path,
  and the same program takes 3 seconds.
- **Evidence:** the import cuts the export down to
  what a claim can be checked on: 1,461 functions, 5,089 direct calls
  and 197 imported symbols that something calls, in 143 KB.
- **Agent, ledger:** as before. Claude filed every claim through the
  real `ledger-mcp` binary. The session is in
  `crash-handler.session.jsonl`.
- **Claim kind:** `call_edge`, new with this trial: one function calls
  another directly.

Each guess was made from the program's messages alone: which function
mentions "Failed to upload" and which mentions "writing minidump". The
calls were not read first.

## What held

| Claim | Held on |
| --- | --- |
| The upload function calls `HttpOpenRequestA` | 1 export |
| It calls `HttpSendRequestA` | 1 |
| It calls `InternetOpenA` | 1 |
| It calls `InternetCloseHandle` | 1 |
| The same, with the function named by its address | 1 |
| The crash handler calls `CreateFileW` | 1 |
| It calls `TerminateProcess` | 1 |
| It calls `GetProcAddress` | 1 |

## What was caught

- **"The crash handler calls `MiniDumpWriteDump`."** Refuted: the
  program does not import it. The handler looks it up by name when it
  runs and calls it through a pointer, which is what the
  `GetProcAddress` claim then showed.
- **"The crash handler calls the upload function."** Refuted, with the
  handler's 99 call targets listed. The upload is reached some other
  way.
- **"The entry point calls the crash handler."** Refuted: the entry
  point calls the C runtime's start-up code.

## What was turned away

Two claims were refused and left unchecked, because the export says
nothing about their caller:

- A caller whose name had a typing error.
- A function Rizin did not find. See the first finding.

## Checking the tool

Every verdict above is only as good as Rizin's analysis, so the export
was compared with two other readings of the same file.

- **Calls agree with objdump.** For 1,383 of the 1,386 functions that
  occupy one byte range, Rizin's direct calls are exactly the `call`
  instructions objdump prints there. The three that differ were not
  explained; the one looked at has blocks outside its range, so the
  comparison does not fit it.
- **A quarter of the functions are missing.** The file's own exception
  table lists 2,325 code ranges. 637 of them (27%) lie in no function
  Rizin recovered.
- **Some calls cannot be seen.** 266 call instructions in 104 recovered
  functions go through a register or a pointer in memory. No call-edge
  claim can speak about them.

## Metrics

1. **Wrong claims caught: 3 of 3 refuted.** A fourth, the typing error,
   was refused instead of refuted.
2. **Attempts per accepted claim: 13 proposals for 8 accepted claims
   (1.63)**, about 270 tokens of tool traffic per accepted claim.
3. **Claims that passed and later failed:** none staged; there is one
   build.

## Findings

- **Fixed: a function the tool missed refuted a true claim.** objdump
  shows the function at `0x1400066c0` calling `CloseHandle`. Rizin did
  not recover that function, and the first version of the checker
  answered "refuted: not in the recovered code". A refutation is
  permanent, so a gap in the tool would have closed a true finding for
  good. A caller the export does not contain is now refused as evidence
  that does not apply, and the claim stays unchecked.
- **Fixed: a tail call was not a call.** In Rizin's own `main`, the
  call to `rz_main_rizin` is compiled as a jump, and "main calls
  rz_main_rizin" was refuted. A jump to another function or to an
  import now counts as a call. That added 99 edges to this export.
- **Open: a claim can only be about what the tool found.** With 27% of
  the code ranges unrecovered, a quarter of the program is out of reach.
  The exception table is a second, independent list of where functions
  start; feeding it to the analysis should close most of the gap. A
  wider analysis has since brought the 27% down to 11.5%
  (`rzil-coverage.md`).
- **Open: "held on 1" counts exports, not observations.** One tool read
  one file once. A second tool reading the same file would make the
  number mean something; objdump was used for that by hand here.
- **Open: calls through pointers.** The most interesting call in this
  program, the one that writes the crash dump, is one of them.
- **Open: the names will not survive a rebuild.** Without symbols Rizin
  names a function after its address (`fcn.140009c40`), so a claim by
  name is a claim by address. A rerun on a new build has nothing to
  match on yet, and the rerun does not read binary facts.
- **Open: the claim's binary name is not tied to the evidence.** The
  facts carry the file's SHA-256; the claim carries only a name the
  agent chose, and any export can be cited under it.
- **Not tested:** a claim cited on two exports at once, and facts over
  the 16 MiB evidence limit. This program's facts are 143 KB.
