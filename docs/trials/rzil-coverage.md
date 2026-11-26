# RzIL coverage and function recovery

26 November 2026. Two measurements on four programs: how much of a
program Rizin 0.9.1 recovers as functions, and how much of what it
recovers RzIL can give a meaning to. `rzil-coverage.py` makes them and
`rzil-coverage.txt` is its output. The programs were read, never run.

## The programs

| Program | Format | Instructions in recovered functions |
| --- | --- | --- |
| `UnityCrashHandler64.exe`, the target of trial 6 | Windows, x86-64 | 152,814 |
| `ls` | Linux, x86-64 | 24,578 |
| `librz_core.so`, Rizin's own core library | Linux, x86-64 | 378,886 |
| `ninja`, a build tool | Linux, AArch64 | 44,190 |

Only `librz_core.so` has names for some of its functions, the ones
it exports.

## Function recovery

A compiler writes an unwind table into the program: the exception table
of a Windows program, `.eh_frame` of a Linux one. It lists code ranges
and does not depend on Rizin. The measure is the share of those ranges
whose first instruction lies in a function Rizin recovered.

| Program | `aaa` | `aaa; aap` | `hasnext`, `aaa` | `hasnext`, `aaa; aap` |
| --- | --- | --- | --- | --- |
| Crash handler | 74.5% | 74.5% | 88.5% | 88.5% |
| `ls` | 55.9% | 100% | 89.2% | 100% |
| `librz_core.so` | 40.9% | 99.9% | 81.4% | 100% |
| `ninja` | 93.4% | 93.4% | 97.8% | 97.8% |

`aaa` is Rizin's standard analysis and what the ledger ran in trial 6.
`aap` scans for the instructions a function usually starts with.
`analysis.hasnext` makes Rizin look for another function right after
the end of each one it finds. `aaaa` was tried too and recovered
exactly what `aaa; aap` does.

**The ledger now runs the last column.** It is the best or equal best
on every program.

### Is the extra code real?

A setting that finds more could also invent functions, and a claim that
holds on an invented function is worse than a function that is missing.
Two checks:

- **Calls agree with a second disassembler.** For each function that is
  one byte range, the calls Rizin lists were compared with the call
  instructions objdump (llvm-objdump for AArch64) prints in the same
  bytes. A jump Rizin lists as a call was accepted: that is a tail
  call. With the new setting they agree in 99.90%, 100%, 99.85% and
  99.74% of the functions compared, no worse than with `aaa`.
- **Some of the extra functions are not functions.** On the crash
  handler 734 of the instructions in "functions" are `int3`, the
  padding between functions. On `ninja` 177 are `invalid` or `udf`:
  data that was read as code. `hasnext` is what brings both in.

So the calls can be trusted as far as this check reaches, and the list
of functions now contains some padding and some data.

## RzIL lifting

For every instruction in a recovered function, whether RzIL gives it a
meaning. Measured with the setting the ledger now runs.

| Program | Instructions with a usable meaning | Functions lifted in full |
| --- | --- | --- |
| Crash handler | 97.05% | 55.1% |
| `ls` | 95.87% | 59.8% |
| `librz_core.so` | 98.10% | 80.5% |
| `ninja` (AArch64) | 98.20% | 80.2% |

The second column is the one that matters for a proof: a statement
about a function can only be proved over RzIL if every instruction in
the function is lifted. One in five to almost one in two functions has
at least one instruction that is not.

- **x86-64 fails silently.** An instruction the lifter has no meaning
  for comes back as `empty`, exactly like `endbr64`, which really does
  nothing. Checked on single instructions: `cdqe`, `setz al`,
  `bswap rax`, `movaps xmm0, xmm1` and `int3` are all `empty`. Read
  naively, RzIL says a sign extension does nothing. What is missing:
  the SSE moves and arithmetic, the whole `setcc` family, `bt` and
  `bts`, `bswap`, `cdqe`, and the traps `int3` and `ud2`.
- **AArch64 fails honestly.** An instruction that is not lifted has no
  RzIL at all. What is missing: floating point and vector instructions
  (`fmov`, `scvtf`, `fdiv`, `movi`, `dup`) and some forms of `str`,
  `ldr`, `stp` and `ldp`.

## What follows for the ledger

- **Anything built on RzIL must treat `empty` as "not lifted"** unless
  the instruction is on a short list of ones that truly do nothing, and
  must refuse a function that has an unlifted instruction. The script's
  list is `nop`, `endbr64`, `endbr32`, `bti`, `hint`, `fnop`, `pause`.
- **A claim can now be about padding or data.** The functions list is
  larger and less clean. Nothing was seen to go wrong with call edges,
  but a claim kind that reads a function's body should check that the
  body decodes.
- **11.5% of the crash handler is still out of reach**, 267 code ranges
  that no setting recovered. The exception table says where they are;
  giving its entries to the analysis is the obvious next step.

## Not measured

- **A second lifter.** The roadmap asks how often RzIL disagrees with
  one. None is installed; `pypcode` would do.
- **Whether lifted instructions are lifted correctly.** "Lifted" here
  means RzIL has something to say, not that it is right.
- **Functions in more than one byte range**, in the call comparison.
  They are 3% to 4% of the functions of the crash handler and `ninja`
  and over half of those of `ls` and `librz_core.so`.
- **The unwind table is not complete either.** It lists 273 ranges for
  `ninja`, where plain `aaa` already finds 183 functions it does not
  list. Whether those are all real was not checked.
- The times in the output include printing every instruction. In the
  server the crash handler takes 3.4 seconds, up from 3.1.
