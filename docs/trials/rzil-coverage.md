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

## A second lifter

27 November 2026. `lifter-compare.py` asks RzIL and P-code (Ghidra's
lifter, through pypcode 4.1.0) about every instruction in the recovered
functions of the same four programs; `lifter-compare.txt` is its output.
One run per program; both lifters are deterministic.

The two answers are compared by their effects: which registers the
instruction writes, whether it writes memory, and whether control leaves
it. RzIL's `empty` counts as not lifted unless the instruction is on the
list of ones that do nothing. P-code that only names the instruction (a
user-defined operation) counts as not lifted too.

| Program | Instructions | Only P-code lifts | Only RzIL lifts | Neither | Both lift | Effects differ, of those both lift | The same, setting one flag aside |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Crash handler | 152,814 | 3,692 (2.42%) | 11 | 819 | 148,292 | 26,512 (17.88%) | 377 (0.25%) |
| `ls` | 24,578 | 1,016 (4.13%) | 0 | 0 | 23,562 | 3,741 (15.88%) | 115 (0.49%) |
| `librz_core.so` | 378,886 | 7,087 (1.87%) | 0 | 128 | 371,671 | 35,407 (9.53%) | 205 (0.06%) |
| `ninja` (AArch64) | 44,190 | 579 (1.31%) | 10 | 218 | 43,383 | 0 | 0 |

**How often do they disagree?** On whether an instruction has a meaning
at all, in 1.3% to 4.1% of instructions, and almost always the same way:
P-code lifts what RzIL does not. On what a lifted instruction does, never
on AArch64 and in 9.5% to 17.9% of instructions on x86-64.

- **One flag is 96.9% to 99.4% of the x86-64 differences.** RzIL sets the
  auxiliary carry flag in `add`, `sub`, `cmp`, `inc` and `dec`; P-code
  leaves that flag out of them. The processor does set it, so RzIL is
  right and P-code is silent. It matters to decimal arithmetic and to
  code that saves the flags, and to nothing else.
- **The rest is 0.06% to 0.49%, and there RzIL is wrong three ways.**
  Each was confirmed on a single instruction:
  - `neg` sets the carry flag only. The overflow, sign, zero and parity
    flags, which the processor sets, are left as they were (310
    instructions in the three programs).
  - The SSE2 `movsd xmm0, qword [mem]` is lifted as the string
    instruction of the same name: it writes `rdi` and `rsi` and never
    `xmm0` (257 instructions).
  - `rep stosb` stores once and moves `rdi`; the count in `rcx` is
    neither read nor written (24 instructions with a `rep` prefix).
- **The x87 instructions differ in bookkeeping:** P-code updates the
  floating-point instruction pointer and RzIL the status word (99
  instructions in `ls` and `librz_core.so`).
- **Whole functions.** The measure a proof needs: both lifters lift
  every instruction of the function, with the same effects.

  | Program | RzIL alone lifts in full | Both, same effects | Both, setting the flag aside |
  | --- | --- | --- | --- |
  | Crash handler | 55.1% | 7.1% | 51.8% |
  | `ls` | 59.8% | 31.2% | 59.2% |
  | `librz_core.so` | 80.5% | 32.8% | 79.9% |
  | `ninja` (AArch64) | 80.2% | 80.2% | 80.2% |

What limits this: effects are compared, not values. Two lifters that
agree a register is written can still disagree about what is written to
it; `neg` shows the kind of error that hides there, since only its flags
gave it away. That needs both meanings run on the same inputs, which is
Phase 5. One build of each lifter was used, and P-code was given one
instruction at a time.

## What follows for the ledger

- **Anything built on RzIL must treat `empty` as "not lifted"** unless
  the instruction is on a short list of ones that truly do nothing, and
  must refuse a function that has an unlifted instruction. The script's
  list is `nop`, `endbr64`, `endbr32`, `bti`, `hint`, `fnop`, `pause`.
- **A claim can now be about padding or data.** The functions list is
  larger and less clean. Nothing was seen to go wrong with call edges,
  but a claim kind that reads a function's body should check that the
  body decodes.
- **RzIL cannot be the only lifter under a proof on x86-64.** Three of
  its meanings are wrong and nothing marks them. A function's RzIL is
  usable where a second lifter agrees on every instruction; with the
  auxiliary carry flag set aside that is 52% to 80% of functions, about
  what RzIL lifts in full by itself.
- **11.5% of the crash handler is still out of reach**, 267 code ranges
  that no setting recovered. The exception table says where they are;
  giving its entries to the analysis is the obvious next step.

## Not measured

- **Whether lifted instructions compute the right values.** The second
  lifter is compared by effects only; see above.
- **Functions in more than one byte range**, in the call comparison.
  They are 3% to 4% of the functions of the crash handler and `ninja`
  and over half of those of `ls` and `librz_core.so`.
- **The unwind table is not complete either.** It lists 273 ranges for
  `ninja`, where plain `aaa` already finds 183 functions it does not
  list. Whether those are all real was not checked.
- The times in the output include printing every instruction. In the
  server the crash handler takes 3.4 seconds, up from 3.1.
