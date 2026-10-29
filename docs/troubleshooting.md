# Troubleshooting Guide

Common issues encountered when running Frama-C (`RTE`, `Eva`, `WP`, `E-ACSL`) and Clang LibFuzzer on real-world C codebases, and how to resolve them.

---

## 1. Frama-C Kernel Parsing & Preprocessing Errors

### Symptom: `[kernel] user error: syntax error` on GCC/Clang Intrinsics or System Headers
- **Cause:** The target C file or its `-I` flags pulled in host `/usr/include` headers containing compiler-specific extensions (`__builtin_va_arg_pack`, inline assembly `__asm__`, or SIMD intrinsics) instead of Frama-C's standard library (`__fc_libc`).
- **Fix:**
  1. Never pass `-I/usr/include` or `-I/usr/local/include` in `CPPFLAGS`. Let Frama-C use its default `__fc_libc` headers.
  2. Ensure `-machdep gcc_x86_64` (already the default in `GNUmakefile.template`, `run_eva_slice.py`, and `run_wp_function.py`) is active so GNU C extensions supported by Frama-C are enabled.
  3. Guard hardware inline assembly or unsupported compiler intrinsics with `#ifndef __FRAMAC__ ... #else ... #endif` in the `workspace/work/` shadow tree.

---

## 2. E-ACSL + LibFuzzer Build & Runtime Issues

### Symptom: Linker or Shadow Memory Conflict When Combining E-ACSL with AddressSanitizer (`-fsanitize=address`)
- **Cause:** E-ACSL embeds its own shadow-memory runtime (`rtl`) to track byte-level pointer validity (`\valid`), initialization (`\initialized`), and sub-object bounds. AddressSanitizer (`ASan`) also maps shadow memory and intercepts `malloc`/`free`. Running both in the same binary causes immediate `mmap` collisions or false aborts.
- **Fix:**
  - Compile E-ACSL fuzz binaries with `-fsanitize=fuzzer` **without** `-fsanitize=address` (as configured in `run_eacsl_fuzz.py`). E-ACSL's own runtime already detects out-of-bounds accesses, use-after-free, bad free, uninitialized reads, and sub-object overflows.

### Symptom: `e-acsl-gcc.sh` Rejects Complex Unbounded Quantifiers (`\forall integer k; ...`)
- **Cause:** E-ACSL can only compile **bounded** quantifiers where the lower and upper bounds of the quantified integer variable `k` are syntactic integer expressions (e.g., `\forall integer k; 0 <= k < len ==> ...`).
- **Fix:** Always write explicit integer lower and upper bounds in `\forall` and `\exists` predicates (`0 <= k < n`), and use the `integer` type (or `size_t` / `int`) explicitly.

---

## 3. Eva Abstract Interpretation Precision Issues

### Symptom: Eva Reports High `Unknown` (Orange) Alarm Counts (> 30%) on a Module Slice
- **Cause:** Loop widening or path merging occurred before precision could stabilize, or an external helper function had no ACSL contract (`builtins:missing-spec`).
- **Fix:**
  1. Check `workspace/eva/<mod>/eva.log` for `missing-spec` warnings. Add a contract stub to `external_stubs.h` for any unmodeled external function so Eva does not widen its return value to `[-inf, +inf]`.
  2. Increase `--slevel` (e.g., `--slevel 250` or `--slevel 500`) in `/framac-eva` so Eva tracks more separate execution paths before merging states.
  3. Add `/*@ loop pragma UNROLL 32; */` above small fixed-bound parsing loops in `workspace/work/`.

---

## 4. Deductive Verification (`WP`) Issues

### Quick Symptom-to-Fix Reference

| Symptom in `wp.log` / `run_wp_function.py` | Root Cause | Exact Fix |
| :--- | :--- | :--- |
| Every goal after a loop fails, even for untouched variables | Missing `loop assigns` (WP havocs all memory on every iteration) | Write `loop assigns` (**Step A**) before any `loop invariant` (**Step B**). |
| `loop invariant` is `Valid` for `established`, `Unknown` for `preserved` | Invariant is not inductive across `i -> i + 1` or omits modified variables | Conjoin loop counter bounds (`0 <= i <= n`) with accumulator/pointer relationship (`p == base + i`), or drill down with `--prop <name> --dump-goal`. |
| `loop invariant` fails `established` on `0 <= i <= n` | `n` can be negative on entry | Add `requires n >= 0;` (or use unsigned `size_t`). |
| `[wp] warning: Missing assigns clause` | Loop or callee lacks `assigns` (`run_wp_function.py` flags this as `unsound_proof`) | Add explicit `loop assigns ...;` and callee `assigns ...;`. |
| `[wp] warning: Memory model hypotheses for function ...` | `-wp-check-memory-model` detected raw `\separated` missing on pointer arguments | Add `requires \separated(p + (0 .. n-1), q + (0 .. m-1));` to the function contract. |
| `[rte:annot] warning: ... Through function pointer ... cannot generate ...` | Indirect call `fp(...)` without `calls` specification | Add `//@ calls f1, f2;` above the call or `//@ assert fp \in {&f1, &f2};`. |
| `Instance of 'Pre-condition ...' status: Unknown` at call site | Caller has not proven callee's `requires` | Add an intermediate `//@ assert ...;` before the call or strengthen the caller's loop invariant / `requires`. |
| `while (count--) { ... }` fails `rte:unsigned_overflow` | Post-decrement wraps `0U -> UINT_MAX` on loop exit | Use `--no-warn-unsigned` (recorded in `reduced_checks` as an assumption) or bound a non-wrapping counter. |
| Pointer cast `(uint32_t *)byte_buf` rejected by `Typed` model | Type reinterpretation across pointer types | Pass `--wp-model Typed+cast` to `run_wp_function.py`. |
| Address taken `&local_var` passed to helper | Stack variable address taken | Pass `--wp-model Typed+ref` (the default in `run_wp_function.py`). |
| `syntax error` on `terminates` or `exits` | Wrong ACSL clause order in function contract | Order clauses strictly: `requires` -> `terminates` / `decreases` -> `exits` -> `assigns` -> `ensures` -> `behavior`. |

### Symptom: Every Goal After a Loop Fails in WP, Even for Variables the Loop Never Touches
- **Cause:** Missing `loop assigns` clause on the loop! In Frama-C WP, if a loop does not have a `loop assigns` clause, WP assumes the loop body can arbitrarily modify **all memory in the program** on every iteration.
- **Fix:** Always follow `prover_brief.md`'s mandatory order: write `loop assigns` (**Step A**) before writing any `loop invariant` (**Step B**).

### Symptom: `loop invariant` Is Marked `Valid` for Establishment, But `Unknown` for Preservation
- **Cause:** The invariant is true on loop entry (`i == 0`), but not inductive—meaning knowing the invariant holds at iteration `i` is not strong enough for the SMT solver to prove it holds at `i + 1`.
- **Fix:**
  - Conjoin the relationship between the loop counter `i` and the accumulator/pointer offset (e.g., `loop invariant offset == i * sizeof(elem_t);` and `loop invariant 0 <= i <= count;`).
  - Ensure all variables modified inside the loop body have their bounds constrained in the `loop invariant`.
  - Run `run_wp_function.py --prop <clause_name> --dump-goal` and inspect `vc_goal_dumps` to see the exact unproven hypothesis in the sequent.

### Symptom: PowerShell Splits Frama-C or Docker CLI Flags Containing `.` or `=`
- **Cause:** Windows PowerShell parses unquoted arguments containing `.` or `=` (like `-wp-model=Typed+ref` or `-report-csv=out.csv`) into multiple tokens.
- **Fix:** Always invoke container commands through [`wrappers/framac-docker.ps1`](file:///C:/Users/Florian/OneDrive/Documents/Dev/frama-c/wrappers/framac-docker.ps1) and double-quote any CLI flag containing `=` or `.`.
