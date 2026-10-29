# Troubleshooting Guide

Common issues encountered when running Frama-C (`RTE`, `Eva`, `WP`, `E-ACSL`) and Clang LibFuzzer on real-world C codebases, and how to resolve them.

---

## 1. Frama-C Kernel Parsing & Preprocessing Errors

### Symptom: `[kernel] user error: syntax error` on GCC/Clang Intrinsics or System Headers (`_Float128`, etc.)
- **Cause:** The target C file or its `-I` flags pulled in host `/usr/include` headers containing glibc/compiler-specific extensions (`_Float128`, `__builtin_va_arg_pack`, inline assembly `__asm__`, or SIMD intrinsics) instead of Frama-C's standard library (`__fc_libc`).
- **Fix:**
  1. Never pass `-I/usr/include` or `-I/usr/local/include` in `CPPFLAGS`. `build_callgraph_dag.py` automatically strips host system include paths from `compile_commands.json` so Frama-C uses its portable `__fc_libc` headers.
  2. If the target requires third-party system headers (e.g., `<bsd/string.h>`, `<openssl/evp.h>`), pass `--target-packages "<pkg>"` (`-TargetPackages` in PowerShell) to `framac-docker` so the real `-dev` package is installed in the container image.
  3. Ensure `-machdep gcc_x86_64` (already the default in `GNUmakefile.template`, `run_eva_slice.py`, and `run_wp_function.py`) is active so GNU C extensions supported by Frama-C are enabled.
  4. Guard hardware inline assembly or unsupported compiler intrinsics with `#ifndef __FRAMAC__ ... #else ... #endif` in the `workspace/work/` shadow tree.

### Symptom: `[kernel:annot-error] unbound logic variable alse` or `orall`
- **Cause:** An ACSL annotation containing `\false`, `\forall`, `\at`, or `\base_addr` was written through an unescaped Python or shell string, turning `\f` into ASCII `0x0c` (form-feed), `\a` into `0x07`, or `\b` into `0x08`.
- **Fix:** Always use raw Python strings (`r"..."`) or file-editing tools when writing ACSL annotations. `acsl_ast.py` (`check-acsl-only`) automatically flags control characters (`\x07`, `\x08`, `\x0c`) inside ACSL comments.

---

## 2. E-ACSL + LibFuzzer Build & Runtime Issues

### Symptom: `e-acsl-gcc` Fails on `__fc_builtin.h`, `__fc_libc/stdlib.h` (`\old(endptr)`), or Unknown Legacy Flag `--rte=`
- **Cause:**
  1. `e-acsl-gcc` runs `frama-c -no-frama-c-stdlib` so its second pass can compile `instrumented.c` with host `clang` against host glibc. If a harness guards `#include "__fc_builtin.h"` only with `#ifdef __FRAMAC__`, `e-acsl-gcc` enters that block and fails because `__fc_builtin.h` is not on the host include path, and host `<math.h>`/`<stdlib.h>` expose `_Float128` prototypes on glibc >= 2.26.
  2. Frama-C 33+ replaced legacy `e-acsl-gcc.sh` long flags (`--c-flags`, `--rte=all`) with `e-acsl-gcc` short flags (`-F`, `-G`, `-E`, `-e`, `-l`), and running `-rte` across all functions without `-rte-select` instruments unused inline helpers.
- **Fix:** `harness_dual.c.template` guards `#include "__fc_builtin.h"` and `eva_main()` with `#if defined(__FRAMAC__) && !defined(__FRAMAC_EACSL__)`, and `run_eacsl_fuzz.py` / `GNUmakefile.template` automatically pass `-D__FRAMAC_EACSL__ -D_Float128=double` along with `-rte-select` and `-e-acsl-functions` scoped to the functions defined in the target slice `.c` files. Full compiler diagnostics are saved to `<out-bin>.compile.log`. If `e-acsl-gcc` still fails in `campaign` mode, `--engine auto` falls back to native `clang -fsanitize=fuzzer,address,undefined`.

### Symptom: `frama-c` (Eva / WP) Cannot Find `<bsd/string.h>`, `<json-c/json.h>`, `<netinet/ip_icmp.h>`, or `__int32_t`
- **Cause:** `frama-c` runs with `-frama-c-stdlib` (`-nostdinc`), searching only `__fc_libc` and explicit `-I` flags so host `/usr/include` does not shadow `__fc_libc`.
- **Fix:** `run_eva_slice.py`, `run_wp_function.py`, and `GNUmakefile.template` automatically append `-I/opt/framac-pipeline/templates/fc_stubs -include fc_compat_types.h`, providing bodyless ACSL-annotated prototypes for `bsd/string.h`, `json-c/json.h`, `netinet/ip_icmp.h`, and glibc `__int8_t`..`__uint64_t` typedefs while keeping external specifications `Considered valid` (`STATUS_ASSUMED`) in the ledger.

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
