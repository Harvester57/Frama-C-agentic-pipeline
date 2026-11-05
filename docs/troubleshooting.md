# Troubleshooting Guide

Common issues encountered when running Frama-C (`RTE`, `Eva`, `WP`, `E-ACSL`) and Clang LibFuzzer on real-world C codebases, and how to resolve them.

If a symptom is not listed here, look it up in the upstream manuals in [`./references/README.md`](./references/README.md). Grep [`./references/INDEX.md`](./references/INDEX.md) or the manual itself, then read only the matching lines.

---

## 1. Frama-C Kernel Parsing & Preprocessing Errors

### Symptom: `[kernel] user error: syntax error` on GCC/Clang Intrinsics or System Headers (`_Float128`, etc.)
- **Cause:** The target C file or its `-I` flags pulled in host `/usr/include` headers containing glibc/compiler-specific extensions (`_Float128`, `__builtin_va_arg_pack`, inline assembly `__asm__`, or SIMD intrinsics) instead of Frama-C's standard library (`__fc_libc`).
- **Fix:**
  1. Never pass `-I/usr/include` or `-I/usr/local/include` in `CPPFLAGS`. `build_callgraph_dag.py` automatically strips host system include paths from `compile_commands.json` so Frama-C uses its portable `__fc_libc` headers.
  2. If the target requires third-party system headers (e.g., `<bsd/string.h>`, `<openssl/evp.h>`), pass `--target-packages "<pkg>"` (`-TargetPackages` in PowerShell) to `framac-docker` so the real `-dev` package is installed in the container image.
  3. Ensure `-machdep gcc_x86_64` (already the default in `run_eva_slice.py`, `run_wp_function.py`, and `run_eacsl_fuzz.py`, which every Make recipe calls) is active so GNU C extensions supported by Frama-C are enabled.
  4. Guard hardware inline assembly or unsupported compiler intrinsics with `#ifndef __FRAMAC__ ... #else ... #endif` in the `workspace/work/` shadow tree.

### Symptom: `[kernel:annot-error] unbound logic variable alse` or `orall`
- **Cause:** An ACSL annotation containing `\false`, `\forall`, `\at`, or `\base_addr` was written through an unescaped Python or shell string, turning `\f` into ASCII `0x0c` (form-feed), `\a` into `0x07`, or `\b` into `0x08`.
- **Fix:** Always use raw Python strings (`r"..."`) or file-editing tools when writing ACSL annotations. `acsl_ast.py` (`check-acsl-only`) automatically flags control characters (`\x07`, `\x08`, `\x0c`) inside ACSL comments.

---

## 2. E-ACSL + LibFuzzer Build & Runtime Issues

### Symptom: `e-acsl-gcc` Fails on `__fc_builtin.h`, `__fc_libc/stdlib.h` (`\old(endptr)`), or Unknown Legacy Flag `--rte=`
- **Cause:**
  1. `e-acsl-gcc` runs `frama-c -no-frama-c-stdlib` so its second pass can compile `instrumented.c` with host `clang` against host glibc. If a harness guards `#include "__fc_builtin.h"` only with `#ifdef __FRAMAC__`, `e-acsl-gcc` enters that block and fails because `__fc_builtin.h` is not on the host include path, and host `<math.h>`/`<stdlib.h>` expose `_Float128` prototypes on glibc >= 2.26.
  2. Frama-C 33+ installs `e-acsl-gcc` (no `.sh`). Its `-h` lists only the short flags (`-F`, `-G`, `-E`, `-e`, `-l`, `-n`, `-C`, `-M`), though long options such as `--rte=all` are still accepted. Running `-rte` across all functions without `-rte-select` instruments unused inline helpers.
- **Fix:** `harness_dual.c.template` guards `#include "__fc_builtin.h"` and `eva_main()` with `#if defined(__FRAMAC__) && !defined(__FRAMAC_EACSL__)`, and `run_eacsl_fuzz.py` automatically passes `-D__FRAMAC_EACSL__ -D_Float128=double` along with `-rte-select` and `-e-acsl-functions` scoped to the functions defined in the target slice `.c` files. Full compiler diagnostics are saved to `<out-bin>.compile.log`. If `e-acsl-gcc` still fails in `campaign` mode, `--engine auto` falls back to native `clang -fsanitize=fuzzer,address,undefined`.

### Symptom: `frama-c` (Eva / WP) Cannot Find `<bsd/string.h>`, `<json-c/json.h>`, `<netinet/ip_icmp.h>`, or `__int32_t`
- **Cause:** `frama-c` runs with `-frama-c-stdlib` (`-nostdinc`), searching only `__fc_libc` and explicit `-I` flags so host `/usr/include` does not shadow `__fc_libc`.
- **Fix:** `run_eva_slice.py` and `run_wp_function.py` automatically append `-I/opt/framac-pipeline/templates/fc_stubs -include fc_compat_types.h`, providing bodyless ACSL-annotated prototypes for `bsd/string.h`, `json-c/json.h`, `netinet/ip_icmp.h`, and glibc `__int8_t`..`__uint64_t` typedefs while keeping external specifications `Considered valid` (`STATUS_ASSUMED`) in the ledger.

### Symptom: Selftest `compiled: false` With `undefined reference to 'main'` / `fail to compile/link un-instrumented code`
- **Cause:** by default `e-acsl-gcc` instruments **and** links the original sources. A libFuzzer harness has no `main()`, so that link fails and `e-acsl-gcc` exits 1, even though the instrumented file was written.
- **Fix:** `run_eacsl_fuzz.py` passes `-n` (instrument only) in stage 1.

### Symptom: Every Input Crashes in `shadow_alloca` (`e_acsl_segment_tracking.c`), or Valid Stack Accesses Fail `\valid`
- **Cause:** E-ACSL initializes its runtime at the top of `main()`, and a harness has none. Without full memory tracking, its memory analysis leaves a caller's stack buffer untracked, so a callee's valid write fails `\valid`. With full tracking but no runtime initialization, the runtime segfaults on the first tracked stack block.
- **Fix:** automatic. Fuzz builds use `-e-acsl-full-mtracking` and link [`../templates/eacsl_runtime/fuzz_init.c`](../templates/eacsl_runtime/fuzz_init.c), whose `LLVMFuzzerInitialize` calls `__e_acsl_memory_init` and `__e_acsl_globals_init`. Do not define `LLVMFuzzerInitialize` in a harness (`reason: eacsl_init_hook_conflict`). The selftest's `benign_input_clean` check catches either regression.

### Symptom: E-ACSL Reports `rte: initialization` on Benign Inputs
- **Cause:** E-ACSL builds pass `-rte-initialized @all`, so every read must be of initialized memory, and memory written outside instrumented code is never marked initialized. The usual culprits:
  1. target code reads libFuzzer's `data` directly instead of the harness copy `fuzz_buf`, for example in a hand-written or `custom` harness;
  2. an external library behind `fc_stubs` fills a buffer;
  3. `read`/`recv` fill a buffer.
- **Fix:**
  - Pass `fuzz_buf` (generated harnesses do), or copy the input into the harness's own buffer with `memcpy`, which E-ACSL marks initialized.
  - If a library-filled buffer is the cause, initialize it before the call (`= {0}` / `memset`) or rerun with `--no-rte-initialized`. That opt-out is recorded in `reduced_checks`, and Eva still reports uninitialized reads statically.
  - Per-function exclusion (`-rte-initialized=@all,-f`) only works for non-`static` functions in Frama-C 33.
  - The crash verifier classifies such reports as `harness_induced`.

### Symptom: Every Input Fails `\initialized(&__retres)` in a `__gen_e_acsl_<fn>` Wrapper
- **Cause:** an E-ACSL gap in Frama-C 33. The wrapper that checks a function contract registers its `__retres` with the runtime but never marks it initialized after `__retres = <fn>(...)`. Under `-rte-initialized`, any `ensures` that reads `\result` then fails on the first input.
- **Fix:** automatic. Between instrumentation and compilation, `run_eacsl_fuzz.py` inserts the missing `__e_acsl_initialize` after each such assignment; the build report counts them in `compile.wrapper_result_inits`. This is sound, because the callee's own return value is still checked for uninitialized reads. A report of this failure means the build ran without that step: rebuild it, and never weaken a contract to get past it.

### Symptom: `implicit cast: cannot cast from __e_acsl_mpz_t to size_t` (E-ACSL silently in GMP-only mode)
- **Cause:** `e-acsl-gcc` splits the values of `-e`/`-E`/`-F`/`-l` on spaces and re-parses the tokens. A standalone `-g` inside `-e` is read as its own `--gmp` option (`-e-acsl-gmp-only`).
- **Fix:** `run_eacsl_fuzz.py` normalizes every passthrough value: `-g` becomes `-gline-tables-only`, `-I dir` becomes `-Idir`, and other standalone single-letter tokens or paths with spaces are refused (`reason: eacsl_argv_unsafe`). `run_eacsl_fuzz.py selftest` checks that the compile log never contains `-e-acsl-gmp-only`.

### Symptom: Campaign Reports `engine_used: eacsl` but E-ACSL Never Fires, or the Guardrail Always Passes
- **Cause:** `e-acsl-gcc -O <out>` writes the instrumented executable to `<out>.e-acsl`; `<out>` is a plain build.
- **Fix:** the script selects `<out>.e-acsl` and refuses any binary without E-ACSL instrumentation (`reason: eacsl_binary_not_instrumented`). The guardrail refuses uninstrumented binaries (`guardrail_error`) instead of reporting `passed_dynamic_oracle`.

### Symptom: `redefinition of 'timeval'` / `'timespec'` or Conflicting `fd_set` Types When Compiling the Instrumented File
- **Cause:** the instrumented file printed by Frama-C is self-contained (it has no `#include` lines and already contains every typedef). Force-including headers that pull in host system headers into its compile duplicates those typedefs.
- **Fix:** `run_eacsl_fuzz.py` builds in two stages. All preprocessor flags (`-I`, `-D`, `-include`) go to instrumentation (`-E`) only; the instrumented file is compiled with codegen flags only (`e-acsl-gcc -C -e ...`). `fc_compat_types.h` is empty whenever `__FRAMAC__` is undefined. Boundary stub headers need no E-ACSL-specific branches.

### Symptom: `syntax error` on `__int32_t`, `u_short` (E-ACSL Host-Header Mode)
- **Cause:** E-ACSL runs Frama-C with `-no-frama-c-stdlib`, so the glibc-internal and BSD aliases must come from host headers.
- **Fix:** in host-header mode `fc_compat_types.h` includes glibc `<sys/types.h>`, so the aliases are identical to glibc's by construction. Do not hand-write `__intN_t` typedefs: `__int64_t` is `long` on LP64 and `long long` on ILP32.

### Symptom: `undefined reference to 'open_fallback_N'` at Link Time
- **Cause:** in host-header mode, the Variadic translation emits `<fn>_fallback_<N>` for variadic calls without a libc specification (`open`, `fcntl`, `ioctl`, ...), and the E-ACSL RTL does not define them.
- **Fix:** automatic. The script generates `<out-bin>_fallbacks/eacsl_fallbacks.c`, which forwards to the real function (or fails with `ENOSYS` when the signature or header is unknown, recorded as `mode: enosys`), compiles it to a link-only object, and retries the link once. Never add these definitions to the instrumented sources: each definition shifts the fallback numbering. `--no-variadic-translation` passes `-variadic-no-translation` to Frama-C instead.

### Symptom: `call to undeclared function 'X'` or `invalid application of 'alignof' to an incomplete type`
- **Cause:** a [`../templates/fc_stubs/`](../templates/fc_stubs/) header lacks a prototype the target calls, or declares an opaque handle (`struct json_object`) as incomplete. E-ACSL emits `alignof` on pointed-to types.
- **Fix:** add the prototype and complete the handle with a single dummy member (see [`../templates/fc_stubs/README.md`](../templates/fc_stubs/README.md)). Tool JSONs list missing prototypes under `undeclared_functions`. For Eva/WP this is a soundness issue: Frama-C invents `int X()`.

### Symptom: Instrumentation Aborts With `no function 'X'`
- **Cause:** `-rte-select` / `-e-acsl-functions` named a function that is absent from the parsed AST (disabled by `#if`, or in a file that failed to parse).
- **Fix:** function discovery runs on preprocessed sources. Names Frama-C still rejects are dropped once and listed in `rte_select_dropped`.

### Symptom: E-ACSL Crash With `failure: null` or a Location Inside the E-ACSL Runtime (`unsafe_initialize`)
- **Cause:** heap corruption made the E-ACSL RTL crash before it printed the failing assertion.
- **Fix:** automatic. The crash input is replayed on a sanitizer build of the same slice; `attribution` and `failure_source: sanitizer_replay` give the precise file:line. The crash is still classified from the E-ACSL run.

### Symptom: Why Not `-L` / Frama-C's libc for E-ACSL?
- E-ACSL aborts on Frama-C libc specifications (`unbounded ranges are not part of E-ACSL`, `share/libc/string.h`). Host-header mode is the only supported E-ACSL mode.

### Symptom: Linker or Shadow Memory Conflict When Combining E-ACSL with AddressSanitizer (`-fsanitize=address`)
- **Cause:** E-ACSL embeds its own shadow-memory runtime (`rtl`) to track byte-level pointer validity (`\valid`), initialization (`\initialized`), and sub-object bounds. AddressSanitizer (`ASan`) also maps shadow memory and intercepts `malloc`/`free`. Running both in the same binary causes immediate `mmap` collisions or false aborts.
- **Fix:**
  - Compile E-ACSL fuzz binaries with `-fsanitize=fuzzer` **without** `-fsanitize=address` (as configured in `run_eacsl_fuzz.py`). E-ACSL's own runtime already detects out-of-bounds accesses, use-after-free, bad free, uninitialized reads, and sub-object overflows.

### Symptom: `e-acsl-gcc` Rejects Complex Unbounded Quantifiers (`\forall integer k; ...`)
- **Cause:** E-ACSL can only compile **bounded** quantifiers where the lower and upper bounds of the quantified integer variable `k` are syntactic integer expressions (e.g., `\forall integer k; 0 <= k < len ==> ...`).
- **Fix:** Always write explicit integer lower and upper bounds in `\forall` and `\exists` predicates (`0 <= k < n`), and use the `integer` type (or `size_t` / `int`) explicitly.

### Symptom: Wrapper Exits With Code 2: `-NoInnerSandbox` / `--no-inner-sandbox` (or `-AllowDegradedSandbox` / `--allow-degraded-sandbox`) "is no longer supported"
- **Cause:** The bubblewrap layer was removed. The hardened container, with Docker's default seccomp and AppArmor profiles, is the only isolation boundary, and target-controlled binaries run under [`../scripts/sandbox_exec.py`](../scripts/sandbox_exec.py) (rlimits, env allowlist, timeout). The legacy flags fail hard rather than being silently ignored.
- **Fix:** Remove the flag from the command line or script. No replacement flag is needed.

### Symptom: LeakSanitizer Reports `LeakSanitizer has encountered a fatal error` or `LeakSanitizer does not work under ptrace`
- **Cause:** LeakSanitizer (enabled by default with `-fsanitize=address` in the native LibFuzzer fallback) uses `ptrace` to stop threads while scanning. Docker's default seccomp profile allows `ptrace` on kernels >= 4.8; older hosts block it.
- **Fix:** Do not relax seccomp. Set `ASAN_OPTIONS=detect_leaks=0` (or pass LibFuzzer `-detect_leaks=0`) for the campaign and record in the run notes / agent result that leak detection was disabled, so missing leak coverage is visible.

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
| `loop invariant` is `Valid` for `established`, `Unknown` for `preserved` | Invariant is not inductive across `i -> i + 1` or omits modified variables | Conjoin loop counter bounds (`0 <= i <= n`) with accumulator/pointer relationship (`offset == i * sizeof(elem_t)`), constrain all variables modified in the loop body, or drill down with `--prop <clause_name> --dump-goal` (`vc_goal_dumps`). |
| `loop invariant` fails `established` on `0 <= i <= n` | `n` can be negative on entry | Add `requires n >= 0;` (or use unsigned `size_t`). |
| `[wp] warning: Missing assigns clause` | Loop or callee lacks `assigns` (`run_wp_function.py` flags this as `unsound_proof`) | Add explicit `loop assigns ...;` and callee `assigns ...;`. |
| `[wp] warning: Memory model hypotheses for function ...` | `-wp-check-memory-model` detected raw `\separated` missing on pointer arguments | Add `requires \separated(p + (0 .. n-1), q + (0 .. m-1));` to the function contract. |
| `[rte:annot] warning: ... Through function pointer ... cannot generate ...` | Indirect call `fp(...)` without `calls` specification | Add `//@ calls f1, f2;` above the call or `//@ assert fp \in {&f1, &f2};`. |
| `Instance of 'Pre-condition ...' status: Unknown` at call site | Caller has not proven callee's `requires` | Add an intermediate `//@ assert ...;` before the call or strengthen the caller's loop invariant / `requires`. |
| `while (count--) { ... }` fails `rte:unsigned_overflow` | Post-decrement wraps `0U -> UINT_MAX` on loop exit | Use `--no-warn-unsigned --wrap-lines <lines>` (the declared lines are recorded in `reduced_checks` as an assumption; any other unsigned overflow goal not fully proved leaves the function unproven) or bound a non-wrapping counter. |
| Pointer cast `(uint32_t *)byte_buf` rejected by `Typed` model | Type reinterpretation across pointer types | Pass `--wp-model Typed+cast` to `run_wp_function.py`. |
| Address taken `&local_var` passed to helper | Stack variable address taken | Pass `--wp-model Typed+ref` (the default in `run_wp_function.py`). |
| `syntax error` on `terminates` or `exits` | Wrong ACSL clause order in function contract | Order clauses strictly: `requires` -> `terminates` / `decreases` -> `exits` -> `assigns` -> `ensures` -> `behavior`. |

### Symptom: PowerShell Splits Frama-C or Docker CLI Flags Containing `.` or `=`
- **Cause:** Windows PowerShell parses unquoted arguments containing `.` or `=` (like `-wp-model=Typed+ref` or `-report-csv=out.csv`) into multiple tokens.
- **Fix:** Always invoke container commands through [`../wrappers/framac-docker.ps1`](../wrappers/framac-docker.ps1) and double-quote any CLI flag containing `=` or `.`.

---

## Resources, Caches and Scheduling

The full guide is [`./resources-and-caching.md`](./resources-and-caching.md) (Section 9 lists symptoms). The most common ones:

- **A command prints "queue position N" and waits:** the measured pool is busy. `python3 scripts/resources.py status` (on the host) lists the leases. Leases of killed wrappers are released once their containers exit (`resources.py gc`).
- **A WP report has `"status": "analysis_error"`:** Frama-C was killed or timed out (`reason`: `oom_killed`, `timeout`, `crashed`). Nothing was proven or refuted. The recorded peak memory makes the next lease larger, and the scheduler retries once before marking the units `blocked`.
- **Suspected stale cache result:** re-run with `FRAMAC_CACHE=off` and compare, then `python3 /opt/framac-pipeline/scripts/cache.py clear`.
- **The shared cross-run store stays empty:** only the exact allowlisted commands (`python3 /opt/framac-pipeline/scripts/pipeline_make.py run build|eva|wp-sweep|ingest`, with or without `$S/...`) may write it. Unrecognized commands, extra un-allowlisted options, or `FRAMAC_CACHE_RW=off` keep the store read-only (`FRAMAC_CACHE_MODE=ro` inside the container).
- **An ad-hoc command is OOM-killed at 1 GiB:** commands the broker does not recognise run as `light` (1 CPU, 1 GiB). Pass `-Class` / `--class` (for example `build` or `phase-dynamic`).
- **`RunLockTimeout`:** another container held the run's `ledger` or `merge` lock for longer than `FRAMAC_LOCK_TIMEOUT`. A holder whose heartbeat stopped (`FRAMAC_LOCK_STALE`, default 120 s) is broken automatically, and an interrupted merge is rolled back from `state/merge-journal.json` by the next merge.
- **Need the previous static behavior:** `FRAMAC_BROKER=off` (`-NoBroker`) for container sizing, `FRAMAC_SCHEDULER=waves` for Phase 3 dispatch.
