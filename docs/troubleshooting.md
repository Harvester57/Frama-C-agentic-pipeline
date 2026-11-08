# Troubleshooting Guide

Common issues encountered when running Frama-C (`RTE`, `Eva`, `WP`, `E-ACSL`) and Clang LibFuzzer on real-world C codebases, and how to resolve them.

If a symptom is not listed here, look it up in the upstream manuals in [`./references/README.md`](./references/README.md). Grep [`./references/INDEX.md`](./references/INDEX.md) or the manual itself, then read only the matching lines.

---

## 0. Frama-C 34 (Selenium) Upgrade Notes

Behavior changes since Frama-C 33 that the pipeline already accounts for:

- **Empty named behaviors are forbidden.** `behavior b: ;` in a function or statement contract is now a fatal `[kernel:annot-error] ... unexpected token ';'` (verified on the dev image). `acsl_ast.py` (`verify_acsl_only` / `find_empty_named_behaviors`) rejects them mechanically before splicing, and `run_wp_function.py` maps the kernel error to a repair hint.
- **ACSL clause order relaxed.** ACSL extensions may now precede `requires`, and `terminates`/`decreases` may sit anywhere between `requires` and `behavior` (verified: `assigns \nothing; terminates x > 0;` parses). The `exits`/`assigns`/`ensures` order is still enforced. The prover brief's recommended order remains valid.
- **Array-to-pointer decay removed in comparisons.** The kernel no longer implicitly converts an array to a pointer in `==`/`!=`/`<`/... comparisons, so array operands keep their array type. `kernel_ast_dump.ml` now matches both pointer and array operands when setting the `pointer_compare` feature.
- **New unsequenced-effect warnings (UB CC.35, upstream #@1219 fixed).** Local definitions with unsequenced side effects (e.g. `int x = i++ + i;`) now produce a `[kernel]` warning. Warnings do not change `-report-csv` statuses; no parser change needed.
- **Fine-grained `-rte-initialized` configuration fixed.** The option-hook bug that blocked per-function exclusion for `static` functions is fixed: `-rte-initialized=@all,-s` now emits zero initialization assertions for a `static` function `s` (verified with `-print` on the dev image). Prefer per-function exclusion over a global `--no-rte-initialized` (which is recorded in `reduced_checks`).
- **GCC machine modes partially supported.** `__attribute__((mode(<MODE>)))` is now converted to integer types (partial support), so targets using machine modes parse instead of failing with a syntax error.
- **`FRAMAC_TESTING` env var.** Frama-C 34+ exposes `FRAMAC_TESTING` (`Cmdline.inside_tests`) to mark test executions and guard extra verifications. Set it only for the repo's own test invocations of `frama-c`, never for production pipeline runs.
- **Base image is now 35.0~~dev (Bromine).** The pinned `framac/frama-c:dev` digest in the `Dockerfile` reports `35.0~~dev (Bromine)`. As of the master archive used for the upstream mining (2026-11-06), the Changelog's `<next-release>` section is still empty, so no 34→35 behavior changes need porting yet — but re-check `Changelog`/`Changelog_detailed.md` in the master archive on every base-image bump and port any `-`/`!` entries here. Upstream reference snippets mined from that archive live in [`./upstream/sources/`](./upstream/sources/README.md).

---

## 1. Phase 0: Build Capture, Frama-C Model & Gates

### Symptom: `"status": "needs_build_recipe"` (Exit Code 3 From `build_capture.py run`)
- **Cause:** the target's build failed, built no C file, or has no recipe. Phase 0 has no inventory without a build, so it stops here. The checkpoint keeps the same status until a capture succeeds.
- **Fix:**
  1. Read `diagnostics` in `workspace/reports/build_capture.json`: `first_error` with its context, `missing_headers`, `candidate_packages` (a heuristic from headers, pkg-config modules, CMake packages and commands) and `packages_not_installed`.
  2. Ask the user for a corrected command, packages or flags. Never record a recipe the user has not given or confirmed.
  3. Record it with `run_metadata.py set-build ... --package <pkg>` and rerun the capture with `-BuildImage -Scratch -TargetPackages "<pkgs>"` (`--build-image --scratch --target-packages`). A success clears the status.
- **Without a recipe at all:** `build_capture.py propose` prints one guessed from the build files, as a starting point for the user.

### Symptom: The Build Capture Times Out (1800 s) on a Build That Works by Hand
- **Cause:** a parallel build under `bear` can sit idle until the capture's timeout. A failed parallel build is retried once with one job, but a timeout is not: it ends as `needs_build_recipe`.
- **Fix:** rerun the capture through the broker (no `-NoBroker`), which sizes the build's jobs from its lease, or put `-j1` in the recipe's command. A build that is not parallel-safe (x509-parser's Makefile) gets the serial retry automatically.

### Symptom: A Unit's `parse.status` Is `gcc_fallback` in `phase0_model.json`
- **Cause:** Frama-C could not parse the unit with its build flags. Its functions and edges come from GCC's `-fcallgraph-info` instead, without loops, complexity, signatures or indirect-call candidates. `parse.error` holds Frama-C's first error, and the ledger flags the unit's functions (`bookkeeping.callgraph_fallback`).
- **Fix:** read `parse.error` and the log under `workspace/reports/phase0_model/`. The usual causes are the ones in Section 2 (host headers, compiler extensions); fix the cause, then rerun `phase0_model.py run`. Eva and WP will fail on that unit the same way until it parses. Fuzzing still works.

### Symptom: The Model Fails With the Dump Module (`kernel_ast.py` Compile Error)
- **Cause:** the image's Frama-C changed in a way `scripts/phase0_dump.ml` does not compile against.
- **Fix:** run `python3 /opt/framac-pipeline/scripts/phase0_model.py selftest`. The image build runs it too, so a Frama-C upgrade that breaks the dump module fails the image build first.

### Symptom: Every Unit Records `no_threat_model` (or `invalid_threat_model`)
- **Cause:** the target has no `THREAT_MODEL.md` with a fenced `framac-threat-model` JSON block (or the block does not validate against `schemas/threat_model.schema.json`).
- **Fix:** `python3 /opt/framac-pipeline/scripts/trust.py check-threat-model [PATH]` lists the errors (exit 2) or reports the missing block (exit 1). Put a corrected copy at `workspace/THREAT_MODEL.md` (it wins over the target's own), then run `trust.py run`, rebuild the DAG and rerun `security_props.py run`. Without a threat model, trust follows the default rules and only Layer 3 properties are generated.

### Symptom: The Reach Gate Fails (`harness_reach.py check` Exit 1, or `make` Stops at `reach-gate`)
- **Cause:** a harness does not reach one of its module's API entry points, a Tier 1A/1B/2 module has no harness (`no_harness`), or a harness changed after the check ran (its digest no longer matches `phase0_gates.json`).
- **Fix:** add a `--dispatch-case` per unreached entry point and rerun `check`, or record a reason with `harness_reach.py exempt` (`/framac-slice` Step 4b). A sub-module is checked only against the unit's entry points in its own scope; entry points no harness's scope holds are reported as the unit's gaps.

### Symptom: `dynamic: entry points never executed by the corpus` in `phase0_gates.json`
- **Cause:** after `coverage-<mod>`, `reach-dynamic-<mod>` found an entry point the gate holds the module to that no input executed. Fuzz and Eva of that module stop at the gate until it is fixed.
- **Fix:** read `executions: 0` in `workspace/reports/coverage/<mod>.json`. If the harness never calls the function, add a case. If it does, the corpus is stuck behind an input check: seeds, a dictionary or a larger budget may help. Or exempt the entry point with a reason. The gap stays while the harness is unchanged.

### Symptom: A Harness Misses a Build Flag (`-include config.h`, a Quoted `-D`, `-std=`)
- **Cause:** harnesses take the unit's flags from the DAG. The unit's `-include` files are kept apart (`force_includes`) and applied by `generate_harness.py`. Quoted `-D` values (`-DLOG_PATH="log.txt"`) and the build's `-std=` are not copied, because later stages split and re-join flag strings (and a C89 `-std` rejects the C99 harness).
- **Fix:** state such flags in the harness's `--cppflags` yourself.

### Symptom: A File Compiled by Several Units With Different Flags Is Analysed in One Configuration Only
- **Cause:** a source file belongs to the first unit that compiles it, with that unit's flags (qlz's four executables build `quicklz.c` with different settings).
- **Fix:** none automatic yet. To analyse another configuration, write a harness whose flags state it.

### Symptom: No Seeds, or a Harness Case Without Seeds
- **Cause:** the recipe has no test command; the tests call the API through header `static inline` functions or nested library calls, which the `-Wl,--wrap` recorders do not see; or the harness's case layout (overlapping slots, structs deeper than one `{ptr, len}` level) cannot be filled.
- **Fix:** read `workspace/reports/seed_harvest.json` and `workspace/reports/seeds/<mod>.json`. Seeds are an improvement, never a requirement: the campaign runs from its own corpus without them.

### Symptom: A Generated Header (`config.h`) Is Missing in Eva, WP or the E-ACSL Build
- **Cause:** generated headers stay in the build tree on the scratch volume. The model reads them there, but the later analyses read `workspace/work`, which holds only the target's source tree.
- **Fix:** none automatic yet. Copy the generated header into a harness include directory (`workspace/harnesses/include/`) on the sidecar's `-I` path.

---

## 2. Frama-C Kernel Parsing & Preprocessing Errors

### Symptom: `[kernel] user error: syntax error` on GCC/Clang Intrinsics or System Headers (`_Float128`, etc.)
- **Cause:** The target C file or its `-I` flags pulled in host `/usr/include` headers containing glibc/compiler-specific extensions (`_Float128`, `__builtin_va_arg_pack`, inline assembly `__asm__`, or SIMD intrinsics) instead of Frama-C's standard library (`__fc_libc`).
- **Fix:**
  1. Never pass `-I/usr/include` or `-I/usr/local/include` in harness flags. Frama-C must use its portable `__fc_libc` headers: the target's own system headers reach it from the snapshot through `-idirafter`, searched after Frama-C's libc.
  2. If the target requires third-party system headers (e.g., `<bsd/string.h>`, `<openssl/evp.h>`), add the `-dev` package to the build recipe and rerun the build capture (`--build-image --target-packages "<pkg>"`, `-BuildImage -TargetPackages` in PowerShell). The capture copies the headers and libraries to the run's snapshot (`workspace/snapshot/`), and the analysis image reads them from there (`-idirafter`, after Frama-C's libc). The analysis image itself never gets target packages. Check `snapshot.headers` in `workspace/reports/build_capture.json`.
  3. Ensure `-machdep gcc_x86_64` (already the default in `run_eva_slice.py`, `run_wp_function.py`, and `run_eacsl_fuzz.py`, which every Make recipe calls) is active so GNU C extensions supported by Frama-C are enabled.
  4. Guard hardware inline assembly or unsupported compiler intrinsics with `#ifndef __FRAMAC__ ... #else ... #endif` in the `workspace/work/` shadow tree.

### Symptom: `[kernel:annot-error] unbound logic variable alse` or `orall`
- **Cause:** An ACSL annotation containing `\false`, `\forall`, `\at`, or `\base_addr` was written through an unescaped Python or shell string, turning `\f` into ASCII `0x0c` (form-feed), `\a` into `0x07`, or `\b` into `0x08`.
- **Fix:** Always use raw Python strings (`r"..."`) or file-editing tools when writing ACSL annotations. `acsl_ast.py` (`check-acsl-only`) automatically flags control characters (`\x07`, `\x08`, `\x0c`) inside ACSL comments.

---

## 3. E-ACSL + LibFuzzer Build & Runtime Issues

### Symptom: `e-acsl-gcc` Fails on `__fc_builtin.h`, `__fc_libc/stdlib.h` (`\old(endptr)`), or Unknown Legacy Flag `--rte=`
- **Cause:**
  1. `e-acsl-gcc` runs `frama-c -no-frama-c-stdlib` so its second pass can compile `instrumented.c` with host `clang` against host glibc. If a harness guards `#include "__fc_builtin.h"` only with `#ifdef __FRAMAC__`, `e-acsl-gcc` enters that block and fails because `__fc_builtin.h` is not on the host include path, and host `<math.h>`/`<stdlib.h>` expose `_Float128` prototypes on glibc >= 2.26.
  2. Frama-C 33+ installs `e-acsl-gcc` (no `.sh`). Its `-h` lists only the short flags (`-F`, `-G`, `-E`, `-e`, `-l`, `-n`, `-C`, `-M`), though long options such as `--rte=all` are still accepted. Running `-rte` across all functions without `-rte-select` instruments unused inline helpers.
- **Fix:** `harness_dual.c.template` guards `#include "__fc_builtin.h"` and `eva_main()` with `#if defined(__FRAMAC__) && !defined(__FRAMAC_EACSL__)`, and `run_eacsl_fuzz.py` automatically passes `-D__FRAMAC_EACSL__ -D_Float128=double -U__SIZEOF_INT128__` (host `<linux/types.h>` declares `__int128` typedefs, which Frama-C rejects, only when that macro is defined) along with `-rte-select` and `-e-acsl-functions` scoped to the functions defined in the target slice `.c` files. Full compiler diagnostics are saved to `<out-bin>.compile.log`. If `e-acsl-gcc` still fails in `campaign` mode, `--engine auto` falls back to native `clang -fsanitize=fuzzer,address,undefined`.

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
  - Per-function exclusion (`-rte-initialized=@all,-f`) works for `static` functions too since Frama-C 34 (option-hook bug fixed; in Frama-C 33 it only worked for non-`static` functions).
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
- **Target-specific compat headers** (e.g. completing OpenSSL 3 opaque handles `EVP_PKEY`, `BIGNUM`, ... for the fuzz build) must be delivered **source-side**: pass them to `generate_harness.py --compat-include <header>` so the harness `#include`s them after the module header. Never add them to cppflags as `-include`: force-including a header that pulls in system headers re-registers libc properties per merged translation unit and the Frama-C kernel aborts with `trying to register twice property 'assumes nonnull_p'`.

### Symptom: Instrumentation Aborts With `no function 'X'`
- **Cause:** `-rte-select` / `-e-acsl-functions` named a function that is absent from the parsed AST (disabled by `#if`, or in a file that failed to parse).
- **Fix:** function discovery runs on preprocessed sources. Names Frama-C still rejects are dropped once and listed in `rte_select_dropped`.

### Symptom: A Crash Reproducer Is Large or Hard to Read
- **Fix:** `python3 /opt/framac-pipeline/scripts/pipeline_make.py run minimize` runs cvise (installed in the container image) on every unverified candidate's reproducer, under the sandbox, accepting only variants that still crash with the same fingerprint. Each crash artifact gets a `<artifact>.min` sibling; `workspace/reports/minimize/index.json` maps fingerprints to the reports. Crash verifiers should replay the `.min` first (`skills/framac-wp/crash_verifier_brief.md`).

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

## 4. Eva Abstract Interpretation Precision Issues

### Symptom: Eva Reports High `Unknown` (Orange) Alarm Counts (> 30%) on a Module Slice
- **Cause:** Loop widening or path merging occurred before precision could stabilize, or an external helper function had no ACSL contract (`builtins:missing-spec`).
- **Fix:**
  1. Check `workspace/eva/<mod>/eva.log` for `missing-spec` warnings. Add a contract stub to `external_stubs.h` for any unmodeled external function so Eva does not widen its return value to `[-inf, +inf]`.
  2. Run `pipeline_make.py run eva-tune`, then read `tuning` in `workspace/reports/eva/<mod>.json`. It tries slevel, unrolling and the other precision options as a fixed ladder, and says what helped and why any run was rejected ([`./resources-and-caching.md`](./resources-and-caching.md), Section 6). If nothing helped, look at the harness: a symbolic input length, for one, leaves every option with the same Unknowns.
  3. For a small fixed-bound parsing loop the ladder did not settle, add `//@ loop unroll 32;` above it in `workspace/work/`. Do not write `loop pragma UNROLL`: the kernel rejects it and the run fails.

### Symptom: An Eva Run Is Slow (or Hangs) on a Module Slice
- **Fix:** every Eva run writes `workspace/eva/<mod>/flamegraph.txt` (`-eva-flamegraph`). Render it to `flamegraph.svg`/`flamegraph.html` with `python3 /opt/framac-pipeline/scripts/pipeline_make.py run flamegraph-<mod>` (it renders the existing file and never re-runs Eva; or `scripts/eva_flamegraph.py --dir workspace/eva/<mod>`), then read the widest bars: they name the functions where Eva spends its time. Cross-check `workspace/eva/<mod>/nonterm.log` and the report's `nonterm` field (`workspace/reports/eva/<mod>.json`): a non-terminating loop is the usual cause of a hang, and `-eva-slevel`/`-eva-auto-loop-unroll` tuning (Step 2a of `/framac-eva`) is the usual fix.

### Symptom: `repair_hints` in the Eva Report (recursive call, or function with neither code nor specification)
- **Cause:** ported from upstream `frama-c-script make-wrapper` (see [`./upstream/sources/make_wrapper_tips.md`](./upstream/sources/make_wrapper_tips.md)). `run_eva_slice.py` matches `detected recursive call` and `Neither code nor (specification|... assigns clause) for function X,` in `eva.log` and lists the matching pipeline action in `repair_hints`.
- **Fix:** follow the hint's `action`: add the defining file to the module sources (locate it via `build_callgraph_dag.py`'s function index), add a stub/contract in `templates/acsl/external_stubs.h`, or enable the recursion fallback with `pipeline_make.py params set --module <mod> --eva-recursion-fallback` (recorded in `reduced_checks`).

---

## 5. Deductive Verification (`WP`) Issues

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
| Pointer cast `(uint32_t *)byte_buf` or `(void *)attr + 4` stays unproven under `Typed` | Type reinterpretation across pointer types, which the `Typed` memory model does not support | Do not switch to `Typed+cast`: the WP manual calls that model unsound, and `run_wp_function.py` records any proof under it as `unsound_proof`. When such goals stay unproven, `run_wp_function.py` re-runs the function once under `Typed+cast` as a diagnostic (`cast_model_probe`, never credited). If that probe proves every goal, the report sets `wp_cast_limitation` and `next_synthesis_focus: wp_typed_cast_limitation_stop_now`: stop, since a stronger contract will not help (on libmnl, `Typed+nocast`, `Bytes` and cast-free contracts left the same goals unproven). The unit stays unproven by WP: report it as a WP memory-model limit. |
| Address taken `&local_var` passed to helper | Stack variable address taken | Pass `--wp-model Typed+ref` (the default in `run_wp_function.py`). |
| `syntax error` on `terminates` or `exits` | Wrong ACSL clause order in function contract | Order clauses strictly: `requires` -> `terminates` / `decreases` -> `exits` -> `assigns` -> `ensures` -> `behavior`. |

### Symptom: `unsound_proof` With `Neither code nor specification for function X`

- `X` is called but has neither a body nor a contract. Frama-C generates a default contract and WP would trust it, so the proof does not hold.
- Add a contract to the prototype through `strengthening_requests`, or use a stub from `templates/acsl/external_stubs.h` for an external function.
- `Neither code nor explicit exits and terminates for function X` is a different message: `X` has a specification, and this one is harmless.

### Symptom: A Unit Stays Uncovered With `wp_trivial_clause_only` or `wp_limits_unmet`

- `wp_trivial_clause_only`: every `L4_*`, `L5_*` or `L6_*` clause of that class holds whatever the function does. Write a clause that constrains the output or state.
- `wp_limits_unmet`: the report has no `limits`, or its contract check did not pass. Re-run with the current `run_wp_function.py`; reports written before verdict limits existed are not credited.

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
