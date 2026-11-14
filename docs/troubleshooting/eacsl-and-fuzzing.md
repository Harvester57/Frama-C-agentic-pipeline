# E-ACSL + LibFuzzer Build & Runtime Issues

Issues encountered in E-ACSL instrumentation (`e-acsl-gcc`, `eacsl_toolchain.py`), runtime shadow memory, LibFuzzer / sanitizer campaigns (`run_eacsl_fuzz.py`), crash parsing/fingerprinting (`fingerprint.py`), and reproducer minimization. For `--api` harness layout and `build-check` module triage, see [`./harnesses-and-seeds.md`](./harnesses-and-seeds.md). For Dual-Oracle Guardrail checks in Phase 3, see [`./wp-and-guardrail.md`](./wp-and-guardrail.md).

---

### Symptom: Fuzz Stage Fails With `ZeroDivisionError: integer modulo by zero` in `artifact_dispatch_case`; Campaigns `not_run`
- **Seen on:** benchmark runs `ab-fc35dev` and `ab-fc34` (2026-11-13), on both analysis images: `fuzz: rc=1` on cryptolib, minmea, oscs-qlz, oscs-semver, oscs-stmr, qcbor-dev and qcbor-master, and `benchmark.py compare` against `phase0-r1` reports `campaign no longer runs: not_run` for their modules. The fuzz log ends `File ".../run_eacsl_fuzz.py", line 1429, in artifact_dispatch_case: return first[0] % n_cases ... ZeroDivisionError: integer modulo by zero`, then `make: *** [.../pipeline.mk:148: fuzz-minmea] Error 1`. Recall stayed 7/7: the replays do not go through the campaign.
- **Cause:** a pipeline bug from `f23757c` (M4 hardening). `dispatch_case_count` started reading the harness sidecar first and returned its `dispatch_case_count` as is. Every sidecar records that field, 0 for a harness that is not a dispatch harness, so a plain `LLVMFuzzerTestOneInput` harness was taken for a dispatch harness with 0 cases: `run_campaign_rounds` ran dispatch rounds, and the first crash it recorded computed `first[0] % 0`. The sidecar shortcut also skipped the old check that the source holds `FRAMAC_FUZZ_SKIP_CASES`, without which a build cannot skip cases.
- **Fixed (uncommitted, written in a worktree while the benchmark ran, then applied to the checkout):** [`../../scripts/run_eacsl_fuzz.py`](../../scripts/run_eacsl_fuzz.py) `dispatch_case_count` reads the sidecar only for a source holding the skip macro and returns None for a count of 0 or an empty case list; `artifact_dispatch_case` returns None for `n_cases <= 0`; `run_campaign_rounds` runs fork mode when `n_cases` is 0. Test: `tests/test_run_eacsl_fuzz.py::test_a_harness_that_is_not_a_dispatch_harness_runs_in_fork_mode`. The two A/B runs both carry the bug, so their fuzz results compare like for like but are not campaign results.

### Symptom: `e-acsl-gcc` Fails on `__fc_builtin.h`, `__fc_libc/stdlib.h` (`\old(endptr)`), or Unknown Legacy Flag `--rte=`
- **Cause:**
  1. `e-acsl-gcc` runs `frama-c -no-frama-c-stdlib` so its second pass can compile `instrumented.c` with host `clang` against host glibc. If a harness guards `#include "__fc_builtin.h"` only with `#ifdef __FRAMAC__`, `e-acsl-gcc` enters that block and fails because `__fc_builtin.h` is not on the host include path, and host `<math.h>`/`<stdlib.h>` expose `_Float128` prototypes on glibc >= 2.26.
  2. Frama-C 33+ installs `e-acsl-gcc` (no `.sh`). Its `-h` lists only the short flags (`-F`, `-G`, `-E`, `-e`, `-l`, `-n`, `-C`, `-M`), though long options such as `--rte=all` are still accepted. Running `-rte` across all functions without `-rte-select` instruments unused inline helpers.
- **Fix:** `harness_dual.c.template` guards `#include "__fc_builtin.h"` and `eva_main()` with `#if defined(__FRAMAC__) && !defined(__FRAMAC_EACSL__)`, and `run_eacsl_fuzz.py` automatically passes `-D__FRAMAC_EACSL__ -D_Float128=double -U__SIZEOF_INT128__` (host `<linux/types.h>` declares `__int128` typedefs, which Frama-C rejects, only when that macro is defined) along with `-rte-select` and `-e-acsl-functions` scoped to the functions defined in the target slice `.c` files. Full compiler diagnostics are saved to `<out-bin>.compile.log`. If `e-acsl-gcc` still fails in `campaign` mode, `--engine auto` falls back to native `clang -fsanitize=fuzzer,address,undefined`.

### Symptom: Selftest `compiled: false` With `undefined reference to 'main'` / `fail to compile/link un-instrumented code`
- **Cause:** by default `e-acsl-gcc` instruments **and** links the original sources. A libFuzzer harness has no `main()`, so that link fails and `e-acsl-gcc` exits 1, even though the instrumented file was written.
- **Fix:** `run_eacsl_fuzz.py` passes `-n` (instrument only) in stage 1.

### Symptom: Every Input Crashes in `shadow_alloca` (`e_acsl_segment_tracking.c`), or Valid Stack Accesses Fail `\valid`
- **Cause:** E-ACSL initializes its runtime at the top of `main()`, and a harness has none. Without full memory tracking, its memory analysis leaves a caller's stack buffer untracked, so a callee's valid write fails `\valid`. With full tracking but no runtime initialization, the runtime segfaults on the first tracked stack block.
- **Fix:** automatic. Fuzz builds use `-e-acsl-full-mtracking` and link [`../../templates/eacsl_runtime/fuzz_init.c`](../../templates/eacsl_runtime/fuzz_init.c), whose `LLVMFuzzerInitialize` calls `__e_acsl_memory_init` and `__e_acsl_globals_init`. Do not define `LLVMFuzzerInitialize` in a harness (`reason: eacsl_init_hook_conflict`). The selftest's `benign_input_clean` check catches either regression.

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

### Symptom: The E-ACSL Selftest Passes Although the Result-Init Pass, the `isnan` Shim or the errno Shim Is Broken
- **Seen on:** C1 of [`../plans/templates-and-stubs-improvement-plan.md`](../plans/templates-and-stubs-improvement-plan.md), `framac-analysis:latest` (Frama-C 35.0~~dev), 2026-11-10.
- **Cause:** the canary called no function with a contract on its result, used no `<math.h>` classification macro and never wrote `errno`, so a regression of `mark_wrapper_results_initialized`, of `-D__SUPPORT_SNAN__` with the `fc_stubs/eacsl` `math.h` shim, or of the errno stub and shim (S5) still passed the selftest and showed only on a target. Frama-C 35 checks `\initialized` on a contract wrapper's `__retres` only where the `ensures` reads a field of a struct `\result` (`\initialized(&\result.n)`); a scalar `\result` (`ensures \result <= len`, `\result >= 0`, `\result == \old(x) + 1`) or a pointer `\result` gets no such check, so a canary with a scalar result would not catch the regression.
- **Fix (fixed, C1):** `templates/eacsl_canary/canary.c` runs three more calls on every input, before its input-dependent bugs: `canary_clamp` (`ensures \result.len <= span.len` on a struct result), `canary_classify` (`isnan`) and `canary_errno` (`errno = 0`, `strtol` of an out-of-range number, then `/*@ assert canary_errno_synced: synced != 0; */` on `errno == ERANGE`). `tests/test_eacsl_canary.py` (Docker) builds the canary four times: production passes, and without the result-init pass (`\initialized(&\result.len)`) or without the errno shim (`canary_errno_synced`) `benign_input_clean` fails; without `-D__SUPPORT_SNAN__` the build fails.

### Symptom: Every Call Fails `\initialized` on a Formal Parameter (`\initialized(&s.len)`, often at a Function's First Statement)
- **Cause:** an E-ACSL gap, reproduced on Frama-C 35. Each function registers its formals with `__e_acsl_store_block` but never marks them initialized, although the caller has just written them. Under `-rte-initialized`, the first read of a by-value struct field, or of a scalar formal through its address, fails whatever the caller passed. The assertion is blocking, so nothing after it in that function is ever checked. In QCBOR run-5, 13 of 29 crash candidates were this artifact, and it hid a real signed overflow a few lines below one of them.
- **Fix:** automatic. Between the two stages, `run_eacsl_fuzz.py` inserts `__e_acsl_full_init` after each formal's registration; the build report counts them in `compile.formal_inits`, and the selftest canary reads a by-value struct and an address-taken scalar formal on every input. Locals are untouched, so uninitialized locals are still reported. The cost: E-ACSL no longer reports a struct passed by value with uninitialized members. A report of this failure means the build ran without that step: rebuild it rather than using `--no-rte-initialized`. Upstream report (draft, not filed): [`frama-c-eacsl-formal-params-initialized.md`](../upstream/frama-c/frama-c-eacsl-formal-params-initialized.md).

### Symptom: E-ACSL Formals Uninitialized or Scalar Const Global Aborts on Non-`UL` Integer Suffixes
- **Cause:** `_STORE_BLOCK_LINE_RE` and `_READONLY_SCALAR_RE` in `scripts/eacsl_toolchain.py` required `\d+UL`. Size constants emitted with `U`, `L`, `ULL`, or bare digits failed to match, leaving formals uninitialized or const scalars without address-of.
- **Fix (fixed, uncommitted, `scripts/eacsl_toolchain.py`):** Replaced `\d+UL` with `\d+[uUlL]*`. Added a warning when store_block lines exist in text but none match the regex.

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

### Symptom: Why Not `-L` / Frama-C's libc for E-ACSL?
- E-ACSL aborts on Frama-C libc specifications (`unbounded ranges are not part of E-ACSL`, `share/libc/string.h`). Host-header mode is the only supported E-ACSL mode.

### Symptom: `undefined reference to 'open_fallback_N'` at Link Time
- **Cause:** in host-header mode, the Variadic translation emits `<fn>_fallback_<N>` for variadic calls without a libc specification (`open`, `fcntl`, `ioctl`, ...), and the E-ACSL RTL does not define them.
- **Fix:** automatic. The script generates `<out-bin>_fallbacks/eacsl_fallbacks.c`, which forwards to the real function (or fails with `ENOSYS` when the signature or header is unknown, recorded as `mode: enosys`), compiles it to a link-only object, and retries the link once. Never add these definitions to the instrumented sources: each definition shifts the fallback numbering. `--no-variadic-translation` passes `-no-variadic-translation` to Frama-C instead (no fallbacks are emitted).

### Symptom: Link Repair and Fallback Function Generation Fail on LLVM lld `undefined symbol:` Diagnostics
- **Cause:** `_UNDEFINED_REF_RE` in `scripts/run_eacsl_fuzz.py` and `_FALLBACK_UNDEFINED_RE` in `scripts/eacsl_toolchain.py` only parsed GNU ld's `undefined reference to 'X'`, ignoring LLVM lld's `undefined symbol: X`.
- **Fix (fixed, uncommitted, `scripts/run_eacsl_fuzz.py`, `scripts/eacsl_toolchain.py`):** Expanded regexes to match both `undefined reference to` and `undefined symbol:`.

### Symptom: `call to undeclared function 'X'` or `invalid application of 'alignof' to an incomplete type`
- **Cause:** a [`../../templates/fc_stubs/`](../../templates/fc_stubs/) header lacks a prototype the target calls, or declares an opaque handle (`struct json_object`) as incomplete. E-ACSL emits `alignof` on pointed-to types.
- **Fix:** add the prototype and complete the handle with a single dummy member (see [`../../templates/fc_stubs/README.md`](../../templates/fc_stubs/README.md)). Tool JSONs list missing prototypes under `undeclared_functions`. For Eva/WP this is a soundness issue: Frama-C invents `int X()`.
- **Target-specific compat headers** (e.g. completing OpenSSL 3 opaque handles `EVP_PKEY`, `BIGNUM`, ... for the fuzz build) must be delivered **source-side**: pass them to `generate_harness.py --compat-include <header>` so the harness `#include`s them after the module header. Never add them to cppflags as `-include`: force-including a header that pulls in system headers re-registers libc properties per merged translation unit and the Frama-C kernel aborts with `trying to register twice property 'assumes nonnull_p'`.

### Symptom: Instrumentation Aborts With `no function 'X'`
- **Cause:** `-rte-select` / `-e-acsl-functions` named a function that is absent from the parsed AST (disabled by `#if`, or in a file that failed to parse).
- **Fix:** function discovery runs on preprocessed sources. Names Frama-C still rejects are dropped once and listed in `rte_select_dropped`.

### Symptom: Linker or Shadow Memory Conflict When Combining E-ACSL with AddressSanitizer (`-fsanitize=address`)
- **Cause:** E-ACSL embeds its own shadow-memory runtime (`rtl`) to track byte-level pointer validity (`\valid`), initialization (`\initialized`), and sub-object bounds. AddressSanitizer (`ASan`) also maps shadow memory and intercepts `malloc`/`free`. Running both in the same binary causes immediate `mmap` collisions or false aborts.
- **Fix:**
  - Compile E-ACSL fuzz binaries with `-fsanitize=fuzzer` **without** `-fsanitize=address` (as configured in `run_eacsl_fuzz.py`). E-ACSL's own runtime already detects out-of-bounds accesses, use-after-free, bad free, uninitialized reads, and sub-object overflows.

### Symptom: The E-ACSL Fuzz Binary Never Sees an `errno` Set by libc (`errno == ERANGE` After `strtol`, `EINTR`/`EBADF` After `read` Take the Wrong Branch)
- **Seen on:** S5 of [`../plans/templates-and-stubs-improvement-plan.md`](../plans/templates-and-stubs-improvement-plan.md), a minimal repro in `framac-analysis:latest` built with `run_eacsl_fuzz.compile_eacsl_binary` (2026-11-10).
- **Cause:** `templates/fc_stubs/errno.h` maps `errno` to the tracked global `__fc_eacsl_errno` in E-ACSL builds, and libc never writes it: `ERRNO_AFTER_STRTOL=0 ERANGE=34 v=9223372036854775807`. The mapping cannot simply go away. glibc's errno lives in libc.so's TLS block, outside the TLS segment the E-ACSL runtime shadows (only the executable's block; probe: `errno_location=0x7f6007f480c0 tls_segment=[0x7f6007f48140,0x7f6007f48440)`). Without the stub every input aborts with `e_acsl_segment_tracking.c:1018: Use of invalid address ... in unsafe_initialize`. Registering the address from `fuzz_init.c` (`__e_acsl_store_block(__errno_location(), sizeof(int))` and `__e_acsl_full_init`) crashes instead with `UndefinedBehaviorSanitizer: SEGV on unknown address 0x000000000000 ... e_acsl_segment_tracking.c:303:22 in shadow_alloca`.
- **Fix (fixed, commit 7a23e9e):** `run_eacsl_fuzz.py` links a generated, link-only errno shim (`<out>_errno_shim/eacsl_errno_shim.o`, `-Wl,--wrap=<fn>` for the functions of `ERRNO_SHIM_FUNCTIONS` in `scripts/eacsl_toolchain.py` that the slice calls). Each wrapper copies the global into libc's errno before the call and libc's errno back after it, and the variadic fallbacks sync errno the same way. The build result records `errno_shim` (the wrapped functions, or `status: failed` with `unsynced`) as a coverage caveat. Remaining gap, by design: after a libc call outside the table, or a call through a function pointer, the target still reads the last errno it wrote, and the global is shared across threads. Add a function to the table when a target branches on its errno.

### Symptom: Libc Calls in Complex Statements Lack Errno Shims
- **Cause:** `_CALL_SITE_RE` in `scripts/eacsl_toolchain.py` expected calls only at line starts or after `=;{}`. Calls in `if (f) fclose(f);`, `return close(fd);`, and ternary expressions were missed, leaving `__fc_eacsl_errno` unsynced after those calls.
- **Fix (fixed, uncommitted, `scripts/eacsl_toolchain.py`):** Extended `_CALL_SITE_RE` delimiters to include `(`, `)`, `:`, `!`, `?`, `&`, `|`, `,`, and keywords `return`, `else`, while excluding control keywords with lookahead. Added a warning when a libc call gets no errno shim.

### Symptom: E-ACSL Ignores an Unbounded Quantifier (`invalid E-ACSL construct ... Missing upper bound for i. '. Ignoring annotation.`)
- **Cause:** E-ACSL can only compile **bounded** quantifiers where the lower and upper bounds of the quantified integer variable `k` are syntactic integer expressions (e.g., `\forall integer k; 0 <= k < len ==> ...`). It does not fail the build on an unbounded one: it warns, keeps the clause as a comment in the instrumented file, and checks nothing.
- **Seen on:** step M4 of [`../plans/templates-and-stubs-improvement-plan.md`](../plans/templates-and-stubs-improvement-plan.md) (2026-11-10), a repro in `framac-analysis:latest` (Frama-C 35.0~~dev). It ran the real `run_eacsl_fuzz.py guardrail --functions session_status` on the `tests/fixtures/security_props` session library, with the `L5_sanitized_log_line` assertion MetAcsl generates (`L5_no_crlf(tmp)`) pasted into the source: `[e-acsl] ...:57: Warning: invalid E-ACSL construct ... in quantification ∀ ℤ i; 0 ≤ i ⇒ ... Missing upper bound for i. '. Ignoring annotation.`, and the guardrail returned `passed_dynamic_oracle`.
- **Generated security properties: not a pipeline defect.** Guardrail builds never see the MetAcsl properties or what MetAcsl generates from them. `run_wp_function.py` writes `security_meta_<fn>.c` into WP's out-dir and passes it to the WP run only (`-meta ... -then-last`); the generated clauses live in that Frama-C project and are never printed back to a source file. The prover guardrail (`prover_brief.md`, `--sources {scratch_module_sources}`) and the parent re-check (`workspace_overlay.py`) compile the sidecar sources and the harness only, and the prover brief forbids copying meta-properties into the source. So the L4–L6 meta properties are checked by WP only, never dynamically. Of the generated predicates only `L5_no_crlf` is unbounded; the wipe predicate (`templates/metacsl/l6_wiped.acsl`, `0 <= i < count`) is translated and checked by E-ACSL. A meta file passed by mistake to `--sources` is parsed and ignored without a warning (no `-meta`).
- **Open pipeline bug (clauses in the source):** `run_eacsl_fuzz.py` does not scan the compile log for `Ignoring annotation` / `invalid E-ACSL construct`, so the guardrail reports `passed_dynamic_oracle` for a clause it never executed. The quantifier hint in `derive_eacsl_diagnostic_hints` runs only on `compile_error`, so it never fires here. To make: the guardrail and build report list the annotations E-ACSL ignored (file:line and reason), and a clause ignored in the checked function does not count as dynamically checked.
- **Fix:** Always write explicit integer lower and upper bounds in `\forall` and `\exists` predicates (`0 <= k < n`), and use the `integer` type (or `size_t` / `int`) explicitly.

### Symptom: An E-ACSL `\exists` Passes Although One of Its Conjuncts Is False (`\exists integer i; 0 <= i < n && P && Q` Checks Only `Q`)
- **Seen on:** S4 of [`../plans/templates-and-stubs-improvement-plan.md`](../plans/templates-and-stubs-improvement-plan.md) (2026-11-10), `framac-analysis:latest` (Frama-C 35.0~~dev, E-ACSL). In a minimal repro (`requires` clauses, called with `size == 5`, `char buf[8] = "abc"`), `\exists integer n; 0 <= n < size && n == 1000 && n >= 0` passed, and so did `\exists integer n; 0 <= n < size && buf[n] == 'z' && \valid(buf + (0 .. n))`; with the two conjuncts swapped, both fail as they should. In the S4 stubs, the conjuncts moved into one predicate call (`0 <= i < n && P(s, i)`) are all checked: the E-ACSL cases of `tests/test_fc_stub_repairs.py` stop the overflowing and unterminated calls.
- **Cause:** an E-ACSL translation bug of guarded quantifiers: the conjunct right after the guard is dropped. Not reported upstream yet.
- **Fix in the S4 stubs (fixed):** every E-ACSL quantifier in `fc_strlcpy.h`, `bsd/string.h` and `json-c/json.h` has exactly one predicate call after its guard (`__fc_bsd_cpy_fits(...)`, `__fc_json_nul(...)`); `tests/test_fc_stub_repairs.py::test_eacsl_quantifiers_have_one_conjunct_after_the_guard` enforces it.
- **Fixed for the vocabulary (integration of S4 and S8, branch `templates-stubs-integration`):** S8 replaced `valid_nstring` and gave `valid_read_nstring` libc's semantics without a quantifier; the E-ACSL `valid_read_string` and `valid_string` in `templates/fc_stubs/fc_compat_types.h` still had the dropped form (`\exists integer i; 0 <= i <= 65536 && \valid_read(s + (0 .. i)) && s[i] == '\0'`) and now call one predicate after the guard (`__fc_eacsl_read_nul_at`, `__fc_eacsl_nul_at`), checked by `tests/test_fc_stub_repairs.py::test_compat_eacsl_string_predicates_have_one_conjunct_after_the_guard`. **Open pipeline bug:** contracts written by provers and breakers can hit it too: a guardrail can pass a clause it did not check in full. Not yet done: a lint over guardrail sources, and an upstream report.

### Symptom: E-ACSL Rejects a Pointer the Program Got From an Uninstrumented Library (`\valid_read` False on a `strdup`, `getenv` or json-c String)
- **Seen on:** S4 of [`../plans/templates-and-stubs-improvement-plan.md`](../plans/templates-and-stubs-improvement-plan.md) (2026-11-10), `framac-analysis:latest` and `framac-build:latest` (json-c 0.18). A string `json_object_get_string` returned, passed back to `json_object_new_string`, failed a `valid_read_string`-style precondition; so did `strdup`'s result passed to `strlcpy`.
- **Cause:** E-ACSL tracks only memory the instrumented code allocates (its own `malloc`, stack, globals). Blocks a library allocates internally (json-c's objects and strings, libc's `strdup` through its internal allocator, `getenv`'s environment) are not in the shadow memory, so `\valid_read` and `\block_length` are false or zero on them.
- **Fix in the S4 stubs (fixed):** the E-ACSL branches of `fc_strlcpy.h`, `bsd/string.h` and `json-c/json.h` check a pointer argument only when it lies in tracked memory (`\valid_read(s) ==> ...`), and require library handles only to be non-NULL where the library asserts on NULL. **Open pipeline bug (general):** any E-ACSL contract or RTE check on such a pointer (a prover's `requires valid_read_string(s)` in a guardrail build, an RTE on a read through it) is a false alarm, and the pipeline does not tell a fuzz crash of this kind from a real one. To make: `run_eacsl_fuzz.py` / `eacsl_toolchain.py` register the blocks the known allocating library calls return (`__e_acsl_store_block` after the call), or classify crashes whose pointer comes from such a call.

---

## Sanitizer Campaigns, Crash Parsing & Minimization

### Symptom: LeakSanitizer Reports `LeakSanitizer has encountered a fatal error` or `LeakSanitizer does not work under ptrace`
- **Cause:** LeakSanitizer (enabled by default with `-fsanitize=address` in the native LibFuzzer fallback) uses `ptrace` to stop threads while scanning. Docker's default seccomp profile allows `ptrace` on kernels >= 4.8; older hosts block it.
- **Fix:** Do not relax seccomp. Set `ASAN_OPTIONS=detect_leaks=0` (or pass LibFuzzer `-detect_leaks=0`) for the campaign and record in the run notes / agent result that leak detection was disabled, so missing leak coverage is visible.

### Symptom: E-ACSL Crash With `failure: null` or a Location Inside the E-ACSL Runtime (`unsafe_initialize`)
- **Cause:** heap corruption made the E-ACSL RTL crash before it printed the failing assertion.
- **Fix:** automatic. The crash input is replayed on a sanitizer build of the same slice; `attribution` and `failure_source: sanitizer_replay` give the precise file:line. The crash is still classified from the E-ACSL run.

### Symptom: A Crash Reproducer Is Large or Hard to Read
- **Fix:** `python3 /opt/framac-pipeline/scripts/pipeline_make.py run minimize` runs cvise (installed in the container image) on every unverified candidate's reproducer, under the sandbox, accepting only variants that still crash with the same fingerprint. Each crash artifact gets a `<artifact>.min` sibling; `workspace/reports/minimize/index.json` maps fingerprints to the reports. Crash verifiers should replay the `.min` first (`skills/framac-wp/crash_verifier_brief.md`).

### Symptom: `UndefinedBehaviorSanitizer: SEGV on unknown address` Is Not Parsed as a Failure
- **Open pipeline bug** (found 2026-11-10 while diagnosing the guardrail entry in [`./wp-and-guardrail.md`](./wp-and-guardrail.md), on the output of a libmnl guardrail binary built by E-ACSL on Frama-C 35). E-ACSL binaries print a deadly signal as `UndefinedBehaviorSanitizer:DEADLYSIGNAL`, then `==N==ERROR: UndefinedBehaviorSanitizer: SEGV on unknown address ...`, a stack and a `SUMMARY:` line. `parse_eacsl_failure`, `parse_sanitizer_failure` and `parse_runtime_failure` in `scripts/run_eacsl_fuzz.py` all return `None` on it: the UBSan pattern expects `runtime error:` and the ASan pattern `AddressSanitizer`. Verified only on these functions. What a fuzz campaign or a crash replay then records for such a crash (an unparsed candidate, presumably) has not been checked.
- **Fix to make:** Phase 1 step S2 owns failure parsing ([`../plans/phase1-remediation-plan.md`](../plans/phase1-remediation-plan.md), `scripts/failure_identity.py` after S1): parse the UBSan and libFuzzer deadly-signal reports (kind from the headline, location from the first target frame), with a fixture from this output. The guardrail does not depend on it: it reads the stack itself (`crash_outside_checked_functions`).

### Symptom: E-ACSL and Sanitizer Parser Misses Locations in Non-`.c`/`.h` Source Files (`.inc`, `.y`, `.cpp`)
- **Cause:** `scripts/run_eacsl_fuzz.py` regexes `_FN_RE`, `_ERR_RE`, `_OLD_RE`, and `_UBSAN_RE` required files to have `.c`, `.h`, `.i`, or `.acsl` extensions. Errors in included template headers (`.inc`), grammar specifications (`.y`), or other extensions were rejected and returned `None`.
- **Fix (fixed, uncommitted, `scripts/run_eacsl_fuzz.py`):** Changed file patterns to `(?:[A-Za-z]:)?[^\s:'"]+`, anchored by `:(?P<line>\d+)(?::\d+)?: Error:` and `: runtime error:`.

### Symptom: Sanitizer Crash Fingerprinted as `unknown#unknown_function` Despite Stack Trace
- **Cause:** `_STACK_FRAME_RE` in `scripts/run_eacsl_fuzz.py` coupled function extraction to `.c`/`.h` file and line presence. When symbols were in non-`.c` files or had binary offset addresses (`(/bin+0x123)`), `_STACK_FRAME_RE` skipped the frame, resulting in `candidates = []` and fingerprinting as `unknown#unknown_function`.
- **Fix (fixed, uncommitted, `scripts/run_eacsl_fuzz.py`):** Decoupled function extraction from file and line in `_STACK_FRAME_RE`, with defensive guards against `None` file paths in `_parse_segment_failure` and `parse_sanitizer_failure`.

### Symptom: Multi-Word AddressSanitizer Errors Misclassified as `mem_access`
- **Cause:** `_ASAN_ERR_RE` in `scripts/run_eacsl_fuzz.py` matched `[A-Za-z0-9_-]+`, truncating `attempting double-free` and `attempting free on address which was not malloc()-ed` to `"attempting"`. `_map_sanitizer_alarm_kind` failed to match `"bad-free"` or `"attempting free"` and defaulted to `mem_access`.
- **Fix (fixed, uncommitted, `scripts/run_eacsl_fuzz.py`):** Added explicit multi-word kinds to `_ASAN_ERR_RE`, added `"double-free" in low` to `_map_sanitizer_alarm_kind`, and normalized kind slug names.

### Symptom: Access Size Variations Fragment ASan Crash Fingerprints
- **Cause:** `_ASAN_OP_RE` in `scripts/run_eacsl_fuzz.py` preserved `of size <N>` in the fingerprinted predicate, causing identical bugs with different read/write byte widths (e.g. 1 vs 4 bytes) to yield distinct fingerprints.
- **Fix (fixed, uncommitted, `scripts/run_eacsl_fuzz.py`):** Normalized operation capture in `_ASAN_OP_RE` to direction only (`READ` / `WRITE`), dropping the byte size from the fingerprinted predicate.

### Symptom: Predicate Normalizer Strips Expression Keywords `check`, `admit`, `assert`
- **Cause:** `_LABEL_RE` in `scripts/fingerprint.py` matched `(?:assert|check|admit)\s+` without requiring a trailing colon, erroneously stripping variable names in expressions like `check > 0`.
- **Fix (fixed, uncommitted, `scripts/fingerprint.py`):** Required colon `:(?!:)` after label keywords in `_LABEL_RE`. Precompiled `_ALARM_KIND_RE` once at module scope to eliminate per-call regex compilation.
