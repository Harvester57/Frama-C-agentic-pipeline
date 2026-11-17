# mpack run-1 supervision report (2026-11-17)

- **Runs index:** [`./README.md`](./README.md)
- **Troubleshooting catalog:** [`../troubleshooting/README.md`](../troubleshooting/README.md)

External, read-only supervision of the opencode-driven `standard` run of `mpack`. This report is updated at each milestone. The session started in `run-1`, abandoned it 8 minutes later, and continues in `run-2` (see the status table).

## Final summary

- **Final status:** neither run reached a terminal state. `run-1` was abandoned by the agent at 01:26 UTC, and `run-2` was stopped by the user during Phase 0 harness generation (about 01:40 UTC). Both still say `run_status: in_progress`; the supervisor left them alone.
- **Wall-clock time:** `run-1` 8 min; `run-2` about 14 min, all in Phase 0 (timeline below, from the supervisor's observations).
- **Fixes:** S1, merged into `phase1-remediation` as `c9b29a4`. A fresh run gets the test runner classified as test and `libmpack.a`'s API (319 entry points), so the seed recorder can wrap `mpack_*` calls from the test suite. `--scope src/mpack` is no longer needed.

## Parameters

| Parameter | Value |
| :--- | :--- |
| Run directory | `C:\Users\Florian\framac-pipeline\mpack\run-1`, then `run-2` from 01:26 UTC |
| Target | `mpack` at `9eacca4d3127` (target checkout dirty) |
| Profile / scope | `standard`; `run-1` whole target, `run-2` `--scope src/mpack` |
| opencode session | `ses_e18ea6dd2ffeoMLaV6cS00IwIn` ("Framac-verify mpack standard", model `deepseek-v4.1-flash`) |
| Run tag | `run-1-636addc410b7`, then `run-2-42659b61e061` (repo key `mpack-e43fcfd4660d`) |
| Pipeline | `phase1-remediation` at `3369898` (clean tree) |
| Poll / stall / recurrence limit | 2 min / 10 min / 3 |
| Fix mode | `hold`: fixes stay on their branches until the run ends |
| Supervision started | 2026-11-17 01:20 UTC (run-1 created 01:18:50 UTC) |

## Status

`progress.json` does not exist yet, so phase times come from the supervisor's timeline.

| Time (UTC) | Phase | Event |
| :--- | :--- | :--- |
| 01:18:50 | Phase 0 | `run-1` created (`run_metadata.py init`). |
| 01:19:04 | Phase 0 | Shadow overlay initialised (41 files). `trust.py check-threat-model` reports `no_threat_model`: the target's `THREAT_MODEL.md` has no `framac-threat-model` block. |
| 01:20:39-01:21:38 | Phase 0 | The model copies `THREAT_MODEL.md` into `workspace/`, appends a structured block, and the check passes (`ok`). |
| 01:21:48 | Phase 0 | `build_capture.py propose` returns `null` (mpack has no library build; its Ninja build only makes test executables). The model proposes a recipe that compiles `src/mpack/*.c` into `.build/mpack-lib/libmpack.a` and then builds the Ninja `everything-debug` suite. The user confirms it at 01:24. |
| 01:24:24-01:24:44 | Phase 0 | Build capture `ok` in 7.6 s: `libmpack.a` (6 files), `.build/unit/everything-debug/runner` (16 files, **test = false**), `.build/unit/flagtest`. |
| 01:25:08-01:26:03 | Phase 0 | The model finds that the test runner would be analysed as Tier 1A product code. `run_metadata.py` has no `set-scope`, so it abandons `run-1` and creates `run-2` with `--scope src/mpack` (S1). |
| 01:26:04-01:26:40 | Phase 0 | `run-2`: overlay, threat-model copy (check `ok`), `set-build`, build capture (same 3 units). |
| 01:26:40-01:27:01 | Phase 0 | `phase0_model.py run` `ok` in 13 s: 700 functions, 2983 edges, all 3 units parsed. |
| 01:27:11-01:29:07 | Phase 0 | CodeQL and trust: 74 facts, 461 untrusted / 239 trusted / 397 boundary. CodeQL alone decides 8 functions. |
| 01:29:17-01:29:30 | Phase 0 | `seed_harvest.py record` `ok`: the test suite ran 1,032,144 checks, but only **2 calls** were recorded, `test_system` and `test_common`, and no mpack API call (S1). |
| 01:30:29-01:31:09 | Phase 0 | `fuzz_assets.py discover` finds nothing: `test/fuzz/fuzz.c` is a stdin program, not a libFuzzer target. The model copies `test/messagepack/*.mp` into `inputs/corpora/mpack-messages` and maps the 5 files to `mpack_tree_init_{data,pool,stream}`. |
| 01:31:09 | Phase 0 | Call-graph DAG built: `libmpack_a` reaches 498 functions and is split into 11 Tier 1A submodules anchored on `mpack_*` API functions, so the DAG gives the library its API even though the model's `entry_points` are only the two `main`s. |
| 01:31:39-01:31:51 | Phase 0 | Stubs (none needed); `security_props.py`: 8 `sanitized` properties. `public_headers` lists `examples/sax-example.h` and `test/fuzz/fuzz-config.h`, not `mpack.h` (it sits inside the source dir), so the model passes `--header src/mpack/mpack.h` by hand. |
| ~01:36-01:40 | Phase 0 | The user stops `run-2` during harness generation to wait for the S1 fix, because seed quality matters for mpack. `run_status` stays `in_progress` and no `RUN_TAG` container is left. |

## Fixes

| Id | Fingerprint | Branch | State |
| :--- | :--- | :--- | :--- |
| S1 | Phase 0 / `build_capture.py run` / a test executable that mixes product and test sources is classified non-test | `sup/mpack-test-runner-classification` (`c2ddddb`, `a6edeb5`, `339919b`) | Merged into `phase1-remediation` as `c9b29a4` after the user stopped `run-2` |
| S1b | Phase 0 / `build_capture.py run` / S1 recurrence: the test driver's product sources sit in an executable, not a library | `sup/mpack-test-driver-any-holder` (`c57d2ea`) | Held until `run-3` ends |
| CRLF | Phase 0 / `seed_harvest.py record` / test command exits 127 `not found` on a CRLF shebang (target-side; the pipeline gap is the late diagnosis) | `sup/crlf-script-check` (`90cc197`, `16c86eb`) | Verified by the fixer (5933 passed); held until `run-3` ends |
| S2 | Phase 0 / `seed_harvest.py record` / only outermost calls before the first longjmp are recorded | `sup/recorder-longjmp-safe` (`84f76b6`) | **Merged live** at 03:45 (fast-forward). Test: `tests/test_seed_harvest_longjmp.py::test_recorder_records_outermost_calls_after_a_longjmp` |
| S3 | Phase 0 / `generate_harness.py --entry-style argv` / implicit declaration of `main` | `sup/mpack-argv-main-prototype` (`a13e149`, `2e1fc93`) | Verified by the supervisor (diff read, `tests/test_harness_argv.py` 13 passed, 2 skipped on Windows; the fixer's Docker clang repro goes from exit 1 to exit 0). Held until `run-3` ends |
| S4 | Phase 0 / `pipeline_make.py build-check` / E-ACSL frontend syntax error on `__restrict__` (host headers) | fixer running (`sup/mpack-eacsl-restrict`) | In progress |
| S5 | Phase 0 / `pipeline_make.py build-check` / clang rejects Frama-C's `missing proto` redeclaration of `__builtin_{add,mul}_overflow` | same fixer as S4 | In progress |

S1 commits and tests:

- `c2ddddb` adds the `main_in_test_source` test rule.
- `339919b` adds the public-header fallback (`PUBLIC_FALLBACK_RULE`). The fixer first wrote it, removed it when the supervisor wrongly pointed at plan H1, and then restored it.
- Tests are in `tests/test_build_capture.py`:
  - `test_a_test_driver_compiling_the_library_again_is_a_test_unit`
  - `test_the_seed_recorder_no_longer_wraps_the_test_drivers_functions`
  - `test_only_drivers_with_main_in_a_test_source_over_library_sources_are_marked` (5 cases)
  - `test_a_stray_header_outside_the_sources_does_not_hide_a_static_librarys_api`
  - `test_public_headers_that_declare_the_librarys_functions_are_kept`

Supervisor's check: the branch's `build_capture.py run` was run on the real mpack tree (tag `sup-mpack-real`, `framac-build:latest`, 600 s cap). It gives the runner `test` (`main_in_test_source`), and `libmpack.a` 319 entry points (0 before) through the fallback.

### S1: the test runner is classified as product code

- `test_reason()` in `scripts/build_capture.py` marks a unit as test only by a name word, a test directory in its path, all its own sources being test sources, or a name ending in `test(s)` with one test source. mpack's `.build/unit/everything-debug/runner` links `src/mpack/*.c` (its own objects) together with `test/unit/src/*.c`, and its `main` is `test/unit/src/test.c#main`. It matches none of these rules.
- Effect 1: the target's unit-test suite would enter Phases 1-3 as Tier 1A product code. The model avoided that by restarting with `--scope src/mpack`, and lost `run-1`.
- Effect 2: `seed_harvest.py` builds its recorder from the model's entry points and embedded API. The runner's embedded API includes the `test_*` driver functions, and only outermost calls are recorded, so the harvest recorded `test_system` and `test_common` and nothing from the mpack API. The library unit has `embedded_api: []` and no API entry points. Phase 1 therefore starts with only the 5 imported `.mp` files as seeds.

## run-3

| Parameter | Value |
| :--- | :--- |
| Run directory | `C:\Users\Florian\framac-pipeline\mpack\run-3` (created 02:06:27 UTC, `standard`, no scope) |
| opencode session | `ses_e18bf3f4dffeZGjIvB98TOZiz2` ("framac-verify full mode mpack standard") |
| Pipeline | `phase1-remediation` at `fe9775f` (includes the S1 merge `c9b29a4`) |

| Time (UTC) | Phase | Event |
| :--- | :--- | :--- |
| 02:06:27 | Phase 0 | `run-3` created. |
| 02:11:13 | Phase 0 | The model proposes a different recipe from run-2: `make -C examples sax-example && python3 test/unit/configure.py && ninja -f .build/unit/build.ninja`, with no static library. Its alternative "add a static library unit" was not chosen. |
| 02:12:34 | Phase 0 | Build capture: `runner` **test = false** again; `examples/sax-example` (example plus `src/mpack/*.c`) is the product unit; `flagtest`. **S1 recurrence 1/3**: `mark_test_drivers` requires the product sources to be in a *library*, and here they are in an executable. |
| 02:13:04 | Phase 0 | The model misreads `TEST_DIRS` (it believes `unit` is in it) while diagnosing. The pipeline bug is real, but its explanation is wrong. |
| 02:13:46 | Phase 0 | The model proposes adding a static library to the recipe itself (`build/libmpack.a` from `src/mpack/*.c`), so that S1's library rule applies. The user accepts. The first `set-build` is mangled by host PowerShell (`basename` expanded); the model rewrites it without `$` or quotes. |
| 02:15:52 | Phase 0 | Re-capture in the same run: `runner` is `test` (`main_in_test_source`); `build/libmpack.a` has 319 entry points (public-header fallback); `examples/sax-example` is a product unit. |
| 02:16:36 | Phase 0 | `phase0_model.py run` `ok`: 476 functions (700 in run-2, when the test code was included), 1007 edges, 321 entry points. 128 warnings, all of one kind: `mpack-platform.c` emits the inline functions (`MPACK_EMIT_INLINE_DEFS`), and the model maps each to its header definition. This is benign noise. |
| 02:22:12 | Phase 0 | `seed_harvest.py record` with test command `tools/unit.sh more`: `no_calls_recorded`, exit 127, `sh: 1: tools/unit.sh: not found`. The target checkout is CRLF (`core.autocrlf=true`, `i/lf w/crlf`), so the shebang reads `#!/bin/sh\r`. This is target-side. The model diagnosed it at 02:23:57. At the user's request, a fixer (`sup/crlf-script-check`) is adding an early CRLF-script check and failure hints. |
| 02:25:07 | Phase 0 | Harvest rerun with `python3 test/unit/configure.py && ninja -f .build/unit/build.ninja more`: status `ok`, the suite passes, but only **3 calls** are recorded (`mpack_realloc` ×2, `mpack_tag_cmp`), although the runner was relinked with 342 wrappers. **S2:** the recorder's `fc_depth` counter is not `longjmp`-safe. mpack's tests `longjmp` out of library calls (`test/unit/src/test.c:51`, `TEST_TRUE_SETJMP`), `fc_leave()` is skipped, and every later call looks nested. |
| 02:28:55-02:30:21 | Phase 0 | No fuzz assets: `test/fuzz/fuzz.c` is an AFL stdin harness. The DAG has 3 modules and 12 `libmpack_a` clusters (363 Tier 1A, 77 1B, 28 Tier 2, 8 Tier 3). Security properties: 3. The `.mp` corpus is mapped to `mpack_tree_init_{data,pool}` and `mpack_reader_init{,_data}`. |
| 02:30:34-02:32:14 | Phase 0 | `--api` harnesses for all 12 clusters; the only skipped cases are the 3 `*_init_stdfile` ones (`FILE` is incomplete under Frama-C). |
| 02:32:14-02:34 | Phase 0 | `sax_example` argv harness: **S3**. The argv entry style calls `main(argc, argv)` with no declaration (the comment at `generate_harness.py:1235` claims a synthesized declaration, but none is emitted), so it fails when the module header does not declare `main`. The model's workarounds hit target-side limits: `--include-source` fails because `sax-example.h` has no include guard, and `--header none --include-source` fails because mpack cannot be built as one translation unit (`MPACK_INTERNAL`, include guards). S3 is queued behind the two running fixers. |
| 02:34:18-02:34:41 | Phase 0 | S3 workaround in the run directory: a prototype header `workspace/harnesses/include/sax_main.h` passed with `--extra-include`. The `sax_example` harness then compiles (prelude clean). |
| 02:35:12 | Phase 0 | `flagtest` exempted (the configure flag probe `.build/unit/flagtest.c`). `harness_reach.py check` fails on 4 modules. Three clusters miss only `mpack_{tree,reader,writer}_init_stdfile` (skipped because `FILE` is incomplete). `sax_example` misses 7 extension/timestamp functions that exist only in its build: the example is compiled with `-DMPACK_EXTENSIONS=1` and `libmpack.a` is not. This is a recipe choice, not a pipeline bug; building the library with `-DMPACK_EXTENSIONS=1` would analyse the extension code in the library. |
| ~03:35 | Phase 0 | The model exempts the `*_init_stdfile` cases and the 7 `sax_example` extension/timestamp functions. Its reach gate passes. |
| 03:38:25 | Phase 0 | `pipeline_make.py build-check`: every module is `build_failed`, with `[kernel] workspace/work/src/mpack/mpack-writer.c:1274: User Error: syntax error ... char* __restrict__ p`. **S4**, a pipeline gap. Frama-C 34 knows only `restrict` and `__restrict`. Its own libc defines `__restrict__` (`share/libc/features.h:94`), so Phase 0, Eva and WP parse. The E-ACSL frontend uses host headers (`-no-frama-c-stdlib`), where nothing defines it. mpack spells `MPACK_RESTRICT` as `__restrict__` under `__GNUC__` (`mpack-platform.h:1329`). |
| 03:40:45 | Phase 0 | The model reaches the same diagnosis on its own. As a run-local workaround, it regenerates every harness with `-D__restrict__=restrict` in the cppflags (`state/gen_harnesses2.sh`), then reruns the reach gate and `pipeline_make.py gen`. |
| 03:44 | Phase 0 | `build-check` rerun (container `framac-9f14465bd6b7`). |
| 03:45 | — | **S2 merged live** into `phase1-remediation` (fast-forward to `84f76b6`), under the user's authorisation to intervene. The supervisor reran the longjmp regression test in `framac-build:latest` (gcc and clang PASS) and `tests/test_seed_harvest*.py` on Windows (23 passed, 1 skipped). |
| 03:46:32 | — | Supervisor nudge sent to the session with the user's permission (`opencode run --session`, queued behind the running step). It asks the model to rerun `seed_harvest.py record` with the same test command, regenerate the `--api` harnesses so the new seeds bind, rerun reach, gen and build-check, and keep the `__restrict__` workaround. |
| 03:48:18 | Phase 0 | The nudge is delivered when the build-check step ends. Every module fails at the next step, the clang compile of the E-ACSL output: `fuzz_<mod>.instrumented.c: error: cannot redeclare builtin function '__builtin_add_overflow'`. Frama-C prints `extern int ( /* missing proto */ __builtin_add_overflow)(...)` and `__builtin_mul_overflow`. mpack enables both through `__has_builtin`, which is true under `-G clang` (`mpack-platform.h:1895-1923`). **S5**: the same E-ACSL compat gap as S4, added to the S4 fixer's scope. |
| 03:49:14 | Phase 0 | The model chooses `-DMPACK_HAS_OVERFLOW_BUILTINS=0` itself, so mpack uses its plain C fallback. It adds the flag to `state/gen_harnesses2.sh`, then reruns the capture and seed harvest as the nudge asked. |
| 03:50:39 | Phase 0 | The seed harvest with S2 live returns `ok` in 45 s: **55,714 calls recorded (9,641 unique)**, against 3 before, with 342 functions planned. S2 is confirmed in the live run. |

S1 recurrence: the fix is on `sup/mpack-test-driver-any-holder` at `c57d2ea`, verified by the supervisor (diff read, 15 driver tests pass) and **held** until `run-3` ends. It extends the holder condition to any other non-test unit (library, executable, unlinked) that is not itself a test-driver candidate. On the real tree with the no-library recipe, the runner is `test` and `sax-example` stays product with 342 `mpack_*` embedded-API functions.

## Model struggles that are not pipeline bugs

| Time (UTC) | Message | Observation | Suggested skill or brief change |
| :--- | :--- | :--- | :--- |
| 01:18:52 | `GpZCiEEQ` | The model put `echo EXIT_TRUST=$?` inside the double-quoted wrapper command. Host PowerShell expanded `$?` to `True`, so the exit code was lost. The model noticed and avoided it afterwards. | The `framac-slice` skill warns about host expansion of paths only; it could name `$?` and `$VAR` too and recommend single quotes. |
| 01:25:08 | `ej9elxK6` | The scope can only be set at `init` (`run_metadata.py` has no `set-scope`), so changing the scope after build capture costs a whole new run. | Either add `run_metadata.py set-scope` for Phase 0 before the ledger seed, or have the `framac-slice` skill say to decide the scope before `init` when the build mixes test and library sources. |

## Open pipeline bugs

- run-3: S1b and CRLF are fixed and held on their branches. S3 and S4 have fixers running. The run works around both: S3 with `workspace/harnesses/include/sax_main.h`, S4 with `-D__restrict__=restrict` in the harness cppflags.
- run-1 and run-2: S1 is fixed and merged. Two gaps are noted, not fixed: there is no `run_metadata.py set-scope`, and the shipped `.mp` fixtures are not discovered as a corpus (`fuzz_assets.py` only looks in directories named `corpus`, `seed` or `fuzz`).
