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

## Model struggles that are not pipeline bugs

| Time (UTC) | Message | Observation | Suggested skill or brief change |
| :--- | :--- | :--- | :--- |
| 01:18:52 | `GpZCiEEQ` | The model put `echo EXIT_TRUST=$?` inside the double-quoted wrapper command. Host PowerShell expanded `$?` to `True`, so the exit code was lost. The model noticed and avoided it afterwards. | The `framac-slice` skill warns about host expansion of paths only; it could name `$?` and `$VAR` too and recommend single quotes. |
| 01:25:08 | `ej9elxK6` | The scope can only be set at `init` (`run_metadata.py` has no `set-scope`), so changing the scope after build capture costs a whole new run. | Either add `run_metadata.py set-scope` for Phase 0 before the ledger seed, or have the `framac-slice` skill say to decide the scope before `init` when the build mixes test and library sources. |

## Open pipeline bugs

- None from this run: S1 is fixed and merged. Two gaps are noted, not fixed: there is no `run_metadata.py set-scope`, and the shipped `.mp` fixtures are not discovered as a corpus (`fuzz_assets.py` only looks in directories named `corpus`, `seed` or `fuzz`).
