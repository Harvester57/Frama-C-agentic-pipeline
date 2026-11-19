# nginx 1.31.9 run-5: supervision report

- **Documentation Hub:** [`../README.md`](../README.md)
- **Run reports index:** [`./README.md`](./README.md)
- **Earlier runs:** [`./2026-11-19-nginx-run4-supervision.md`](./2026-11-19-nginx-run4-supervision.md) (run-4), [`./2026-11-19-nginx-run3-supervision.md`](./2026-11-19-nginx-run3-supervision.md) (run-3), [`./2026-11-19-nginx-run1-supervision.md`](./2026-11-19-nginx-run1-supervision.md) (run-1 and run-2)
- **Troubleshooting:** [`../troubleshooting/README.md`](../troubleshooting/README.md)

This report covers the external, read-only supervision of nginx 1.31.9 run-5. run-5 was the first nginx run without OpenSSL: the user asked to drop the TLS code and keep all non-TLS nginx (`src/core`, `src/event`, `src/os`, `src/http` with HTTP/1 and HTTP/2), so the build recipe lost `--with-http_ssl_module`, `--with-http_v3_module` and `libssl-dev`, with no `--scope`. It was driven by Antigravity (Gemini) in a new conversation, from a kickoff prompt the supervisor wrote and the user pasted. The supervisor never wrote in the run directory, never messaged the session and never touched its containers. One mid-run message, written by the supervisor after the user chose an option, was pasted by the user.

## Parameters

| Parameter | Value |
| :--- | :--- |
| Run dir | `C:\Users\Florian\framac-pipeline\nginx-1.31.9\run-5` (`nginx-1.31.9-3e44199e7906 / run-5-1313fab0b611`) |
| Target | `C:\Users\Florian\OneDrive\Documents\Dev\targets\nginx-1.31.9` (no VCS); configure without SSL, QUIC and HTTP/3; packages `libpcre2-dev zlib1g-dev` |
| Session | Antigravity conversation `4d7b54b1-4821-4f82-befb-f18a6ed2b56b`, read through its `transcript.jsonl` and step outputs |
| Pipeline code | worktree `.agents/worktrees/nginx-run5-main`, detached at `2db5762` (main `6217968` with the run-4 report), clean at the start |
| Fix mode | `hold` |
| Poll / stall / recur limit | 2 min / 10 min / 3 |

## Status

**run-5 ended `incomplete` at 21:25, 2 h 49 min after the kickoff at 18:36:32, in Phase 1.** It is the first nginx run to pass Phase 0 (build-check `ok: true` at 20:58). The recorded reason is:

> Phase 1 reach-dynamic gate failed (exit 2, compile_error): coverage build lacks link_repair in checkout 2db5762 so cov_nginx__ngx_bpf and cov_nginx__ngx_http_script failed to link (undefined reference to ngx_core_module, ngx_modules, ngx_module_names); Phase 1 fuzzing ran with --fuzz-engine sanitizers (without E-ACSL) after e-acsl-gcc exceeded 3600s

The report has 0 confirmed findings, 0 needs-validation and 0 rejected candidates, and 5499 open units. It shows `unverified_candidates: 0` although both fuzz campaigns ended `crash_found` (55 distinct fingerprints, none ingested or verified; S16). No container of the run was left.

The earlier fixes worked on the real run: S7 (`objs/ngx_modules.c` kept), S8 (parse history, `p0-f2f1fa9467361a0d`), S10 (stub-check `inconclusive` instead of `violated`; no contract weakened), the feature-test macros, and link repair (it added `src/core/nginx.c` and `objs/ngx_modules.c` to both sanitizer builds, with no duplicate `main`, because `-Dmain=__framac_module_main_<mod>` renames it).

### Timeline

`run-metadata.json` and `progress.json` do not timestamp the steps (only `phase_done` 0 at 20:58:33), so these times come from the supervisor's timeline (file mtimes, container state and transcript steps, local time).

| Time | Step | Duration |
| :--- | :--- | :--- |
| 18:36:32 | Kickoff received; `run_metadata.py init` at 18:36:51 | |
| 18:37:50-18:38:50 | Build capture with no OpenSSL: the model checked `ngx_auto_config.h` (no `NGX_OPENSSL`, `NGX_HTTP_SSL`, `NGX_QUIC`) and that no OpenSSL, QUIC or HTTP/3 source was compiled | 1 min |
| 18:39:00-18:44:07 | Phase 0 model: 1679 functions, 8779 edges (run-4: 2240 and 12167); parse peak 2928 MiB (run-4: 10472) | 5 min 7 s |
| 18:44:12-18:46:51 | CodeQL and trust, after the model this time; seed harvest; fuzz assets (none); DAG: `nginx__ngx_http_script` (1650 functions, 102,784 lines) and `nginx__ngx_bpf` (23 functions) | 2 min 39 s |
| 18:46:59-18:51:46 | 4 stub headers (crypt, pcre2, sys/eventfd, zlib), 4 authors, 20 functions filled; stub-check passes with 7 `inconclusive` records | 4 min 47 s |
| 18:47:22 | Security properties: 15 (run-4: 23) | |
| 18:52:04-19:02:36 | `--api` harnesses with the manual prelude: 582 cases and 34 skips, then three regenerations (`--extra-include` of 8 headers, dispatch cases) to 607 cases and 14 skips; 4 exemptions; reach gate passes with no gaps | 10 min 32 s |
| 19:02:41-19:02:48 | Ledger seed (5522 units), `validate_artifacts` (0 errors), checkpoint, `pipeline_make.py gen` | < 1 min |
| 19:02:54-20:07:01 | `run build --jobs 1` under `-Memory 32g`: E-ACSL instrumentation of `nginx__ngx_bpf`, killed at the 3600 s build limit (S14) | 1 h 4 min |
| 20:07-20:30 | Sanitizer fallback build of `nginx__ngx_bpf` (engine `auto`); the user decides "Sanitizers for both" | 23 min |
| 20:30:37-20:31:14 | The model cancels the build, records `params set --fuzz-engine sanitizers` for both modules, regenerates and restarts the build | < 1 min |
| 20:31:17-20:50:08 | Sanitizer builds: `nginx__ngx_bpf` peak 226 MiB, `nginx__ngx_http_script` peak 360 MiB (lease 3607 MiB each, 555 s and 572 s, no OOM) | 18 min 51 s |
| 20:50:12-20:58:34 | build-check passes: both modules `sanitizers_chosen`; Phase 0 checkpoint | 8 min 22 s |
| 20:58:38-21:17:02 | Phase 1 fuzzing: `crash_found` on both modules | 18 min 24 s |
| 21:17:08-21:24:54 | Coverage and `reach-dynamic`: both coverage builds fail to link (S15); gate exit 2 | 7 min 46 s |
| 21:25:22-21:26:07 | `set-status incomplete`, report | < 1 min |

## Findings and fixes

The numbering continues from the run-4 report.

### S13. `security_props` reads declared callees' `assigns` from the real headers, not from the stub overlay (fixed, held)

- **Fingerprint:** `security_props.py` warning listing all 20 filled stub functions under `declared_callees.no_assigns` of `L4_auth_state_ngx_http_core_access_phase`, right after the stubs were filled and stub-check passed.
- **Cause:** `_Contracts` read `external_decls` (the real headers in the snapshot), never the overlay `workspace/stubs/*.h` that holds the `assigns`. The documented remedy (write the stub, rerun) could not work.
- **Fix (held):** branch `sup/nginx-security-props-stub-assigns` (`f1e4bd3`, `2dffe9c`, `2d9a011`, `95fa07e`, on `2db5762`). An `_Overlay` reads `FRAMAC_STUB_OVERLAY_DIR` or `<run-dir>/workspace/stubs`, skips `FC_STUB_DRAFT` blocks, and its contract wins over the declaration's. `acsl_ast._next_after_params` skips trailing `__attribute__` and `__asm__`. Tests: `tests/test_security_props.py::test_a_stub_overlay_contract_replaces_the_bare_declaration`, `::test_overlay_contracts_by_name_and_without_an_overlay`, `tests/test_header_decl_spans.py::test_a_prototype_with_trailing_attributes_is_a_declaration`. Fixer: 7453 passed, 312 skipped, ruff, mypy, generated-text and docs checks clean. Supervisor: read the diff, 95 passed and 80 skipped on the two test files.
- **Replay on run-5 (read-only):** `no_assigns` goes from 24 to 5 (`accept4`, `posix_fadvise`, `pwritev`, `statfs`, `strerrordesc_np`, which have no prototype); the nginx instances do not change. **Open:** `run_wp_function._set_assigns_functions` does not read the overlay either.

### S14. An E-ACSL build killed at the build time limit is reported as a generic failure (report fixed, held; the cost is open)

- **Fingerprint:** `workspace/harnesses/fuzz_nginx__ngx_bpf.compile.log`, `Returncode: 124`, last line `/home/opam/.opam/5.5/bin/e-acsl-gcc exceeded the 3600 s build time limit`.
- **What happened:** the 23-function `nginx__ngx_bpf` builds 135 of the 137 files (O1), so its E-ACSL instrumentation is a whole-program Frama-C. The container was at 10.68 GiB at 35 minutes, 3.0 × the 3607 MiB lease and 3.7 × the parse peak. At 3600 s `fuzz_build._run_tool` killed it; no instrumented file was written. Engine `auto` fell back to ASan/UBSan. build-check would have shown a bare `eacsl_fallback` with `first_error: null` and no `next_step`, and `nginx__ngx_http_script` would have spent another hour the same way.
- **User decision (20:20):** fuzz both modules with the sanitizers. The supervisor wrote the message, the user pasted it. Phase 1 lost the E-ACSL-only checks (sub-object overflow, `\initialized`).
- **Fix of the report (held):** branch `sup/nginx-eacsl-build-timeout` (`20f8c53`, `90cb8cd`, `c0d9e7d`, `a28b5dc`, on `6217968`). `fuzz_build` gives reason `eacsl_build_timeout`; `KNOWN_EACSL_FAILURES` gets it first, with the limit parsed from the log and the sanitizers `next_step`; `_first_build_error` returns the limit line; the `fuzz-<mod>` gate message says a smaller unit is the fix. Tests: `tests/test_pipeline_make.py::test_build_check_names_an_eacsl_build_killed_at_the_time_limit`, `tests/test_tool_sizing.py::test_an_instrumentation_killed_at_the_build_time_limit_is_named_as_such`, and one changed assertion; 3 failed before the fix. Fixer: 7452 passed, 312 skipped, all checks clean. Supervisor: read the diff, 158 passed and 1 skipped on the two files, ruff clean.
- **Open:** the whole-program instrumentation cost itself (the unit split), and, found by the fixer, a MetAcsl properties build killed at the limit would be followed by a second, plain E-ACSL build of another hour.

### S15. The coverage build has no link repair (fixed, held)

- **Fingerprint:** `reach-dynamic` exit 2; `workspace/reports/coverage/<mod>.json` `status: compile_error`, `reason: the coverage build failed`; `cov_nginx__ngx_bpf.coverage_compile.log`: `undefined reference to 'ngx_core_module'`, `'ngx_modules'`, `'ngx_module_names'`.
- **Cause:** `fuzz_coverage.coverage_report` calls `fuzz_build.compile_coverage_binary` once with the module's raw sources. Only the fuzz, sanitizer and replay builds run `repair_sources_for_link`. The troubleshooting entry from ptf-original run-2 (2026-11-10) said this was fixed ("uncommitted"); that fix never reached the code.
- **History:** a scan of every ref found 81 versions of `coverage_report` across 99 commits, none taking a DAG or calling `repair_sources_for_link`.
- **Fix (held):** branch `sup/nginx-coverage-link-repair` (`acd2ef6` fix, `4703a87` and `c4385f1` docs, on `6217968`). The repair loop moves out of `build_module_binary` into `fuzz_build.repair_link_rounds`, unchanged; the new `build_coverage_binary` uses it, and `coverage_report` records the final `sources` and `link_repair`. `run_eacsl_fuzz.py coverage` gets `--dag` with the build's default (`workspace/reports/callgraph_dag.json`). The same gap is closed in `minimize --sources` and in the candidate replay builds of `crash_replay` (`replay-candidates`, `minimize-candidates`), which would have failed on nginx the same way. Tests: six in `tests/test_coverage_link_repair.py` (five failed before the fix, one guard passed) and `tests/test_harness_reach.py::test_coverage_after_link_repair_is_measured_like_any_other`. Fixer: 7458 passed, 312 skipped, all checks clean. Supervisor: read the diff, 135 passed and 5 skipped on the touched test files, ruff and mypy clean.
- **Read-only replay on run-5:** with run-5's DAG, model and the failed compile output kept in each coverage report, round 1 adds exactly `src/core/nginx.c` and `objs/ngx_modules.c` for both modules, the same as their fuzz builds. Not verified by a real rebuild.
- **Open:** the `guardrail` mode and the loop-seed guard (`loop_seeds.py`) still build without link repair. The fixer also saw one unexplained failure of `tests/test_benchmark.py::TestFetch::test_checkout_is_pinned_sparse_and_byte_exact` (passed alone and in two later full runs), recorded in `resources-and-infra.md`.

### S16. The report of a run stopped in Phase 1 hides its fuzz crashes (open)

- Both campaigns ended `crash_found`: 90 kept artifacts, 55 distinct fingerprints, 2 artifacts with no fingerprint. Most are `mem_access` in functions the `--api` harness calls directly with fabricated structures (`ngx_create_pidfile`, `ngx_init_cycle`, `ngx_init_setproctitle`, `ngx_palloc_small`, `ngx_http_variables_init_vars`, the `ngx_http_script_*_code` handlers), so many are probably harness-induced. One is a UBSan `division_by_zero` in `ngx_hash_find`. None was verified.
- `generate_report.py` lists only `candidates.json`, which `ingest` writes after fuzzing and Eva, so `REPORT.md` names none of them. Recorded as an open pipeline bug in `ledger-and-verifier.md`.

### Other observations

- **The unit split (O1)** still makes one cluster of 1650 of 1679 functions. Measured on run-5's model: 4761 of 8779 edges are indirect, resolved by signature (`cmd->set` 109 candidates, variable `get_handler` 88, event handlers 43), and Alias narrowing is off (`narrowing_reason: disabled`). With direct edges only, no function reaches more than 286 functions (`ngx_http_upstream_init`). With indirect edges, 405 functions reach more than 1000 each (`ngx_destroy_pool` 1 → 1092, `ngx_output_chain` 36 → 1092), so the overlap merge folds everything together. This is the root of S14, and the next risk is Eva's 7200 s cap on that cluster.
- **Stub-check `inconclusive` (non-blocking):** six pcre2 functions (exit -11, fabricated opaque handles) and `deflate` (exit -6): `E-ACSL RTE failed ... \valid_read(&strm->avail_out)` with `strm` NULL, because the driver passes NULL for the typedef'd pointer `z_streamp` (S10's documented limit). The contract is correct and was not changed; it is never exercised dynamically.
- **`"RWF_*" redefined` warnings:** 952 in the E-ACSL compile log, located at `workspace/stubs/sys/eventfd.h:1043` against `templates/acsl/acsl_vocabulary.h:1371`, but the overlay has 24 lines and the vocabulary 68. The positions come from Frama-C's annotation preprocessing, not from the files. Noise, not investigated further.
- **build-check rebuilt both modules** (473 s and 481 s, peaks 161 and 296 MiB by rusage) although `run build --jobs 1` had just built them. Not diagnosed.
- **The first-build estimate** asked 3607 MiB for an E-ACSL build that used at least 10.68 GiB (open, added to `resources-and-infra.md`). The killed attempt left no resource-history record.

## Troubleshooting entries and upstream drafts

- `security-properties.md`: S13 (on its branch).
- `eacsl-and-fuzzing.md`: S14, under the heading the run's model used, so the two merge into one entry (on its branch).
- `harnesses-and-seeds.md`: S15, correcting the false "fixed" claim of the ptf entry and adding the guardrail and loop-seed gap (on its branch).
- `ledger-and-verifier.md`: S16, new open entry.
- `resources-and-infra.md`: run-5's measured E-ACSL memory added to the open first-build estimate entry; a cross-link to S14 (on S14's branch).
- The run's model also wrote uncommitted entries for S14 and S15 in the run checkout (`.agents/worktrees/nginx-run5-main`). They are superseded by the branch versions and were left in place.
- No upstream draft: none of these is a Frama-C or E-ACSL bug.

## Model behaviour (not pipeline bugs)

- **Good throughout.** Gemini kept every rule the kickoff set: the no-OpenSSL checks after the capture, CodeQL after the model, stub authors given the run checkout only, no weakened contract over an `inconclusive`, no preprocessor lines in the overlay, the manual prelude at once, `--extra-include` chosen from the skip reasons, dispatch cases for the pthread, regex, shm and printf functions, four exemptions each with a specific reason (`main`, `ngx_thread_cond_wait`, `ngx_thread_task_post`, `ngx_vslprintf` naming its `ngx_slprintf` case), no gate run during a regeneration, exit codes read before any claim, and peaks reported from the resource history.
- **Mid-run decision.** On the user's message it cancelled the build, removed the run's own container, recorded both `params set` choices through a `set -e` script, regenerated and rebuilt, and recorded the reason in a troubleshooting entry. It did not take the sanitizers on its own.
- **Stop.** On the `reach-dynamic` failure it opened the coverage log, found the missing link repair, wrote an entry, set the run `incomplete` with the exact reason and ran the report, as the kickoff said.
- **Minor:** one harmless malformed tool call (step 174) and one inline Python syntax error in an inspection command (step 42).

## Open items

- Open pipeline bugs: O1 (unit split on callback-heavy C, root of S14), S14's whole-program E-ACSL cost and the MetAcsl double build, the guardrail and loop-seed builds without link repair (S15), S16, S11 (automatic prelude), S12 (`__fc_` pthread tags), the exemption gate gap, no direct case for a `va_list` function, the first-build E-ACSL estimate, S13's `run_wp_function` gap, the `z_streamp` driver limit, and the errno Docker test.
- Held branches; a dry run merged all five onto `origin/main` without conflict: `docs/nginx-run4-report`, `sup/nginx-security-props-stub-assigns`, `sup/nginx-eacsl-build-timeout`, `sup/nginx-coverage-link-repair`, and this report's `docs/nginx-run5-report`.
- Not verified: Eva on the 1650-function cluster (never reached), the 55 crash fingerprints, and why build-check rebuilt both modules.
