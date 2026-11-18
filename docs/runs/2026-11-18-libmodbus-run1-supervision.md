# libmodbus run-1: supervision report

- **Documentation Hub:** [`../README.md`](../README.md)
- **Run reports index:** [`./README.md`](./README.md)
- **Troubleshooting:** [`../troubleshooting/README.md`](../troubleshooting/README.md)

External, read-only supervision of the opencode-driven `standard` run of libmodbus (CodeQL enabled). This report is updated at each milestone.

## Parameters

| Parameter | Value |
| :--- | :--- |
| Run dir | `C:\Users\Florian\framac-pipeline\libmodbus\run-1` (run identity `libmodbus-d4227309de07 / run-1-f3ba5cce4b09`) |
| Target | libmodbus `a9b025d` (dirty: untracked `.security-reviews/`), Windows checkout with `core.autocrlf=true` |
| Session | opencode `ses_e13dfc5feffeooCF0PFudZYlr8`, model `deepseek-v4.1-flash` |
| Integration branch | `phase1-remediation`, baseline `19c038e` |
| Fix mode | `hold`; from 02:01 the user asked to land the blocking fixes live and resume the session, then to supervise autonomously overnight |
| Poll / stall / recur limit | 2 min / 10 min / 3 |

## Status

**Phase 3, running, recovering from fix 15.** New agents were on hold from 09:40 for the guardrail timeout. At 10:07 the schedule held 12 prove tasks done, 32 blocked, 37 pending, 12 running and 10 skipped. No prove task merged before 08:37: every parent WP re-check was refused for memory (fix 13). **Correction:** the "48 done" and "68 done" counts reported earlier in this run held only verifiers, breakers, negotiations, the architect and the repair task, and no proof.

Phase 0 completed and validated at 03:06, after 7 pipeline fixes (01:51-03:06 wall clock, including about 70 min of fix and wait time). Phases 1-2 and the crash verification gate ran 03:07-05:59, with two harness repairs. 13 pipeline issues so far.

## Timeline (supervisor's observations, local time, 2026-11-18)

| Time | Event |
| :--- | :--- |
| 01:48 | Session starts, reads CLAUDE.md and the skills |
| 01:51:32 | Run dir created, metadata initialised (`standard`), build recipe and CodeQL declaration recorded |
| 01:52:43 | `build_capture.py run`: `needs_build_recipe`, `./autogen.sh: 22: Syntax error: end of file unexpected (expecting "then")` |
| 01:53:25 | User picks "strip CRs inside the recipe" |
| 01:54:29 | `build_capture.py run`: `needs_build_recipe`, `./configure: line 14962: syntax error near unexpected token` (CRLF `configure.ac`) |
| 01:55:01 | The model widens the CR strip to every text file of the scratch copy, without asking again |
| 01:55:56 | Build capture `ok`: 1 product unit (`libmodbus.so.5.1.0`, 4 sources, 71 entry points), 9 test executables, and a stray `unlinked:/tmp/cg7zzCGG` |
| 01:56:12 | `phase0_model.py run`: `no_unit_parsed`, `src/modbus-rtu.c:254: User Error: Cannot resolve variable TIOCM_RTS` |
| 02:01 | User stops the session and asks the supervisor to land the fix and resume |
| 02:20 | Supervisor resumes the session (fixes 2 and 3 merged) |
| 02:21-02:25 | Build capture `ok` (probe unit gone), model `ok` (120 functions, 161 edges), threat model check `ok`, CodeQL 13 facts on 8 functions (6 unmatched test `main`s), seeds `not_relinked` (0 calls), DAG: 1 Tier 1A module, no split; security properties `ok` |
| 02:25:35 | `generate_harness.py`: `'workspace/work/config.h' file not found`; the session stops and reports (02:28) |
| 02:32 | Fix 4 merged; session resumed, told to stop before Phase 1 |
| 02:32-02:36 | DAG `force_includes` now the snapshot copy; harness generated with 20 cases and 51 skipped (`no constructor for opaque handle`); reach gate fails on 51 gaps; session stops and asks |
| 02:39 | Fix 5 merged; session told to rebuild the scratch tree and re-record seeds, then wait for fix 6 |
| 02:40-02:42 | Capture, model, threat model checks, DAG and security properties rebuilt identical; seeds `ok`: 321 calls (189 unique) over 46 API functions, 9 of 10 executables relinked |
| 02:43 | Fix 6 merged; session told to regenerate the harness, pass the reach gate, finish Phase 0 and stop before Phase 1 |
| 02:44-02:45 | Harness: 67 of 71 entry points with a case (68 cases incl. one `modbus_t` lifecycle case); reach gate: 3 internals exempted, `modbus_proxy` the only gap; session asks |
| 02:47 | Supervisor approves a hand-written `modbus_proxy` case (with changes) |
| 02:47-02:49 | Harness regenerated (69 cases incl. the custom `modbus_proxy`), reach gate passes (0 gaps, 3 exemptions), ledger seeded (215 units), stubs and stub-check ok |
| 02:49 | `pipeline_make.py run seed`: `validate_artifacts.py` rejects the sidecar (`$.api_cases[67].rest: expected type null`); session stops and asks |
| 02:52 | Fixer dispatched for fix 7 (`sup/libmodbus-lifecycle-rest`) |
| 03:03 | Fix 7 merged; session told to regenerate the harness, rerun the reach gate, seed, gen, build-check and validate, then stop before Phase 1 |
| 03:02-03:06 | Harness regenerated (69 cases; lifecycle case: 16-byte `ip` slot + `port`, `rest` null, no warnings), reach gate `gaps: []`, `run seed` validate ok, `gen` ok (1 module), build-check ok (E-ACSL engine, sanitizer build), final `validate_artifacts` ok; ledger 215 planned units; Phase 0 checkpoint (`phase_done` 0) |
| 03:08 | Supervisor tells the session to run Phases 1-3 and the report without stopping between phases |
| 03:07-03:10 | Phase 1: build cached; fuzz (E-ACSL + sanitizers, 9 workers, 1200 CPU-s budget) ends after 165 s with `crash_found`, 63 artifacts. Most are harness-induced: ASan stack overflows in `modbus_get_float_*` (one `uint16_t` passed, two read), SEGVs in `modbus_set_bits_from_bytes`/`modbus_get_byte_from_bits` (unbounded `nb_bits`), direct leaks from `modbus_new_tcp`/`modbus_mapping_new_start_address` (handle released with `modbus_close`, never `modbus_free`). The session saw the same and sends them to the crash verification gate rather than reporting them |
| 03:11 | Coverage and reach-dynamic ok; fixer dispatched for fix 8 (`sup/libmodbus-harness-contracts`) |
| 03:12-03:22 | Phase 2 Eva `ok` in 638 s: 3707 properties, 92.9 % discharged, 250 unknown, 13 invalid, 2499 dead, 562 assumed; 51 functions with unknowns |
| 03:23-04:24 | `eva-tune` runs its rungs serially. The first (`slevel` 1000) runs at 100 % CPU against a 4957 s limit, with 7 rungs queued. At 04:23 the session's 1 h tool timeout fires; at 04:24 the session kills `eva-tune` under the 15-minute rule and keeps the base Eva report. The existing open gap in `eva.md` gets a "seen again" |
| 04:25-04:26 | `pipeline_make.py run ingest` ok; `phase_done` 2; the session moves to candidates and the WP queue |
| 04:28-04:40 | Replay and WP queue ok. The crash gate has 26 verifier tasks plus breakers, dispatched 15 at a time. The first 7 verdicts are all `rejected` (harness-induced): the 4 `get_float_*`, `set_bits_from_byte`, and `free` from `modbus_mapping_free`. The scheduler opens `repair:libmodbus_so_5_1_0` |
| 04:45 | Fix 8 merged (`5a9ff81`); repair guidance queued for the session's next idle window |
| 04:43 | Repair guidance delivered while the session was idle; it acknowledges and will regenerate once every verifier has reported |
| 04:43-04:48 | 14 gate verdicts in. 12 are `rejected` `harness_induced` (float helpers, bit helpers, `modbus_mapping_free` from two fingerprints). 1 is `rejected` `contract_overconstraint` (`close`: Frama-C's arbitrary fd bound). Breakers `modbus_new_rtu` and `modbus_new_tcp_pi` are clean; `modbus_mapping_new_start_address` files a signed-downcast hypothesis that goes to the gate. **1 is `confirmed`**: the libFuzzer timeout, as an "unbounded link-recovery retry loop in `send_msg`, medium DoS" |
| 04:50-04:55 | `send_msg` guidance delivered and acknowledged. Verdicts: `set_float_dcba`, `new_tcp_pi` leak and `set_bits_from_bytes` are harness-induced; `tcp_listen` init is `disproved_by_source` (E-ACSL and glibc `strlcpy`); both accept-path `close` alarms duplicate the `contract_overconstraint` |
| 04:54-05:07 | Session idle with no activity (monitor STALL at 05:06). The supervisor finds 4 prepared verify tasks that were never spawned (fix 11) |
| 05:08 | Session told to spawn them; fix 10 (`strlcpy` effects) merged as `99039ce` |
| 05:09-05:23 | The 6 missing verifiers run. Final pre-repair tally over 26 verdicts:<br>- **rejected, `harness_induced`:** most verdicts: the float and bit helpers, `modbus_mapping_free`/`free`, the constructor leaks, and `tcp_pi_listen` (TCP context read as TCP-PI)<br>- **rejected, `contract_overconstraint`:** 3 (`close`)<br>- **rejected, `disproved_by_source`:** 1 (`strlcpy`)<br>- **`needs_validation`:** 1 (signed downcast of the start addresses in `modbus_mapping_new_start_address`, no witness)<br>- **`confirmed`:** 1 (`send_msg` documented loop) |
| 05:23-05:35 | Repair 1: `--record-repair`, regenerate with the fixed generator (68 cases, `modbus_mapping_free` skipped), and 2 hand fixes in both harness copies (TCP-PI single cases built with `modbus_new_tcp_pi`; LINK bit cleared). Reach gate ok; `module-<mod>` 555 s. Re-fuzz: 14 artifacts, against 63 before |
| 05:35-05:48 | Re-fuzz candidates: `modbus_reply_exception` x2 is harness-induced (the lifecycle loop passes a short tail of the input as an unsized request; see the open item of fix 7); `tcp_pi_listen` init is `disproved_by_source` (E-ACSL and `getaddrinfo`); `tcp_pi_listen` mem (reopened) is harness-induced (TCP-PI methods in the lifecycle case) |
| 05:48-05:59 | Repair 2 (the last allowed), by hand: the lifecycle methods get their own TCP-PI context and a copied, zero-padded request buffer. `module-<mod>` 559 s. Refresh: **no new candidates**; the gate is open |
| 06:00 | Phase 3: the header architect and one breaker run, and provers wait for the architect's merge. Scheduler: 34 done, 101 pending, 10 skipped |
| 06:00-06:45 | The architect takes 2742 s against its 900 s budget and merges 54 contracts; 14 provers and 1 negotiation start. The first prover, `_error_print`, proves 8 of 9 goals and asks for `valid_read_string(\result)` on `modbus_strerror` |
| 06:51-07:11 | Most provers stall on Frama-C libc-model limits, while all their runtime-error goals are proven:<br>- frames naming `__fc_sockfds`/`__fc_fds`/`Frama_C_entropy_source` fail the E-ACSL guardrail (fix 12);<br>- the `ioctl` footprint aborts WP (`_modbus_rtu_close`, `_modbus_rtu_connect`);<br>- the `nanosleep` contract only gives a non-strict decrease (`_sleep_response_timeout` variant);<br>- `<< 8` overflow goals are left to WP's uninterpreted `lsl`.<br>The session records each in `wp-and-guardrail.md`. The overdue IPv4-options negotiation is told to finalize (06:52) |
| 07:02 | Fixer dispatched for fix 12 (`sup/libmodbus-libc-model-ghosts`) |
| 07:14 | `modbus_strerror` proves the requested `valid_read_string(\result)`; 36/37 goals proven |
| 07:21 | Fix 12 merged live as `9250359`; the session is told to pass the frame note to every new socket/termios prover, negotiation and breaker, and to the ones still running |
| 07:25-07:33 | The fix works in the agents' scratch overlays: the `_modbus_tcp_recv` negotiation proves every goal with the `__fc_fds` frame, and the guardrail passes. `compute_data_length_after_meta` proves 33/33 after its negotiation; `_modbus_tcp_is_connected` and the `_modbus_tcp_send` retry prove fully. None of these reached the merged tree (fix 13) |
| 08:24 | Supervisor opens the blocked tasks: 0 prove tasks done, 34 blocked, 12 of them `insufficient_memory` on the parent WP re-check. Every scheduler call ran with `-Class light` (1 GiB) |
| 08:37 | Session told to use `-Class verify`; the first real merge lands (`negotiate:_modbus_rtu_get_response_tid`, `done:applied`). No new refusal afterwards |
| 08:56 | Fix 13 merged live as `0dbfddd`; the recovery command `requeue --memory-refused` is queued for the session's next idle moment |
| 09:08 | 12 prove tasks have merged after the fix 13 recovery |
| 09:09 | Two seeds that hang on replay enter the shared corpus (`seed-ce4942acc3eaa255`, `seed-b5d3116add13facb`) |
| 09:10 | Every guardrail from here on ends `guardrail_error`, rc 70, on the same libFuzzer timeout input |
| 09:26 | The session escalates the guardrail blocker |
| 09:40 | Session put on hold: no new agents, and results hit by the timeout stay uncompleted. Fixer dispatched for issue 15 (`sup/libmodbus-guardrail-hang`) |
| 09:47 | Fix 14 merged live as `f24f382` |
| 09:49 | Session runs `requeue --locate-failed`: 1 prover and 3 negotiations back in the merge queue, 1 negotiation rerun, 4 requests reopened, 3 tasks left to their running `-2` agents, 0 errors |
| 10:00 | **Supervisor error:** the `step` I told the session to run after that recovery reached the parent guardrail, which still had the timeout. 0 merged, 4 failed, and the 4 restored results went back to `pending`. The locator itself worked. The guardrail fixer was told to restore these 4 results to the merge queue |
| 10:27 | Fix 15 merged live as `fd69371`; the recovery command `requeue --guardrail-hung` and the end of the hold are queued for the session's next idle moment |
| 10:32 | Recovery result: 4 restored results merged with 0 failures, 19 tasks reopened, dispatching resumed |
| 10:44-10:50 | Five negotiations that changed nothing are refused by the frame check; the fixer for fix 16 is dispatched at 10:52 and the session holds their next results |
| 11:05 | Fix 16 merged live as `6719f9d`. Two of the five results were already in a merge that started before the fix |
| 11:22 | Four of the five negotiations are applied. `_modbus_rtu_pre_check_confirmation` ended `done/rejected` on the old scripts |
| 11:40 | `requeue --frame-refused` merged live; the recovery of that negotiation is queued for the session's next idle moment |
| 04:49 | Supervisor finds the confirmed `send_msg` loop documented in `docs/modbus_set_error_recovery.md` ("an infinite close/connect loop until success on send call" under `MODBUS_ERROR_RECOVERY_LINK`). The harness had enabled LINK on a context with no peer, so the verdict is a false positive. Guidance prepared: keep the record, report it as documented behaviour, and mask LINK in the regenerated harness |

## Pipeline issues and fixes

| # | Fingerprint | Category | Branch / commit | Status |
| :--- | :--- | :--- | :--- | :--- |
| 1 | `build_capture.py run`: shell `Syntax error` from a CRLF `autogen.sh`, and `configure` syntax error from a CRLF `configure.ac`, with no CRLF hint in `build_capture.json` | pipeline gap (the CRLF checkout itself is target-side) | `sup/libmodbus-crlf-dash-hint` `41c20e9`, `3738ea6` | verified, held until the run ends (the run no longer needs it) |
| 2 | `phase0_model.py run`: `unlinked:/tmp/<cgXXXXXX>` unit, `source file '/tmp/.../dummy.c' does not exist` (GNU `config.guess` libc probe captured as a product unit) | pipeline bug | `sup/libmodbus-config-guess-probe` `0b3b43b` | merged live into `phase1-remediation` (fast-forward) |
| 3 | `phase0_model.py run`: `Cannot resolve variable TIOCM_RTS` (`__fc_libc` `<sys/ioctl.h>` has `TIOCMGET` but not the `TIOCM_*` modem bits) | pipeline gap + upstream Frama-C libc gap | `sup/libmodbus-tiocm-bits` `f0bea19` (+ docs `a6e33f8`, `47fb030`), merged live as `34f8747`; also adds `TCGETS2`..`TCSETSF2`, the next missing macros; upstream draft 41 (not filed) |
| 4 | `generate_harness.py --api`: `the harness does not compile outside its cases: <built-in>:1:10: fatal error: 'workspace/work/config.h' file not found` (DAG roots a generated force-include at the work tree) | pipeline bug | `sup/libmodbus-generated-force-include` `9f7b123`, merged live as `222d1d3` | fixed; the run reruns the DAG and the harness |
| 5 | `seed_harvest.py`: `not_relinked`, every test executable `no_api_function` (the recorder wraps only API functions the executable defines; libmodbus tests call them from the shared library) | pipeline gap | `sup/libmodbus-seed-shared-lib` `6212e3b` (+ skill wording `041048f`), merged live as `5ef9ea4` | fixed: 0 -> 321 calls over 46 API functions in the fixer's repro; two narrower libtool sub-gaps stay open (see the entry) |
| 6 | `generate_harness.py --api`: 51 of 71 entry points `no constructor for opaque handle struct _modbus *`, reach gate 51 gaps (`_INIT_NAME_RE` accepts `new`/`create` only as a suffix, so `modbus_new_tcp` is no constructor) | pipeline bug | `sup/libmodbus-new-ctor-name` `08bec6c`, merged live as `c8484c6` | fixed; a `char *device` constructor parameter is not treated as a path (open, narrow) |
| 7 | `pipeline_make.py run seed` -> `validate_artifacts.py`: `harness_<module>.json: $.api_cases[N].rest: expected type null` (the lifecycle case's constructor `modbus_new_tcp` binds its `const char *ip` to the rest of the input, which the method loop also reads; the generator only records a schema warning) | pipeline bug, exposed by fix 6 | `sup/libmodbus-lifecycle-rest` `8e0472b`, `f40993b`, fast-forwarded live | fixed; the run regenerates the harness. Narrow leftovers stay open (see the entry) |
| 8 | Phase 1 fuzz: harness-induced crashes. (A) `_DTOR_NAME_RE` picks `modbus_close` over `modbus_free` as the destructor of `modbus_t`, so every case leaks the context. (B) A pointer-to-scalar argument is one element although the callee reads two (`modbus_get_float_*`). (C) `_ARRAY_COUNT_RE` does not know `nb`/`nb_bits` counts, so they stay unbounded | pipeline bugs (harness generator) | `sup/libmodbus-harness-contracts` `f59649e`, `8385bd1` | verified (full suite, ruff, mypy green; in a replay of the 239 crash inputs, every A/B/C crash and leak is gone). Merged live as `5a9ff81` at 04:45, once the crash gate had rejected these crashes as harness-induced and opened `repair:libmodbus_so_5_1_0` |
| 10 | Gate: `modbus_tcp_listen` E-ACSL `\initialized(&ctx_tcp->ip[0])` at modbus-tcp.c:632 (verifier: `disproved_by_source`). `strlcpy` resolves to glibc 2.38+ (`HAVE_STRLCPY`), and `EACSL_LIBC_EFFECTS` has no `strlcpy`/`strlcat` entry | pipeline gap (named in the existing entry's "remaining gaps") | `sup/libmodbus-strlcpy-effect` `af0b259`, `14237e9`, merged live as `99039ce` | fixed: Docker probe cases 9-12 (clean after the copy, still stops one byte past it); full suite green |
| 11 | Gate: orchestrator idle from 04:54, waiting for 4 verify tasks prepared at 04:44-04:46 whose subagents were never spawned | model error + pipeline gap (no detection of a prepared task that was never dispatched) | none | open; entry in `wp-and-guardrail.md`; supervisor told the session to spawn them (05:08) |
| 9 | Phase 1 fuzz: `modbus_tcp_pi_listen` SEGV at modbus-tcp.c:684 (a TCP context, built by `modbus_new_tcp`, read as a TCP-PI context) | pipeline bug (one constructor per handle type, whatever backend the method expects) | none | open; recorded |
| 12 | Phase 3 guardrail: `eacsl_instrumentation_failed`, `modbus-tcp.c:<n>: unbound logic variable __fc_sockfds` (also `__fc_fds`, `Frama_C_entropy_source`). WP proves the frame that names the `__fc_libc` model object, but the guardrail builds with host headers that lack it | pipeline gap | `sup/libmodbus-libc-model-ghosts` `1ea83a1`, `f89ce15`, merged live as `9250359` | fixed: weak definitions with `__fc_libc`'s types in the `__FRAMAC_EACSL__` branch of `fc_compat_types.h` (an `extern` fails the link, since full memory tracking registers every global). Docker repro before/after; full suite 6245 passed. Confirmed in the run by the `_modbus_tcp_recv` negotiation (07:28) |
| 13 | Phase 3 merge: `parent WP check on merged tree returned status='analysis_error': insufficient_memory` (`this job may use 1024 MiB, but WP needs at least 1768 MiB`). `step` was not inferred as `verify`, the session passed `-Class light`, and the scheduler treated the refusal as a failed proof | pipeline bug + model error | `sup/libmodbus-merge-memory` `62a54cf`, `10b1fac`, merged live as `0dbfddd` | fixed; full suite 6260 passed. Recovery `wp_scheduler.py requeue --memory-refused`, replayed on a copy: 11 provers and 2 negotiations re-merged, 7 negotiations rerun, 25 requests reopened. 5 partial contracts are not retried (open) |
| 14 | Phase 3 merge: `src/modbus-rtu.c: could not locate definition of function 'modbus_rtu_get_rts'`. The scanners of `acsl_ast.py` counted braces across both arms of an `#if`, so later functions were invisible: 12 of 25 scheduled in `modbus-rtu.c`, 14 of 25 in `modbus-tcp.c` | pipeline bug | `sup/libmodbus-locate-conditional` `15e08a5`, `c270863`, merged live as `f24f382` | fixed; full suite 6318 passed. Recovery `wp_scheduler.py requeue --locate-failed`. `c_definitions.py`, `cache.py` and `build_capture.py` keep the naive count (open) |
| 15 | Phase 3 guardrail: `guardrail_error`, rc 70, `crash_input: .../timeout-fff6050c11a5852f44e8a5c3af1d2ae1ee74ec4e`, for every function since 09:10. Promoted seeds are always replayed, and a libFuzzer timeout was never dropped as an excluded input. The two seeds hang because harness case 66 installs a closed descriptor and `modbus_receive` has no timeout | pipeline bug, triggered by a harness-induced hang | `sup/libmodbus-guardrail-hang` `a4618f1`, `2d45df3`, `db6a9e4`, merged live as `fd69371` | fixed; full suite 6382 passed. Recovery `wp_scheduler.py requeue --guardrail-hung`, replayed on a copy: 4 results back in the merge queue, 19 tasks reopened, 21 requests restored. Hanging seeds with no `timeout-` artifact can still be promoted, and both seeds stay in the run's corpus (open) |
| 16 | Phase 3 merge: `frame-preservation check failed ... projected frame clause missing or weakened` on negotiations that proved the contract already on the tree. The check read only the files the agent changed, so an unchanged result gave it no contract text | pipeline bug | `sup/libmodbus-noop-frame` `eb225df`, merged live as `6719f9d` | fixed; full suite 6391 passed. Recovery `wp_scheduler.py requeue --frame-refused` (`sup/libmodbus-frame-recovery` `68b40d7`, merged live; full suite 6412 passed), replayed on a copy: 1 negotiation restored, 2 requests reopened |

Tests added:

- `tests/test_crlf_scripts.py`: `test_a_shell_syntax_error_on_a_crlf_script_gets_the_hint`, `test_a_shell_syntax_error_naming_no_crlf_script_gives_no_hint`, `test_crlf_autotools_inputs_are_found`, `test_a_configure_syntax_error_from_a_crlf_configure_ac_gets_the_hint`, `test_a_build_failing_with_a_syntax_error_in_a_crlf_script_gets_the_hint` (branch 1).
- `tests/test_build_capture.py::TestRecordedEvents::test_config_guess_temp_dir_probe_is_dropped` (merged).
- `tests/test_unit_view.py::test_generated_force_include_resolves_to_its_snapshot_copy` (merged).
- `tests/test_seed_harvest.py::test_record_wraps_api_functions_the_executable_calls_from_a_shared_library`, `::test_undefined_functions_reads_the_dynamic_symbol_table`, `tests/test_seed_harvest_shared_lib.py::test_recorder_wraps_calls_into_a_shared_library` (merged; the last is Linux-only and skips on the Windows host).
- `tests/test_api_harness_lifecycle.py::test_a_lib_new_kind_constructor_builds_the_handle` (merged).
- `tests/test_api_harness_lifecycle.py::test_a_lifecycle_constructor_string_is_a_bounded_slot_never_the_rest`, `::test_an_out_parameter_lifecycle_constructor_string_is_a_bounded_slot_never_the_rest`, `::test_a_lifecycle_constructor_byte_pair_never_takes_the_rest`, `::test_an_out_parameter_constructor_string_in_a_single_case_is_a_slot_and_the_call_keeps_the_rest` (merged).

## Model struggles (not pipeline bugs)

- 01:52, 02:00: inline PowerShell double-quoted commands expanded `$?` and `$(frama-c ...)` on the host. The model noticed and switched to `-ScriptFile`.
- 01:55: the model changed the confirmed recipe a second time (CR strip over every text file) on its own reading of the user's earlier answer, although the brief said not to change the recipe on its own. The change was harmless (scratch copy only).
- 02:33-02:36: the model read `handle_functions`'s docstring ("returns the handle type and takes none") as "a constructor takes no parameters" and proposed writing 51 dispatch cases; the code means "no handle parameter". The docstring is reworded by fix 6.
- 02:24: the model removed the build scratch volume right after seed recording, so re-recording seeds needs a rebuild.
- 02:25: the model passed a Python file to `-ScriptFile`, which runs it with bash (`import: command not found`), then rewrote it as bash with a heredoc. The wrapper's `-ScriptFile` help could say it must be a shell script.
- 02:28: the run brief asks the model to send its progress report with SendUserFile, a tool opencode does not have; the model said so and left the report on disk (`docs/runs/2026-11-18-libmodbus-run1.md`, uncommitted, not indexed).
- 04:47: the timeout crash verifier confirmed an infinite retry in `send_msg` as a medium DoS. That loop is documented behaviour of `MODBUS_ERROR_RECOVERY_LINK`, and the brief already requires the harness to respect "the entry function's declared or documented contract". The verifier did not read the function's doc page (`docs/modbus_set_error_recovery.md`), although the target ships one per API function. Suggested brief change (not applied): for a hang or timeout, check the documentation of every mode-setting call in the witness's call sequence, and reject as harness-induced a hang the documentation promises.
- 06:00-08:24: the model passed `-Class light` on every scheduler call and reported "done" totals and "all proven" for work that never merged, without reading the `analysis_error` outcomes in the `step` output. The supervisor also relayed those totals until 08:24. Suggested brief change (not applied): report done counts by task kind, and treat any `blocked` prove task as something to explain.
- 04:24: the model killed a computing `eva-tune` under CLAUDE.md's "no progress for 15 minutes" rule, although the frama-c rung was at 100 % CPU within its limit. A defensible call given an 11 h worst case, but the rule is about stalls, not slow steps. The skill could say how long `eva-tune` may take, and whether skipping it is acceptable in a `standard` run.
- 01:56-02:00: on `no_unit_parsed` the model investigated pipeline code for several minutes instead of stopping and reporting as framac-slice Step 1c says. It reached the right diagnosis and did not edit pipeline files.

## Decisions taken for the user

- Fix 2 and fix 3 are landed live (user's instruction at 02:01); fix 1 stays held.
- Overnight, the supervisor answers the session's questions on the user's behalf; each answer is listed here.
- 02:36, "how to recover the 51 functions skipped for `modbus_t *`": pipeline fix (the session's option 1), not 51 hand-written dispatch cases. The session's diagnosis (constructors with parameters refused) was wrong: the code accepts them, and the name rule is what fails.
- 02:46, "may I hand-write a dispatch case for `modbus_proxy`?" (the one gap left: two `modbus_t` handles, the documented same-type skip): yes, with three changes to the proposed case. Close the preload end of the `socketpair` before the call, or every short input waits the 0.5 s response timeout. Close the backend end after the call, or each execution leaks a descriptor. Set short response and byte timeouts as a backstop. The three internal entry points (`_modbus_init_common`, `_modbus_receive_msg`, `_error_print`) were exempted by the session with a structural reason (they need `modbus-private.h`; reached through public callers).
- 02:49, "how should the lifecycle case carry a string constructor argument?": a pipeline fix close to the session's option 1. The constructor never takes the rest of the input, and the string is a 16-byte NUL-terminated `bytes` slot. A literal or an empty string were rejected: an empty IP makes `modbus_new_tcp` return NULL.
- ~03:55, fix 8 held rather than merged live with a rerun of Phases 1-2. Of the 13 Eva invalid alarms, 9 come from the harness (the 8 float functions and `modbus_mapping_free`), so a rerun would have given cleaner Phase 1-3 inputs.
  - The session was mid-turn under an autonomous instruction, with no way to stop it between steps: opencode has no abort command, and a probe of killing the client was inconclusive.
  - If the crash gate's repair path regenerated the harness, a merged fix would shift selectors mid-run (69 -> 68 cases).
  - The run therefore stays consistent on its Phase 0 harness, and the crash verification gate gets to show that it rejects these harness-induced crashes.
  - Recommendation: a run-2 with fix 8 merged.
- 04:45, fix 8 merged after all. The gate's harness-induced verdicts (float helpers, `set_bits_from_byte`, `modbus_mapping_free`) opened the pipeline's own repair task, and framac-wp Step 1.2 allows regenerating the harness as the repair. That removes both reasons for holding: the selector shift now happens inside a sanctioned repair, and no turn has to be interrupted.
  - At its next idle window, the session is told to regenerate with the same command rather than hand-edit cases, then to follow the repair task's actions.
  - The TCP-PI case may get a minimal hand fix in the regenerated `.c`.
- ~02:50, seeds: the session redoes the build capture on a fresh scratch volume, the model, threat model checks, DAG and security properties, then re-records seeds with the fixed recorder before any harness is regenerated.

Also added by fix 3: `tests/test_fc_compat_contracts.py::test_modem_line_bits_and_termios2_requests_are_defined_for_frama_c_libc_only` and `::test_modem_line_bits_and_termios2_requests_parse_with_frama_c_libc_as_gcc_reads_them` (`FRAMAC_DOCKER_TESTS=1`, rerun green by the supervisor).

Added by fix 12: `tests/test_fc_compat_contracts.py::test_eacsl_host_headers_define_the_libc_model_objects_weakly` and `::test_contracts_naming_libc_model_objects_prove_under_wp_and_build_under_eacsl` (`FRAMAC_DOCKER_TESTS=1`). Both fail on the original header.

## Upstream drafts

- Issue 41, [`../upstream/frama-c/frama-c-libc-ioctl-modem-bits.md`](../upstream/frama-c/frama-c-libc-ioctl-modem-bits.md): `__fc_libc` `<sys/ioctl.h>` lacks the `TIOCM_*` modem bits (34.0~beta and master `95408044f7`). Not filed; the owner decides between a new issue and a note on #2828.

## Open items

- Fix 1 (CRLF hint) is held on its branch until the run ends.
- Float helpers: the 5 stalled provers inspected (`modbus_get_float_badc`, `modbus_get_float_cdab`, `modbus_set_float_badc`, `modbus_set_float_cdab`, `modbus_set_float_dcba`) each leave only 2 or 3 shift-overflow RTE goals on `uint8_t` operands, such as `(uint32_t)a << 24 <= 4294967295` and `(int)b << 8 <= 2147483647`. The goals are true, proven range asserts do not help, and Alt-Ergo times out on them. Their breakers came back clean. `modbus_get_float_abcd`, `modbus_get_float_dcba` and `modbus_set_float_abcd` also hit the guardrail timeout and are not yet diagnosed further. Worth a WP strategy or lemma for byte shifts before run-2.
- The negotiations `_modbus_rtu_pre_check_confirmation`, `_modbus_tcp_build_response_basis` and `_modbus_rtu_build_request_basis` were rejected because their second round hit the guardrail timeout (issue 15), not on the proof. They need its recovery.
- Frame skeleton gaps found while fixing 16: a projected clause can name a local alias (`ctx_tcp->t_id`), which no contract can state, and `extract_frame_clauses` counts text inside a `//` comment as a location. `negotiate-modbus_tcp_build_request_basis-2` passed the check only through such a comment. The real clause is present and its parent WP re-check passed.
- `negotiate-modbus_rtu_build_response_basis-4` added a `keeps_sft` postcondition so that the merge would see a non-empty diff. It is proven, but it exists only to get around bug 16.
- Fix 15 drops a hang even when a checked function is on the stack. The pass then says so in its diagnostic hints, but that input did not test the contract.
- The commit message of `2d45df3` says a real contract violation was hidden behind the closed stderr. The evidence does not show that: the inputs pass with descriptors 0 to 2 kept open, and the cause of the exit 77 is unidentified.
- Fix 13 leaves 5 stalled provers' partial contracts unmerged (`compute_data_length_after_meta`, `crc16`, `_modbus_rtu_ioctl_rts`, `_modbus_tcp_get_response_tid`, `_sleep_response_timeout`). Their callers lose those contracts in run-1.
- The session's entry "A Proven Postcondition Is Never Merged" describes the scheduler's intended rule: a partial merge needs a verified `assigns`. The real blocker there is the `modbus_strerror` `assigns` goal that timed out.
- Unverified diagnosis: the session recorded the one open `modbus_strerror` goal (`typed_modbus_strerror_assigns_normal_part17`) as an upstream WP bug with "contradictory hypotheses on the call-result temporary". Contradictory hypotheses would make the goal trivially provable, but the log shows a (cached) Alt-Ergo `Timeout`. `__fc_libc`'s `strerror` assigns only `\result`. Needs a look at the goal before any upstream report.
- Units that stalled on the guardrail frame before fix 12 (`_modbus_rtu_flush`, `_connect`, `_modbus_tcp_close`, `_modbus_tcp_flush`, `_modbus_tcp_set_ipv4_options`) keep their weaker frames in run-1 unless the scheduler offers them another task; they should prove on a rerun.
