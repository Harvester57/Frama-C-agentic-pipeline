# libmodbus run-1 progress (2026-11-18)

Run directory: `C:\Users\Florian\framac-pipeline\libmodbus\run-1`
Target: `C:\Users\Florian\OneDrive\Documents\Dev\targets\libmodbus` (read-only)
Profile: `standard`. CodeQL: enabled (user declared the LGPL-2.1-or-later target open source).
Threat model: `/target/.security-reviews/20261118T003542Z-nogit/ThreatModel.md`, sha256 `1441dd05...b5aab9c`, pinned and never edited.

This log lives in `docs/runs/` because `docs/AGENTS.md` keeps `docs/` to its category directories and places chronological run logs here; the brief asked for `docs/progress/`, which does not exist.

## Phase status

| Phase | Status | Notes |
| :--- | :--- | :--- |
| 0 Setup | done | `run_metadata.py init --profile standard`; build recipe and CodeQL declaration recorded with origin/declared-by user. |
| 0 Build capture | done | `status: ok`, 1 shared library unit (`libmodbus.so.5.1.0`, 4 sources, 71 entry points) and 9 test executables. |
| 0 Model + trust | done | `status: ok`, 120 functions, 161 edges; threat model `ok` before and after the model; 120 untrusted / 0 trusted. |
| 0 CodeQL | done | 13 facts on 8 functions; 6 unmatched (test `main`s, not in the model); 26 rows. |
| 0 Seeds | done | Re-recorded after the shared-library fix: `status: ok`, 321 calls / 189 unique over 46 API functions, 5 traces, 4 data files. The test command exits 255 (target-side, calls kept). |
| 0 DAG + properties | done (rebuilt) | One module `libmodbus_so_5_1_0`, Tier 1A, no unit split. Tiers: 95 x 1A, 17 x 1B, 8 x 2, 0 x 3. 5 L5 properties, 60 `l3_frame` functions, 14 `l5_sanitized`. |
| 0 Harnesses | done | 67 of 71 entry points generated (69 cases: 68 generated incl. 1 `modbus_t` lifecycle + 1 hand-written `modbus_proxy` case). Reach gate `gaps: []` with the 3 internal entry points exempted. |
| 0 Ledger + gates | done | Ledger 215 units (120 `rte`, 21 `l2_termination`, 60 `l3_frame`, 14 `l5_sanitized`), all `planned`. `stubs`/`stub-check` rc 0. `build-check`: `engine_used: eacsl`, sanitizer build ok, Phase 0 checkpoint saved (`phase_done: 0`). `validate_artifacts`: `ok: true`, 0 errors. |
| 1 Fuzz | done (165 s wall) | `eacsl+sanitizers`, 1200 CPU-s budget, 9 workers, 186-entry auto dictionary, 105 seed inputs. Report `crash_found`: 63 artifacts, all replayed reproducible. Clusters: `modbus-data.c` float/bits helpers (2-byte objects for 4-byte reads/writes), constructor leaks (`modbus_new_tcp`, `modbus_new_tcp_pi`), and one timeout plus two unparsed crashes (likely the `modbus_t` lifecycle or `modbus_proxy` blocking). All are candidates, not findings. |
| 1 Coverage + reach | done | `coverage` rc 0; `reach-dynamic` rc 0 (no dynamic gaps). |
| 2 Eva | done (638 s) | 3707 obligations, 3444 Valid (92.9%), 250 Unknown (51 functions), 13 Invalid, 2499 Dead, 562 Assumed. The 13 Invalid mirror the fuzz clusters (float helpers, `free`/`close` preconditions, accept paths). |
| 2 Eva tune | cut (stall rule) | `eva-tune` produced only `base.json`; its first rung (`slevel=1000`, 82-min limit) ran 60 min at 100% CPU with no artifact and 7 rungs queued. Stopped per the 15-minute no-progress rule; container killed; base Eva report kept, no tuning decision. |
| Ingest + replay | done | 26 unverified candidates; ledger now 17 `candidate`, 36 `covered`, 162 `planned`. `replay` and `wp-queue` rc 0. |
| Gate + 3 WP | Phase 3 running | 29 distinct candidates: 22 `harness_induced` (two harness-repair rounds), 3 `contract_overconstraint`/`duplicate`, 2 `disproved_by_source` (libc `strlcpy`, `getaddrinfo`), 1 `needs_validation` (signed downcast), 1 `confirmed` (`send_msg` LINK retry, documented -> false positive). Gate open; architect and first prover/breaker tasks dispatched. |
| 4 Report | not started | waits for Phase 3. |

## Environment fixes already landed by the supervisor

- `34f8747` (templates/fc_stubs/fc_compat_types.h): TIOCM_* and termios2 request bits for `__fc_libc`. Fixed the original `src/modbus-rtu.c:254: Cannot resolve variable TIOCM_RTS` and the model now parses.
- `0b3b43b` (build_capture.py): drops the config.guess libc-probe compile, so `unlinked:/tmp/cgXXXXXX` is gone from the capture.

## Target-side issue (workaround accepted by the user)

The checkout has `core.autocrlf=true`; `autogen.sh`, `configure.ac`, `*.am` and the test shell scripts are CRLF, so autotools produced a broken `configure`. The recorded recipe strips CRs over all text files of the scratch copy before `./autogen.sh`; the read-only target is untouched. Not a pipeline defect.

## New pipeline issues recorded in this session

1. `harnesses-and-seeds.md`: `generate_harness.py --api` fails with `'workspace/work/config.h' file not found` when the build force-includes a generated `config.h`. Fixed by the supervisor in `9f7b123` (DAG now records `workspace/snapshot/generated/config.h`); rerun of the DAG and harness confirmed.
2. `harnesses-and-seeds.md`: `seed_harvest.py record` reported `not_relinked` / 0 calls for a target whose tests link the API as a shared library. Fixed by the supervisor in `5ef9ea4`; re-recording after a fresh capture gives `status: ok`, 321 calls / 189 unique over 46 API functions.
3. `harnesses-and-seeds.md`: `--api` skips every function taking an opaque handle built by `<lib>_new_<kind>`. Fixed by the supervisor in `08bec6c`; after the fix, 67 of 71 entry points are generated.
4. `harnesses-and-seeds.md`: the parameterized constructor made `api_harness.lifecycle_case` put its string argument in `rest`, which `harness_sidecar.schema.json` forbids for lifecycle cases. Fixed by the supervisor in `8e0472b`/`f40993b`; the lifecycle case now has a 16-byte `bytes` slot (last byte forced to 0), `rest: null`, no schema warnings.

`modbus_proxy` (the one reach gap after the constructor fix) is covered by one hand-written `--dispatch-case`: it builds frontend and backend TCP contexts, preloads the backend's side of a `socketpair` with the rest of the input, closes the write end before the call, sets 1 ms response/byte timeouts on both contexts, calls `modbus_proxy`, and releases both contexts. A `single`/`out-parameter` generated case is impossible for it because the call takes two handles of the same type and ownership is unknown; that is the existing documented limitation (the c-ares out-parameter entry in `docs/troubleshooting/harnesses-and-seeds.md`), not a new bug.

## Blocking error (exact)

None: all Phase 0 gates pass.

## Phase 1 and 2 notes

- Fuzz report: `workspace/reports/fuzz/libmodbus_so_5_1_0.json`, `engine_used: eacsl+sanitizers`, `crash_found`, 63 artifacts (all `reproducible: true`), seeds `ok` (105 inputs from the 321 recorded calls), auto dictionary 186 entries.
- Crash clusters and probable causes (to be decided by the Crash Verification Gate, not here):
  - `modbus-data.c` float getters/setters (`modbus_get_float_*`, `modbus_set_float_*`): the generated cases pass a single `uint16_t` where the function reads/writes two registers. Likely harness-induced undersized objects.
  - `modbus_set_bits_from_byte`/`_bytes`, `modbus_get_byte_from_bits`: counts (`nb_bits`) come from the input unbounded; the caller contract caps them (8 or `nb`). Likely harness-induced.
  - leaks in `modbus_new_tcp`/`modbus_new_tcp_pi`/`modbus_mapping_new_start_address`: generated constructor cases close the handle without freeing it. Likely harness-induced.
  - one `timeout`, two unparsed crashes, `modbus_tcp_pi_listen` SEGV, accept `close` preconditions: need the verifier; the lifecycle and `modbus_proxy` cases can block, and are the first suspects for the timeout.
- Eva: base report kept (`tuning` empty). No `eva-tune` decision: the ladder was stopped after 60 min on its first rung. This is a budget cut, not a complete-coverage claim; the 250 Unknown obligations in 51 functions remain for WP.
- Phase 3 queue: 26 crash-verifier tasks and breaker tasks; first batch of 15 agents (12 verifiers, 3 breakers) dispatched.

## Phase 3 gate and harness repair

- Gate verdicts on the 26 pre-repair candidates: 20 rejected `harness_induced` (2-byte float objects, unbounded bit indices, leaked constructors, stack `modbus_mapping_t`, one-register `modbus_write_registers`, TCP-PI on a TCP context), 2 rejected `duplicate` and 1 rejected `contract_overconstraint` (Frama-C's arbitrary 1024 descriptor bound on `close`), 1 rejected `disproved_by_source` (libc `strlcpy` does not mark `ip[0]` initialized for E-ACSL), 1 `needs_validation` (unsigned start addresses downcast to `int`, no witness), 1 `confirmed` (`send_msg` LINK-mode retry loop).
- The `send_msg` finding is **confirmed by the gate but documented behaviour, so a false positive, not a reportable target bug**. `docs/modbus_set_error_recovery.md` says: "This mode will try an infinite close/connect loop until success on send call ... The reconnection attempt can hang for several seconds if the network to the remote target unit is down." The record is left as the gate wrote it.
- Repair: `--record-repair`, then regenerated with the generator fixes `f59649e`/`8385bd1` (68 cases, 66 entries, `modbus_mapping_free` skipped). Two permitted hand fixes: TCP-PI cases 25/26 build their context with `modbus_new_tcp_pi`, and the single/lifecycle `modbus_set_error_recovery` cases clear `MODBUS_ERROR_RECOVERY_LINK` (comment cites the doc). Reach gate passes; `module-libmodbus_so_5_1_0` rebuilt in 555 s; `refresh: done`.
- Post-repair fuzz: 14 artifacts, 9 in `modbus_tcp_pi_listen` (the lifecycle case still builds one TCP context for all 45 methods, so its TCP-PI methods remain harness-induced), 3 in `modbus_reply_exception` (under verification), 2 timeouts.
- Second repair (attempt 2/2): the lifecycle case's TCP-PI arms now build and release their own `modbus_new_tcp_pi` context, and its `modbus_reply`/`modbus_reply_exception` arms copy the remaining input into a zeroed 4024-byte request buffer. Reach gate passes; module rebuilt in 559 s; `refresh: done` with **no new candidates**. The re-fuzz after this repair is clean of harness-induced failures.
- Post-repair Eva: 3755 obligations, 3500 Valid (93.2%), 252 Unknown in 52 functions, 3 Invalid (the `close` fd-model alarms only).
- Ledger: 154 `planned`, 44 `covered`, 8 `candidate`, 5 `deferred`, 4 `blocked`.
- Phase 3 started: the header architect passed (54 baseline contracts in `src/modbus.h`, Frama-C kernel typecheck clean, E-ACSL dynamic oracle `passed_dynamic_oracle`, 37/54 functions reached by the oracle). First swarm: 14 provers + 1 negotiation. Two guardrail expressiveness gaps were recorded in `docs/troubleshooting/wp-and-guardrail.md` (`assigns errno` unbound in units without `<errno.h>`; ranged `\initialized` postcondition with a formal bound).

## Phase 3 progress (WP / breaker / negotiation swarm)

- Scheduler counts by task kind at the switch to `-Class verify`: **arch** 1 done; **breaker** 19 done / 7 running; **negotiate** 29 done / 6 running / 2 pending; **repair** 1 done; **verify** 30 done; **prove** 0 done / 36 blocked / 55 pending / 2 running / 10 skipped.
- **Correction (supervisor steer):** every earlier `wp_scheduler.py step`/`complete` in this session ran with `-Class light` (1 GiB), so the parent WP re-check of each merge in the container was refused with `insufficient_memory` (WP needs ~1768 MiB); 12 prove tasks were recorded `analysis_error` for that reason and several negotiations were resolved as `rejected_by_callee`. From this point all `step`/`complete`/`merge-pending` calls use `-Class verify`. No prove unit is described as proven or merged here until its merge succeeds; the units below are **agent-level results awaiting/undergoing merge**.
- Agent-level results awaiting merge (each `all_proven` under WP + `passed_dynamic_oracle` in its own scratch): `compute_data_length_after_meta`, `compute_meta_length_after_function`, `_modbus_rtu_is_connected`, `_modbus_tcp_is_connected`, `_modbus_tcp_recv`, `_modbus_tcp_send`, `_modbus_tcp_check_integrity`, `_modbus_tcp_close`, `_modbus_tcp_build_response_basis`, `_modbus_rtu_build_response_basis`, `modbus_init_common`, `_modbus_rtu_build_request_basis`, `_modbus_rtu_get_response_tid`, `modbus_get_float_cdab`.
- First successful merge with the verify class: `modbus_get_float_cdab` (`checkpoint.saved: true`, parent WP report written, 0 `insufficient_memory`).
- Recovery (`requeue --memory-refused`, run once on the supervisor's instruction): `ok: true`, `errors: []`, `restored: 11`, `negotiations_restored: 2`, `negotiations_rerun: 7`, `requests_restored: 25`, `left: 1`, `partial_merges_refused: 5`, `obstructions_forgotten: 25`.
- First step after recovery merged 15 tasks in one batch (11 prove + 4 negotiate) with 0 `insufficient_memory`: `_modbus_tcp_send`, `_modbus_tcp_check_integrity`, `compute_meta_length_after_function`, `_modbus_rtu_pre_check_confirmation`, `_modbus_rtu_build_response_basis`, `_modbus_tcp_build_response_basis`, `_modbus_tcp_send_msg_pre`, `_modbus_set_slave` (RTU + TCP), `_modbus_rtu_build_request_basis`, `_modbus_init_common`, `modbus_get_float`, plus four negotiated contracts (`compute_data_length_after_meta`, `_modbus_tcp_recv`, `_modbus_tcp_build_request_basis` and its retry).
- Prove tasks done after that step: 12 (plus 25 blocked, 43 pending, 13 running, 10 skipped).
- New merge-side pipeline bug found in this phase and recorded in `docs/troubleshooting/wp-and-guardrail.md`: `could not locate definition of function` for definitions placed after a function that contains `#ifdef`/`#else` branches (brace-depth counting in `function_declaration_spans`); `_modbus_tcp_select` and three RTU getters were requeued/blocked by it although their patches apply cleanly.
- **Unverified Phase 3 crash observations (not findings):** the `breaker-modbus_tcp_connect` campaign's module-wide E-ACSL build produced assertion failures outside its target, in `modbus-rtu.c` lines 1053 (`modbus_rtu_set_serial_mode`), 1126 (`modbus_rtu_get_serial_mode`), 1243 (`modbus_rtu_set_custom_rts`), 1348 (`modbus_rtu_set_rts_delay`) and `modbus-tcp.c:841` (`modbus_tcp_pi_listen`, the known lifecycle `\initialized` alarm). They have not been through the Crash Verification Gate in this phase and must not be reported as target bugs until they are; they are listed here so the gate/report step can pick them up.
- The supervisor's guardrail fix `9250359` (`templates/fc_stubs/fc_compat_types.h`) is confirmed live: frames naming `__fc_sockfds[s]`, `__fc_fds[fd]` and `Frama_C_entropy_source` now prove under WP and pass `run_eacsl_fuzz.py guardrail`. It closed `_modbus_tcp_close`, `_modbus_tcp_recv`, `_modbus_tcp_send` and `_modbus_tcp_check_integrity` in this run.
- Remaining stalls are non-code and recorded in `docs/troubleshooting/wp-and-guardrail.md`: the uninterpreted `lsl` on `<< 8` (TCP pre-check, `crc16`), the variadic `ioctl` footprint aborting any `assigns` in the RTU termios functions, `nanosleep` non-strict `remaining` defeating the L2 variant in `_sleep_response_timeout`, `\initialized`/libc-model timeouts, and two pipeline gaps (a proven clause never merged because its prover stalled on an unrelated tool-generated sub-goal; an indirect call to `static` callees in sibling translation units that cannot carry a `calls` spec).
- Breaker campaigns on the RTU/TCP wrappers and helpers are all `clean` with replayed seeds (`not_reproduced`); the only recurring E-ACSL artifact is the pre-existing `modbus_tcp_pi_listen` `\initialized(&ai_ptr->ai_socktype)` crash from the lifecycle case, which the gate already classified `harness_induced`.

## Phase 3 close

- Queue drained with no `ready`, `running` or `pending` work: **done 175** (arch 1, breakers 61, negotiate 42, prove 35, repair 1, verify 35), **blocked 58** prove units, **skipped 10**. The scheduler's `done` flag stays false only because those 58 prove units are parked on structural limits: single-translation-unit `ctx->backend` calls whose static targets cannot be named, contract-less `send_msg`/`_modbus_receive_msg`/`check_confirmation`/`_modbus_rtu_ioctl_rts`, the `lsl` shift encoding, variadic `ioctl`/`inet_pton` unbounded `assigns`, and per-agent WP wall budgets.
- All **35** crash candidates are verified. Every Phase-3 crash candidate was rejected: `toolchain_artifact` (`modbus_rtu_set_serial_mode` NULL-context `\old` snapshot), `disproved_by_source` (`getaddrinfo` shadow), or `contract_overconstraint` (caller-level `L5_sanitized_send_msg`, four independent verifications, with the sink-level `L5_sanitized__modbus_tcp_send` already correct for TCP).
- **Correction on the WP cache:** it was not poisoned. Both calls of `negotiate-modbus_receive_msg` used the same prover and the same 2 s timeout, so replaying the cached timeouts was correct; the call ran out of wall time. A longer per-goal timeout makes WP run the prover again, which is why the `-2` attempt (10 s, 600 s wall, private cache) produced a real verdict.
- **Correction on `modbus_write_register`:** it merged **without an assigns clause**. Its contract proves the NULL-case postcondition and leaves the frame to WP's computed over-approximation because `write_single` is still contract-less; it is not a proof of the function's frame.

## What is on disk

- `workspace/reports/`: capture, model, CodeQL, seeds, DAG, security props, gates, fuzz, coverage, Eva, replay, `wp_queue.json`
- `workspace/harnesses/harness_libmodbus_so_5_1_0.c` and `.json` (69 cases), `fuzz_libmodbus_so_5_1_0*` builds
- `coverage-ledger.json` (215 units), `candidates.json` (26), `state/`
