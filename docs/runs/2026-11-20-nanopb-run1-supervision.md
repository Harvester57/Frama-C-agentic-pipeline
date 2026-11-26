# nanopb run-1: supervision report

- **Target:** nanopb, commit `93550bb52a62` (Windows checkout, dirty), profile `standard`, full mode.
- **Run directory:** `~/framac-pipeline/nanopb/run-1`, run tag `run-1-077c7903f6f3`, repo key `nanopb-772d6044d6b6`.
- **Driver:** a Claude Code session on Sonnet 5.5 (`nanopb-run`), started by the supervisor session at the user's request. It shares this checkout.
- **Pipeline:** `main` at `6877117`, plus 55 files of another session's uncommitted changes in `scripts/`, `templates/`, `tests/` and `wrappers/`. The run executes those as they are.
- **Fix mode:** `hold`. Five fixers, each in a worktree cut from `main` at `6877117`: two at the user's request (22:50), three by the supervisor rule for a confirmed bug in clean files (see Fixes).
- **Status:** run ended **`incomplete`** at 2026-11-21 01:23:20 local (`run_status` in `run-metadata.json`, `00:23:20Z`). Final report written 2026-11-21 (local time, UTC+1).

## Final status

- **Run status:** `incomplete`. Reason, verbatim from `run-metadata.json`: "Phase 3 stopped by user decision after the 17 unaffected WP tasks (29 pb_istream_t functions and 10 callers of an uncontracted leaf not run; 16 of the 17 are gated behind them, so only pb_enc_fixed ran, ending blocked). Causes: open pipeline bug L3_writers_ostream_* abort on pb_istream_t formals; open pipeline bug #ifdef twin-definition merge refusal (pb_release); wp-sweep out-dir lock regression (parallel same-file jobs); WP limits (void* cast of stream->state, union read, indirect call, valid_function). Candidates: 5 harness_induced (repaired), 1 needs_validation (pb_write sizing-stream bytes_written wrap)."
- **Reports:** `REPORT.md` (24.8 kB), `FINDINGS-DETAIL.md` (53 bytes: no confirmed finding), `NEEDS-VALIDATION.md` (4.6 kB), `report.sarif` (2.0 kB), all written at 01:23:32.
- **Total wall-clock:** 5 h 19 min 43 s, from `created_at` 20:03:37 to the terminal `updated_at` 01:23:20 (both from `run-metadata.json`). The driver session started at 20:02.
- **The user's checks** (threat model SHA, item 7, CodeQL) all passed; see "The user's checks".

### Wall-clock per phase

The run records no per-phase timestamps (`progress.json` holds only `phase_done` and `updated_at`), so these times come from the supervisor's timeline: run files and their mtimes, `progress.json` changes and the driver's transcript.

| Phase | From | To | Duration | Share |
| :--- | :--- | :--- | ---: | ---: |
| Phase 0 (overlay, build capture, model, CodeQL and trust, seeds, fuzz assets, DAG, properties, harness, gates) | 20:03:37 | 20:14:21 | 10.7 min | 3% |
| Phase 1 fuzz campaign | 20:14 | 20:17 | 2.5 min (148 s) | 1% |
| Phase 2 Eva, then the first eva-tune ladder | 20:17 | 21:00 | 43 min (Eva 98 s, ladder 2438 s) | 13% |
| Fuzz coverage, `reach-dynamic`, ingest, replay, `wp-queue` | 21:00 | 21:01 | 1 min | <1% |
| Crash Verification Gate (5 verifiers, 1 header architect) | 21:03 | 21:06 | 3 min | 1% |
| Harness repair 1 and the module rerun (build, fuzz, Eva) | 21:08 | 21:14 | 6 min | 2% |
| Second eva-tune ladder and loop trials | 21:14 | 00:11 | 2 h 57 min (10,630 s) | 55% |
| Phase 3 WP (scheduler waves, verifiers, breakers) | 00:12 | 01:18 | 66 min | 21% |
| `wp-sweep`, the driver's re-proof workaround, Phase 4 reports | 01:18 | 01:23 | 5 min | 2% |

The second eva-tune ladder alone took more than half the run. Four rungs and two loop trials hit the recursion gap (fixed on `sup/nanopb-eva-tune-recursion`, merged to main in `794b367`), and the ladder moved Unknown from 89 to 27.

## Timeline

Times are local (UTC+1), from the run's files, `progress.json` and the driver's transcript.

| Time | Event |
| :--- | :--- |
| 20:02 | Driver session started. Docker Desktop was stopped; the driver started it. |
| 20:03:37 | `run-1` created (`run_metadata.py init`). |
| 20:04 | `workspace_overlay.py init`: 170 files, `crlf_scripts` 19 (target-side, Windows checkout). |
| 20:05 | Recipe recorded (`agent_confirmed`, the user's flags); the test command strips CRs from the four generator scripts it runs. CodeQL enabled (open source, declared by the user). `trust.py check-threat-model`: exit 0. |
| 20:06 | Build capture `ok`: two link units (`build/libprotobuf-nanopb.a`, `.so.0`). `phase0_model.py run --threat-model ...`: SHA-256 `024e264f...` matches the user's value. |
| 20:06-20:08 | `codeql_trust.py run` and `trust.py run` `ok` (CodeQL 2.27.3). |
| 20:08 | `seed_harvest.py record`: `no_test_units` (0 seeds). |
| 20:09-20:11 | `fuzz_assets.py` discover, map, import. |
| 20:12 | DAG, stubs, security properties (6), `--api` harness (36 cases), reach gate 36/36. |
| 20:14:21 | Phase 0 done (`gen`, `build-check` `eacsl`), `phase_done` 0. Phase 0 took about 10.7 min. |
| 20:14-20:17 | Phase 1 fuzz campaign: 148 s, `crash_found`, 25 artifacts. |
| 20:17-20:19 | Phase 2 Eva: 98 s (Eva 46 s), 783 properties, 98.34% discharged, 11 Unknown, 2 Invalid, 1844 Dead. |
| 20:19-21:00 | eva-tune ladder, 2438 s: `slevel` timed out at 239 s; `unroll`, `history`, `values`, `relational`, `returns`, `precision`, `perfn` completed. Result: 771 Valid, 10 Unknown (from 11), 2 Invalid, 1844 Dead unchanged, 98.47%. |
| 21:00 | Fuzz coverage and `reach-dynamic`: 36/36 entry points executed, 773 corpus inputs, 3 crashed entry points (`pb_field_iter_begin_extension`, `_const`, `pb_field_iter_find_extension`). Ingest. |
| 21:01 | `replay`, `wp-queue` (`wp_queue.json`); `phase_done` 2. |
| 21:03-21:06 | Crash Verification Gate: `wp_scheduler.py step --prepare` gave 5 Crash Verifier briefs (one per crash site) and 1 header-architect brief (`pb.h`). The verifiers reported `rejected` (`harness_induced`); the architect ended `failed` (guardrail error, below). `step --complete` for all six at 21:06; 78 tasks pending, no prover brief yet. |
| 21:08 | Harness repair 1 of 2 (`generate_harness.py --record-repair`, then the driver's `repair/fix_harness_1.py`): 14 dispatch cases rewritten in both the Eva and the LibFuzzer copy to use one valid `PB_BIND` descriptor (`fh_Msg`: int32, bool, string[8]), iterators from `pb_field_iter_begin`, extensions with a real type, and `pb_decode`/`pb_decode_ex` streams built from the input. Reach gate `ok`; module rerun (build, fuzz, Eva) started at 21:09. |
| 21:09-21:14 | Rerun on the repaired harness: fuzz `clean` (0 artifacts, same budget, libFuzzer `cov: 412`); Eva 129 s, 943 properties, 853 Valid, 90 Unknown, 0 Invalid, 1421 Dead, 90.46%, no non-terminating statement. Second eva-tune ladder started 21:14. |
| 21:31 | Second ladder: `slevel` (1000) ended `analysis_timeout` after 1030 s. The rung limit is 8 x the base run (129 s), floor 600 s (`eva_options.py` `trial_timeout`), so 1030 s. |
| 21:48-22:21 | `unroll` `analysis_timeout` (1030 s); `history` `ok` 372 s, Unknown 90 to 28; `values` and `relational` `ok` (100 s, 90 Unknown); `returns` `analysis_timeout` after a 137 s retry: its first attempt took 893 s and aborted on the `pb_read` recursion (pipeline gap, below). |
| 22:38 | `precision` `analysis_timeout` after a 463 s retry (first attempt about 567 s, same gap). |
| 22:56 | `perfn` `analysis_timeout` after a 516 s retry (same gap). Of the 8 rungs, 3 finished (`history` best: 28 Unknown); loop trials follow. |
| 23:03-23:21 | Loop trials on `history` (limit 600 s): `pb_decode_varint32_eof` and `pb_decode_varint` `analysis_timeout` after 315 s and 347 s retries, the same recursion gap (the fix, merged in `794b367`, covers loop trials). `pb_field_iter_find` running. |
| 23:33-00:11 | Loop trials `pb_field_iter_find`, `pb_field_iter_find_extension`, `pb_read`, `pb_skip_varint`: all six trials added nothing (`selected_loops: []`). eva-tune ended 00:10 after 2 h 57 min (10,630 s): selected `history` (`slevel` 500, `partition-path` 2), Unknown 89 to 27 in 12 functions (module report: 891 Valid, 28 Unknown, 0 Invalid, 1421 Dead, 96.95%). The four stale `loop-*.json` from the first ladder were not selected. |
| 00:12 | Phase 3: repair task closed by `wp_scheduler.py refresh`; 78 tasks (68 prove, 10 negotiate). First wave: 11 subagents (provers for `buf_read`, `buf_write`, `load_descriptor_values`, `advance_iterator`, `pb_default_field_callback`, `safe_read_bool`, `decode_pointer_field`, `pb_release`, `pb_ostream_from_buffer`; negotiators for `pb_const_cast`, `pb_istream_from_buffer`). `safe_read_bool` and `pb_release` completed by 00:15, `queued_for_merge`. |
| 00:20 | First results: `safe_read_bool`, `pb_release`, `pb_ostream_from_buffer` `all_proven`; `decode_pointer_field` `blocked`; negotiator `pb_const_cast` `stalled_after_k_retries`. Every guardrail so far `passed_dynamic_oracle` (the repaired harness no longer crashes, so the mutation-burst bug has not recurred). |
| 00:56 | The driver asked the supervisor whether to finish the 56 remaining WP tasks (29 `pb_istream_t` functions blocked by the L3 bug, 10 depending on leaves left without a contract, 17 unaffected) or stop after the 17 and end `incomplete`. The supervisor forwarded it to the user, who answered "Stop after the 17" (01:01); the supervisor relayed those words at 01:01. Proven so far: `pb_ostream_from_buffer`, `safe_read_bool` (`pb_release` lost to the `#ifdef` merge bug). Of the 17, only `pb_enc_fixed` could run (it ended `blocked`: its callees `pb_encode_fixed32`/`64` have no contract); the other 16 depend on skipped tasks. |
| ~01:10 | `pb_write`: the breaker was `clean` (no artifact); the prover's stall claim went to a Crash Verifier as a fault hypothesis: `verify-pb_write_8ad57b9b03` `needs_validation` (fingerprint `pb_encode.c#pb_write::rte::8ad57b9b03`). On a sizing stream (`callback == NULL`) `pb_write` skips the guard at `pb_encode.c:121-122` and `bytes_written += count` (line 136) wraps; shown by a standalone driver (two calls with count 2^63), not through the module harness. Defined unsigned behaviour, no memory write, only a wrong size count; reaching it through the public API needs a 2^64-byte sizing pass or a caller passing count >= 2^63. The Phase 3 gate held while it ran, then reopened. |
| 01:18-01:20 | `pipeline_make.py run wp-sweep` (15 jobs): `incomplete`, `make: *** [wp-sweep] Error 1`. `pb_ostream_from_buffer` came back `rc=1` with no report (`out_dir_locked`: its `pb_encode.c` sibling `safe_read_bool` held the shared per-file `--out-dir`), and the sweep ingest turned the proved unit `blocked`. Pipeline bug, confirmed by the supervisor (below). |
| 01:21-01:22 | The driver's run-dir workaround `repair/resweep_one.py` (calls `pipeline_make.sweep` with the sweep list restricted to the lost function, `--jobs 1`): first `analysis_error` `insufficient_memory` (the wrapper inferred the `light` class for the custom script, 1024 MiB), then `all_proven` with `-Class wp`; the driver re-ingested `pb_ostream_from_buffer`'s report with `ledger.py ingest-wp`, and the unit went back to `covered`. The `wp-sweep/summary.json` on disk is the last restricted sweep (1 job), not the 15-job one. |
| 01:23 | `run_metadata.py` status `incomplete` (01:23:20); `REPORT.md`, `FINDINGS-DETAIL.md`, `NEEDS-VALIDATION.md`, `report.sarif` (01:23:32). No `run-1-077c7903f6f3` container left. |

Observation: eva-tune spent 40 min (sequential rungs, one CPU) to move one Unknown to Valid, while 1844 obligations stay Dead behind the harness's NULL descriptors. No tuning rung can recover Dead code a harness never reaches; a ladder that stops early when the Dead share dominates would have saved most of that time. Not a defect; a cost observation for the plan's end validation. The harness repair reruns the whole ladder, and with the longer base run each rung may take up to 1032 s, so a repair costs up to the full ladder again.

Note on the 36/36 dynamic reach: `pb_decode` ran 4 times and every reader case ran with a zeroed stream, so "executed" here means the entry was called, not that its decoding paths ran (see the harness finding below).

## The user's checks

- **Threat model:** used in place (`/target/.security-reviews/20261120T174556Z-nogit/ThreatModel.md`), not copied; `check-threat-model` exit 0; `trust.threat_model.sha256` in the model is `024e264ff9850f43ab6dcf5e5c7b139db72d59bce41cb448c71ba55a1d904c58`, as expected.
- **Item 7 (checked by the supervisor in `phase0_model.json` and `security_props.json`):**
  - `pb_decode.c:108` (`pb_read`) and `:131` (`pb_readbyte`) resolve to `buf_read`; `pb_encode.c:107` (`pb_write`) resolves to `buf_write`. Source `type-match`, narrowing disabled, in both units.
  - The call rules have call sites: `L4_call_buf_read` (instances `pb_read`, `pb_readbyte`), `L4_call_buf_write` and the sink property `L5_sanitized_buf_write` (instance `pb_write`).
  - `pb_write` is treated as forwarding: `L5_sanitized_pb_write` has `forwarded_to: ["buf_write"]` and no MetAcsl goal.
- **CodeQL:** one fact, on cmake's compiler-id probe (`CMakeCCompilerId.c#main`, `argv`); `trust.py` drops it with the warning `codeql: 1 function(s) not in the model`. CodeQL contributes no fact to the library, as expected for a library with no input reader.

## Results (the user's requested summary)

### Candidates and verdicts

| Candidate | Source | Verdict | Basis |
| :--- | :--- | :--- | :--- |
| `pb_common.c#advance_iterator::mem_access::b1a6780c1e` (`pb_common.c:126`) | Phase 1 fuzz (the 25 artifacts collapse to 5 crash sites) | `rejected` `harness_induced` | `checked` |
| `pb_common.c#load_descriptor_values::mem_access::7be2f29bc8` (`pb_common.c:17`) | Phase 1 fuzz | `rejected` `harness_induced` | `checked` |
| `pb_common.c#pb_field_iter_begin_extension::mem_access::45b43790e7` (`pb_common.c:168`) | Phase 1 fuzz | `rejected` `harness_induced` | `checked` |
| `pb_common.c#pb_field_iter_find::mem_access::b1a6780c1e` (`pb_common.c:201`) | Phase 1 fuzz | `rejected` `harness_induced` | `located` |
| `pb_encode.c#safe_read_bool::mem_access::cf43114efe` (`pb_encode.c:130`) | Phase 1 fuzz | `rejected` `harness_induced` | `located` |
| `pb_encode.c#pb_write::rte::8ad57b9b03`: `bytes_written += count` wraps on a sizing stream (`pb_encode.c:136`) | Prover stall claim, sent as a fault hypothesis | `needs_validation`, no severity | Shown by a standalone driver (two calls with count 2^63), not through the module harness. Defined unsigned behaviour, no memory write, only a wrong size count. The campaign builds have no unsigned-overflow check. Next step in `NEEDS-VALIDATION.md` |

Verdicts and bases are read from the run's `findings.json` (6 records). The 5 rejections are the crash sites the harness produced with fuzzed trusted descriptors and zeroed iterators. After repair 1, the fuzz run was `clean` with the same budget.

Confirmed findings: **0**. The `pb_write` breaker found nothing (`clean`). The Phase 3 guardrails the supervisor saw (up to 00:20) all passed their dynamic oracle; the later ones were not checked one by one.

### Units proved per layer

From the ledger (`coverage-ledger.json`, 209 units) and `REPORT.md` section 5. Every covered unit carries open assumptions (30 `boundary_assumption`, 6 `other`), so nothing is proven unconditionally.

| Layer / obligation class | Covered (with assumptions) | By | Blocked | Planned or in progress |
| :--- | ---: | :--- | ---: | ---: |
| RTE | 15 | Eva 13; WP 2 (`pb_ostream_from_buffer`, Bytes model; `safe_read_bool`, Eva and WP) | 11 | 51 |
| L1 functional contracts | none is a ledger class; 1 of the 2 WP proofs has a `functional` contract shape (`pb_ostream_from_buffer`), `safe_read_bool` is `safety_only` | | | |
| L2 termination | 1 | WP (`safe_read_bool`) | 1 | 27 |
| L3 frame | 0 | | 10 | 39 |
| L3 isolation | 0 | | 10 | 39 |
| L4 call rule | 0 | | 3 | 0 |
| L5 sanitized sink | 0 | | 1 | 0 |
| L6 | no unit in the ledger | | | |
| **Total** | **16** (3 WP units, 13 Eva) | | **36** | **156** |

The 13 Eva RTE covers are `pb_const_cast`, `pb_field_iter_begin`, `pb_field_iter_begin_extension_const`, `pb_field_iter_next`, `pb_dec_bool`, `pb_istream_from_buffer`, `pb_enc_bool`, `pb_encode_fixed32`, `pb_encode_fixed64`, `pb_encode_svarint`, `pb_encode_tag`, `pb_encode_varint_32` and `pb_get_encoded_size`. The `pb_release` proof (`all_proven`) never reached the ledger: the `#ifdef` merge bug refused it.

### Gaps

- **Not run (user decision):** 29 functions taking a `pb_istream_t *` (the L3 asset bug aborts every WP run on them) and 10 callers of a leaf left without a contract. 16 of the 17 unaffected tasks depend on those.
- **Blocked, pipeline bugs:**
  - L3 `\formal(stream)->bytes_written` on `pb_istream_t` (`decode_pointer_field`, `pb_readbyte` and the others): fixed on `sup/nanopb-l3-asset-param-type`.
  - `pb_release` lost to the `#ifdef` twin merge refusal: fixed on `sup/nanopb-ifdef-twin-definitions`.
  - `pb_ostream_from_buffer` dropped by the sweep out-dir lock: the driver repaired the ledger by hand; the fix is on `sup/nanopb-wp-sweep-outdir`.
- **Blocked, WP limits (not pipeline bugs):**
  - The `void *` to `pb_byte_t *` cast of `stream->state` in `buf_read` and `buf_write`: Typed leaves 8 goals, Bytes 3 (the known [WP cast blocker](../troubleshooting/wp-and-guardrail.md)).
  - `\valid_function` on `stream->callback` (`pb_read`).
  - The `lsl` bound and `valid_obj` of a pointer read from memory (`advance_iterator`).
  - `load_descriptor_values` (about 5000 VCs, no verdict in time).
- **Blocked, spec:** `pb_enc_fixed` (its callees have no contract because their negotiations were rejected), and `pb_write`'s `l5_sanitized` (the wrap goal, which is the `needs_validation` candidate).
- **Dynamic and Eva:**
  - 1421 Dead properties after the repair. One hand-written descriptor instance leaves `decode_static_field`, `load_descriptor_values`, `pb_field_set_to_default`, `encode_array`, `decode_callback_field`, submessages, bytes, extensions and defaults unreached (plan SD6).
  - The reader cases (`pb_read`, `pb_decode_varint`, ...) still get a zeroed stream.
  - 0 seeds: `seed_harvest` `no_test_units`.
  - The shipped fuzzer and corpora feed no harness case (the generated descriptors are missing with `-Dnanopb_BUILD_GENERATOR=OFF`). The driver copied `regressions/` and `sample_data/*.pb` to `inputs/corpora/` by hand.
- **Configuration scope:** the default build only, with no `PB_*` option, as the threat model assumes. Code under `#ifdef PB_ENABLE_MALLOC` (the allocating arm of `pb_release`, for example) is outside the analysed configuration.

## Findings of the supervision

### The `--api` harness inverts nanopb's trust split

Measured on `harness_libprotobuf_nanopb_a.json` against the threat model's `input_sources`:

- 25 of 36 cases give an attacker parameter no input byte. In `pb_decode` the stream is zeroed (`callback` NULL, `bytes_left` 0), so the decoder reads nothing. Every reader case also gets a zeroed stream.
- 11 cases fill a trusted parameter from the input, mostly the descriptor `pb_msgdesc_t` (`pb_decode`, `pb_encode`, `pb_field_iter_begin`).
- 3 functions without attacker data get a case.

The 25 crash artifacts, mapped to their dispatch case:
- 10 from a fuzzed descriptor (`pb_decode`, `pb_decode_ex`, `pb_encode_ex`);
- 10 from a zeroed iterator that holds a trusted descriptor pointer (`pb_field_iter_find`, `_find_extension`, `_next`);
- 5 from functions without attacker data (`pb_field_iter_begin_extension`, `_const`).

All 25 have harness-induced shapes; the run's Crash Verifiers decide each one.

Eva stops at the NULL descriptor accesses (non-terminating statements at `pb_common.c:126`, `:168`, `:201`), so 1844 obligations are Dead, most of the decoder and encoder. The ledger handles this correctly (Dead never counts as proof).

Plan: [`../plans/archive/schema-driven-api-harness-plan.md`](../plans/archive/schema-driven-api-harness-plan.md) (proposal, not implemented).

**Early data point (repair 1, one hand-written schema instance).** The driver's repair gave 14 cases one valid descriptor (int32, bool, string[8]). On the rerun:

| | Before repair | After repair 1 |
| :--- | ---: | ---: |
| Fuzz artifacts | 25 | 0 |
| Eva properties | 783 | 943 |
| Invalid | 2 | 0 |
| Unknown | 11 (10 after tuning) | 90 |
| Dead (all) | 1844 | 1421 |
| Dead outside `LLVMFuzzerTestOneInput` | 1310 | 1039 |
| Non-terminating statements | 3 | 0 |

- The decoder is now analysed for real: `buf_read`, `pb_read`, `pb_readbyte`, `pb_decode_inner`, `decode_basic_field`, `pb_dec_varint` and `pb_dec_string` appear among the surviving Unknown functions, which go to WP. The lower discharge rate (90.46%) is that new code being reached, not a regression.
- Dead fell by only about a fifth outside the fuzz entry, because one message with three static scalar fields leaves `decode_static_field` (126 Dead), `load_descriptor_values` (119), `pb_field_set_to_default` (76), `encode_array` (72), `decode_callback_field` (70), submessages, bytes, extensions and defaults unreached. This supports the plan's SD6 (several instances covering the field kinds), not one instance.

### Pipeline bugs and gaps

| Fingerprint | Category | Status | Entry |
| :--- | :--- | :--- | :--- |
| `seed_harvest` record: `no_test_units` for a test suite that builds its own copy of the library (scons) | Pipeline gap | Open (written by the driver) | [`../troubleshooting/harnesses-and-seeds.md`](../troubleshooting/harnesses-and-seeds.md) |
| Shipped fuzzer and corpora feed no case (generated descriptors missing, `-Dnanopb_BUILD_GENERATOR=OFF`) | Pipeline gap | Open (written by the driver; plan S3) | same file |
| Fuzz report: `seed_harvest.py record has not run` although it ran (`scripts/seed_harvest.py` about line 1768) | Pipeline bug, cosmetic | Open. Not dispatched: `scripts/seed_harvest.py` is in the dirty list | same file (written by the supervisor) |
| `--api` harness fills trusted parameters and zeroes attacker ones | Pipeline design gap | Open, planned | [`../plans/archive/schema-driven-api-harness-plan.md`](../plans/archive/schema-driven-api-harness-plan.md) |
| Guardrail `guardrail_error` on a sanitizer crash outside the checked functions found by the mutation burst (`run_eacsl_fuzz.py` about line 2043); the `pb.h` contract was exercised (64 corpus inputs clean, `pb_default_field_callback` reached 8 times) but the error discarded that result | Pipeline bug (code and docstring disagree; policy chosen in `b967da7`) | Fixed; fixer dispatched at the user's request (2026-11-20 22:50), branch `sup/nanopb-guardrail-mutation-sanitizer`, merged to main in `6ce14ac` | [`../troubleshooting/wp-and-guardrail.md`](../troubleshooting/wp-and-guardrail.md) |
| eva-tune rungs repeat the first Eva attempt that aborts on the `pb_read` recursion, then retry with what is left of the rung budget (`returns`: 893 s lost, 137 s retry, `analysis_timeout`); `elapsed_s` hides the lost time | Pipeline gap | Fixed; fixer dispatched at the user's request (2026-11-20 22:50), branch `sup/nanopb-eva-tune-recursion`, merged to main in `794b367` | [`../troubleshooting/eva.md`](../troubleshooting/eva.md) |
| L3 asset properties `L3_writers_ostream_bytes_written` / `_max_size` guard `\formal(stream)->bytes_written` by parameter NAME (`security_props.py` `assets()`), so every `pb_decode.c`/`pb_common.c` function with a `pb_istream_t *stream` (47 and 49 instances, `buf_read` and `pb_read` among them) aborts WP: `Cannot find field bytes_written in type struct pb_istream_s` | Pipeline bug (found by the driver, confirmed by the supervisor in `security_props.json` and `wp_decode_pointer_field.json`) | Fixed; fixer dispatched 00:35 (supervisor rule for a confirmed bug in clean files; tests go in a new module because `tests/test_security_props*.py` are dirty), branch `sup/nanopb-l3-asset-param-type`, merged to main in `2444bd7`. The run ended `incomplete` partly for it | [`../troubleshooting/security-properties.md`](../troubleshooting/security-properties.md) (written by the driver) |
| Merge refuses a proven contract on the compiled `#else` twin of a function defined twice (`pb_release`, `pb_decode.c:1424` and `:1440`): `agent modified content outside assigned function 'pb_release'`; `acsl_ast.contract_declaration_spans` takes the first definition only (deliberate, pinned by `test_the_same_function_defined_in_both_arms_keeps_the_first_definition`) | Pipeline bug (found by the driver, confirmed by the supervisor in `wp_schedule.json` and `acsl_ast.py:1343`); the run lost the `pb_release` proof | Fixed; fixer dispatched 00:50 (tests in a new module, the conditionals and frame tests are dirty), branch `sup/nanopb-ifdef-twin-definitions`, merged to main in `95a17c9` | [`../troubleshooting/wp-and-guardrail.md`](../troubleshooting/wp-and-guardrail.md) (written by the driver) |
| `pipeline_make.py run wp-sweep`: `WP output directory 'workspace/reports/wp-sweep/work/pb_encode.c' is already locked by another active run`, `out_dir_locked`; a proved, merged unit turns `blocked`. A regression between the per-file sweep `--out-dir` and the 2026-11-20 out-dir lock | Pipeline bug (found by the driver, confirmed by the supervisor in `pipeline_make.py` `sweep`) | Fixer dispatched after the run ended (supervisor rule, clean files), branch `sup/nanopb-wp-sweep-outdir`, merged to main in `7cf7e5d` | [`../troubleshooting/wp-and-guardrail.md`](../troubleshooting/wp-and-guardrail.md) (written by the driver, Fix updated by the supervisor) |
| `insufficient_memory` (`wp needs 1768 MiB but the pool has 1024 MiB`) when re-proving through the driver's run-dir script | Not a pipeline defect: the wrapper inferred `light` for `repair/resweep_one.py`, which no class pattern knows; a real `pipeline_make.py sweep` / `run wp-sweep` is sized as a phase | The driver's entry blamed "a direct `pipeline_make.py sweep` without `-Class wp`"; the supervisor corrected cause and fix by calling `resources.infer_class` on the three command strings (`run wp-sweep` and `sweep` give `phase-static`, the script gives `light`) | same file (corrected by the supervisor) |
| Crash Verifier brief never names the threat model the run was given; the `pb_write` verifier wrote "the target's own threat-model text was not found in the run directory" | Brief gap | Open, not dispatched (brief change) | [`../troubleshooting/ledger-and-verifier.md`](../troubleshooting/ledger-and-verifier.md) (written by the supervisor) |
| Verifier briefs do not list the allowed `evidence[].phase` values; two verifiers wrote `verify`, `validate_artifacts` refused it, and they corrected it to `verifier` | Brief gap (model error caught by the validator) | Suggestion only | none |
| 19 CRLF scripts, `spm_headers/` symlinks stored as text | Target-side, not a pipeline defect | Worked around in the recipe (CRs stripped from the 4 scripts the tests run) | [`../troubleshooting/phase0-build-and-model.md`](../troubleshooting/phase0-build-and-model.md) (written by the driver) |

### Model behaviour (not pipeline bugs)

- The driver wrote its own wrapper shortcut (`fc.ps1`, in its scratchpad) and kept to `pipeline_make.py` targets; no pipeline file was edited.
- It copied `regressions/` and `sample_data/*.pb` to `<run>/inputs/corpora/` by hand, the documented import location, because `fuzz_assets.py discover` does not find them by name.
- It ran Eva before fuzz coverage and `reach-dynamic`; the Phase 1 skill allows Eva alongside fuzzing, and it ran coverage afterwards (21:00), as it said.
- It added a "Seen again" note on nanopb to the eva-tune duration entry in `eva.md`, linking to the supervisor's recursion entry. One detail there is off: `slevel` and `unroll` timed out at 1030 s inside their first attempt, not after a retry.
- In Phase 3 it prepared four agents (`pb_write` negotiator and breaker, `pb_encode_fixed32` and `pb_encode_fixed64` negotiators) and only started them later, after the user's stop decision: a bookkeeping slip, not a pipeline bug (the scheduler kept the tasks pending). It also gave the `pb_write` breaker a task beyond its brief (whether `bytes_written += count` can wrap on a sizing stream, naming an input only if found); a candidate from it still goes through a Crash Verifier.
- After the sweep lost `pb_ostream_from_buffer`, it wrote a run-dir script (`repair/resweep_one.py`, driver transcript line 2759) that monkeypatches `pipeline_make.sweep_list` to the one function, then re-ingested the report by hand with `ledger.py ingest-wp`. This was outside the documented sweep, but recorded in the troubleshooting entry with the pipeline still marked defective, and no pipeline file was edited. It then blamed the script's `insufficient_memory` on the sweep itself, without reading `resources.py` (its entry says "the lease code was not read"); the supervisor corrected that entry. Suggestion (not applied): the Phase 4 skill could say that a run-dir script calling a phase function needs an explicit `-Class`.
- It received each subagent's completion notice several times (the harness repeats them) and processed each result once.
- Its harness repair follows the WP skill's repair task (`--record-repair` first, at most 2 per module). The rewrite is by hand in the generated harness, which is the documented repair, not a gate bypass. It is the hand-made version of the plan's S3 (a schema instance in place of fuzzed descriptor bytes), so the rerun's Dead count and crashes are an early data point for that plan. The reader cases (`pb_read`, `pb_decode_varint`, `pb_decode_svarint`, `pb_decode_bool`, `pb_skip_field`, `pb_make_string_substream`) are not in the 14 and still get a zeroed stream, so `buf_read` is still reached only through `pb_decode`/`pb_decode_ex`.

## Fixes

The guardrail and eva-tune fixers were dispatched at 22:50 at the user's request. The L3 (00:35), `#ifdef` (00:50) and sweep out-dir (after the run) fixers were dispatched by the supervisor rule for a confirmed bug in files outside the dirty list. All five were held until the terminal state (`hold`), then merged; their worktrees (column below) are removed.

| Fingerprint | Branch | Worktree | Status |
| :--- | :--- | :--- | :--- |
| guardrail `guardrail_error` on a burst-mutation sanitizer crash outside the checked functions | `sup/nanopb-guardrail-mutation-sanitizer` | `.agents/worktrees/sup-nanopb-guardrail-mutation-sanitizer` | committed `e97d37d`; 3 tests in `tests/test_guardrail_p1.py` (2 fail on the old code); fixer's full suite 7994 passed, ruff, mypy, check_generated_text clean; supervisor reread the diff and reran the file (89 passed); merged to main in `6ce14ac`, branch deleted |
| merge span takes the first of two `#ifdef`/`#else` definitions | `sup/nanopb-ifdef-twin-definitions` | `.agents/worktrees/sup-nanopb-ifdef-twin-definitions` | committed `63e5c14`, `0dd053e` (fixer) and `7510cb6` (supervisor: the pinned assertion in `tests/test_acsl_ast_conditionals.py`, which the fixer could not edit); 21 tests in `tests/test_ifdef_twin_definitions.py`; fixer's full suite 8013 passed plus that one assertion; supervisor reran the twin, conditionals, frame and merge tests (66 and 96 passed); merged to main in `95a17c9`, branch deleted (the dirty `tests/test_acsl_ast_conditionals.py` was handled as described under "Merge at the terminal state") |
| L3 asset `\formal` guards applied by parameter name, not type | `sup/nanopb-l3-asset-param-type` | `.agents/worktrees/sup-nanopb-l3-asset-param-type` | committed `570965d`, `bb6840b`; 15 tests in `tests/test_security_props_asset_param_type.py` (12 fail on the old code); Docker on nanopb's sources: 406 `Cannot find field` errors to 0, instances 47/49 to 20/22; adds the optional schema field `param_type`; fixer's full suite 8008 passed, ruff, mypy, check_generated_text clean; supervisor reread the selection logic and reran the security_props tests (100 passed); merged to main in `2444bd7`, branch deleted |
| eva-tune rungs repeat the aborting recursion attempt | `sup/nanopb-eva-tune-recursion` | `.agents/worktrees/sup-nanopb-eva-tune-recursion` | committed `7c2b480`, `2ff5040`; 13 tests in `tests/test_eva_tune_recursion.py` (7 fail on the old code, 1 skipped without `make`, `make -n` checked in the analysis image); fixer's full suite 8005 passed, ruff, mypy, check_generated_text clean; supervisor reread the diff and reran it with `test_eva_tuning.py` (168 passed); merged to main in `794b367`, branch deleted |
| sweep jobs of one file share a `--out-dir` and lose the out-dir lock | `sup/nanopb-wp-sweep-outdir` | `.agents/worktrees/sup-nanopb-wp-sweep-outdir` | committed `080a20a` (`pipeline_make.py` `sweep()`: out-dir `work/<slug>/<function>`; one assertion in `tests/test_pipeline_make.py`); 2 tests in `tests/test_wp_sweep_outdir.py` (both fail on the old code); fixer's full suite 7995 passed, ruff, mypy, check_generated_text clean; supervisor reread the diff and reran the new module with `test_pipeline_make.py` (113 passed); merged to main in `7cf7e5d`, branch deleted |

### Merge at the terminal state

Done on 2026-11-21, after the run reached `incomplete`. Nothing is pushed.

- **Dry-run:** all five branches merged without conflict into a scratch worktree at `main` (`6877117`), in the order guardrail, eva-tune, L3, `#ifdef`, sweep. The combined tree passed: `pytest -n auto` 8049 passed, 330 skipped; ruff, mypy (345 files) and `check_generated_text.py` clean.
- **Merge:** `main` fast-forwarded to the five `--no-ff` merge commits, `6ce14ac`, `794b367`, `2444bd7`, `95a17c9` and `7cf7e5d`. The tree is identical to the tested one.
- **Dirty file:** `tests/test_acsl_ast_conditionals.py` held another session's uncommitted formatting change. It was saved as a patch, the file was restored for the fast-forward, and the patch was re-applied cleanly. It is unstaged again, and the `#ifdef` assertion and the formatting change are both present (66 passed).
- **Full suite in the main checkout** (with the other session's 55 uncommitted files): 8049 passed, 330 skipped; ruff and mypy clean.
- **Branches:** all five deleted with `git branch -d` (fully merged), and their worktrees and the dry-run worktree removed. `tools/sync_skill_mirrors.py --check` passes.
- **Real-target check:** none yet. The next nanopb run is the end-to-end check of the five fixes, especially the L3 and `#ifdef` fixes that blocked 30 or more units here.

The Fix bullets of the five troubleshooting entries now name these merge commits.

## Troubleshooting entries

Written or updated during this run (all uncommitted in the main checkout):

| File | Entry | Written by | Status |
| :--- | :--- | :--- | :--- |
| [`../troubleshooting/wp-and-guardrail.md`](../troubleshooting/wp-and-guardrail.md) | Guardrail `guardrail_error` on a sanitizer crash outside the checked functions | supervisor | fixed, merged to main |
| same | Merge refuses the proven contract on the compiled `#ifdef` twin (`pb_release`) | driver; supervisor added the Fix bullet | fixed, merged to main |
| same | `wp-sweep` `out_dir_locked` turns a proved unit `blocked` | driver; supervisor confirmed it and updated the Fix bullet | fixed, merged to main |
| same | `insufficient_memory` from a run-dir script without `-Class` | driver; supervisor corrected the cause | not a pipeline defect |
| [`../troubleshooting/eva.md`](../troubleshooting/eva.md) | eva-tune rung ends `analysis_timeout` after a short retry (recursion first attempt) | supervisor; driver added a "Seen again" note to the older duration entry | fixed, merged to main |
| [`../troubleshooting/security-properties.md`](../troubleshooting/security-properties.md) | L3 `\formal(stream)->bytes_written` on `pb_istream_t` formals | driver; supervisor added the Fix bullet | fixed, merged to main |
| [`../troubleshooting/ledger-and-verifier.md`](../troubleshooting/ledger-and-verifier.md) | Crash Verifier brief never names the run's threat model | supervisor | **open** |
| [`../troubleshooting/harnesses-and-seeds.md`](../troubleshooting/harnesses-and-seeds.md) | Fuzz report says `seed_harvest.py record has not run` although it ran | supervisor | **open** (cosmetic; `seed_harvest.py` is dirty) |
| same | `seed_harvest` `no_test_units` for a scons suite with its own library copy; the shipped fuzzer and corpora feed no case | driver | **open** gaps |
| [`../troubleshooting/phase0-build-and-model.md`](../troubleshooting/phase0-build-and-model.md) | CRLF scripts and text symlinks in a Windows checkout | driver | target-side, not a pipeline defect |

No upstream Frama-C or E-ACSL draft: the WP limits met here (the `void *` cast, `\valid_function`) are already known and recorded.

## Open pipeline bugs after this run

- Crash Verifier brief: no threat-model path (brief gap; open).
- `seed_harvest` status line in the fuzz report (cosmetic; open, its file is dirty).
- `seed_harvest` `no_test_units` for a test suite that builds its own library copy, and shipped fuzzers whose generated descriptors are missing (gaps; open).
- The `--api` harness fills trusted parameters and zeroes attacker ones (design gap; plan [`../plans/archive/schema-driven-api-harness-plan.md`](../plans/archive/schema-driven-api-harness-plan.md), not implemented).
- Verifier briefs do not list the `evidence[].phase` values (suggestion only).

The five fixed bugs (guardrail burst, eva-tune recursion, L3 asset type, `#ifdef` twins, sweep out-dir) are merged into local `main` and not pushed.

## Not verified by the supervisor

- The `pb_write` wrap was shown by the verifier's standalone driver; the supervisor did not rerun it.
- The per-phase times come from the supervisor's timeline, not from run timestamps.
- None of the five fixes was rerun on the full nanopb target. Each was checked on its unit tests, and the L3 fix also on nanopb's sources in Docker by its fixer. The real-target check is the next nanopb run.
- The driver's entry on `seed_harvest` `no_test_units` and the shipped fuzzer gap were read, not reproduced.
