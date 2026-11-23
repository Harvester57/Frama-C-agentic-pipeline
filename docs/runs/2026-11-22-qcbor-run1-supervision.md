# QCBOR run-1 (2026-11-22): supervision report

- **Target:** QCBOR v2.0-beta-1, commit `47df2bc4240d` (tag checked out; `dirty: true` in `run-metadata.json` only because of the untracked `.security-reviews/`), profile `standard`, full mode.
- **Run directory:** `~/framac-pipeline/QCBOR/run-1`, created 2026-11-22 22:10:20 local. The earlier QCBOR run directories (run-1 to run-6, 2026-11-09 to 2026-11-14) are no longer on disk, so the pipeline numbered this run `run-1`, not `run-7`. Run tag: `run-1-f5a3a2e5f257`.
- **Driver:** a Claude Code session on Sonnet 5.5 (`qcbor-run`), started by the supervisor at the user's request. It shares this checkout.
- **Pipeline:** `main` at `069ab4b`. The 10 uncommitted files in the checkout are all under `docs/upstream/frama-c/` (draft 46, another session's work); the run executes no uncommitted pipeline code.
- **Threat model:** `.security-reviews/20261122T195552Z-47df2bc/ThreatModel.md`, passed in place. SHA-256 `6b073f84d8b45ea0f8fa4239621aec018133858f36850f875c1b216f79713e99`, checked by the supervisor at 22:09 (matches the user's value). The model is "valid but partial" (Q1-Q3 unanswered, default build assumed).
- **CodeQL:** enabled, open source, declared by the user (`run-metadata.json` `codeql`, 22:10:28).
- **Fix mode:** `hold`. Fixes stay on `sup/QCBOR-<slug>` branches until the run ends; any live merge needs the user's approval.
- **Status:** **`incomplete`, stopped by the user** at about 00:45 during Phase 2 `eva-tune` (`run-metadata.json` `incomplete_reason`, written by the driver at 00:47:09).
  - Done: Phase 0, Phase 1 (fuzz, judge, coverage, dynamic reach) and the base Eva run.
  - Not run: `eva-tune`, `ingest`, `wp-queue`, the Crash Verification Gate and Phase 3 WP.
  - Docker Desktop's engine had also restarted and killed the `eva-tune` container (`error waiting for container: unexpected EOF`, exit 125) under load from another session.
  - No `run-1-f5a3a2e5f257` container is left (checked by the supervisor at 00:48). `state/progress.json` still says `status: running`, `phase_done: 0` (last updated 22:15 local).

## Final summary

- **Wall clock:** 22:10:20 to 00:47:09, **2 h 37 min**. Per phase, from the run's files and the supervisor's timeline:
  - Phase 0: 22:10 to 22:15, about 5 min.
  - Phase 1: 22:15 to 23:17, 62 min (fuzz explore 53 min, judge 3 min, coverage and dynamic reach 5 min).
  - Phase 2: base Eva 23:18 to 00:14, 56 min. `eva-tune` from 00:24 until the stop.
- **Findings:** none. No QCBOR defect was confirmed or rejected: the Crash Verification Gate never ran. Its one candidate (case 116) is harness-induced (F3).
- **The user's checks:**
  1. Threat-model identity passed.
  2. Harness scope: 29 of 34 private entries harnessed, mismatches listed.
  3. Caller-storage parameters are exempted, not bound to instances.
  4. CodeQL ok: 0 facts added, 3 dropped.
  5. One harness-induced candidate from a shape the model did not list. It was never verified, because the gate did not run.
  6. Coverage priorities 3, 6 and 7 and the BigNumber paths were not exercised by Phase 1 nor analysed by Eva. Known bug 09 (`ProcessBigNumber`) is likely still present and was out of reach.
- **Fixes (held by the supervisor; F1 and F2 since reached `main` through another session):**
  - F1, `sup/QCBOR-trusted-cstring-instance` (`4b92d56`, `8520a72`): on `main`;
  - F2, `sup/QCBOR-stateful-sequence-cases` (`5743663`, `f72347c`), stacked on F1: on `main`;
  - F3, `sup/QCBOR-string-rest-zero-copy` (`95b9c83`), stacked on F2: its `api_harness.py` guard is on `main` as a separate commit; its `benchmark_seeded.py` guard is not.

  At 00:50 on 2026-11-23, the session working [`../plans/phase1-qcbor-lessons-plan.md`](../plans/phase1-qcbor-lessons-plan.md) merged `feat/phase1-qcbor-lessons` into `main` (`ecc274b`). That branch contains F1 and F2 and its own F3 commit (`6e9f982`, `api_harness.py` and its test only). It also adds W1-A, a caller-storage buffer builder (`fb2b073`), and W1-B, multi-segment traces (`981de81`). The supervisor did not do this merge. A dry run of `95b9c83` onto `ecc274b` conflicts in `scripts/api_harness.py` and `tests/test_api_harness_soundness.py`, which hold two versions of one fix. Only F3's `scripts/benchmark_seeded.py` hunk and its assertion in `tests/test_benchmark_seeded.py` are left to land. Neither file is in the checkout's dirty list.
- **Open pipeline bugs and gaps recorded this run:**
  - the 256-call trace cap (`harnesses-and-seeds.md`; W1-B on `main` now harvests several segments, not checked on QCBOR);
  - F3's `benchmark_seeded.py` guard, still only on `sup/QCBOR-string-rest-zero-copy`;
  - `pSavedState` and `pInfo` still auto-exempt (`harnesses-and-seeds.md`);
  - the byte rest's one-past-the-end pointer of length 0 (`harnesses-and-seeds.md`);
  - five stateful-case gaps (`harnesses-and-seeds.md`);
  - the MetAcsl L5 property on a buffer-descriptor sink (`security-properties.md`);
  - Eva's certain-in-some-contexts alarms filed as Unknown, with 97 Dead functions (`eva.md`);
  - containers outside the host broker oversubscribing the host (this report's timeline; not a troubleshooting entry, since it is an environment conflict between sessions).
- **Not verified:**
  - the fixes under the E-ACSL build and Eva on the real `libqcbor_a` harness;
  - whether the three `decode_nesting.h` alarms are reachable in real executions;
  - which Eva cut kills which Dead function;
  - drafts 01 and 08 on v2.0-beta-1.

## Timeline

Times are local (UTC+1), from the run's files, `progress.json` and the driver's transcript.

| Time | Event |
| :--- | :--- |
| 22:09 | Supervisor baseline: `main` at `069ab4b`, threat model SHA-256 checked, no framac container running. |
| ~22:10 | Driver session started (Sonnet 5.5). |
| 22:10:20 | `run-1` created (`run_metadata.py init`); resources measured as 1 CPU / 1024 MiB in the driver's container, pool 30 CPUs / 36096 MiB from the host broker. Warning: the run dir is on 9p. |
| 22:10:28 | CodeQL enabled (open source, declared by the user). Run identity `QCBOR-90cd38bae564` / `run-1-f5a3a2e5f257`. |
| 22:10:31 | `trust.py check-threat-model` on the in-place model: `status: ok`, no error. `resources.py recommend`: pool 30 CPUs / 36096 MiB; the run dir is on 9p. |
| 22:10:42 | `workspace_overlay.py init`: 48 files, 0 CRLF scripts. `build_capture.py propose` proposed `cmake -S . -B build && cmake --build build` with no test command; the driver asked the user instead. |
| 22:11:00 | The user chose `make` + `./qcbortest` in the driver session; recorded with `origin: user` (22:11:05). |
| 22:11:10 | Build capture `ok` in 2.7 s: units `libqcbor.a` (static_lib, 9 sources) and `qcbortest` (executable, test). Snapshot empty (`files: 0`, digest of the empty input): QCBOR needs only libc and toolchain headers, which are excluded. |
| 22:11:20 | `phase0_model.py run --threat-model /target/.security-reviews/...`: `libqcbor.a` `ok`, `qcbortest` `skipped_test`; 757 functions, 1135 edges, 3.8 s. |
| 22:11:24-22:12:21 | `codeql_trust.py run` (56 s, CodeQL 2.27.3) and `trust.py run`, both `ok`. |
| 22:12:35-22:13:35 | Seeds (`seed_harvest.json`), fuzz assets, DAG, stubs, security properties, `--api` harness `libqcbor_a` (126 cases, 42 auto-exempt), reach gate `passed` (135/158 reached, 23 exempt). |
| 22:15:34 | Phase 0 done (`build-check`), `phase_done` 0. Phase 0 took about 5 min. |
| 22:15:30 | Phase 1 `pipeline_make.py run fuzz` started (container `framac-c5f799aef069`). |
| ~22:35 | Driver's check: 7 sanitizer workers at about 5.8k exec/s each, about 6M execs each, no crash, coverage flat at about 2860 edges. Per-worker budget `-max_total_time=3086` (about 51 min), so the explore stage should end near 23:10; the E-ACSL judge stage follows. |
| ~23:00 | Driver's monitor saw no container once at 22:00Z; it was a transient `docker ps` failure (the supervisor's poller saw the container up at the same time). |
| 23:08:42 | Fuzz explore ended: `make fuzz` rc 0 in 3190 s, `status: clean`, no artifact. 141.4M executions on 7 sanitizer workers (21820 CPU s of a 21600 s budget), `max_cov` 2876 edges, `max_ft` 5216, corpus 2591 after merge, peak RSS 475 MiB, no OOM kill; `keep_going` stopped on `no_new_case`, 0 skipped or blinded cases; auto dictionary of 237 entries. The E-ACSL judge then replays the seeds and a sample of the corpus. |
| 23:12:15 | E-ACSL judge: 3225 of 43465 inputs judged (1177 mandatory seeds, 2048 of the grown corpus, the rest left out by the cap), 3224 pass, 1 `crash_found` on case 116 (harness-induced, see check 5 and F3). |
| 23:17:26 | Coverage (`coverage/libqcbor_a.json`) and dynamic reach: 118 of 158 entry points executed by the corpus. Phase 2 (Eva, then `eva-tune`) started next. |
| 23:18-00:14 | Eva base run, unsharded, `status: ok` in 3362 s (under the 7200 s cap): 4315 properties, 4071 Valid, 244 Unknown in 79 functions, 0 Invalid, 3325 Dead, 361 assumed, 94.35% discharged. One `nonterm` (`qcbor_main_decode.c:1409`). Disk: `flows.log` 1.96 GB, `flows.json` 620 MB; the flamegraph, about 1 GB during the run, ends at 2.2 MB. `eva-tune` started at about 00:22. See check 6 for what the Dead count hides. |
| 00:30-00:39 | **External load.** From 00:30, about 25 containers from image `framac-master-audit:189053d` started, plus two `framac-analysis:latest` and one `framac-codeql:latest`, none labelled `framac.run`. They belong to another session, not to this run or to the supervisor's fixers, which had all finished. By 00:37 the host CPU was at 99% and the Docker Desktop API answered `500 Internal Server Error` to `docker ps` (58 s per call). `eva-tune`'s `tune/base/flamegraph.txt` was last written at 00:35:04. The supervisor sent the user a push notification and touched nothing. These containers are outside the host broker, so the run's CPU leases do not account for them. |
| 00:40-00:45 | `docker top` on the run container: `eva-tune`'s `frama-c` (pid 87796) alive after 15.5 min at 32% of one core (CPU starvation, not a stall). The driver had said it would apply the 15-minute no-progress rule. At the user's word ("send"), the supervisor messaged the driver: it is starvation, do not stop `eva-tune` under that rule. This is the only message sent to the driver so far. |
| ~00:45 | **The user stopped the run** ("stop the run"). The supervisor relayed it to the driver, quoting the user's words: stop `eva-tune` cleanly, remove only `run-1-f5a3a2e5f257` containers, record the run as stopped by the user, start nothing new. |
| 00:47:09-00:48 | The driver recorded `run_status: incomplete` with the user's stop as the reason, and the note that Docker Desktop's engine had restarted and killed the `eva-tune` container (exit 125). The supervisor's poller saw the terminal status at 00:47:43; no run container was left. |

## The user's checks

### 1. Threat model identity

**Passed.** `trust.threat_model` in `workspace/reports/phase0_model.json` (written 22:12:21): `status: ok`, `sha256: 6b073f84d8b45ea0f8fa4239621aec018133858f36850f875c1b216f79713e99`, equal to the user's value; path `/target/.security-reviews/20261122T195552Z-47df2bc/ThreatModel.md` (in place, not copied). `trust.py check-threat-model` printed `status: ok`, `errors: []` at 22:10:31. The transcript keeps only the JSON, not the exit code; `cmd_check` returns 0 exactly when the status is `ok` (`scripts/trust.py:1077`), so it exited 0.

Trust summary: 353 untrusted functions (158 from the threat model, 191 from the call graph, 4 by default), 404 trusted (18 from the threat model), 162 on the boundary, 18 overridden. The 158 is the block's 159 `input_sources` minus `main`.

`trust.py` warnings (7):

- `input source main is not a function of the build` and `output_sinks names cmd_line_main.c#fputs_wrapper, which is not a function of the build`: the test program `qcbortest` is a `skipped_test` unit, so its functions are not in the model. Expected; not a pipeline defect.
- `public_lib export ... is missing from THREAT_MODEL.md input_sources` for `UsefulOutBuf_Init`, `QCBORDecode_CompatibilityV1`, `QCBORDecode_SetMemPool` and `QCBOREncode_Init`. These are the 4 exported functions among the model's 13 `no-attacker-data` ones (the other 9 are static inline in headers, so the build has no symbol for them). The block has no field for `no-attacker-data`, so the pipeline counts them as `untrusted:default`. Check 2 follows what the harness does with them.
- The CodeQL warning (check 4).

### 2. Harness scope against the block's 159 `input_sources`

Source: the sidecar `workspace/harnesses/harness_libqcbor_a.json` (22:13:12) and `workspace/reports/harness_reach.json` (22:13:35), compared by the supervisor's script with the block. One harness module, `libqcbor_a` (Tier 1A), `dispatch` style: **126 cases, 42 `api_auto_exempt`, 0 `reach_exempt`**. Reach gate `passed`: 158 entry points, 135 reached by the harness, 23 unreached and exempt, 0 gaps.

**2a. The 34 `*_Private_*` entry exports: 29 harnessed, 5 mismatches.** All 34 are `untrusted:threat_model` DAG entry points. Not harnessed:

| Function | Reason in `api_auto_exempt` | Expected by the model? |
| :--- | :--- | :--- |
| `QCBORDecode_Private_MapSearch` | `trusted parameter pInfo has no instance` | Yes (Unknowns, "Harness binding") |
| `QCBORDecode_Private_GetDoubleConvertInMapSZ` | `trusted parameter szLabel has no instance` | No |
| `QCBORDecode_Private_GetInt64ConvertInMapSZ` | same | No |
| `QCBORDecode_Private_GetTaggedStringInMapSZ` | same | No |
| `QCBORDecode_Private_GetUInt64ConvertInMapSZ` | same | No |

The 29 others each have one case (`AppendCBORHead`, `AddBuffer`, `GetNextTagContent`, `SearchAndGetArrayOrMap`, `CloseMapUnsorted`, `InIndefString` and the rest).

**2b. The 18 `trusted_callers`: all 18 match.** Each is `trusted:threat_model` and none has a case. 9 of them (the 11 decoder helpers minus `QCBORDecode_Private_GetItemInMapNoCheck` and `QCBORDecode_Private_GetNextMapOrArray`) are still entry points in the model; the reach gate counts only the 158 untrusted entry points, so they are exempt as trusted, not through `api_auto_exempt`. The other 9 (those two and the 7 `IEEE754_*`) are not entry points at all.

**2c. The 13 `no-attacker-data` functions: none harnessed.** 9 are static inline or otherwise not exported (`trusted:default`, not entry points). The 4 exported ones (`QCBORDecode_CompatibilityV1`, `QCBORDecode_SetMemPool`, `QCBOREncode_Init`, `UsefulOutBuf_Init`) are `untrusted:default` in the trust summary, because the block cannot list `no-attacker-data` functions, but they are not among the reach gate's 158 entry points and have no case. `QCBOREncode_Init` and `UsefulOutBuf_Init` are used as `api_helpers` (set-up calls inside other cases). So in effect they are exempted, though the record calls them untrusted.

**2d. Other `input_sources` not harnessed: 37**, all in `api_auto_exempt`, plus `main` (not in the build). With the 5 above, that is all 42 auto-exempt entries:

| Reason | Count | Of which unreached (reach-gate exempt) |
| :--- | ---: | ---: |
| `trusted parameter szLabel has no instance` | 26 (4 `*_Private_*`, 22 public) | 13 |
| `MantissaBuffer` / `BufferForMantissa` / `BigNumberBuf` | 4 / 4 / 3 | 2 / 2 / 3 |
| `pInfo`, `pSavedState`, `Buffer`, `Dest`, `pDest` | 1 each | 0, 1, 1, 0, 1 |
| **Total** | **42** | **23** |

The 22 public `szLabel` functions: `QCBORDecode_SeekToLabelSZ`, `EnterArrayFromMapSZ`, `EnterMapFromMapSZ`, `EnterBstrWrappedFromMapSZ`, `GetBoolInMapSZ`, `GetSimpleInMapSZ`, `GetItemInMapSZ`, `GetNextTagNumberInMapSZ`, the three `Get*ConvertAllInMapSZ` getters, and the `GetT*InMapSZ` getters (`BigFloat`, `BigFloatBigMantissa`, `BigFloatBigMantissaRaw`, `BigNumber`, `BigNumberRaw`, `DecimalFraction`, `DecimalFractionBigMantissa`, `DecimalFractionBigMantissaRaw`, `EpochDate`, `EpochDays`, `MIMEMessage`).

`szLabel` is a `const char *` label the application chooses. The model leaves it out of `params`, so `api_harness.py` treats it as trusted and finds no instance for a C string. The model did not anticipate this (its "Harness binding" row lists only caller storage, `pSavedState` and `pInfo`). It costs the harness the text-label branch of map search: `QCBORDecode_SeekToLabelSZ` is named in Coverage Priority 3. There are two ways to close it:

- In the pipeline: bind a trusted C-string parameter to a fixed literal. A fixer is working on that (F1).
- In the model: list `szLabel` in `params`, as the model already does on purpose for other parameters the application chooses (`EncodeHead`'s `uMajorType`/`uMinLen`, `UsefulBuf_SubString`'s `uStart`). The label would then be fuzzed. That needs a model rerun and a new run.

No function outside the block's `input_sources` is harnessed.

### 3. Trusted-parameter binding

**Every entry function whose caller-storage parameter is trusted is exempted (`trusted parameter <name> has no instance`), not bound to a schema instance or a builder; none gets raw bytes.** This is the outcome the model's Unknowns "Harness binding" row expected for these functions. Where storage does appear in a harnessed case, it is bound through a builder: for example the encoder cases (`AppendCBORHead`, `AddBuffer`) call `QCBOREncode_Init` with a harness-owned 4024-byte static array whose length comes from the input (capped at 4024). The supervisor checked the cases named in check 5 and the encoder cases; it did not scan all 126 cases' trusted-role parameters.

| Parameter | Functions exempted for it |
| :--- | :--- |
| `BigNumberBuf` | `QCBORDecode_GetTBigNumber`, `QCBORDecode_GetTBigNumberInMapN`, `QCBORDecode_ProcessBigNumber` (`GetTBigNumberInMapSZ` is exempted for `szLabel` first) |
| `MantissaBuffer` | `QCBORDecode_GetTBigFloatBigMantissa`, `GetTBigFloatBigMantissaRaw`, `GetTDecimalFractionBigMantissa`, `GetTDecimalFractionBigMantissaRaw` |
| `BufferForMantissa` | the four matching `*InMapN` getters (the `*InMapSZ` ones are exempted for `szLabel`) |
| `pSavedState` | `QCBORDecode_RestoreCursor` |
| `pInfo` | `QCBORDecode_Private_MapSearch` |
| `Buffer` | `QCBOREncode_EncodeHead` |
| `Dest` / `pDest` | `UsefulBuf_CopyOffset`, `UsefulOutBuf_CopyOut` |

`Storage` and `Pool` appear only in set-up functions: `QCBOREncode_Init` and `UsefulOutBuf_Init` (`Storage`) run as `api_helpers` inside other cases, and `QCBORDecode_SetMemPool` (`Pool`) has no case. Of the 23 unreached entry points the reach gate exempts, 10 are in this table (`GetTBigFloatBigMantissa`, `...InMapN`, `GetTBigNumber`, `...InMapN`, `GetTDecimalFractionBigMantissa`, `...InMapN`, `ProcessBigNumber`, `RestoreCursor`, `EncodeHead`, `UsefulOutBuf_CopyOut`); the others are reached through callers the harness does drive.

A builder that gives a trusted by-value `UsefulBuf` a fixed backing array would cover the first, second, third, sixth and seventh rows. It is not in the current generator; whether to add one is the user's call.

### 4. CodeQL

**Both ended `ok`.** `codeql_trust.py run`: CodeQL 2.27.3, database 5.0 s, query `templates/codeql/trust/untrusted_functions.ql` 49.5 s, 4 rows, 0 outside the target, 3 functions. `trust.py run`: `codeql.status: ok`, `facts: 0`, `unmatched: 3`, `with_codeql: 0`.

- **Facts CodeQL adds: 0.**
- **Dropped as "not in the model": 3 functions (all 4 rows):** `cmd_line_main.c#main`, `test/run_tests.c#RunTestSet`, `test/run_tests.c#RunTestsQCBOR`. All three are in the test program, which Phase 0 skips (`skipped_test`).

This is what the user expected for a library with no input reader: the only reader calls CodeQL found are in the test driver.

### 5. Harness-induced crashes

What the harness can produce, from the generated cases (`harness_libqcbor_a.c`, cases 45 and 89):

| Shape the model warns about | In this run's harness |
| :--- | :--- |
| By-value `QCBORItem` in `QCBORDecode_ProcessBigNumber` | **Not exercised**: auto-exempted for `BigNumberBuf`, unreached. |
| Unterminated label array in `QCBORDecode_Private_MapSearch` | **Not exercised**: auto-exempted for `pInfo`. |
| Unterminated `pTarget` in `QCBORDecode_Private_SearchAndGetArrayOrMap` | **Cannot occur**: `pTarget` is a zeroed `QCBORItem` array (112 bytes), so its first entry already has `uLabelType == QCBOR_TYPE_NONE` (0), the terminator. The case searches for nothing; the input drives only the decoder (`QCBORDecode_Init` on the remaining bytes, fuzzed decode mode). |
| `uMajorType`/`uMinLen` outside the wrapper constants in `QCBOREncode_Private_AppendCBORHead` | **Cannot occur**: both are trusted scalars, zeroed (major type 0 = `CBOR_MAJOR_TYPE_POSITIVE_INT`, `uMinLen` 0); only `uArgument` is fuzzed. |
| The same in `QCBOREncode_EncodeHead` | **Not exercised**: auto-exempted for `Buffer`, unreached. |

So none of the five shapes can produce a crash in this run. A candidate at these functions would come from another path; the Crash Verifiers' handling is checked when the gate runs (`findings.json` `rejection_class`, the verifiers' `result.json` and transcripts).

**One harness-induced candidate arose from a shape the model did not list** (judge, 23:12). The E-ACSL judge confirmed `memcpy: unallocated (or insufficient) space in source space` on `seed-17a8a928db558c9c` (32 bytes), case 116, a recorded decoder `sequence`; fingerprint `unknown#main::mem_access::8674205c9c`, return code 77, `reproducible` and `standalone_confirmed`. The supervisor's diagnosis: the input is the selector plus exactly the 31 bytes of the case's fixed slots, so the harness's string-rest copy is `memcpy(c11a0, block + 32, 0)`, a zero-length copy from one past the end of the exact-size input block. E-ACSL's `memcpy` aborts on it; ASan does not. The defect is in the harness code (`api_harness.py`, string rest without a `rest_n == 0` guard); QCBOR code never runs before the abort. Expected at the gate: `rejection_class: harness_induced`. The parsed failure names `main` in an `unknown` file, so the verifier has to read the frames to see that the copy is the harness's (to check). Pipeline bug F3.

### 6. Findings against Coverage Priorities 1-10

Pending the findings. What the Phase 1 explore stage reaches, read at about 22:52 from the workers' libFuzzer logs (`/tmp/fuzz_scratch_libqcbor_a_115/fuzz-*.log` in the run's container, read-only) and from the corpus:

- **Edge coverage:** 2870 of the binary's 4775 instrumented edges (60%; the count includes the harness and every function of `libqcbor.a`, also the exempted and unreached ones). The seeds alone (1177 from `qcbortest`, plus 7239 per-case `floor_*` inputs the pipeline writes) gave 2566 (54%) at `INITED`. Fuzzing added about 300 edges, nearly all in the first 1.5M execs per worker (2819 by then), then about 50 more over the next 9M. 7 workers, about 10.5M execs each, 0 crashes.
- **Per case:** all 126 cases have corpus inputs. The decoder cases hold most of them (`Private_EnterBoundedMapOrArray` 8312, `VGetNextConsume` 4552, `Private_GetDoubleConvert` 3137). 21 cases hold at most 3: 13 encoder cases, `Enter{Array,Map,BstrWrapped}FromMapN`, and 5 small `UsefulBuf`/`Init` cases.
- **Why the encoder cases are flat:** 11 of them are `QCBOREncode_Init` and one call on an empty context, with the storage length as the only input, so they reach only the error path. Coverage Priority 6 (map sort over pre-encoded bytes) and most of Priority 7 (nesting open/close) are therefore not fuzzed; no sequence case drives the encoder. This is the open run-6 gap "Generated Cases for the `*InMap*` Spiffy Accessors Call the Accessor on a Fresh Context", extended in `docs/troubleshooting/harnesses-and-seeds.md` to the encoder.
- **Consequence for F1:** the `*InMapSZ` cases F1 adds are single calls after `QCBORDecode_Init` too. If they hit the same fresh-context limit, they reach `QCBOR_ERR_MAP_NOT_ENTERED` rather than the label search; the coverage stage's per-function report will show it.
- **Coverage stage (23:13, `clang-source-coverage`, all 43465 corpus inputs replayed, 0 failed):** `libqcbor.a` sources, 2754 of 4020 regions (68.5%) and 244 of 315 functions executed; with the headers' inline functions, 2880 of 4566 regions and 292 of 757 functions. Dynamic reach: 118 of 158 entry points executed; the 40 others are the 26 `*InMapSZ`/`SeekToLabelSZ`/`*SZ` entries (F1), the `BigMantissa`/`BigNumber` getters, `ProcessBigNumber` and `RestoreCursor` (caller storage, check 3), and `UsefulBuf_CopyOffset`/`UsefulOutBuf_CopyOut`. All are exempt, so the dynamic gate passes.
- **Eva (Phase 2) does not reach most of the gaps either, and reaches less than fuzzing did.**
  - 97 library functions have only `Dead` properties. They include the whole Priority 6 sort (`SortMap`, `ConsumeNext`, `UsefulOutBuf_Compare`), `ProcessBigNumber`, the `ExpBigMantissa*` and `Exponentitate*` functions, `MemPool_*`, `RestoreCursor` and `UsefulBuf_CopyOffset`.
  - 48 of the 97 were executed by the fuzz corpus, some millions of times (`QCBORDecode_Private_GetNextFullString` 5.6M, `QCBOR_Private_DecodeString` 605k), so `Dead` there is not "the harness cannot reach it".
  - `eva.log` shows three alarms certain in some call stacks that stop propagation, all in `decode_nesting.h` (`:299` `Ascend`, `:92` `IsBoundedEmpty`, `:385` `LevelUpCurrent`). The report and `red_alarms.csv` file them as `Unknown`, and nothing in the pipeline reads `red_alarms.csv`.
  - The `nonterm` at `qcbor_main_decode.c:1409` comes with a `garbled mix` of harness buffer addresses in the tag number; by the code, the index there is in 0..3.
  - Not diagnosed: which cut kills which function, and whether the three certain alarms are reachable in real executions. Recorded as an open gap in `docs/troubleshooting/eva.md`, "Eva Reports 0 Invalid, but `eva.log` Says `got status invalid (stopping propagation)`".
  - The 79 functions with Unknown obligations (the WP queue's Eva evidence) include `MapSearch`, the nesting helpers, the IEEE 754 conversions, the BigNumber conversions and `UnMapTagNumber`.
- **Known QCBOR bugs from run-5/run-6 ([`../upstream/qcbor/`](../upstream/qcbor/README.md)):** v2.0-beta-1 (`47df2bc`) descends from the `dev` commit those runs analysed (`9bd0845`) and has the upstream fixes for drafts 02-07 and 10 (#438, #445-#450). Draft 09 (signed overflow negating `INT64_MIN` in `QCBORDecode_ProcessBigNumber`) is likely still present: the 22 changed lines of `qcbor_number_decode.c` since `9bd0845` do not touch that function (supervisor's reading of the diff, not re-run). Phase 1 never executed `ProcessBigNumber` (auto-exempted for `BigNumberBuf`), so it could not find it. Drafts 01 (all-zero big number encode over-read) and 08 (`GetArrayOrMap` uninitialized length, MSan-only) were not re-checked on this version.
- **Priority functions** (executions, covered regions / regions): `QCBOREncode_Private_SortMap` 6, 7/26; `QCBOREncode_Private_ConsumeNext` 0, 0/51; `UsefulOutBuf_Compare` 54, 11/24; `UsefulOutBuf_Swap` 26, 14/15 (Priority 6: the sort's comparison and item walk are mostly not run). `QCBORDecode_Private_MapSearch` 2455, 70/97: the label search **is** reached, through the `*InMapN` and enter-map paths of the decoder cases, so the fresh-context limit holds for the single-call accessor cases, not for the function itself (Priority 3 partly covered). `QCBORDecode_ProcessBigNumber` 0/100, `QCBORDecode_Private_ExpBigMantissa{,Raw}Main` 0/41 and 0/53, `QCBOR_Private_ExponentiateNN` 0/32, `QCBOR_Private_Exponentitate10`/`2` 0, `MemPool_Function` 0/28 and `QCBORDecode_SetMemPool` 0/13: these are the exempted caller-storage paths (`BigNumberBuf`, `Pool`). The decoder core is fully covered: `GetNextMapOrArray` 28/28, `GetNextTagNumber` 22/22, `NestLevelAscender` 26/26, `ConsumeItem` 15/15, `IEEE754_HalfToDouble` 49/49, `UsefulInputBuf_GetBytes` 9/9 (millions of executions each).

## Pipeline problems and fixes

| ID | Fingerprint | Diagnosis | Branch | State |
| :--- | :--- | :--- | :--- | :--- |
| F1 | Phase 0 / `generate_harness.py --api` / `trusted parameter szLabel has no instance` | Pipeline gap in `scripts/api_harness.py` `_param_roles`: a trusted `const char *` input has no instance path, so 26 `*SZ` entry points are auto-exempted (13 end up unreached). Troubleshooting entry: `docs/troubleshooting/harnesses-and-seeds.md`, "`--api` Auto-Exempts Entry Points With a Trusted C-String Label or Caller Storage" (merged with the driver's entry). The sidecar's 16 other exemptions are caller storage: output buffers (now covered on `main` by W1-A, not checked on QCBOR), `pInfo` and `pSavedState` (still open). | `sup/QCBOR-trusted-cstring-instance` (`4b92d56`, `8520a72`) | Green and held (`hold` mode). Fixer dispatched 22:20, returned 22:37. Tests added: `tests/test_p2a_schema_trust_harness.py::test_trusted_cstring_*` (10) and `::test_trusted_non_string_pointer_stays_exempt` (4); the regression test failed on `069ab4b` with `{'lookup.c#lookup': 'trusted parameter szLabel has no instance'}`. Fixer's checks: `pytest -n auto` 8601 passed, `ruff`, `mypy scripts tests`, `check_generated_text.py`, docs tests. Supervisor's checks: read the diff, reran the 27 tests of the module, and regenerated run-1's harness on a scratch copy: 147 cases instead of 126, auto-exempt 21 instead of 42, reach 145/158 instead of 135/158, the LibFuzzer copy compiles. E-ACSL build of the regenerated harness not run. `api_harness.py` is not in the dirty list. |
| F2 | Phase 0 / `generate_harness.py --api` / stateful entry point called once on a fresh context | Encoder closers and sorters (11 single cases whose only input is the storage length) and the decoder `*InMap*` accessors run straight after `Init`, so they only reach their error path (Coverage Priorities 3, 6, 7); no recorded sequence drives the encoder or enters a map. Existing troubleshooting entry "Generated Cases for the `*InMap*` Spiffy Accessors Call the Accessor on a Fresh Context" (open since run-6). | `sup/QCBOR-stateful-sequence-cases` (`5743663`, `f72347c`), stacked on F1 | Green and held. Fixer dispatched about 22:55 at the user's request, returned about 23:45. Diagnosis: the trace recorder keeps one `./qcbortest` trace cut at 256 calls (open bug); the compile probe silently dropped the one recorded encoder chain (`array type 'unsigned char[16]' is not assignable`, fixed); `sequence_case` ignored trust roles (fixed). The fix adds a stateful `sequence` case (opener or data calls first, from traces or the model) for each entry point that can only fail on a fresh context, and reports dropped cases. Tests added: 6 in `tests/test_p2a_schema_trust_harness.py`, each failing before. Fixer's checks: `pytest -n auto` 8607 passed, `ruff check`, `mypy`, `check_generated_text.py`. Scratch reproduction: 147 to 209 cases (61 stateful), reach gate and compile pass; 120 s pinned ASan fuzz: `SortMap` 25/26, `ConsumeNext` 10/51, `UsefulOutBuf_Compare` 22/24, and `MapSearch` runs past the map-not-entered guard 1.9M times. Supervisor reread the diff (generic: opener/closer words, scope nouns, call-graph reach) and reran the 41 tests of the two changed modules. E-ACSL build and Eva on the new cases not run. Troubleshooting: the "Fresh Context" entry rewritten and a new "Recorded Sequence Case the Compile Probe Refuses Vanishes" entry. |
| F3 | Phase 1 judge / `run_eacsl_fuzz` / `memcpy: unallocated (or insufficient) space in source space` in `LLVMFuzzerTestOneInput` | The `--api` string rest copies `rest_n` bytes with no `rest_n == 0` guard; an input that ends at the last slot gives a zero-length `memcpy` from one past the end of the exact-size input block, which E-ACSL rejects. 27 of 126 cases have a string rest. Troubleshooting entry: "The E-ACSL Judge Confirms `memcpy: unallocated (or insufficient) space in source space`...". | `sup/QCBOR-string-rest-zero-copy`, stacked on F2 | Green and held (`95b9c83`). Fixer dispatched about 23:50 and returned about 00:00. The fix guards the string-rest copy with `if (rest_n > 0)` and also fixes the same copy in `scripts/benchmark_seeded.py`. Why only one seed: E-ACSL accepts a one-past-the-end source while it stays in the block's 32-byte heap segment, so only a block whose length is a multiple of 32 aborts (read from the E-ACSL source; 4-, 16- and 32-byte blocks reproduced). Tests: 2 new in `tests/test_api_harness_soundness.py` (the clang one skips on this host; its C program ran by hand in the image) and 1 assertion in `tests/test_benchmark_seeded.py`, each failing before. Fixer's checks: `pytest -n auto` 8608 passed, `ruff`, `mypy`, `check_generated_text.py`; E-ACSL reproduction with the pipeline's two-stage flags: the 32-byte input aborts before and passes after. Supervisor reread the diff and reran the two modules (42 passed, 1 skipped). Not re-run on the real harness. The fixer also found that a byte rest can hand the target a one-past-the-end pointer of length 0 (same mechanism); recorded as an open bug in the same troubleshooting entry, not fixed. |

Open, found while answering the user's questions (no fixer):

- **Eva's certain-in-some-contexts alarms are filed as Unknown.** Three `got status invalid (stopping propagation)` alarms in `decode_nesting.h` are consolidated to `Unknown`; `red_alarms.csv` is written but never read, so they become no candidate and the code they cut is reported as plain `Dead` (97 functions, 48 of them executed by fuzzing). Troubleshooting: `docs/troubleshooting/eva.md`. Root cause per function not diagnosed.

- **MetAcsl L5 property on a buffer-descriptor sink.** `security_props.json` has `meta_engines: []` (the default: WP only), so neither the E-ACSL build nor Eva checks MetAcsl properties in this run. The only L5 property with instances, `L5_sanitized_UsefulOutBuf_Flush`, checks `\initialized(\called_arg(pMe))`: the `UsefulOutBuf` descriptor, not the bytes `{UB.ptr, data_len}` it sends, and the harness zeroes that descriptor, so it would hold trivially. The threat-model schema cannot name a buffer held in a field. Troubleshooting: `docs/troubleshooting/security-properties.md`, "`L5_sanitized_<sink>` for a Sink That Takes a Buffer Descriptor Checks the Descriptor".

## Model struggles (not pipeline bugs)

None observed. The driver used the pipeline's Make targets in order, read containers only through `docker ps`/`docker exec`, edited no pipeline file and no generated artifact, and recorded its own troubleshooting entry (the `api_auto_exempt` one). Two small misreadings, both harmless:
- At 22:00Z it took a transient `docker ps` failure for "no container", then corrected itself.
- It treated the Eva flamegraph size as a progress signal, and it said it would apply CLAUDE.md's 15-minute no-progress rule to `eva-tune` while that step was starved of CPU. The user's relayed message settled that.

Suggested brief change (not applied): the 15-minute rule should say to check the step's process CPU (`docker top`) before calling a silent Eva or WP step stalled.
