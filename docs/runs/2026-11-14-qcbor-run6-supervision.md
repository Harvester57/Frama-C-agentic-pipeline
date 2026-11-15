# QCBOR `run-6`: External Supervision Report (2026-11-14 / 2026-11-15)

## 1. Run & Supervision Header

- **Supervision status:** Completed cleanly at user request (`2026-11-15T02:42+01:00` / `01:42Z`) after all 4 supervisor fixer subagents finished (`6 h 46 min` supervised window); the underlying `opencode` run remains healthy and active (`run_status: "in_progress"`, `phase_done: 2`, executing post-repair `fuzz` + Pre-WP Crash Verification Gate unattended overnight).
- **Target:** `QCBOR` (`C:\Users\Florian\OneDrive\Documents\Dev\targets\QCBOR`, commit `9bd08456d46ac5fbaa7822420fd3e25e0e9c486f`, `dirty: true`, verification profile `deep`).
- **Run directory:** `C:\Users\Florian\framac-pipeline\QCBOR\run-6` (run tag `run-6-221f0ac385af`, repo key `QCBOR-90cd38bae564`).
- **Driven by:** `opencode` session `ses_e2495bbafffeoKf1Ij8d4RLgz1` ("QCBOR deep profile", model `deepseek-v4.1-flash`, variant `high`).
- **Timestamps:**
  - Run started: `2026-11-14T18:55:37Z` (`19:55:37+01:00`).
  - Supervision started: `2026-11-14T18:58:11Z` (`19:58:11+01:00`).
  - Supervision stopped (per user instruction once Fixer F4 completed): `2026-11-15T01:42:30Z` (`02:42:30+01:00`).
- **Integration baseline & fix mode:**
  - Branch `phase1-remediation` at commit `40c7ed75adaa499bdac7546fbfa6c2ad2809cf3d`.
  - Fix mode: `hold` (all 4 verified fixer branches kept isolated in `.agents/worktrees/sup-QCBOR-*` so the running `opencode` session's bind-mounted `/opt/framac-pipeline` checkout and its live uncommitted working-tree hot-patches are never disturbed mid-run; 4-branch Octopus merge dry-run verified conflict-free and test-green).
  - Pre-existing dirty files at supervision start (all `minmea` documentation from prior session, left untouched): `docs/bugs-found/README.md`, `docs/bugs-found/minmea/README.md`, `docs/troubleshooting/harnesses-and-seeds.md`, `docs/upstream/README.md`, `docs/upstream/minmea/README.md`, `docs/upstream/minmea/04-rescale-pr105-comment.md`.

---

## 2. Phase-by-Phase Wall-Clock Breakdown & Container Stats

Timestamps below are in local time (`UTC+1`).

| Phase / Milestone | Start (`UTC+1`) | End (`UTC+1`) | Wall Clock | Container & Resource Stats | Outcome |
| :--- | :--- | :--- | ---: | :--- | :--- |
| Session & Setup (`run_metadata.py init`) | 19:55:37 | 19:56:36 | 59 s | `light` (`framac-analysis:latest`) | `deep` profile initialized; threat model copied into `workspace/THREAT_MODEL.md` and schema-validated. |
| Phase 0: Build capture, model, seeds, DAG, security props, harnesses, gates | 19:56:44 | 20:02:00 | 5 min 16 s | `framac-build` (`make -j4 all` + `./qcbortest`) & `framac-analysis` (`12 CPUs / 20 GiB`) | `libqcbor.a` (9 C files, Tier 1A, 26 waves, 755 functions parsed by Frama-C, 0 GCC fallback); 4,389 seed calls harvested; `--api` harness with `--extra-include qcbor_spiffy_decode.h` generated 181 cases (`171/171` static entry reach); 999 ledger units seeded (`382` deferred `header_unreached`); `build-check` passed (`engine_used: "eacsl"`, `phase_done: 0`). |
| Phase 1: E-ACSL + LibFuzzer campaign (`pipeline_make.py run fuzz`) | 20:02:19 | 20:41:25 | 39 min 06 s | `phase-dynamic` (`12 CPUs / 20 GiB`, 7 LibFuzzer workers; ~30-98% CPU, `0.6`-`1.1 GiB` RAM) | `status: "crash_found"` (`eacsl+sanitizers`): `sanitizers` ran 12 rounds (`521.6 s`, 45 skipped cases, 25 artifacts), `eacsl` ran 15 rounds (`519.6 s`, 46 skipped cases, 26 artifacts); `51` reproducible crash artifacts across `23` unique fingerprints (`139` raw `crash-*` files), `10,091` corpus+seed inputs (`21 min 45 s` spent in 14 single-threaded Stage 1 `frama-c -e-acsl` skip-mask rebuilds). |
| Phase 1: Coverage & Dynamic Reach Gate (`coverage` + `reach-dynamic` + repair) | 20:41:49 | 21:03:57 | 22 min 08 s | `phase-dynamic` / `build` (`12 CPUs / 20 GiB`) | Initial `coverage` (`332/755` functions) flagged `QCBORDecode_Private_ExitBoundedLevel` (`0` `.profraw` hits due to Round 1 callee crash); agent added case `181` + 2 CBOR map/array seeds (`10,093` inputs, `347/755` functions, `3,039/4,522` regions, `171/171` entry points executed) and re-passed `build-check`. |
| Phase 2: Unsharded Abstract Interpretation (`eva`) | 21:03:58 | 23:38:27 | 2 h 34 min 29 s | `phase-static` (`1 CPU` single-threaded OCaml kernel, `100%` 1-core CPU, peak `2.18 GiB / 20 GiB` RAM) | Timed out (`status: "analysis_timeout"`, `9,269.6 s`: `7,200 s` 5-domain base + `900 s` `cvalue_fast` + `900 s` `cvalue_imprecise_alloc`), emitting `flamegraph.txt`. |
| Phase 2: 9-Shard Abstract Interpretation (`gen` + `run eva`) | 23:39:20 | 01:45:14 (+1d) | 2 h 05 min 54 s | `phase-static` (`-j 9` shard workers -> 1 long-tail shard `shard4`; peak `6.4 GiB / 20 GiB` RAM across 9 shards, `2.05 GiB` on `shard4`) | All 9 shards (`shard0`..`shard8`) completed `status: "ok"` (`0` fallbacks, `makespan_s: 6,220.4` on `shard4`, `total_s: 11,596.8`), discharging **91.67%** (`8,081 / 8,815` valid, `729` unknown across `211` surviving functions, `5` invalid, `6,508` dead; merged `libqcbor_a.json` = `207.0 MiB`). |
| Phase 2 -> 3 Transition (`eva-tune`, `ingest`, `replay`, `wp-queue`) | 01:45:50 (+1d) | 01:51:28 (+1d) | 5 min 38 s | `phase-static` / `light` (`20 GiB` container for `ingest` + `replay`) | `eva-tune` skipped for sharded module (`81.4 s`); after live `EVA_REPORT_MAX_BYTES` hot-patch, `ingest` + `replay` + `wp-queue` succeeded (`122.2 s`), recording `phase_done: 2` and queuing `369` Phase 3 tasks (`28` `verify`, `1` `arch`, `340` `prove`). |
| Pre-WP Crash Verification Gate (Batch 1 + `case 129U` repair + Batch 2 prep) | 01:51:57 (+1d) | 02:42:30 (+1d, ongoing) | 50 min 33 s (ongoing) | `wp` (`8.56 GiB`) for `step --prepare` & Crash Verifiers; `phase-dynamic` (`20 GiB`) for post-repair `fuzz` | Batch 1 (`9/28` verifiers) finished with **7 `confirmed`** (`3` `medium` in `UsefulOutBuf_AppendUsefulBuf` / `UsefulOutBuf_Compare`, `4` `low` shift UB in `src/ieee754.c`) and **2 `rejected` (`harness_induced`)** in `DecodeNesting_LevelUpCurrent` (`case 129U`). Agent guarded `case 129U`, prepared Batch 2 (`8` verifiers), and is mid-way through post-repair `eacsl` fuzzing (`framac-8964e628ce15`). |

---

## 3. Stalls, Failures & Triage Log

Categories follow [`../../.agents/skills/run-supervisor/SKILL.md`](../../.agents/skills/run-supervisor/SKILL.md): **(a)** pipeline bug, **(b)** model error, **(c)** target-side issue, **(d)** upstream Frama-C/E-ACSL bug, **(e)** waiting on user.

| Time (`UTC+1`) | Phase | Message ID | Cat. | Failure / Stall Observed | Root Cause | Resolution |
| :--- | :--- | :--- | :---: | :--- | :--- | :--- |
| 19:59:08 | Phase 0 (Step 3) | `msg_1db6d7cb6` | `a` | `pipeline_make.py run stubs` exited 1 (`workspace/build/Makefile not found: run pipeline_make.py gen first`). | [`../../scripts/pipeline_make.py`](../../scripts/pipeline_make.py) `run_targets` requires `workspace/build/Makefile` before Step 5's `gen`, blocking Phase 0 targets (`slice-init`..`seed`). | Agent ran `stub_gen.py run`; **fixed & tested** by Fixer F1 on `sup/QCBOR-phase0-make-bootstrap` (`4dcb52f`, held). |
| 19:59:51 | Phase 0 (Step 4) | `msg_1db6dfcce` | `b` | Initial `--api` harness missed 23 spiffy-decode entry points (`158/181`). | Agent passed only `inc/qcbor/qcbor.h` (v1 umbrella header omitting `qcbor_spiffy_decode.h`). | Agent self-corrected in 40 s by passing `--extra-include workspace/work/inc/qcbor/qcbor_spiffy_decode.h` (`171/171` static reach). |
| 20:15:26 | Phase 1 (`fuzz`) | `msg_1db7c592f` | `a` + `d` | `21 min 45 s` of the `39 min 06 s` Phase 1 wall clock spent in 14 single-threaded Stage 1 `frama-c -e-acsl` rebuilds (~93 s and ~27 MB cache growth each). | `-DFRAMAC_FUZZ_SKIP_CASES` changes `cppflags` in the Stage 1 cache key every round and clobbers `workspace/harnesses/fuzz_<mod>`; in addition, E-ACSL's `argv_alloca()` under `--full-mtracking` increments `environ` to `NULL` (`getenv` returns `NULL`). | **Fixed & tested** by Fixer F3 on `sup/QCBOR-fuzz-runtime-skip-cases` (`aeac81d`, held: 4096-bit runtime env skip bitset + `-Wl,--wrap=__e_acsl_memory_init` `environ` shim); drafted Upstream Issue 18. |
| 20:41:25 | Phase 1 (`fuzz`) | `msg_1db7c6968` | `d` | E-ACSL aborted on dispatch case `5` (`UsefulInputBuf_Compare`) with `memcpy: overlapping memory areas`, while `sanitizers` passed cleanly. | Frama-C 34.0~beta `eacsl_builtin_memcmp` (`e_acsl_string.c:240`) calls `validate_overlapping_spaces(..., "memcpy")` on `memcmp` (copy-paste bug violating ISO C 7.24.4.1). | Reproduced in Docker (`framac-analysis:latest`); drafted Upstream Issue 17 ([`../upstream/frama-c/frama-c-eacsl-memcmp-overlapping-buffers.md`](../upstream/frama-c/frama-c-eacsl-memcmp-overlapping-buffers.md)). |
| 20:45:06 | Phase 1 (`reach-dynamic`) | `msg_1db976351` | `a` | `harness_reach.py dynamic` failed on `QCBORDecode_Private_ExitBoundedLevel` (`0` `.profraw` hits), and appending repair case `181` shifted `fuzz_buf[0] % N` (`181 -> 182`), dropping `case 74` executions to `0` and invalidating crash inputs with `byte0 >= 181`. | Crashing inputs land in `workspace/crashes/` (excluded from `corpus/` and skipped in rounds 2+); `check_dynamic` ignored crash-attributed entry reach; modulo selector shifts on `N` change. | Crashing-entry reach **fixed & tested** by Fixer F2 on `sup/QCBOR-reach-dynamic-gate` (`d5ae38a`, held); modulo selector shift documented in [`../troubleshooting/harnesses-and-seeds.md`](../troubleshooting/harnesses-and-seeds.md). |
| 20:46:48 | Phase 1 (repair) | `msg_1db992b15` | `a` | `generate_harness.py ... --api --dispatch-case ... --record-repair ...` returned `0` without regenerating `harness_libqcbor_a.c`. | `--record-repair` returned early in `generate_harness.py`, ignoring accompanying generation flags. | **Fixed & tested** by Fixer F3 on `sup/QCBOR-fuzz-runtime-skip-cases` (`aeac81d`, held). |
| 20:53:22 | Phase 1 (`coverage`) | `msg_1db9ec9d5` | `a` | Adding seed files without touching `harness_libqcbor_a.c` deadlocked at `coverage-libqcbor_a` (`phase0_gates.py` refused `DYNAMIC_GAP_ERROR`). | `coverage-%` in `templates/pipeline.mk` ran `phase0_gates.py check --need reach` without `--allow-dynamic-gap`. | **Fixed & tested** by Fixer F2 on `sup/QCBOR-reach-dynamic-gate` (`d5ae38a`, held). |
| 01:45:14 (+1d) | Phase 2 (`eva` shards) | `msg_1dc37186b` | `a` | `shard4` ran `6,220.4 s` vs `444`–`1,469 s` on the other 8 shards (`predicted_makespan_s: 800.1`). | `run_eva_slice.py` let `900 s` `cvalue` fallbacks overwrite the `7,200 s` 5-domain `flamegraph.txt`, and `eva_shards.case_costs()` split shared callee cost uniformly instead of by call multiplicity (`case 171U` 18-call sequence). | **Fixed & tested** by Fixer F4 on `sup/QCBOR-eva-flows-bloat-and-caps` (`800e9d2`, held). |
| 01:47:11 (+1d) | Phase 2 -> 3 (`ingest` & `step --prepare`) | `msg_1dcac2569`..`msg_1dcb5acc3` | `a` + `b` | Merged `libqcbor_a.json` (`207.0 MiB`, `201.1 MiB` pretty-printed `flows`) hit `64 MiB` `ArtifactError` in `function_facts.py`, `ledger.py`, `workspace_overlay.py`, and `wp_scheduler.py`, then OOM-killed `wp_scheduler.py step --prepare` in `light` (`1 GiB`) and burnt 3 dispatch suffixes (`-4`). Run agent hot-patched 8 repo files live (violating read-only `/opt/framac-pipeline`). | `eva_shards.merge_flows` multiplied `writes` 9x by whole-dict equality instead of `loc` and kept 6+ KB composite bit-range strings; readers lacked `EVA_REPORT_MAX_BYTES`; `prepare_agent` re-parsed the 207 MiB JSON across 9 worker threads simultaneously. | **Fixed & tested** at root cause by Fixer F4 on `sup/QCBOR-eva-flows-bloat-and-caps` (`a5fe895`, held). |
| 02:11:07 (+1d) | Pre-WP Gate (`repair:libqcbor_a`) | `msg_1dcc20e36`..`msg_1dcc38999` | `a` | `wp_scheduler.py` dispatched `repair:libqcbor_a` after Batch 1 (`9/28` verifiers) while `19` sibling `verify:*` tasks on `libqcbor_a` were still `pending`, exhausting `repair_attempts: 2/2` prematurely; `cmd_refresh` also does not check whether `eva-libqcbor_a` re-ran on the repaired harness digest. | `_ensure_repair` created `repair:<mod>` with `deps: []` instead of waiting on open `verify:*` tasks of `<mod>`; `cmd_refresh` closes `repair:<mod>` without verifying fuzz/Eva input digests. | Premature `repair:<mod>` dispatch **fixed & tested** by Fixer F4 on `sup/QCBOR-eva-flows-bloat-and-caps` (`a17aa9e`, held); stale-digest `refresh` documented as open in [`../troubleshooting/wp-and-guardrail.md`](../troubleshooting/wp-and-guardrail.md). |

---

## 4. Fixes Prepared & Held (`hold` Mode)

All 4 branches were developed in isolated worktrees off `40c7ed75adaa499bdac7546fbfa6c2ad2809cf3d`, have **zero overlapping files across all 22 touched files**, and passed a combined 4-branch Octopus merge dry-run (`210 passed, 3 skipped` on combined targeted suites; `4940 passed, 181 skipped` on full `pytest tests -n auto`; `ruff check`, `ruff format --check`, `mypy`, and `tools/check_generated_text.py` all 100% clean).

| Fixer | Branch (`.agents/worktrees/...`) | Commit(s) | Files Touched | Regression Tests Added |
| :--- | :--- | :--- | :--- | :--- |
| **F1** | `sup/QCBOR-phase0-make-bootstrap` | `4dcb52f` | [`../../scripts/pipeline_make.py`](../../scripts/pipeline_make.py), [`../../tests/test_pipeline_make.py`](../../tests/test_pipeline_make.py) | `test_phase0_targets_bootstrap_makefile_without_gen`, `test_phase1_and_mixed_targets_still_require_gen` |
| **F2** | `sup/QCBOR-reach-dynamic-gate` | `d5ae38a` | [`../../scripts/harness_reach.py`](../../scripts/harness_reach.py), [`../../scripts/phase0_gates.py`](../../scripts/phase0_gates.py), [`../../templates/pipeline.mk`](../../templates/pipeline.mk), [`../../schemas/harness_reach_dynamic.schema.json`](../../schemas/harness_reach_dynamic.schema.json), [`../../tests/test_harness_reach.py`](../../tests/test_harness_reach.py), [`../../tests/test_phase0_gates.py`](../../tests/test_phase0_gates.py) | 5 new tests in [`../../tests/test_harness_reach.py`](../../tests/test_harness_reach.py) & [`../../tests/test_phase0_gates.py`](../../tests/test_phase0_gates.py) (direct crash, dispatch callee crash, `inits` guard, `--allow-dynamic-gap`, `pipeline.mk` recipe guard) |
| **F3** | `sup/QCBOR-fuzz-runtime-skip-cases` | `aeac81d` | [`../../templates/harness_dual.c.template`](../../templates/harness_dual.c.template), [`../../scripts/generate_harness.py`](../../scripts/generate_harness.py), [`../../scripts/run_eacsl_fuzz.py`](../../scripts/run_eacsl_fuzz.py), [`../../tests/test_fuzz_keep_going.py`](../../tests/test_fuzz_keep_going.py), `tests/test_generate_harness.py` | 8 new tests across [`../../tests/test_fuzz_keep_going.py`](../../tests/test_fuzz_keep_going.py) (4096-bit runtime skip bitset, zero-rebuild Docker E-ACSL campaign, non-clobbering legacy fallback, `eacsl_env_keep` wrapper) and `tests/test_generate_harness.py` (combined `--record-repair` + regeneration & rollback) |
| **F4** | `sup/QCBOR-eva-flows-bloat-and-caps` | `a5fe895`, `a17aa9e`, `800e9d2` | [`../../scripts/framac_common.py`](../../scripts/framac_common.py), [`../../scripts/eva_shards.py`](../../scripts/eva_shards.py), [`../../scripts/run_eva_slice.py`](../../scripts/run_eva_slice.py), [`../../scripts/function_facts.py`](../../scripts/function_facts.py), [`../../scripts/ledger.py`](../../scripts/ledger.py), [`../../scripts/workspace_overlay.py`](../../scripts/workspace_overlay.py), [`../../scripts/wp_scheduler.py`](../../scripts/wp_scheduler.py), [`../../tests/test_eva_shards.py`](../../tests/test_eva_shards.py), `tests/test_large_eva_report.py` | 20+ tests in `tests/test_large_eva_report.py` (997 lines) and [`../../tests/test_eva_shards.py`](../../tests/test_eva_shards.py) (`merge_flows` by `loc`, `bound_flow_location`, `spill_large_flows`, `EVA_REPORT_MAX_BYTES` across all 6 readers, single-load `eva_unknown_obligations`, interrupted-prepare dispatch preservation, `_repair_verify_deps` batching, 5-domain timeout flamegraph preservation, multiplicity-weighted `case_costs`) |

### Post-Run Reconciliation Steps (Once `ses_e2495bbafffeoKf1Ij8d4RLgz1` Finishes)

Because `opencode` hot-patched 8 files live in the main working tree (`scripts/framac_common.py`, `scripts/function_facts.py`, `scripts/ledger.py`, `scripts/resources.py`, `scripts/workspace_overlay.py`, `scripts/wp_scheduler.py`, `templates/pipeline.mk`, `tests/test_resources_api.py`), reconcile after the run terminates:
1. Inspect `git diff scripts/ templates/ tests/` in the main checkout: `F4` (`a5fe895`) completely supersedes `opencode`'s ad-hoc edits in `framac_common.py`, `function_facts.py`, `ledger.py`, `workspace_overlay.py`, and `wp_scheduler.py`, and eliminates the need for `opencode`'s `resources.py` / `templates/pipeline.mk` `--class wp` band-aid (which otherwise makes `wp_scheduler.py step` contend with WP provers for 8-CPU broker leases). Revert those 8 working-tree code/test hot-patches (`git checkout -- scripts/ templates/ tests/`), keeping `docs/` intact.
2. Merge all 4 branches cleanly in order:
   ```powershell
   git merge --no-ff sup/QCBOR-phase0-make-bootstrap
   git merge --no-ff sup/QCBOR-reach-dynamic-gate
   git merge --no-ff sup/QCBOR-fuzz-runtime-skip-cases
   git merge --no-ff sup/QCBOR-eva-flows-bloat-and-caps
   ```
3. Run `python -m pytest tests -n auto`, `python tools/check_generated_text.py`, and remove the 4 worktrees under `.agents/worktrees/sup-QCBOR-*`.

---

## 5. `docs/troubleshooting/` Entries Added or Updated

- [`../troubleshooting/resources-and-infra.md`](../troubleshooting/resources-and-infra.md): updated Phase 0 `pipeline_make.py run stubs` / `run seed` `Makefile not found` entry with `QCBOR run-6` evidence and Fixer F1 (`4dcb52f`).
- [`../troubleshooting/eacsl-and-fuzzing.md`](../troubleshooting/eacsl-and-fuzzing.md): added entries for E-ACSL `eacsl_builtin_memcmp` false overlap abort (`UsefulInputBuf_Compare`), `argv_alloca()` clobbering `environ` under `--full-mtracking`, and the `-DFRAMAC_FUZZ_SKIP_CASES` Stage 1 rebuild bottleneck fixed by Fixer F3 (`aeac81d`).
- [`../troubleshooting/harnesses-and-seeds.md`](../troubleshooting/harnesses-and-seeds.md): added entries for `reach-dynamic` crashing entry points / `coverage-%` `DYNAMIC_GAP_ERROR` deadlock (Fixer F2 `d5ae38a`), `generate_harness.py --record-repair` ignoring generation flags (Fixer F3 `aeac81d`), and selector modulo shift (`fuzz_buf[0] % N`) when appending `--dispatch-case` repairs.
- [`../troubleshooting/eva.md`](../troubleshooting/eva.md): added entry for `shard4` `6,220.4 s` makespan imbalance (`cvalue` fallback overwriting 5-domain `flamegraph.txt` + uniform shared-callee cost split) and its fix on Fixer F4 (`800e9d2`).
- [`../troubleshooting/ledger-and-verifier.md`](../troubleshooting/ledger-and-verifier.md): added entry for `ArtifactError: artifact exceeds 67108864 bytes: workspace/reports/eva/<module>.json` and `201 MiB` merged `flows` bloat, fixed by Fixer F4 (`a5fe895`).
- [`../troubleshooting/wp-and-guardrail.md`](../troubleshooting/wp-and-guardrail.md): updated the `wp_scheduler.py step --prepare` OOM entry (`a5fe895`), added the premature `repair:<mod>` dispatch entry (`a17aa9e`), and preserved the stale-Eva-digest `wp_scheduler.py refresh` open bug entry.

---

## 6. Upstream Frama-C / E-ACSL Drafts Written

1. [`../upstream/frama-c/frama-c-eacsl-memcmp-overlapping-buffers.md`](../upstream/frama-c/frama-c-eacsl-memcmp-overlapping-buffers.md) (**Issue 17**): `eacsl_builtin_memcmp` in `share/e-acsl/libc_replacements/e_acsl_string.c:240` calls `validate_overlapping_spaces(..., "memcpy")`, falsely aborting valid `memcmp(buf, buf, n)` / overlapping-slice calls under `--libc-replacements` (violating ISO C17 7.24.4.1).
2. [`../upstream/frama-c/frama-c-eacsl-memory-init-clobbers-environ.md`](../upstream/frama-c/frama-c-eacsl-memory-init-clobbers-environ.md) (**Issue 18**): `argv_alloca()` inside `__e_acsl_memory_init` (`e_acsl_rtl.c`) increments the global `char **environ` pointer directly until `*environ == NULL` under `--full-mtracking`, breaking every subsequent `getenv()` call in user or harness code.
- Both drafts are indexed in [`../upstream/frama-c/README.md`](../upstream/frama-c/README.md) and [`../upstream/frama-c/frama-c-e-acsl-issues.md`](../upstream/frama-c/frama-c-e-acsl-issues.md).

---

## 7. Remaining Open Gaps & Recommendations

1. **Enforce read-only `/opt/framac-pipeline` mount in `wrappers/framac-docker.ps1` and agent prompts:** During `QCBOR run-6`, `opencode` used its host `edit` tool to modify 8 repository files (`scripts/*.py`, `templates/pipeline.mk`, `tests/test_resources_api.py`) directly on the host filesystem instead of treating the pipeline checkout as immutable. Adding an explicit prohibition in [`../../skills/framac-verify/SKILL.md`](../../skills/framac-verify/SKILL.md) and [`../../skills/framac-wp/SKILL.md`](../../skills/framac-wp/SKILL.md) ("never edit files under the pipeline repository during a target run; report pipeline defects in `docs/troubleshooting/` only") will prevent live runs from mutating pipeline code mid-execution.
2. **Stale harness digest check in `wp_scheduler.py refresh --module <mod>`:** As documented in [`../troubleshooting/wp-and-guardrail.md`](../troubleshooting/wp-and-guardrail.md), `cmd_refresh` closes `repair:<mod>` without checking whether `workspace/reports/fuzz/<mod>.json` and `workspace/reports/eva/<mod>.json` match the repaired harness digest (allowing `run-6` to skip a 2-hour 9-shard Eva re-run after editing `case 129U` in `harness_libqcbor_a.c`). `refresh` should verify the fuzz/Eva input digests or explicitly mark the Eva evidence as pre-repair.
3. **Stable dispatch case selector encoding in `templates/harness_dual.c.template`:** Replace `sel % N` with direct index bounds checking (`if (sel >= N) return 0;`) on a fixed-width selector (`uint8_t` / `uint16_t`) so appending `--dispatch-case` entries during Phase 1 or Phase 3 harness repair never remaps previously recorded `corpus/` or `crashes/` inputs to different cases.
4. **Upstream QCBOR findings review once `run-6` finishes:** Batch 1 already confirmed 7 target findings (`UsefulOutBuf_AppendUsefulBuf` 1-byte heap over-read on all-zero big numbers, `UsefulOutBuf_Compare` x2 OOB read / pointer wrap, and 4 `src/ieee754.c` shift UB defects); compare the final `run-6` `REPORT.md` and `findings.json` against [`./2026-11-09-qcbor-run5-assessment.md`](./2026-11-09-qcbor-run5-assessment.md) once the overnight run completes.

---

## 8. Continued Supervision (Claude Opus 5.5, From 2026-11-15 02:27)

Sections 1–7 above are the first supervisor's report, closed at 02:42. Supervision continues from here with the same parameters: `hold` mode, run tag `run-6-221f0ac385af`, integration branch `phase1-remediation` at `40c7ed7`, session `ses_e2495bbafffeoKf1Ij8d4RLgz1`. This section takes precedence over section 4's reconciliation steps wherever the two disagree.

### Merge Decision (Supersedes Section 4's Post-Run Steps)

- **Dirty-file conflict (checked 02:33).** `git diff --name-only 40c7ed7 <branch>` was intersected with `git status --porcelain`:
  - F1 and F3 do not overlap the dirty files.
  - F2 overlaps `templates/pipeline.mk`.
  - F4 overlaps `scripts/framac_common.py`, `function_facts.py`, `ledger.py`, `workspace_overlay.py` and `wp_scheduler.py`.
  - The live run executes the run agent's uncommitted hot patches to those files.
- **User decision (02:35): decide at the terminal state.**
  - At the terminal state, F1 and F3 are merged in order, with a dry run before each.
  - F2 and F4 stay on their branches until the user decides what to do with the hot patches.
  - Section 4's step 1 (`git checkout -- scripts/ templates/ tests/`) and step 2 (merging all four branches) are **not** to be run without that decision. Its claim that F4 "completely supersedes" the hot patches is unverified, because nobody has diffed the hot patches against F4.
- **F5, added 06:02.** `sup/QCBOR-wp-counterexample-false-unknown` (`811dbe8`, `bcd3d74`): the parent WP check must not decide a verdict under `-wp-counter-examples`.
  - It touches only `scripts/run_wp_function.py`, `tests/test_run_wp_counter_examples.py` and `tests/test_tool_parsing.py`, none of them dirty.
  - It is queued after F1 and F3 for the terminal-state merge, with a dry run first.
- **F6, added 07:15.** `sup/QCBOR-wp-preprocess-error-status` (`5166333`, built on F5): a `gcc -E` failure is reported as `analysis_error` / `preprocessing_failed`, not `acsl_syntax_error`.
  - It touches `scripts/run_wp_function.py`, `scripts/mutation_check.py`, `tests/test_tool_sizing.py` and `tests/test_mutation_check.py`, none of them dirty.
  - It is merged after F5, or in F5's place, since it contains F5.

### Observations

| Time (`UTC+1`) | Phase | Message ID | Cat. | Observation |
| :--- | :--- | :--- | :---: | :--- |
| 02:07–02:10 | Pre-WP Gate (ingest) | `msg_1dcbe7b50`, `msg_1dcc09af8` | `b` | Two more quoting failures across PowerShell, `framac-docker.ps1` and `bash -lc`: `SyntaxError: unexpected character after line continuation character` from a nested `python3 -c`, then PowerShell `ParserError: Missing expression after ','`. The agent switched to helper `.sh`/`.py` files under `state/` passed with `-ScriptFile`. Suggested skill change, not applied: `framac-verify` should recommend `-ScriptFile` for anything beyond one command. |
| 02:11 | Pre-WP Gate (`repair:libqcbor_a`) | `msg_1dcc20e36` | `b` | The repair actions in `_describe_repair` (`wp_scheduler.py:2194–2216`) end with `run module-libqcbor_a`, which is fuzz + Eva + ingest + facts (`templates/pipeline.mk:366`). The agent replaced it with `run build fuzz coverage reach-dynamic` + `run ingest` and skipped Eva on purpose. This is a model reinterpretation of a gate. The pipeline gap that lets it through is the open `refresh` bug in [`../troubleshooting/wp-and-guardrail.md`](../troubleshooting/wp-and-guardrail.md). |
| 02:15 | Pre-WP Gate (Batch 2 prepared) | `msg_1dcc5f1ff` | — | The agent saw for itself that verifiers replaying `fuzz_libqcbor_a.e-acsl` while the re-fuzz rebuilds it could give inconsistent results. It ran the re-fuzz in the foreground and dispatched no Batch 2 subagent meanwhile, so the race did not happen. |
| 02:15–03:01 | Pre-WP Gate (post-repair re-fuzz) | `msg_1dcc5f1ff` | `a` (known, held) | `run build fuzz coverage reach-dynamic` finished `rc: 0` in `2,739.4 s` (log `workspace/build/logs/run-20261115T011535Z-11.log`), then `run ingest` in `4.5 s`. During it, `fuzz_libqcbor_a.instrumented.c` and `.e-acsl` were regenerated in place about every 90 s (02:30:09, 02:31:41): the F3 Stage 1 rebuild bottleneck recurring while F3 is held. Not counted as a missed fix. The new fuzz report (`crash_found`, `eacsl+sanitizers`) has 21 fingerprints. `DecodeNesting_LevelUpCurrent` is gone, so the `case 129U` repair worked. |
| ≤03:03 | Pre-WP Gate (`refresh`) | — | `a` (open) | As predicted, `wp_scheduler.py refresh` closed `repair:libqcbor_a` as `done` / `refreshed` with no Eva re-run, so Phase 3 now rests on an Eva report from the pre-repair harness. The scheduler went from `verify` 8 done / 11 pending / 9 running to 8 / 14 / 9: the re-fuzz added 3 new verify candidates. 338 `prove` tasks are still pending. |
| 03:56 | **Pre-WP Gate passed → Phase 3** | — | milestone | All 31 `verify` tasks done, `arch:libqcbor_a` done. The first 9 `prove` tasks are running (317 pending, 14 skipped because their functions hold confirmed crashes). The gate's wall clock from the first `step --prepare` was 01:51:57 → 03:56 (≈2 h 04 min). That includes the 46-min post-repair re-fuzz and the off-schedule `EncodeHead` re-verification. |
| 03:58–04:14 | Phase 3 (first prover window) | transcript after 03:51 | `a` (fixed live, uncommitted) + `a` (open) | The first 6 header provers (`UsefulInputBuf_*`, `UsefulOutBuf_RoomLeft/Reset/IsBufferNULL`) proved all their goals, but the merge requeued them with `inc/qcbor/UsefulBuf.h: agent modified content outside assigned function` and `frame-preservation check failed`. Cause: their contracts sit on the `static inline` definition, not the prototype the merge checks. **The run agent hot-patched the merge gate live** in `scripts/acsl_ast.py` (newly dirty: `splice_prover_changes` retries on the definition span) and `scripts/workspace_overlay.py` (the frame check reads both spans). It re-dispatched the 6 as `-2` and documented the change in [`../troubleshooting/wp-and-guardrail.md`](../troubleshooting/wp-and-guardrail.md). The supervisor read the diff: the scope check is still enforced, just on the other declaration, so the gate is not weakened. The patch has no regression test; the agent ran only existing suites (105 passed). It also recorded an open gap: `frame_skeleton` projects a forwarding wrapper (`UsefulOutBuf_AppendData`) as `assigns \nothing`, and the scheduler dispatches a caller before its same-unit callee has a contract. No supervisor fixer for either: `acsl_ast.py`, `workspace_overlay.py` and `wp_scheduler.py` are dirty, and the `frame_skeleton.py` change needs a design decision. |
| 06:48–06:59 | Phase 3 (manual merge bypass; `Bytes` model; brief hot edit) | `msg_1ddbfe0050014LsSTkxqq01SYF`, `msg_1ddc00dd3001C8k2QkoMDdrwg1`, `msg_1ddc39387001cKdpGCYKxVgLBq`, `msg_1ddc97284001jUi7ljEnJ0Emgm` | `b` + `a` (fixer F6 dispatched) + hot patch | Three findings in this window.
  - **Manual merge bypassing the scheduler.**
    - The run agent wanted to merge the three `*Conformance` contracts that the scheduler had held as `unsound_proof`. It wrote `state/merge_conformance.sh` **into the run dir** and called `workspace_overlay.py merge-agent --role prover ... --allow-partial-wp` by hand, without `--module` or `--cppflags`.
    - `merge-agent` defaults to `--cppflags -I.` (unlike `prepare` and `batch`), so the parent WP check could not find `qcbor/qcbor_main_decode.h`.
    - `run_wp_function.py` labelled the preprocessor failure `acsl_syntax_error`. The merge reported only `parent partial WP check rejected (status='acsl_syntax_error', ...)`, and the agent concluded "no detail", believing its contract was malformed.
    - The merges rolled back, and run state is unchanged except for the script and `state/ma_*.json`.
    - Fixer F6 corrects the label in `run_wp_function.py`. It is on `sup/QCBOR-wp-preprocess-error-status` at `5166333`, built on F5.
      - It touches `run_wp_function.py` and `mutation_check.py` plus tests, none of them dirty.
      - It imports `_CPP_ERROR_RE` from `framac_common.py`, which is dirty; the working copy still defines it identically.
      - The supervisor reran the tests (63 passed). The `merge-agent` CLI default is in the dirty `workspace_overlay.py` and stays open.
  - **`Bytes` memory model.** `QCBOR_Private_DecodeInteger` proved 24/24 with `--wp-model Bytes`, which avoids the `Typed` `[wp:unsupported:union]` unsoundness. `DecodeArrayOrMap` proves 22/22 but is refused under `Typed` for the same warning. The parent check replays the agent's model (`infer_prover_wp_flags` reads `wp_model` from the agent's report), so a `Bytes` proof is re-checked under `Bytes`.
  - **Brief hot edit.** The run agent edited `skills/framac-wp/prover_brief.md` (already dirty), re-synced the mirrors, and ran the mirror tests (10 passed). The edit tells provers to use `--wp-model Bytes` on union-heavy functions. This is another uncommitted hot patch to settle at the end of the run.
  - The run agent also said it may close the run as `incomplete` soon, because of session length. |
| 05:57–06:19 | Phase 3 (throughput, status reporting) | `msg_1dd9cbc69004s2eDeqAGVyVD3i`, `msg_1dda09cbe0014XzwK1qTQlI7os`, `msg_1dda4ff5e001Ps8X9pRAgyoIuO` | `b` (reporting) + known `a` | Four header accessors proved and merged: `BytesAvailable`, `GetError`, `IsNULL`, `IsNULLC`.
  - `DoubleConformance` (8/8) and `SingleConformance` (11/11) prove every goal but are held `unsound_proof`, because the `src/ieee754.h` prototypes they call have no contract yet. This is the known callee-ordering gap; negotiations were opened for those prototypes.
  - The append-wrapper chain (`AppendUint32` → `AppendData` → `AppendUsefulBuf`) stays blocked: its bottom callee is a confirmed-bug function, excluded from proof by design.
  - **Model reporting errors:**
    - The run agent reported "Phase 3: 41+ done", but the scheduler shows `prove/done=6`. The 41 apparently counts verify and other tasks.
    - It attributed the 8th rejection to "the breaker candidate". No breaker has run; the candidate was the `IEEE754_SingleToDouble` prover hypothesis.
    - Neither error changes run state, but a reader of the run agent's status lines gets a wrong picture of progress. |
| 05:30–05:50 | Phase 3 (parent WP check false `Unknown`) | `msg_1dd7b7fa7001BXUdaR0jdFmfUI`, `agents/*/scratch/parent_wp/*.log` | `a` (fixed, held on `sup/QCBOR-wp-counterexample-false-unknown` at `bcd3d74`) | The negotiated `UsefulOutBuf_Reset` contract was refused at merge with `parent WP check on merged tree returned status='unproven_goals_remain'`, and the run agent re-dispatched it as `negotiate-usefuloutbuf_reset-2`. The negotiator's own WP run proved all 11 goals, including `keep_UB_ptr`. The parent check, run with `--counter-examples` and the shared WP cache, logged `[Unknown] typed_UsefulOutBuf_Reset_ensures_keep_UB_ptr (Qed 2ms) (CVC5) (Cached) (Model)`. `UsefulInputBuf_GetError-2`, blocked as `merge_failed` at 04:22, has the same signature on its `keep_buffer` postcondition, which settles the undiagnosed `GetError` block in the 04:20 row. The run agent treats it as an ordinary failure and re-runs the negotiation, which will likely fail the same way. A supervisor fixer (F5) reproduced it in the analysis image on a 9-goal fixture: `all_proven` without the flag, `unproven_goals_remain 7 1` with it, with or without a fresh cache.
  - Root cause: under `-wp-counter-examples`, Frama-C 34 WP drops the frame equality, turning `Prove: true` into an unconstrained `Mptr_0[a] = Mptr_1[a]`. The cache is not involved.
  - Fix, F5 at `bcd3d74`: the verdict now comes from a normal proof pass, and models come from a separate, uncached `_cex` pass that runs only when goals fail.
  - The supervisor reran the tests (21 passed).
  - The fix touches only `scripts/run_wp_function.py` and tests, none of them dirty, so it can be merged at the terminal state.
  - At 06:13 `negotiate-usefuloutbuf_reset-2` merged (`applied ...; the parent WP re-check passed`, 10/10). It did so because the second negotiator **dropped** `ensures keep_UB_ptr` from both declarations (UsefulBuf.h lines 1070-1071 and 2341-2342 keep only `keep_magic` and `keep_UB_len`).
    - The merged `Reset` contract is therefore weaker than the true one: a caller that needs `UB.ptr` to survive `Reset` cannot get it.
    - This is a model workaround of the pipeline bug, not a fault in the negotiator's reasoning; the bug pushed it there.
    - `UsefulOutBuf_Init` is now being re-proved (`a callee contract was strengthened on request`). If it stalls on `UB.ptr`, this is the cause.
  - The supervisor wrote upstream draft Issue 19, [`../upstream/frama-c/frama-c-wp-counter-examples-drops-frame.md`](../upstream/frama-c/frama-c-wp-counter-examples-drops-frame.md), not filed. It was reproduced on `34.0~beta` under run tag `sup-upstream-cex`. |
| 04:40–05:35 | Phase 3 (breakers never dispatched) | `state/wp_schedule.json` at 05:30 | `a` (open, in a dirty file) | There were 12 `breaker:*` tasks `pending` at 05:30, and none had been dispatched since the first appeared. This is not the model ignoring them: `cmd_next` fills its 5-9 slots in `_priority_key` order `(shell_leaf, -height, -eva_unknowns, id)`, and a breaker has height 0. A read-only re-ranking put the breakers at positions 92-104 of about 107 ready tasks, behind every prover with height > 0. They will run only once the prove queue drains, so the "non-blocking" crash hunt on stalled proofs (`IEEE754_DoubleToInt`, 18 Eva unknowns, ranks first) is delayed until the end of Phase 3. No fixer: `wp_scheduler.py` is dirty. Recorded in [`../troubleshooting/wp-and-guardrail.md`](../troubleshooting/wp-and-guardrail.md). |
| 04:44–04:54 | Phase 3 (second hot patch) | `msg_1dd4ed741` | `a` (fixed live, uncommitted) | The run agent found the same root cause as the supervisor: the contract sits on **both** declarations. It extended its `scripts/acsl_ast.py` hot patch with a dual-span branch that accepts edits confined to the prototype and definition spans together. It checked the change on the `Reset-2` and `IsBufferNULL-2` scratch trees (both now splice), but still added no regression test. While doing so it noticed that `Reset`'s contract adds `requires \aligned(...)`, which its callers (`Init`) could not meet. Blocked tasks are terminal, so `Reset` and `IsBufferNULL` keep no contract unless they are re-dispatched. The 8 pending `breaker` tasks had still not been dispatched at 04:54, and the agent's reasoning never mentions them. |
| 04:28–04:44 | Phase 3 (throughput) | `msg_1dd47ed79`, `msg_1dd4ba633`, `msg_1dd4e23c9` | `a` (open, in a dirty file) | In about 50 min of Phase 3, 3 proofs merged and 6 tasks are blocked. Most stalls share one cause: the scheduler dispatches a caller before its same-unit callees have merged contracts, so WP assumes an `assigns \everything` callee and the projected frame goal cannot close. Cases so far: `UsefulOutBuf_AppendData`, `IEEE754_DoubleToSmaller` (its callees `DoubleToSingle` and `SingleToHalf` are still pending), and `UsefulOutBuf_Init`. For `Init`, the prover showed the same tree proves 15/15 once its callee's contract is present. That callee is `Reset`, whose merge was blocked at 04:22 (row below). The run agent first read this as an ordering bug and at 04:44 started checking whether `Reset`'s contract is in `workspace/work`. It isn't: only the bare prototype (line 1063) and definition (line 2324) are there. `CopyUint64ToDouble` and its header variant stall on the WP `Typed` memory model. This is a known limitation, not a pipeline bug. No supervisor fixer: the callee-ordering fix belongs in `wp_scheduler.py`, which is dirty. |
| 04:20–04:28 | Phase 3 (batch merge) | `msg_1dd3821c6`, `msg_1dd4007aa` | `a` (recurs after the run agent's hot patch; open) | The batch merge of 5 re-proven header functions merged only 3. `UsefulOutBuf_Reset-2` and `UsefulOutBuf_IsBufferNULL-2` were blocked again with `agent modified content outside assigned function`: the re-prover wrote the contract on **both** the prototype (`pUOutBuf`) and the definition (`pMe`), and the hot patch accepts only one span. `UsefulInputBuf_GetError-2` was blocked with `parent WP check on merged tree returned status='unproven_goals_remain'` (not yet diagnosed). As of 04:28 the run agent had not noticed: its reasoning treats all 5 as merged, and it moved on to the next window. That makes 1 recurrence of this fingerprint after a fix. No supervisor fixer: `acsl_ast.py` and `workspace_overlay.py` carry the run's own hot patches. Evidence added to [`../troubleshooting/wp-and-guardrail.md`](../troubleshooting/wp-and-guardrail.md). |
| 03:04–03:05 | Pre-WP Gate (Batch 2) | `msg_1dcf2bb67`, `msg_1dcf3698b` | — | Candidate `0e34c586b3` was ingested as confirmed, so 9 of 31 candidates are verified. The agent dispatched 8 Batch 2 verifiers (`ses_e230c97…` children): `SingleToHalf` x2, `ConsumeItem`, `GetArrayOrMap`, `EncodeHead` x2, `AddTNegativeBigNumber`, `BigNumberToUInt`. The run agent also wrote a second troubleshooting entry on the dispatch-selector shift. It duplicated the first supervisor's entry, so the supervisor merged the two in [`../troubleshooting/harnesses-and-seeds.md`](../troubleshooting/harnesses-and-seeds.md). |
| 03:20–03:33 | Pre-WP Gate (verdict reconciliation) | transcript after 03:20 | `a` (open, dirty files) + `b` | The two `EncodeHead` fingerprints got opposite verdicts. The parent tried a nonexistent `ledger.py reopen` (`invalid choice: 'reopen'`), then dispatched an off-schedule re-verifier with a brief that argued the sibling rejection. It plans to ingest the result with `ledger.py ingest-verifier`, bypassing `wp_scheduler.py`. The re-verifier rejected the finding.
  - `ingest-verifier` refused it: `cannot merge conflicting verdicts ... confirmed vs rejected`.
  - At 03:37 the agent **hand-edited `findings.json`** to remove the finding, with a backup at `state/findings.json.bak`. `validate_artifacts.py` rejected the edit (`marked verified but ... have no findings.json record`), and the agent restored the backup (`ok`, 20 findings).
  - The run state is intact, and `EncodeHead` stays confirmed (medium). The table above saying the run will likely drop `EncodeHead` is therefore wrong: the finding stays in the run's report.

  Recorded as an open gap in [`../troubleshooting/ledger-and-verifier.md`](../troubleshooting/ledger-and-verifier.md). No fixer: `ledger.py` and `wp_scheduler.py` are dirty. |

### Target Findings vs. Known Bugs (02:45)

All 7 Batch 1 confirmations are bugs already known from the run-5 review ([`../upstream/qcbor/README.md`](../upstream/qcbor/README.md)). Run-6 has found nothing new in QCBOR so far.

| Run-6 verdict (fingerprint) | Location | Known as |
| :--- | :--- | :--- |
| `IEEE754_DoubleToSingle` shift x3 (`5614f2d044`, `cd899614e4`, `d355106f76`) | `src/ieee754.c:625` | Upstream draft 04 / `QCBOR-02` in [`../bugs-found/qcbor/README.md`](../bugs-found/qcbor/README.md). A third party filed it upstream as laurencelundblade/QCBOR#434 (open, 2026-11-09). |
| `IEEE754_SingleToHalf` shift (`31f1bd25a5`) | `src/ieee754.c:466` | Upstream draft 04 / `QCBOR-03`; also covered by #434. |
| `UsefulOutBuf_AppendUsefulBuf` 1-byte over-read (`26e4dafbc6`) | `src/UsefulBuf.c:523`, root cause `QCBOREncode_Private_SkipLeadingZeros` | Upstream draft 01 (**private**). |
| `UsefulOutBuf_Compare` x2 (`0e34c586b3`, `b939358da2`) | `src/UsefulBuf.c:745`, `:753` | Upstream draft 05. |

Upstream `dev` has moved from `9bd0845` to `19c3367`, but none of those commits touch `src/ieee754.c`, `src/UsefulBuf.c` or `src/qcbor_number_encode.c`, so all seven bugs are still present.

**Batch 2 (verdicts 03:13–03:17).** 7 confirmed, 1 rejected.

| Run-6 verdict (fingerprint) | Decision | Known as |
| :--- | :--- | :--- |
| `IEEE754_SingleToHalf` shift x2 (`5614f2d044`, `ceaaa12428`) | confirmed, low | Draft 04 / #434. |
| `QCBORDecode_Private_GetArrayOrMap` uninitialized `End.uEndOffset` for `[]` / `{}` (`b1b1b1fe2a`) | confirmed, medium | Draft 08 (**private**). |
| `QCBOREncode_Private_BigNumberToUInt` (`e4ea36ae74`) and `QCBOREncode_Private_AddTNegativeBigNumber` (`26e4dafbc6`), one-byte read past an all-zero big number | confirmed, medium | Draft 01 (**private**). These are the other two readers of the same bad `NLZ`. Run-4 and run-5 rejected `AddTNegativeBigNumber` as a duplicate. Run-6 confirms each reader separately. |
| `QCBOREncode_EncodeHead` `uMinLen` > 8 (`ce76fb1dc0` confirmed medium; `02209a353f` **rejected**, "only the harness sets" it) | split | Draft 07. **Verifier disagreement:** two verifiers judged the same decision point differently. Run-5's judgement was public API, so a real but low-severity hardening bug. The gate has no step that reconciles verdicts sharing a decision point. Noted for the final report, not yet triaged as a pipeline bug. |
| `QCBORDecode_Private_ConsumeItem` uninitialized `Item.uNextNestLevel` copied to the caller after a truncated array or map (`b5ec324eae`) | confirmed, low | **New: not in the run-5 review or the upstream drafts.** Upstream `dev` (`19c3367`) reworked this loop: it now `break`s on halting errors and on `QCBOR_ERR_NO_MORE_ITEMS`. It still runs `*puNextNestLevel = Item.uNextNestLevel` after a break, and it now compares `Item.uNextNestLevel` without checking `uReturn`. The defect therefore looks still present on `dev`, but nobody has reproduced it on `19c3367`. |

**Batch 3 (verdicts 03:27–03:35, partial).**

| Run-6 verdict (fingerprint) | Decision | Known as |
| :--- | :--- | :--- |
| `QCBORDecode_GetTEpochDate` (`745871f887`) and `GetTEpochDays` (`f982f8f015`): uninitialized item value stored after a decode error | confirmed, low | Draft 06. |
| `GetTEpochDateInMapN` (same fingerprint `745871f887`, second task) | `needs_validation` | Draft 06. |
| `QCBORDecode_Private_GetItemInMap` uninitialized `uOffset` in an error state (`c132f24cbe`) | confirmed, low | Run-5 left it **unreported** (the "Not reported" note in [`../upstream/qcbor/README.md`](../upstream/qcbor/README.md): never read on that path). Run-6 now confirms a read of the indeterminate value at `qcbor_spiffy_decode.c:516`. That contradicts run-5's reasoning and is worth re-checking before any filing. |
| `AddTNegativeBigNumber` (`9fce4ec630`), `BigNumberToUInt` (second task on `26e4dafbc6`) | confirmed, medium | Draft 01 (**private**). |
| `UsefulOutBuf_Compare`, unbounded `uLen1` wraps the end pointer (`22aa038aa3`, new after the re-fuzz) | confirmed, medium | Draft 05 (same function and missing bounds; this is the length variant of the offset wrap). |
| `EncodeHead` `ce76fb1dc0`: off-schedule re-verification `reverify-encodehead-ce76` | **rejected** | Draft 07. See the observation row below. `ingest-verifier` refused this verdict, so the run keeps the earlier `confirmed` (medium). That matches run-5's judgement. |

So far the only new candidates are `ConsumeItem` (new) and `GetItemInMap` (previously judged unreachable).

**Batch 3 (the rest) and batch 4 (verdicts 03:37–03:51).** The scheduler shows 30 verify tasks done and 1 running. The architect task `arch:libqcbor_a` is done.

| Run-6 verdict (fingerprint) | Decision | Known as |
| :--- | :--- | :--- |
| `UsefulOutBuf_Compare` `uLen1` wrap (`22aa038aa3`) | confirmed, medium | Draft 05. |
| `GetTEpochDateInMapN/SZ`, `GetTEpochDaysInMapN/SZ` (`745871f887`, `f982f8f015` family) | `needs_validation` x3 | Draft 06 (the in-map variants). |
| `QCBORDecode_Private_CheckItemType` (`c8bb6202f9`, `5963747e94`), `QCBORDecode_Private_ProcessTagItem` (`5b85e2af5a`) | rejected, `harness_induced` (case 166) | Run-5 #28. A recurring harness-generation gap, recorded as open in [`../troubleshooting/harnesses-and-seeds.md`](../troubleshooting/harnesses-and-seeds.md). |
| `UsefulBuf_Compare` overlapping `memcmp` (`357c824f07`) | rejected, E-ACSL artifact | Upstream Frama-C Issue 17 ([`../upstream/frama-c/frama-c-eacsl-memcmp-overlapping-buffers.md`](../upstream/frama-c/frama-c-eacsl-memcmp-overlapping-buffers.md)), corroborated independently by a verifier. |

---

## 9. Final Report (Terminal State, 2026-11-15 07:31)

Section 1's "supervision status" line predates section 8. Supervision continued after 02:42 and ended at the run's terminal state.

### Status

- **Final `run_status`: `incomplete`.** Reason recorded by the run agent: `phase3_incomplete`.
  - The Crash Verification Gate closed with 0 unverified candidates: 16 confirmed, 8 rejected, 4 `needs_validation`.
  - The Phase 3 WP sweep was stopped with 310 units pending and 20 blocked, and the Phase 4 `wp-sweep` re-proof was not run.
  - The run agent stopped on its own, citing session length. The pipeline did not force the stop.
- **Artifacts:** `REPORT.md`, `FINDINGS-DETAIL.md`, `NEEDS-VALIDATION.md` and `report.sarif` in the run dir, regenerated 07:30–07:31. `findings.json` was last written at 05:58.
  - `REPORT.md` line 94 gives proof coverage as 0 units proved unconditionally and 70 under assumptions (16 by WP, 54 by Eva) out of 999 units. It also reports 29 blocked units and "459 coverage unit(s) are still planned or in progress".
- **Total wall clock:** 19:55:37 → 07:31:42 = **11 h 36 min**.

### Wall Clock per Phase

`run-metadata.json` records no per-phase timestamps (`started_at` and `phase_times` are empty). The rows below come from the supervisors' timelines and the transcript, not from run timestamps.

| Phase | Start → end (`UTC+1`) | Wall clock |
| :--- | :--- | ---: |
| Setup + Phase 0 | 19:55:37 → 20:02:00 | 6 min |
| Phase 1 (fuzz, coverage, reach repair) | 20:02:19 → 21:03:57 | 1 h 02 min |
| Phase 2 (unsharded Eva timeout, then 9 shards) | 21:03:58 → 01:45:14 | 4 h 41 min |
| Phase 2 → 3 transition | 01:45:50 → 01:51:28 | 6 min |
| Pre-WP Crash Verification Gate (includes the 46 min re-fuzz) | 01:51:57 → 03:56 | 2 h 04 min |
| Phase 3 WP (stopped) | 03:56 → 07:30 | 3 h 34 min |
| Phase 4 report (twice) | 07:30:29 → 07:31:42 | 1 min |

Phase 3 throughput, from the final `state/wp_schedule.json`:
- 9 `prove` tasks merged, 20 blocked, 14 skipped and 295 pending, in 3 h 34 min.
- **2 more were proven but never merged:** `QCBORDecode_Private_MapTagNumber` (24/24, `Typed`) and `QCBOR_Private_DecodeTagNumber` (9/9, `Bytes`). The run closed with both still `merge_queued`, so a resumed run should merge them first.
- At 07:30 a `step --prepare` handed out 9 more tasks. The run agent released them again before setting the status (`requeue_rc=True`, ACSL-only invariant `ok` over 45 files).
- Negotiations: 12 finished, 2 applied (`UsefulOutBuf_Reset`, weakened; `UsefulBufUtil_CopyUint64ToDouble`, under `Bytes`), 10 rejected (`stalled_after_k_retries`), 5 still pending.
- 19 `breaker` tasks were created; none ran.

### Fixes

| # | Fingerprint | Branch → result | Tests added |
| :--- | :--- | :--- | :--- |
| F1 | `pipeline_make.py run stubs`: `Makefile not found` | `sup/QCBOR-phase0-make-bootstrap` `4dcb52f` → **merged** `6590815` | `tests/test_pipeline_make.py` (2) |
| F2 | `reach-dynamic` misses crashing entries; `coverage-%` `DYNAMIC_GAP_ERROR` deadlock | `sup/QCBOR-reach-dynamic-gate` `d5ae38a` → **held** (overlaps the dirty `templates/pipeline.mk`) | `tests/test_harness_reach.py`, `tests/test_phase0_gates.py` (5) |
| F3 | Stage 1 E-ACSL rebuild per fuzz round; `--record-repair` ignores generation flags | `sup/QCBOR-fuzz-runtime-skip-cases` `aeac81d` → **merged** `436691f` | `tests/test_fuzz_keep_going.py`, `tests/test_generate_harness.py` (8) |
| F4 | Eva `flows` bloat (207 MiB), report size caps, `repair:<mod>` before sibling verifiers, shard imbalance | `sup/QCBOR-eva-flows-bloat-and-caps` `800e9d2` → **held** (overlaps 5 dirty scripts) | `tests/test_large_eva_report.py`, `tests/test_eva_shards.py` (20+) |
| F5 | Parent WP check `Unknown ... (CVC5) (Cached) (Model)` on a proven goal | `sup/QCBOR-wp-counterexample-false-unknown` `811dbe8`, `bcd3d74` → **merged** with F6 in `0490c54` | `tests/test_run_wp_counter_examples.py` (3), `tests/test_tool_parsing.py` (updated) |
| F6 | `acsl_syntax_error` for a missing header (`failed to run: gcc -E`) | `sup/QCBOR-wp-preprocess-error-status` `5166333` → **merged** `0490c54` | `tests/test_tool_sizing.py` (2), `tests/test_mutation_check.py` (1) |

How the merges were done:
- The dry run in a scratch worktree merged F1, F3 and F6 in order with no conflicts, and passed `pytest -n auto` (4942 passed, 181 skipped), `ruff check`, `mypy` and `tools/check_generated_text.py`.
- The real merges went to `phase1-remediation` after the run directory had been quiet for 5 minutes.
- In the main checkout, which still holds the run agent's hot patches, `pytest` passes (4942 / 181). `mypy` reports 13 `union-attr` errors in `scripts/acsl_ast.py` and `ruff` reports one `I001` in `scripts/wp_scheduler.py`. Both files are hot-patched and uncommitted, and the merges did not cause either.
- The merged branches and their worktrees were deleted. F2 and F4 and their worktrees are kept.
- **Follow-up commit `4ad9820`:** the F6 hint offered `merge-agent --module` as the fix. The 07:14 retry showed that `--module` does not reach the parent WP check's include paths, so the hint now names `--cppflags`, and `tests/test_tool_sizing.py` asserts it.
- Nothing was pushed.

### Uncommitted Run Hot Patches (User Decision Pending)

The run agent left these files modified in the main checkout:
- `scripts/acsl_ast.py`: the dual-span splice, which fails `mypy`;
- `scripts/workspace_overlay.py`;
- `scripts/wp_scheduler.py`, which fails `ruff`;
- `scripts/framac_common.py`, `scripts/function_facts.py`, `scripts/ledger.py`, `scripts/resources.py`;
- `templates/pipeline.mk`;
- `tests/test_resources_api.py`;
- `skills/framac-wp/prover_brief.md` and its two mirrors: no `\aligned`; `--wp-model Bytes` for union-heavy functions.

The skill brief was edited twice: at 06:59 for unions and at 07:15 for byte-wise `memcpy` casts. The `acsl_ast.py` dual-span change has no regression test.

**F2/F4 probe (07:45).** In a scratch worktree, the run agent's working-tree diff of `scripts/`, `templates/`, `tests/` and the skills was applied and committed on top of `4ad9820`, then each held branch was merged.
- **F2 merges cleanly over the hot patches**, auto-merging `templates/pipeline.mk`. `pytest -n auto` passes: 4947 passed, 181 skipped.
- **F4 conflicts in 5 files:** `framac_common.py`, `function_facts.py`, `ledger.py`, `workspace_overlay.py`, `wp_scheduler.py`.
- Section 4's claim that F4 "completely supersedes" the hot patches is therefore still unverified. Before F4 can land, the hot patches must either be reverted file by file or reconciled with it.

### Troubleshooting Entries and Upstream Drafts (Section 8 Supervisor)

- [`../troubleshooting/wp-and-guardrail.md`](../troubleshooting/wp-and-guardrail.md):
  - stale-Eva `refresh` (open);
  - header dual-declaration recurrence (open);
  - counter-example false `Unknown` (fixed, F5);
  - missing header reported as `acsl_syntax_error` (fixed, F6; `merge-agent` defaults still open);
  - breakers never dispatched (open);
  - union and `memcpy`-cast functions that prove under `--wp-model Bytes` but never get it automatically (open);
  - the `mutation_check` entry cross-referenced.
- [`../troubleshooting/ledger-and-verifier.md`](../troubleshooting/ledger-and-verifier.md): stray `crash-<sha1>` in the run-dir root during verification (open, cause probable).
- [`../troubleshooting/ledger-and-verifier.md`](../troubleshooting/ledger-and-verifier.md): two verifiers giving opposite verdicts on one decision point (open).
- [`../troubleshooting/harnesses-and-seeds.md`](../troubleshooting/harnesses-and-seeds.md):
  - the duplicate selector-shift entries, merged into one;
  - NULL callback or unterminated array in `--api` cases (open).
- Status lines updated to "merged" in [`../troubleshooting/resources-and-infra.md`](../troubleshooting/resources-and-infra.md), [`../troubleshooting/eacsl-and-fuzzing.md`](../troubleshooting/eacsl-and-fuzzing.md) and [`../troubleshooting/harnesses-and-seeds.md`](../troubleshooting/harnesses-and-seeds.md).
- Upstream: **Issue 19**, [`../upstream/frama-c/frama-c-wp-counter-examples-drops-frame.md`](../upstream/frama-c/frama-c-wp-counter-examples-drops-frame.md). Not filed. Related to, but not a duplicate of, pub/frama-c#2787.

### Model Struggles That Were Not Pipeline Bugs

Suggested skill and brief changes below are not applied.

1. **Quoting through PowerShell, `framac-docker.ps1` and `bash -lc`** (`msg_1dcbe7b50`, `msg_1dcc09af8`). The agent recovered with `-ScriptFile`. Suggestion: `framac-verify` should recommend `-ScriptFile` for anything beyond one command.
2. **Gate reinterpretation:** it skipped the Eva part of `run module-<mod>` during the repair (`msg_1dcc20e36`). The pipeline let this through (open `refresh` bug). Suggestion: the repair description should say Eva is mandatory, or mark the evidence as pre-repair.
3. **Verdict reconciliation outside the scheduler** (03:20–03:37):
   - it tried a nonexistent `ledger.py reopen`;
   - it ran an off-schedule re-verifier with an argumentative brief;
   - it **hand-edited `findings.json`**, which `validate_artifacts.py` caught, and restored it.

   Suggestion: a supported reconciliation command, plus a rule in `framac-verify` never to hand-edit generated artifacts.
4. **Manual `merge-agent` calls** with a script written into the run dir (06:48, `msg_1ddc00dd3001C8k2QkoMDdrwg1`), retried at 07:14 with `--module` (`msg_1ddd72df3001C7ogwdoRnYEREH`), which failed the same way. Suggestion: the WP skill should state that merges go only through `wp_scheduler.py step`.
5. **Weakening a true contract to get past a gate:** `negotiate-usefuloutbuf_reset-2` dropped `keep_UB_ptr` (06:13). The pipeline bug (F5) caused it, but the negotiate brief could forbid dropping a requested clause without recording why.
6. **Status reporting:** it said "41+ done" when 6 proofs had merged, and it credited a rejection to a breaker that never ran (`msg_1dda4ff5e001Ps8X9pRAgyoIuO`). Suggestion: quote `wp_scheduler.py status` counts by kind.
7. **Hot-patching pipeline code and skills during the run:** `acsl_ast.py`, `workspace_overlay.py`, `prover_brief.md` and others. Its diagnosis was right each time, but there were no regression tests, and it left a `mypy` and `ruff` failure. See section 7, item 1.

### Open Pipeline Bugs at the End of Run-6

1. `wp_scheduler.py refresh` closes `repair:<mod>` without checking the fuzz and Eva input digests.
2. A header `static inline` contract written on both declarations is out of scope; the hot patch is untested and fails `mypy`.
3. The scheduler dispatches callers before their same-unit or prototype callees have contracts. This blocked `DecodeFloat`, `*Conformance`, `AppendData`, `Init` and others.
4. A wrapper's frame skeleton projects `assigns \nothing` when its writes happen in a callee.
5. The partial-contract merge refuses a true frame whose body keeps cast or `memcpy` goals (`CopyUint64ToDouble`, `CopyDoubleToUint64`, `CopyOffset`, `SingleToInt`).
6. `--wrap-lines` cannot waive `signed_downcast`.
7. Breakers are starved by `_priority_key`: 19 created, 0 run.
8. Two verifiers can give opposite verdicts on one decision point, and nothing reconciles them.
9. `--api` cases pass a NULL callback or an unterminated array (case 166).
10. Dispatch selector modulo shift when cases are appended.
11. `merge-agent` defaults `--cppflags -I.`, its `--module` does not set the parent check's include paths, and the merge rejection message omits the report's `reason`.
12. `run_wp_function.py --cache-dir off` does not disable WP's own cache.
13. `mutation_check.py` COINS maps every `analysis_error` to `prover_limited`.
14. No automatic `--wp-model Bytes` retry for `[wp:unsupported:union]` or cast-limited functions.
15. A verifier probably wrote a libFuzzer crash artifact into the run-dir root.
16. Held fixes: F2 (merges cleanly over the hot patches) and F4 (conflicts in 5 files).

### Target Findings: Final Set

The final `findings.json` holds 28 records: 16 confirmed, 4 `needs_validation` and 8 rejected. `candidates.json` holds 32 verified candidates. The extra fingerprints (`5614f2d044` x2, `d355106f76`, `ceaaa12428`) are deduplicated by decision point: each appears as evidence inside an existing record, and none was dropped.

| Group | Fingerprints (confirmed) | Status |
| :--- | :--- | :--- |
| `UsefulOutBuf_AppendUsefulBuf`, `BigNumberToUInt` x2, `AddTNegativeBigNumber` x2 (all-zero big number) | `26e4dafbc6`, `e4ea36ae74`, `9fce4ec630` | Known: draft 01 (private) |
| `UsefulOutBuf_Compare` x3 | `0e34c586b3`, `b939358da2`, `22aa038aa3` | Known: draft 05 |
| `IEEE754_DoubleToSingle`, `IEEE754_SingleToHalf` shifts | `cd899614e4`, `31f1bd25a5` | Known: draft 04 / laurencelundblade/QCBOR#434 |
| `QCBORDecode_Private_GetArrayOrMap` | `b1b1b1fe2a` | Known: draft 08 (private) |
| `QCBOREncode_EncodeHead` `uMinLen` | `ce76fb1dc0` (sibling `02209a353f` rejected) | Known: draft 07; split verdicts |
| `QCBORDecode_GetTEpochDate`, `GetTEpochDays` | `745871f887`, `f982f8f015` | Known: draft 06; 4 in-map variants `needs_validation` |
| `QCBORDecode_Private_ConsumeItem` | `b5ec324eae` | **New** (low); likely still on upstream `dev` `19c3367`, not reproduced there |
| `QCBORDecode_Private_GetItemInMap` | `c132f24cbe` | Run-5 left it unreported; run-6 contradicts that reasoning. Re-check before filing |

### Not Verified

- Whether `ConsumeItem` and `GetItemInMap` reproduce on QCBOR `dev` `19c3367`.
- F4 against the hot patches: only the textual conflicts are known; the semantics have not been compared.
- Issue 19 on Frama-C `35.0~~dev`.
- F5 was reproduced only on the 9-goal fixture, never on the real `UsefulOutBuf_Reset` contract with `keep_UB_ptr`.
- The stray `crash-fa138ae...` in the run-dir root: its cause is probable, not confirmed, because the verifier's child transcript is not reachable through `opencode session list`.
- None of the documentation changes are committed: the troubleshooting, upstream and run files also carry other sessions' uncommitted edits.
