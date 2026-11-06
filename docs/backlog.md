# Backlog: self-sizing, cache-backed, Make-driven pipeline

What remains open after implementing and committing milestones M0–M6 and the hardening follow-ups (see [`./resources-and-caching.md`](./resources-and-caching.md)). Sections 1 and 2 track open verification items; Sections 3–5 record completed follow-ups.

## 1. Finish the end-to-end agent loop

The demo run (two modules, a planted `table[8]` overflow) reached the header architects with real LLM subagents:
- The crash verifier confirmed the bug (critical) and its verdict was ingested.
- Both architects (`arch-util`, `arch-parser`) pass on the fixed toolchain.

Still to run, preferably on a **fresh run directory**. The old one lives in a temporary scratchpad, and its candidate fingerprint predates the fingerprint fix.
- [ ] `wp_scheduler.py complete --agent-id arch-util` / `arch-parser`, then `merge-pending` (architect merge with the parent re-check).
- [ ] The prover round: `prove:src/util/sum.c#checksum`, plus `prove:src/parser/parser.c#parse_record` for its planned `l2_termination` / `l6_secret` units, which dispatch may refuse because the function's `rte` unit is a `candidate`. Then `complete` and `merge-pending` for each.
- [ ] Breaker and negotiation tasks, if a prover stalls or files strengthening requests.
- [ ] `pipeline_make.py run wp-sweep`, then `run report`; `run_metadata.py set-status`; `checkpoint.py complete`.
- [ ] Check that the final ledger, findings and report are consistent: one finding for the overflow, merged contracts, and swept proofs.

## 2. Verification gaps (not testable on this machine)

- [ ] **Podman**, rootless and rootful: per-controller flags, the refusal when memory/pids limits cannot be enforced, and `sandbox.outer: podman-hardened`. Podman is not installed here (it would need installing in WSL Ubuntu).
- [ ] **Exclusive CPU pinning on multi-NUMA or multi-L3 hosts:** only unit-tested with fake topologies. Confinement to an affinity subset was verified on a real kernel.
- [ ] **A real Slurm allocation:** tested only by emulating its environment variables.
- [ ] **A real cluster node resized between runs:** tested via `docker update` on a running container and via pool caps.
- [ ] **SELinux-enforcing hosts:** the `:z` relabels and `FRAMAC_SELINUX_TARGET` are untested.

## 3. Hardening follow-ups found during the end-to-end run

- [x] **Projected frame skeletons (AutoFraming, arXiv:2610.29046v1):** LLM-synthesized contracts verified fully under WP while their frame clauses stayed unsound (the `parse_value(buf, 2, &buf[1])` aliased-call case). `scripts/frame_skeleton.py` now projects each function's frame into a deterministic skeleton (`\separated` for interfering pointer pairs, `assigns L \from ...` per write) in the facts JSON (schema 2); the prover brief lists it as a required minimum, and `workspace_overlay.py` rejects at merge time any candidate that drops a projected clause (`acsl_ast.check_frame_preserved`). `run_wp_function.py` adds a `frame_summary` so `l3_frame` counts as error-free only with all assigns/separated goals discharged and no missing-assigns warning. `FRAMAC_FRAME_SKELETON=off` for A/B. `kernel_ast_dump.ml` now records RHS expressions on function-level writes (straight-line included), so `\from` footprints are precise instead of the read-root superset. Open follow-up: restate Eva `-deps` footprints over the formals inside the skeleton itself (today they are hints).

- [x] **Shared cache vs hostile targets:** trusted steps read inputs that target code in other containers can rewrite.
  - Closed in [`../scripts/resources.py`](../scripts/resources.py): the host broker keeps `cache_mode="rw"` leases and `runs_target_code=True` leases on the same `run_dir` mutually exclusive in `plan_grant()` and `Broker._acquire()`.
- [x] **Generated Makefile race:** `pipeline_make.py run` regenerates the Makefile in the shared run directory right before `make` reads it.
  - Closed in [`../scripts/pipeline_make.py`](../scripts/pipeline_make.py): `_private_make_runner()` writes `Makefile` and `modules.mk` directly from the in-memory strings returned by `_generate()` into a private temporary directory outside the run directory and passes `-f <tmpdir>/Makefile`.
- [x] **Parent re-check memory:** parallel WP re-checks in `merge-batch` split CPUs but not memory, so they can overcommit the `verify` lease.
  - Closed in [`../scripts/workspace_overlay.py`](../scripts/workspace_overlay.py): `_verify_batch_round` bounds `workers` by `budget.mem_mb // (FRAMAC_KERNEL_RESERVE_MB + WP_MEMLIMIT_MB)` and computes `wp_par` via `wp_parallelism(per_worker_budget)`.
- [x] **Same-named statics in Eva:** `unknown_obligations_by_function` and `dead_alarms` are still keyed by bare function name. Invalid alarms are now matched by file.
  - Closed in [`../scripts/framac_common.py`](../scripts/framac_common.py) (`eva_alarm_in_file`), [`../scripts/run_eva_slice.py`](../scripts/run_eva_slice.py) (`functions_with_properties_by_file`), [`../scripts/ledger.py`](../scripts/ledger.py) (`cmd_ingest_eva`), [`../scripts/wp_scheduler.py`](../scripts/wp_scheduler.py) (`Ctx.eva_unknown_count`), and [`../scripts/workspace_overlay.py`](../scripts/workspace_overlay.py) (`prepare_agent`).
- [x] **Fuzz in an under-sized job:** add an explicit `insufficient_memory` outcome, as WP now has, instead of relying on an OOM error.
  - Closed in [`../scripts/run_eacsl_fuzz.py`](../scripts/run_eacsl_fuzz.py) (`FUZZ_MIN_MEMORY_MB = 3072`, `fuzz_required_memory_mb`, `status="insufficient_memory"`) and [`../scripts/ledger.py`](../scripts/ledger.py) (`cmd_ingest_fuzz` records `fuzz_insufficient_memory`).
- [x] **Unrecognised commands default to `light` (1 CPU, 1 GiB):** extend `infer_class` patterns as new ad-hoc commands appear.
  - Closed in [`../scripts/resources.py`](../scripts/resources.py): `infer_class` handles `pipeline_make.py` with options before `run`/`sweep`, `build_callgraph_dag.py`, `extract_references.py`, `e-acsl-gcc(.sh)`, and `clang`/`gcc` `-fsanitize=...fuzzer`.
- [x] **WSL2 with Docker Desktop is treated as VM-backed,** so affinity confinement is skipped even though WSL2 distributions share that VM.
  - Closed in [`../scripts/resources.py`](../scripts/resources.py) (`is_wsl2` check in `parse_engine_info`).
- [x] **`$S` vs the exact cache allowlist:** trusted steps must spell `/opt/framac-pipeline/scripts/...` in full. Consider having the wrappers expand `$S` before the allowlist check.
  - Closed in [`../scripts/resources.py`](../scripts/resources.py) (`expand_script_var`), [`../scripts/container_entry.sh`](../scripts/container_entry.sh), [`../Dockerfile`](../Dockerfile), [`../wrappers/framac-docker.sh`](../wrappers/framac-docker.sh), and [`../wrappers/framac-docker.ps1`](../wrappers/framac-docker.ps1).
- [x] **Minimum memory:** document the engine memory floor in [`../README.md`](../README.md). WP needs 1768 MiB per job, so a 2 GiB Docker VM cannot run WP.
  - Closed in [`../README.md`](../README.md) and [`./resources-and-caching.md`](./resources-and-caching.md).
- [x] **E-ACSL `__retres` workaround:** it rewrites E-ACSL's generated C text, so it is fragile across Frama-C releases. Report the gap upstream and drop the rewrite once it is fixed.
  - Documented as Issue 8 in [`./upstream/frama-c-e-acsl-issues.md`](./upstream/frama-c-e-acsl-issues.md#issue-8-__gen_e_acsl_fn-wrapper-leaves-__retres-uninitialized-under--rte-initialized).

## 4. Deferred by the plan

- [x] Grow-only rebalancing of running containers via `<engine> update` ([`../scripts/resources.py`](../scripts/resources.py): `rebalance_grants`, `Broker.rebalance` / `Broker.rebalance_running`, and `rebalance` CLI subcommand; [`../wrappers/framac-docker.sh`](../wrappers/framac-docker.sh) and [`../wrappers/framac-docker.ps1`](../wrappers/framac-docker.ps1) pass `--name framac-<lease_id>`).
- [x] An E-ACSL L2 build cache (resilient to line shifts) ([`../scripts/cache.py`](../scripts/cache.py): `normalized_source_digest`, `normalized_dependency_manifest`, `enable_l2=True` in `memoize`; wired into `compile_eacsl_binary` in [`../scripts/run_eacsl_fuzz.py`](../scripts/run_eacsl_fuzz.py)).
- [x] A guardrail verdict cache ([`../scripts/cache.py`](../scripts/cache.py): `guardrail` namespace; [`../scripts/run_eacsl_fuzz.py`](../scripts/run_eacsl_fuzz.py): `corpus_manifest` and verdict memoization in `run_guardrail_check`, skipped for agent scratch builds, `--no-cache`, `--no-verdict-cache`, or `FRAMAC_CACHE=off`, and isolated from `run_store` for `parent_guard` binaries).
- [x] Mirroring resource history into the shared store ([`../scripts/resources.py`](../scripts/resources.py): `write_history` / `history_estimate`).
- [x] Warm-start fuzz corpora across runs ([`../scripts/cache.py`](../scripts/cache.py): `shared_corpus_dir`, `warm_start_corpus`, `publish_corpus`; wired into `_run_campaign_mode` in [`../scripts/run_eacsl_fuzz.py`](../scripts/run_eacsl_fuzz.py), `cmd_ingest_fuzz` in [`../scripts/ledger.py`](../scripts/ledger.py), and `ingest` in [`../scripts/pipeline_make.py`](../scripts/pipeline_make.py)).
- [x] Snapshot manifests for run directories ([`../schemas/run-metadata.schema.json`](../schemas/run-metadata.schema.json), [`../scripts/run_metadata.py`](../scripts/run_metadata.py): `build_snapshot_manifest`, `verify_prior_run_snapshot`, `snapshot` subcommand, and `--snapshot` on `set-status`; [`../scripts/validate_artifacts.py`](../scripts/validate_artifacts.py): `validate_snapshot_manifest` and `snapshot` subcommand).
- [x] `ledger.cmd_transition_many` (one batched commit per scheduler round), batched unit transitions in [`../scripts/wp_scheduler.py`](../scripts/wp_scheduler.py), and a shared argv helper (`framac_common.normalize_flag_args`) for the scripts.

## 5. Housekeeping

- [x] Review and commit the work (on a branch).
- [x] Ruff:
  - Modernized legacy `typing.Dict`/`List`/`Optional`/`Set`/`Tuple` annotations, removed redundant `.encode("utf-8")` (`UP012`), and cleaned up imports across `scripts/` and `tests/`.

