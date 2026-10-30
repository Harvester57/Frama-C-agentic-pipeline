# Backlog: self-sizing, cache-backed, Make-driven pipeline

What is still open after implementing the plan (milestones M0–M6, see `docs/resources-and-caching.md`). Nothing below is committed work yet; the implementation itself is uncommitted too.

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

- [ ] **Shared cache vs hostile targets:** trusted steps read inputs that target code in other containers can rewrite.
  - Today the residual risk is documented, the pre-publish manifest check stops accidental changes, and the store is partitioned per repository.
  - Closing it fully needs one of:
    - snapshot the inputs into a private directory before `build` / `eva` / `wp-sweep`;
    - or have the broker keep writable-cache jobs and target-executing jobs on the same run directory mutually exclusive.
- [ ] **Generated Makefile race:** `pipeline_make.py run` regenerates the Makefile in the shared run directory right before `make` reads it. Render it to a private temporary directory for trusted steps.
- [ ] **Parent re-check memory:** parallel WP re-checks in `merge-batch` split CPUs but not memory, so they can overcommit the `verify` lease.
- [ ] **Same-named statics in Eva:** `unknown_obligations_by_function` and `dead_alarms` are still keyed by bare function name. Invalid alarms are now matched by file.
- [ ] **Fuzz in an under-sized job:** add an explicit `insufficient_memory` outcome, as WP now has, instead of relying on an OOM error.
- [ ] **Unrecognised commands default to `light` (1 CPU, 1 GiB):** extend `infer_class` patterns as new ad-hoc commands appear.
- [ ] **WSL2 with Docker Desktop is treated as VM-backed,** so affinity confinement is skipped even though WSL2 distributions share that VM.
- [ ] **`$S` vs the exact cache allowlist:** trusted steps must spell `/opt/framac-pipeline/scripts/...` in full. Consider having the wrappers expand `$S` before the allowlist check.
- [ ] **Minimum memory:** document the engine memory floor in `README.md`. WP needs 1768 MiB per job, so a 2 GiB Docker VM cannot run WP.
- [ ] **E-ACSL `__retres` workaround:** it rewrites E-ACSL's generated C text, so it is fragile across Frama-C releases. Report the gap upstream and drop the rewrite once it is fixed.

## 4. Deferred by the plan

- [ ] Grow-only rebalancing of running containers via `<engine> update`.
- [ ] An E-ACSL L2 build cache (resilient to line shifts).
- [ ] A guardrail verdict cache (needs a trust and flakiness design).
- [ ] Mirroring resource history into the shared store.
- [ ] Warm-start fuzz corpora across runs.
- [ ] Snapshot manifests for run directories.
- [ ] `ledger.cmd_transition_many` (one batched commit per scheduler round), and a shared argv helper for the scripts.

## 5. Housekeeping

- [ ] Review and commit the work (on a branch).
- [ ] Ruff:
  - New files are clean.
  - About 20 `UP006` / `UP045` / `UP035` / `I001` findings in touched legacy files follow those files' existing style.
  - Modernize them in a separate, style-only change.
