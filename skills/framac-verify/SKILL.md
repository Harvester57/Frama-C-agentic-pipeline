---
name: framac-verify
description: >-
  End-to-end autonomous Frama-C verification and bug-hunting orchestrator for
  large C codebases. Chains Phase 0 (/framac-slice: shadow overlay, call-graph
  DAG, risk-tier slicing, dual harnesses, coverage ledger), Phase 1
  (/framac-fuzz: zero-ACSL RTE + E-ACSL + LibFuzzer dynamic triage), Phase 2
  (/framac-eva: module-level abstract interpretation), the Pre-WP Crash
  Verification Gate, and Phase 3 (/framac-wp: isolated parallel ACSL synthesis
  for AoRTE + Layers 1-6, dispatched by a dependency-driven scheduler). Sizes
  every invocation from the measured machine, runs deterministic per-module
  work through Make, and caches builds, Eva results and proofs. Runs every tool in the hardened
  framac-pipeline container with the target mounted read-only and a run
  directory outside the target; classifies results into a validated coverage
  ledger and verdict records (confirmed / needs_validation / rejected); emits
  REPORT.md, FINDINGS-DETAIL.md, NEEDS-VALIDATION.md, and report.sarif.
argument-hint: "<target-dir> [--module <name>] [--profile quick|standard|deep] [--scope <path>] [--max-agents N] [--fuzz-time SEC] [--run-dir <dir>]"
---

# /framac-verify

Umbrella orchestrator that takes a C codebase (from a single module up to 90,000+ LoC) through the 4-phase hybrid static/dynamic pipeline. Design reference: `docs/v2-design.md`.

The upstream WP, Eva, RTE, ACSL and E-ACSL manuals are available as greppable Markdown in `docs/references/` (see `docs/references/README.md`; mounted inside the container at `/opt/framac-pipeline/docs/references`). Consult them only when a skill, a brief, and `docs/troubleshooting.md` don't answer the question. Grep `INDEX.md` for the topic, then read only the matching line range. `wp_scheduler.py next --prepare` automatically populates `{references_dir}` in rendered briefs.

## Operating modes

- **Full mode** (this workflow): only when the user explicitly asks to verify/audit a codebase with the pipeline, or asks for report artifacts.
- **Guidance mode**: for focused requests ("help me prove this function", "why does WP fail here"), use the relevant phase skill or brief directly on a scratch copy. Do not create a run directory, ledger, or report.
- If the request could mean either, ask one focused question before creating anything.

## Core Principles

1. **Hardened container only.** Every Frama-C, E-ACSL, Clang/LibFuzzer, and helper-script invocation runs through `wrappers/framac-docker.ps1` (Windows) or `wrappers/framac-docker.sh` (POSIX). The container has no network, keeps Docker's default seccomp and AppArmor profiles, the target is mounted read-only at `/target`, and the run directory is the working directory `/framac-run`. Target-controlled binaries additionally run through `scripts/sandbox_exec.py` (rlimits, env allowlist, timeout); outside the container (non-POSIX host) they do not run.
2. **Run directory outside the target.** Default `~/framac-pipeline/<repo>/run-<N>/` (`-NewRun`). A run directory inside the target is allowed only when explicitly requested and git-ignored.
3. **The parent is the only writer of shared state**: `run-metadata.json`, `coverage-ledger.json`, `candidates.json`, `findings.json`, `workspace/work/`, `workspace/corpus/`, and `workspace/crashes/`. Subagents work in isolated scratch overlays (`agents/<agent-id>/scratch/`), write their final JSON result to `agents/<agent-id>/scratch/result.json` (which `wp_scheduler.py complete --agent-id <agent-id>` reads and validates against `schemas/agent-result.schema.json`), and return **one JSON object**. Discard malformed or prose-wrapped results; do not repair them.
4. **Pure-ACSL & Function-Scope Isolation.** After stripping ACSL comments (`/*@ ... */`, `//@ ...`), `workspace/work/` must match `workspace/baseline/` token-for-token (`workspace_overlay.py check-acsl-only`). Prover patches are structurally spliced per function (`workspace_overlay.py merge-agent`) and re-verified by the parent before commit.
5. **Never prove broken code.** Run Phase 1, Phase 2, and the Crash Verification Gate before Phase 3. Functions with `confirmed` or `needs_validation` defects have all active units marked `candidate` and are excluded from WP.
6. **Candidates are not findings.** Tool hits go to `candidates.json`. Each unverified candidate is verified by a fresh Crash Verifier subagent (`skills/framac-wp/crash_verifier_brief.md`) and ingested via `ledger.py ingest-verifier` (which mechanically checks that `confirmed` reproducers replay in the sandbox).
7. **Validate after every shared write**: `python3 /opt/framac-pipeline/scripts/validate_artifacts.py run-dir .`. An invalid ledger cannot drive another assignment.
8. **Two terminal states only**: `complete` (all phases done, every candidate has a verdict, validators pass) or `incomplete` with an exact reason. Never stop mid-phase silently.

---

## Arguments

- `<target-dir>` (required): Path to the target C repository.
- `--module <name>`: Verify only a specific module slice (repeatable). Seed with `--scope` set to the module's `required_sources`, and run its per-module Make targets (`pipeline_make.py run build-<mod> fuzz-<mod> eva-<mod>`, or `module-<mod>`, which also ingests) instead of the all-module ones.
- `--profile quick|standard|deep`: Run profile (default `standard`; see `docs/v2-design.md` Section 9). Profiles change breadth, never the evidence bar.
- `--scope <path>`: Restrict to repository-relative paths (repeatable). Everything else is seeded `out_of_scope`.
- `--max-agents <N>`: Cap on concurrent LLM subagents: pass it as `wp_scheduler.py step --max-agents <N>`. Default: what `resources.py recommend` derives from the measured machine (`max_agents`), capped at 16, or 32 on 32+ CPUs and 64 on 64+ CPUs; `FRAMAC_MAX_AGENTS` replaces that cap.
- `--fuzz-time <SEC>`: Wall-clock override per module for the Phase 1 burst: `pipeline_make.py params set --module <mod> --fuzz-max-time <SEC>` for each module. Default: the profile's CPU-second budget (quick 60, standard 120, deep 900) divided by the workers the machine allows.
- `--run-dir <dir>`: Resume an existing run directory instead of creating a new one.

## Resources

The pipeline sizes itself; do not pass CPU, memory or agent counts to the wrapper.
- Every wrapper call leases CPUs and memory from the measured pool (cgroups, Slurm, the container engine, `FRAMAC_POOL_*` caps). Each tool runs as many provers or fuzz workers as its lease allows; `-wp-memlimit` and `-rss_limit_mb` stay fixed, so results do not depend on the machine.
- Run wrapper commands in the **foreground** and wait for them to finish (or as background jobs only if your host harness explicitly supports non-detaching background commands). A waiting command prints its queue position.

Details, knobs and troubleshooting: `docs/resources-and-caching.md`.

---

## Invocation pattern

All commands below run inside the container from the run directory:

```powershell
# Windows (PowerShell)
$env:PYTHONIOENCODING="utf-8"
& ".\wrappers\framac-docker.ps1" `
  -TargetDir "<target-dir>" -RunDir "<run-dir>" `
  "<command>"
```

```bash
# Linux / macOS (POSIX)
./wrappers/framac-docker.sh \
  --target "<target-dir>" --run-dir "<run-dir>" \
  -- "<command>"
```

Create the run directory once with `-NewRun` (the wrapper prints the path) and pass it as `-RunDir` afterwards. Always use explicit `/opt/framac-pipeline/scripts/<script>.py` paths inside `"<command>"` so host PowerShell never expands `$S` as an empty host variable.

---

## Execution Pipeline

### Setup

1. **Resume** (`-RunDir <existing>`): run `python3 /opt/framac-pipeline/scripts/checkpoint.py load state`. If it reports a `phase_done`, resume after that phase and skip step 2 (`run_metadata.py init` refuses an initialized run). For Phase 3, use `wp_scheduler.py init --reconcile`. Re-initializing the overlay on a changed target fails by design: start a new run instead. If `status` is `needs_build_recipe`, the target did not build: show the user `diagnostics` from `workspace/reports/build_capture.json`, record the corrected recipe with `run_metadata.py set-build`, and resume Phase 0 at the build capture (`/framac-slice` Step 1b).
2. **New run** (`-NewRun`): `python3 /opt/framac-pipeline/scripts/run_metadata.py init --repo <repo> --profile <profile> [--scope <path>]...` (it also records the measured resources).
3. Check the measured machine: `python3 /opt/framac-pipeline/scripts/resources.py recommend`. Read its `warnings`, for example a run directory on a network filesystem.

### Phase 0 — Slicing, DAG, ledger seeding (`/framac-slice`)

Execute `skills/framac-slice/SKILL.md`:
- It captures the target's own build from a recipe the user gave or confirmed (`build_capture.py`, in the build image). A target that does not build stops the run with `needs_build_recipe` until the user fixes the recipe.
- It generates exact-size dual harnesses (`generate_harness.py`, emitting `harness_<mod>.c` and `harness_<mod>.json`).
- It gates every harness on reachability (`harness_reach.py check`): each module's DAG entry points must be reached, or exempted with a recorded reason, before the ledger is seeded.
- It requires every fuzzed module to build with E-ACSL (`pipeline_make.py build-check`), unless `--fuzz-engine sanitizers` was chosen for that module, so Phase 1 never falls back to ASan/UBSan silently.
- Both gates are enforced, not just instructions. They record `workspace/reports/phase0_gates.json`, and the Make targets that consume harnesses check it first: `build-`, `fuzz-`, `coverage-` and `eva-` per module, and `wp-queue` for the whole run. Each stops with the reason instead of running on a failed or stale gate.
- It ends with `ledger.py seed`, which creates one unit per function × obligation class. Tier 3 and out-of-scope work is seeded `deferred` / `out_of_scope` with reasons.
- Then `pipeline_make.py gen` writes the Makefile for the next phases.

Checkpoint `phase_done = 0`.

### Phases 1 and 2 — Fuzzing and abstract interpretation (Make, no subagents)

These per-module runs need no judgment, so Make runs them (`skills/framac-fuzz/SKILL.md`, `skills/framac-eva/SKILL.md`):
1. Regenerate the Makefile in the foreground if harnesses changed since Phase 0: `python3 /opt/framac-pipeline/scripts/pipeline_make.py gen`.
2. Compile every module: `python3 /opt/framac-pipeline/scripts/pipeline_make.py run build`.
3. Run `fuzz` and `eva` in the foreground (sequentially gives standalone `eva` a writable `rw` `/framac-cache` mount; if your harness supports concurrent background wrapper calls, you may run `fuzz` and `python3 $S/pipeline_make.py run eva` concurrently with `ro` cache):
   - `python3 /opt/framac-pipeline/scripts/pipeline_make.py run fuzz`
   - `python3 /opt/framac-pipeline/scripts/pipeline_make.py run eva`
   - `python3 /opt/framac-pipeline/scripts/pipeline_make.py run eva-tune` (the deterministic Eva ladder, for modules that still have Unknowns; `skills/framac-eva/SKILL.md`, Step 2a). Skip it under `--profile quick`, which allows no extra Eva runs.

   Write the `build`, `ingest`, standalone `eva`, `eva-tune` and `wp-sweep` commands as shown, with the full script path `/opt/framac-pipeline/scripts/pipeline_make.py`, so later runs on the same repository reuse their builds, evolved fuzz corpora, Eva results and proofs (`docs/resources-and-caching.md`, Section 5).
4. Measure what each corpus reached, for the report's coverage gaps: `python3 /opt/framac-pipeline/scripts/pipeline_make.py run coverage`.
5. Ingest reports (and publish evolved fuzz corpora to `/framac-cache/corpora/<module>`), then prepare Phase 3:
   - `python3 /opt/framac-pipeline/scripts/pipeline_make.py run ingest`
   - `python3 /opt/framac-pipeline/scripts/pipeline_make.py run replay wp-queue`

Ingestion keeps the fuzz-then-Eva order:
- crashes become fingerprinted candidates;
- all-Valid RTE units become `covered`, with the harness-context assumption recorded;
- Eva `Invalid` becomes a `needs_validation` candidate;
- `Invalid_but_dead` is dead-code evidence only.

Tune modules with `pipeline_make.py params set` when Eva or fuzzing needs it, then re-run the target.

`run wp-queue` records `phase_done = 2` itself.

### Crash Verification Gate and Phase 3 (`/framac-wp`)

Execute `skills/framac-wp/SKILL.md`. Its scheduler loop handles everything:
- **Gate.** Verifier tasks for every `unverified` candidate (`skills/framac-wp/crash_verifier_brief.md`):
  - `confirmed`: the function's units become `candidate` and are excluded from WP. Optional `remediation.fix_patch` is promoted to `agents/<id>/artifacts/` without touching `workspace/work/`.
  - `rejected` as `harness_induced` creates a repair task while `repair_attempts < 2`. Record the repair with `generate_harness.py --record-repair`, fix `harness_<mod>.c`, run `pipeline_make.py run module-<mod>`, then `wp_scheduler.py refresh --module <mod>`.
  - After two attempts, the candidate's linked units become `blocked` (`harness_repair_exhausted`). Regenerating the harness keeps the recorded attempts.
- **Phase 3.** Architects, provers, breakers and negotiations are dispatched as soon as their dependencies are done. Their number follows the measured machine. Under `--profile quick` the scheduler proves only the Tier 1A entry chains and closes every other planned unit itself (`quick_profile_wp_not_scheduled`), so the loop still reaches `done`. Only when the user explicitly skips Phase 3 altogether, close the remaining `planned` units with `python3 /opt/framac-pipeline/scripts/ledger.py close-remaining --reason "quick_profile_wp_not_scheduled: Phase 3 WP not run in quick profile"`; otherwise run the Phase 3 scheduler loop to completion.

Once `wp_scheduler.py status` reports `"done": true`: `python3 /opt/framac-pipeline/scripts/checkpoint.py save-phase state --phase 3 --from-file state/wp_schedule.json`.

### Phase 4 — Export, status, and reports

1. Verify the ACSL-only invariant across the work tree: `python3 /opt/framac-pipeline/scripts/workspace_overlay.py check-acsl-only`.
2. Re-prove merged functions on the final tree, and feed the shared proof cache: `python3 /opt/framac-pipeline/scripts/pipeline_make.py run wp-sweep`.
3. Set the terminal status:
   - `python3 /opt/framac-pipeline/scripts/run_metadata.py set-status --status complete` only if no candidate is unverified and no unit is `planned`/`in_progress`;
   - otherwise `python3 /opt/framac-pipeline/scripts/run_metadata.py set-status --status incomplete --reason <exact reason>`.
4. Export the diff, validate and generate the reports: `python3 /opt/framac-pipeline/scripts/pipeline_make.py run report`. It runs `export-diff`, `validate_artifacts.py run-dir .`, then `generate_report.py`, which refuses invalid inputs.
5. Mark the checkpoint complete: `python3 /opt/framac-pipeline/scripts/checkpoint.py complete state`.
6. `--in-place` is a separate host-side step after the user reviews the report: `python <pipeline>\scripts\workspace_overlay.py apply-in-place --overlay <run-dir>\workspace --target <target-dir>`.

### Kill switches (A/B comparison, troubleshooting)

- `FRAMAC_CACHE=off`: no caches at all.
- `FRAMAC_BROKER=off` (or `-NoBroker`): the wrapper's previous static sizing.
- `FRAMAC_SCHEDULER=waves`: wave-by-wave dispatch with barriers.

## Anti-patterns

Reporting a harness-induced crash as a bug; proving a function under a `requires` that excludes attacker-controlled values at the trust boundary; counting `Valid_under_hyp` as unconditional proof; treating `Invalid_but_dead` as a bug; treating a WP stall as a finding; agents editing shared headers, the shared corpus, or ledgers; executable C changes in the ACSL work tree; running target-controlled binaries outside `sandbox_exec.py`; writing report prose by hand; claiming complete coverage from a profile, tier, or budget cut.
