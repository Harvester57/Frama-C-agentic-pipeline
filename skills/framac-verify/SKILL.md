---
name: framac-verify
description: >-
  End-to-end autonomous Frama-C verification and bug-hunting orchestrator for
  large C codebases. Chains Phase 0 (/framac-slice: shadow overlay, call-graph
  DAG, risk-tier slicing, dual harnesses, coverage ledger), Phase 1
  (/framac-fuzz: zero-ACSL RTE + E-ACSL + LibFuzzer dynamic triage), Phase 2
  (/framac-eva: module-level abstract interpretation), the Pre-WP Crash
  Verification Gate, and Phase 3 (/framac-wp: isolated parallel wavefront ACSL
  synthesis for AoRTE + Layers 1-6). Runs every tool in the hardened
  framac-pipeline container with the target mounted read-only and a run
  directory outside the target; classifies results into a validated coverage
  ledger and verdict records (confirmed / needs_validation / rejected); emits
  REPORT.md, FINDINGS-DETAIL.md, NEEDS-VALIDATION.md, and report.sarif.
argument-hint: "<target-dir> [--module <name>] [--profile quick|standard|deep] [--scope <path>] [--max-agents N] [--fuzz-time SEC] [--run-dir <dir>]"
---

# /framac-verify

Umbrella orchestrator that takes a C codebase (from a single module up to 90,000+ LoC) through the 4-phase hybrid static/dynamic pipeline. Design reference: [`docs/v2-design.md`](../../docs/v2-design.md).

## Operating modes

- **Full mode** (this workflow): only when the user explicitly asks to verify/audit a codebase with the pipeline, or asks for report artifacts.
- **Guidance mode**: for focused requests ("help me prove this function", "why does WP fail here"), use the relevant phase skill or brief directly on a scratch copy. Do not create a run directory, ledger, or report.
- If the request could mean either, ask one focused question before creating anything.

## Core Principles

1. **Hardened container only.** Every Frama-C, E-ACSL, Clang/LibFuzzer, and helper-script invocation runs through `wrappers/framac-docker.ps1` (Windows) or `wrappers/framac-docker.sh` (POSIX). The container has no network, the target is mounted read-only at `/target`, and the run directory is the working directory `/framac-run`. Target-controlled binaries additionally run in the bubblewrap inner sandbox (`scripts/sandbox_exec.py`); if it is unavailable, they do not run.
2. **Run directory outside the target.** Default `~/framac-pipeline/<repo>/run-<N>/` (`-NewRun`). A run directory inside the target is allowed only when explicitly requested and git-ignored.
3. **The parent is the only writer of shared state**: `run-metadata.json`, `coverage-ledger.json`, `candidates.json`, `findings.json`, `workspace/work/`, `workspace/corpus/`, and `workspace/crashes/`. Subagents work in isolated scratch overlays (`agents/<agent-id>/scratch/`) and return **one JSON object** matching `schemas/agent-result.schema.json`. Discard malformed or prose-wrapped results; do not repair them.
4. **Pure-ACSL & Function-Scope Isolation.** After stripping ACSL comments (`/*@ ... */`, `//@ ...`), `workspace/work/` must match `workspace/baseline/` token-for-token (`workspace_overlay.py check-acsl-only`). Prover patches are structurally spliced per function (`workspace_overlay.py merge-agent`) and re-verified by the parent before commit.
5. **Never prove broken code.** Run Phase 1, Phase 2, and the Crash Verification Gate before Phase 3. Functions with `confirmed` or `needs_validation` defects have all active units marked `candidate` and are excluded from WP.
6. **Candidates are not findings.** Tool hits go to `candidates.json`. Each unverified candidate is verified by a fresh Crash Verifier subagent (`skills/framac-wp/crash_verifier_brief.md`) and ingested via `ledger.py ingest-verifier` (which mechanically checks that `confirmed` reproducers replay in the sandbox).
7. **Validate after every shared write**: `python3 /opt/framac-pipeline/scripts/validate_artifacts.py run-dir .`. An invalid ledger cannot drive another assignment.
8. **Two terminal states only**: `complete` (all phases done, every candidate has a verdict, validators pass) or `incomplete` with an exact reason. Never stop mid-phase silently.

---

## Arguments

- `<target-dir>` (required): Path to the target C repository.
- `--module <name>`: Verify only a specific module slice (repeatable).
- `--profile quick|standard|deep`: Run profile (default `standard`; see `docs/v2-design.md` Section 9). Profiles change breadth, never the evidence bar.
- `--scope <path>`: Restrict to repository-relative paths (repeatable). Everything else is seeded `out_of_scope`.
- `--max-agents <N>`: Maximum concurrent subagents per wave or module (default: `8`).
- `--fuzz-time <SEC>`: Duration per module for the Phase 1 burst (default: `60`).
- `--run-dir <dir>`: Resume an existing run directory instead of creating a new one.

---

## Invocation pattern

All commands below run inside the container from the run directory:

```powershell
$env:PYTHONIOENCODING="utf-8"
& "C:\Users\Florian\OneDrive\Documents\Dev\frama-c\wrappers\framac-docker.ps1" `
  -TargetDir "<target-dir>" -RunDir "<run-dir>" `
  "<command>"
```

Create the run directory once with `-NewRun` (the wrapper prints the path) and pass it as `-RunDir` afterwards. `S=/opt/framac-pipeline/scripts` below.

---

## Execution Pipeline

### Setup

1. `-NewRun` (or `-RunDir <existing>`), then: `python3 $S/run_metadata.py init --repo <repo> --profile <profile> [--scope <path>]...`
2. If `state/progress.json` exists (`python3 $S/checkpoint.py load state`), resume from the recorded phase. Re-initializing the overlay on a changed target fails by design: start a new run instead.

### Phase 0 — Slicing, DAG, ledger seeding (`/framac-slice`)

Execute `skills/framac-slice/SKILL.md`. It generates exact-size dual harnesses (`generate_harness.py`, emitting `harness_<mod>.c` and `harness_<mod>.json`) and ends with `ledger.py seed`, creating one unit per function x obligation class. Tier 3 and out-of-scope work is seeded `deferred` / `out_of_scope` with reasons. Checkpoint `phase_done = 0`.

### Phase 1 — Zero-ACSL dynamic triage (`/framac-fuzz`)

Execute `skills/framac-fuzz/SKILL.md`, then ingest: `python3 $S/ledger.py ingest-fuzz workspace/reports/fuzz/*.json`. Crashes become candidates keyed by fingerprint; their units become `candidate`. Checkpoint `phase_done = 1`.

### Phase 2 — Abstract interpretation (`/framac-eva`)

Execute `skills/framac-eva/SKILL.md`, then: `python3 $S/ledger.py ingest-eva workspace/reports/eva/*.json`. Functions whose RTE obligations are all Valid become `covered` (with the harness-context assumption recorded); Eva `Invalid` becomes a `needs_validation` candidate; `Invalid_but_dead` is dead-code evidence only. Checkpoint `phase_done = 2`.

### Pre-WP Crash Verification Gate (`crash_verifier_brief.md`)

For every entry in `candidates.json` with `status: "unverified"`:
1. Spawn a fresh **Crash Verifier Subagent** (`skills/framac-wp/crash_verifier_brief.md`).
2. Validate its JSON output (`python3 $S/validate_artifacts.py agent-result <path>`) and ingest via:
   ```text
   python3 $S/ledger.py ingest-verifier <path> [--replay-report <fuzz.json>] --harness-meta workspace/harnesses/harness_<mod>.json
   ```
3. If `confirmed`: all active units of the buggy function are marked `candidate` and excluded from WP; optional `remediation.fix_patch` is promoted to `agents/<id>/artifacts/` without touching `workspace/work/`.
4. If `rejected` as `harness_induced`: if `repair_attempts < 2`, record the repair (`python3 $S/generate_harness.py --record-repair workspace/harnesses/harness_<mod>.json --reason "<reason>"`), fix `harness_<mod>.c`, and re-run Phase 1 & 2 on `<mod>`; once `repair_attempts == 2`, remaining active units of `<mod>` become `blocked` (`harness_repair_exhausted`).

### Phase 3 — Wavefront WP (`/framac-wp`)

Execute `skills/framac-wp/SKILL.md`. Each architect and prover runs in an isolated overlay (`workspace_overlay.py init-agent`), is merged via `workspace_overlay.py merge-agent` (enforcing pure-ACSL, function scope, and parent-side guardrail + WP re-verification), and updates the ledger via `ledger.py ingest-wp`. Breaker crashes and fault hypotheses go through `ledger.py ingest-agent-hypothesis` and the Crash Verification Gate. Checkpoint `phase_done = 3`.

### Phase 4 — Export, status, and reports

1. Verify the ACSL-only invariant across the work tree: `python3 $S/workspace_overlay.py check-acsl-only`.
2. Export the ACSL diff: `python3 $S/workspace_overlay.py export-diff`.
3. Set the terminal status:
   - `python3 $S/run_metadata.py set-status --status complete` only if no candidate is unverified and no unit is `planned`/`in_progress`;
   - otherwise `python3 $S/run_metadata.py set-status --status incomplete --reason <exact reason>`.
4. Validate: `python3 $S/validate_artifacts.py run-dir .` (must pass).
5. Generate reports: `python3 $S/generate_report.py` (refuses invalid inputs).
6. Mark the checkpoint complete: `python3 $S/checkpoint.py complete state`.
7. `--in-place` is a separate host-side step after the user reviews the report: `python <pipeline>\scripts\workspace_overlay.py apply-in-place --overlay <run-dir>\workspace --target <target-dir>`.

## Anti-patterns

Reporting a harness-induced crash as a bug; proving a function under a `requires` that excludes attacker-controlled values at the trust boundary; counting `Valid_under_hyp` as unconditional proof; treating `Invalid_but_dead` as a bug; treating a WP stall as a finding; agents editing shared headers, the shared corpus, or ledgers; executable C changes in the ACSL work tree; running target-controlled binaries outside the sandbox; writing report prose by hand; claiming complete coverage from a profile, tier, or budget cut.
