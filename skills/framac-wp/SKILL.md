---
name: framac-wp
description: >-
  Phase 3 of the Frama-C verification pipeline. Orchestrates a Wavefront
  Parallel Subagent Swarm to synthesize and prove ACSL contracts (assigns,
  loop invariant, loop variant, requires, ensures, and Layers 1-6 security
  properties) per C function using Frama-C WP + RTE (Alt-Ergo, Z3, CVC5).
  Isolates each subagent in a scratch overlay (agents/<id>/scratch/work/),
  enforces mechanical pure-ACSL and function-scope checks before splicing and
  parent-side re-verifying patches, runs the Dual-Oracle Guardrail, spawns
  Adversarial Breakers on stalled proofs, and verifies all crash/hypothesis
  candidates through independent Crash Verifier subagents.
argument-hint: "<target-dir> --run-dir <dir> [--module <name>] [--function <fn>] [--max-agents N] [--max-retries K]"
---

# /framac-wp

Modular deductive verification stage powered by a **Wavefront Parallel Subagent Swarm**, **Per-Agent Scratch Overlays (`workspace_overlay.py`)**, the **Dual-Oracle Guardrail (`E-ACSL` + `WP`)**, and the **Crash Verification Gate (`crash_verifier_brief.md`)**.

## Architecture Overview

1. **Pre-WP Crash Verification Gate (`crash_verifier_brief.md`):**
   Every `unverified` candidate in `candidates.json` (from Phase 1 fuzzing or Phase 2 Eva `Invalid`) is dispatched to a fresh **Crash Verifier Subagent** (`crash_verifier_brief.md`) and ingested via `ledger.py ingest-verifier`:
   - `confirmed`: all active units of the buggy function become `candidate` and are excluded from WP.
   - `rejected` (`harness_induced`): up to 2 attempts per module (`generate_harness.py --record-repair`), the parent repairs `workspace/harnesses/harness_<mod>.c` and re-runs Fuzz + Eva; if still harness-broken after 2 attempts, the module's units transition to `blocked`.
2. **Stage 3A — Speculative Interface Architect Swarm (Parallel per `.h` file):**
   One subagent per module `.h` header (`header_architect_brief.md`) works in `agents/<id>/scratch/work/`, writes pure-ACSL baseline contracts (`requires`, `assigns`, `ensures`, plus Layers 4–6), and validates them against the Phase 1 corpus. The parent merges and re-verifies each architect overlay with `workspace_overlay.py merge-agent`.
3. **Stage 3B — Wavefront Function Pods (`Wave 0` -> `Wave K`):**
   Iterates through topological waves from `callgraph_dag.json`, filtered to `planned` ledger units.
   - Within each wave `W`, independent functions run in parallel (up to `--max-agents`, default `8`), even when they share a `.c` or `.h` file, because each prover edits its own `agents/<id>/scratch/work/` and the parent structurally splices only that function's contract+body/prototype span (`workspace_overlay.py merge-agent`).
4. **Stage 3C — Adversarial Breaker Escalation & Verification:**
   If a prover stalls after `K` retries (default `K = 4`), spawn an **Adversarial Breaker Subagent** (`breaker_brief.md`). Breaker seeds and fault hypotheses are ingested via `ledger.py ingest-agent-hypothesis`, and any new candidate is verified through a fresh **Crash Verifier Subagent**.
5. **Stage 3D — Cross-Wave Caller-Callee Contract Negotiation:**
   Strengthening requests returned by provers are recorded via `contract_negotiator.py request` and dispatched to the callee prover after wave `W`.

## Ownership & Isolation Rules

- The parent is the only writer of `coverage-ledger.json`, `candidates.json`, `findings.json`, `workspace/work/`, `workspace/corpus/`, and `workspace/crashes/`.
- Before spawning any `architect` or `prover`, run:
  ```text
  python3 $S/workspace_overlay.py init-agent --agent-id <agent-id>
  ```
- Every subagent writes only under `agents/<agent-id>/scratch/` and returns **one JSON object** validated with `validate_artifacts.py agent-result`.
- Provers and architects may add **pure ACSL annotations only** (`/*@ ... */`, `//@ ...`) within their assigned function/header scope. `workspace_overlay.py merge-agent` mechanically rejects any C token modification, scope violation, or `admit`/`axiom` directive, and rolls back if parent-side guardrail or WP re-verification fails on the merged `workspace/work/` tree.

---

## Step-by-Step Orchestration Instructions

`S=/opt/framac-pipeline/scripts`; all commands run through the wrapper with `-TargetDir <target-dir> -RunDir <run-dir>`.

### Step 0 — Run the Pre-WP Crash Verification Gate

Check `candidates.json` for entries with `"status": "unverified"`:
1. For each unverified candidate, spawn a fresh subagent with `crash_verifier_brief.md` (`agent_id: verifier-<n>`).
2. Validate its JSON result (`python3 $S/validate_artifacts.py agent-result agents/<verifier-id>/scratch/result.json`), then ingest:
   ```text
   python3 $S/ledger.py ingest-verifier agents/<verifier-id>/scratch/result.json [--replay-report <fuzz.json>] --harness-meta workspace/harnesses/harness_<mod>.json
   ```
3. If `decision == "rejected"` with `rejection_class == "harness_induced"` and `harness_exhausted == false`:
   - Record the repair attempt: `python3 $S/generate_harness.py --record-repair workspace/harnesses/harness_<mod>.json --reason "<reason>"`
   - Update `workspace/harnesses/harness_<mod>.c`, re-run Phase 1 (`/framac-fuzz`) and Phase 2 (`/framac-eva`) for `<mod>`, and re-run Step 0 on any resulting candidates.

### Step 1 — Load the Topological Work Queue

Read `workspace/reports/callgraph_dag.json`, `workspace/reports/wp_queue.json`, and `coverage-ledger.json`.
- Schedule only `planned` units into `Wave 0, Wave 1, ..., Wave K`.
- Never schedule units in state `candidate`, `covered`, `blocked`, `deferred`, or `out_of_scope`.

### Step 2 — Run Stage 3A: Speculative Header Contracts

1. For each module header `<h_file>`, initialize the architect scratch overlay (`python3 $S/workspace_overlay.py init-agent --agent-id arch-<mod>`) and spawn `header_architect_brief.md`.
2. Validate the returned JSON, then merge and re-verify on `workspace/work/`:
   ```text
   python3 $S/workspace_overlay.py merge-agent --agent-id arch-<mod> --role architect --header <h_file> --module <mod> --sources <sources...> --cppflags '<cppflags>'
   ```

### Step 3 — Run Stage 3B & 3C: Wavefront Function Pods

For `wave_idx` from `0` to `K`:
1. For each function `<fn>` in the wave:
   - Transition its planned units: `python3 $S/ledger.py transition --id <file>#<fn>::<class> --status in_progress --agent-id <prover-id>`
   - Initialize the prover scratch overlay: `python3 $S/workspace_overlay.py init-agent --agent-id <prover-id>`
   - Spawn a **Function Prover Subagent** with `prover_brief.md`.
2. When a prover returns:
   - Validate its JSON result (`python3 $S/validate_artifacts.py agent-result agents/<prover-id>/scratch/result.json`).
   - **`all_proven`**:
     - Merge its scratch annotations into `workspace/work/` and run parent-side guardrail + WP re-verification:
       ```text
       python3 $S/workspace_overlay.py merge-agent --agent-id <prover-id> --role prover --file <c_file> --function <fn> --header <h_file> --module <mod> --sources <sources...> --cppflags '<cppflags>'
       ```
     - Ingest the parent-verified WP report: `python3 $S/ledger.py ingest-wp workspace/reports/wp/<fn>.json`.
     - Save shard checkpoint: `python3 $S/checkpoint.py save-shard state --phase 3 --shard-id <fn> --from-file workspace/reports/wp/<fn>.json`.
   - **`stalled_after_k_retries` or `blocked`**:
     - Copy/promote the scratch WP report and ingest (`python3 $S/ledger.py ingest-wp ...`) so the unit becomes `blocked` with its unproven goals recorded.
     - If the prover reported a `fault_hypothesis`: `python3 $S/ledger.py ingest-agent-hypothesis agents/<prover-id>/scratch/result.json --module <mod>`.
     - Spawn an **Adversarial Breaker Subagent** (`breaker_brief.md`) on the unproven goals:
       - Validate the breaker JSON and run `python3 $S/ledger.py ingest-agent-hypothesis agents/<breaker-id>/scratch/result.json --module <mod>` to promote its seeds to `workspace/corpus/<mod>/` and record any `fault_hypothesis`.
       - If the breaker returned `crash_found`: re-run the module campaign with `--extra-corpus workspace/corpus/<mod> --max-time 30`, ingest with `ledger.py ingest-fuzz`, and verify the new candidate via Step 0 (`crash_verifier_brief.md`).
3. After all pods in `wave_idx` finish, process pending strengthening requests via `contract_negotiator.py` and run `python3 $S/validate_artifacts.py run-dir .` before advancing to `wave_idx + 1`.

### Step 4 — Final Record Re-Verification & Diff Export

1. Confirm `python3 $S/workspace_overlay.py check-acsl-only` passes on `workspace/work/`.
2. In `standard` and `deep` profiles, if any finding record in `findings.json` was upgraded or had its root cause/severity altered during Phase 3, re-verify it with a fresh `crash_verifier_brief.md` subagent.
3. Run `python3 $S/workspace_overlay.py export-diff` to write `workspace/reports/verified_acsl.patch` and copy verified `.h` files to `workspace/contracts/`.
