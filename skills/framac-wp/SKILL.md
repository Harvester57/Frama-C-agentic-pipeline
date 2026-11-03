---
name: framac-wp
description: >-
  Phase 3 of the Frama-C verification pipeline. Synthesizes and proves ACSL
  contracts (assigns, loop invariant, loop variant, requires, ensures, and
  Layers 1-6 security properties) per C function using Frama-C WP + RTE
  (Alt-Ergo, Z3, CVC5) with a swarm of prover subagents. A deterministic
  scheduler (wp_scheduler.py) dispatches each function as soon as its callees
  are merged, sizes concurrency from the measured machine, and keeps all
  bookkeeping. Isolates each subagent in a scratch overlay, enforces mechanical
  pure-ACSL and function-scope checks before splicing, re-verifies merges in
  parallel, runs the Dual-Oracle Guardrail, spawns non-blocking Adversarial
  Breakers on stalled proofs, and verifies all crash/hypothesis candidates
  through independent Crash Verifier subagents.
argument-hint: "<target-dir> --run-dir <dir> [--module <name>] [--function <fn>] [--max-agents N] [--max-retries K]"
---

# /framac-wp

Modular deductive verification stage built from:
- **LLM subagents for everything that needs judgment:** architects, provers, breakers, crash verifiers, negotiators.
- **A deterministic scheduler (`wp_scheduler.py`)** that decides what runs next and keeps the books.
- **Per-agent scratch overlays (`workspace_overlay.py`).**
- **The Dual-Oracle Guardrail** (`E-ACSL` + `WP`).
- **The Crash Verification Gate** (`crash_verifier_brief.md`).

How resources are measured and how caches work: [`docs/resources-and-caching.md`](../../docs/resources-and-caching.md).

## Architecture Overview

1. **Ready queue, not waves.** A function's prover starts as soon as all of these are done:
   - its callees are merged (recursion cycles become ready together);
   - the header architects of its module and of every callee's module;
   - the gate of every fuzz/Eva slice that covers its file.

   The task with the longest chain of callers waiting on it goes first.
2. **Crash Verification Gate.** Every `unverified` candidate becomes a `verify` task for a fresh Crash Verifier subagent.
   - `confirmed` marks the function's units `candidate`; they are excluded from WP.
   - `rejected` / `harness_induced`, with repairs left, creates a `repair` task for you, the parent (up to 2 per module): fix the harness, re-run the module, refresh the scheduler.
   - A gate opens once its candidates are verified and its repairs are done. New candidates (from breakers) or repairs reopen it.
3. **Speculative Interface Architects.** One per module header (`header_architect_brief.md`). It writes baseline contracts in its scratch overlay. The scheduler merges it on completion.
4. **Function Provers.** Several functions of the same `.c` or `.h` can be proved at once: each prover edits its own `agents/<id>/scratch/work/`, and the parent splices only that function's spans.
   - Finished provers are merged in micro-batches per module (`merge-pending`).
   - Merges re-run the guardrail and WP on the merged tree, with per-function WP checks in parallel.
5. **Adversarial Breakers.** A prover that stalls after `K` retries (default `K = 4`) gets a breaker (`breaker_brief.md`). The breaker never blocks the callers. Its seeds and fault hypotheses go through the Crash Verification Gate.
6. **Contract negotiation.** A strengthening request becomes a `negotiate` task as soon as it is ingested, capped per caller/callee pair. The caller is requeued once it resolves. Any merge that changes a contract re-checks the callers already merged (cached).

## Ownership & Isolation Rules

- **Single writer:** the parent is the only writer of `coverage-ledger.json`, `candidates.json`, `findings.json`, `workspace/work/`, `workspace/corpus/`, and `workspace/crashes/`.
- **Locks:** shared state is protected by run-wide locks; merges are journaled, so a killed merge is rolled back by the next one (`docs/resources-and-caching.md`, Section 8).
- **Preparation:** the scheduler prepares every agent (`next --prepare`).
  - It snapshots `workspace/work/` into `agents/<agent-id>/scratch/work/`.
  - It moves the prover's planned units to `in_progress` with a compare-and-set, so a unit that just became a `candidate` is never handed out.
  - It renders `agents/<agent-id>/brief.md` with every template variable filled, including the host paths the agent needs for the wrapper.
- **Agent outputs:** every subagent writes only under `agents/<agent-id>/scratch/`, writes its final JSON result to `agents/<agent-id>/scratch/result.json` (which `wp_scheduler.py complete --agent-id <agent-id>` reads from disk and validates with `validate_artifacts.py agent-result`), and returns **one JSON object**.
- **References:** `prepare-agent` / `next --prepare` automatically fills the `{references_dir}` placeholder in every brief with the path to `docs/references/` (mounted inside the container at `/opt/framac-pipeline/docs/references`). That folder holds greppable Frama-C manuals (see its [`README.md`](../../docs/references/README.md)), which subagents grep only as a last resort.
- **Pure ACSL, in scope:** provers and architects may add **pure ACSL annotations only** (`/*@ ... */`, `//@ ...`) within their assigned function or header. `merge-agent` and `merge-batch` mechanically reject:
  - any C token modification;
  - any scope violation;
  - any `admit` or `axiom` directive.

  They also deduplicate shared header declarations, and roll back when the parent-side guardrail or WP re-verification fails on the merged tree.

---

## Step-by-Step Orchestration Instructions

All commands run through the wrapper with `-TargetDir <target-dir> -RunDir <run-dir>` (`--target` / `--run-dir` in the POSIX wrapper). Use full `/opt/framac-pipeline/scripts/<script>.py` paths so host PowerShell never expands `$S`. The wrapper sizes every container from the measured machine. Do not pass `-Agents`.

### Step 1 — Build the task graph

Run this once, after `pipeline_make.py run ingest replay wp-queue` (which already calls it):

```text
python3 /opt/framac-pipeline/scripts/wp_scheduler.py init
```

When resuming a run that was interrupted, or one started before the scheduler existed, use `init --reconcile`. It returns `in_progress` units with no live agent to `planned` and reports briefs that need re-rendering.

### Step 2 — The dispatch loop (rolling window)

Repeat until `python3 /opt/framac-pipeline/scripts/wp_scheduler.py status` reports `"done": true`:

1. **Hand out ready tasks.**
   ```text
   python3 /opt/framac-pipeline/scripts/wp_scheduler.py next --slots auto --prepare
   ```
   - `--slots auto` = `recommend().max_agents` minus running tasks. It is recomputed each round from the measured machine, and capped by `--max-agents` / `FRAMAC_MAX_AGENTS`.
   - Each entry of `tasks[]` has a `kind`, an `agent_id`, a `role` and a `brief_file`.
   - Entries in `skipped[]` were not handed out, with a reason. For example, a unit that became a `candidate` since `init`: the compare-and-set refused it, so it stays excluded from WP.
   - `parent_tasks[]` are `repair` tasks for you, the parent. They take no agent slot:
     1. Record the attempt:
        ```text
        python3 /opt/framac-pipeline/scripts/generate_harness.py --record-repair workspace/harnesses/harness_<mod>.json --reason "<reason>"
        ```
     2. Fix `workspace/harnesses/harness_<mod>.c`, or regenerate it with `--auto-args` / `--entry-style auto_prototype` for an internal multi-argument function.
     3. Run the task's listed `actions`, typically `pipeline_make.py run module-<mod>`.
     4. Then run `wp_scheduler.py refresh --module <mod>`.
2. **Execute or spawn each task** using its rendered `brief_file` (spawn one subagent per task if your host supports subagents, or execute each task sequentially in the foreground, writing `agents/<id>/scratch/result.json` before calling `complete`). Two kinds carry extra context, which `--prepare` already renders into the brief:
   - **`negotiate`:** a callee prover asked to strengthen its contract. The brief ends with every entry of the task's `requests[]` (the `needed_clause`, the `reason`, the requesting caller). The prover must prove each clause or explain why it does not hold.
   - **`breaker`:** the brief lists the unproven goals from the task's `wp_report`, the stalled prover's own WP report, and names that file.

   Without `--prepare`, render the same briefs with `workspace_overlay.py prepare-agent --request-id <id>` (repeatable) or `--wp-report <path>`.
3. **On each completion:**
   ```text
   python3 /opt/framac-pipeline/scripts/wp_scheduler.py complete --agent-id <id>
   python3 /opt/framac-pipeline/scripts/wp_scheduler.py merge-pending
   ```
   `complete` reads `agents/<id>/scratch/result.json`, validates it, and dispatches by role:
   - **proven** provers are queued for merging;
   - **stalled or blocked** provers:
     - get their WP report ingested;
     - get their hypotheses and strengthening requests recorded, each request emitting a `negotiate` task;
     - leave a non-blocking `breaker` task behind;
   - **verifiers** are ingested with their replay report (`ingest-verifier`);
   - **architects** are merged;
   - a WP run that ended in `analysis_error` (killed or timed out) is retried once with a larger lease, then its units become `blocked`.

   `merge-pending` merges finished provers in micro-batches. It runs when:
   - a module has no running provers;
   - or a ready caller is waiting on an unmerged callee;
   - or ≥ 4 results are queued;
   - or the oldest has waited 5 minutes.

   It ingests each merged function's parent WP report and saves checkpoint shards.
4. Run `python3 /opt/framac-pipeline/scripts/validate_artifacts.py run-dir .` after any manual write.

**Recovery:**
- An agent that never returns: `wp_scheduler.py requeue --stale-minutes <N>` (or `--agent-id <id>`) puts its task back and returns its units to `planned`. If its result arrives later anyway, `complete` still accepts it.
- `status` reports `"stuck": true` when nothing is ready or running yet tasks remain. That usually means a gate is waiting on a repair or verify task (see `gates`), or an agent never returned. Resolve it before looping again.
- **Fallback:** `FRAMAC_SCHEDULER=waves` makes `next` hand out tasks wave by wave, with a barrier between waves. Use it only for A/B comparison.

### Step 3 — Final Record Re-Verification & Diff Export

1. Confirm `python3 /opt/framac-pipeline/scripts/workspace_overlay.py check-acsl-only` passes on `workspace/work/`.
2. In `standard` and `deep` profiles, if any finding record in `findings.json` was upgraded or had its root cause or severity altered during Phase 3, re-verify it with a fresh `crash_verifier_brief.md` subagent.
3. Re-prove every merged function on the final tree: `python3 /opt/framac-pipeline/scripts/pipeline_make.py run wp-sweep`, written exactly so, with the full path. This is the trusted sweep:
   - it does not read the per-run WP cache;
   - it feeds the shared proof cache for later runs;
   - it ingests regressions into the ledger.

   If `workspace/reports/wp-sweep/summary.json` reports `regressions`, those functions' units are now `blocked`. Find out why (usually a later callee contract change) before marking the run complete.
4. Run `python3 /opt/framac-pipeline/scripts/workspace_overlay.py export-diff` to write `workspace/reports/verified_acsl.patch` and copy verified `.h` files to `workspace/contracts/`.
