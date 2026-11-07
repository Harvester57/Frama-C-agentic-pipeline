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
argument-hint: "<target-dir> --run-dir <dir> [--module <name>] [--max-agents N]"
---

# /framac-wp

Modular deductive verification stage built from:
- **LLM subagents for everything that needs judgment:** architects, provers, breakers, crash verifiers, negotiators.
- **A deterministic scheduler (`wp_scheduler.py`)** that decides what runs next and keeps the books.
- **Per-agent scratch overlays (`workspace_overlay.py`).**
- **The Dual-Oracle Guardrail** (`E-ACSL` + `WP`).
- **The Crash Verification Gate** (`crash_verifier_brief.md`).

How resources are measured and how caches work: [resources-and-caching.md](../../docs/resources-and-caching.md).

## Architecture Overview

1. **Continuous reactive sliding-window loop (not wave barriers).** A function's prover starts as soon as:
   - its callees have an initial contract in `workspace/work/` (speculative contract-first dispatch; callers do not wait for callee body proofs);
   - internal static callees without any contract are proven first (Option A);
   - leaf and internal static functions run concurrently with module architects (`arch:<module>`);
   - a module's open verify tasks gate the provers of that module (the finer call-cone gating applies only to a module without a harness sidecar); provers of other modules are not blocked.

   Tasks are prioritized by caller height, then Eva unknown count, then function name.
2. **Crash Verification Gate.** Every `unverified` candidate becomes a `verify` task for a fresh Crash Verifier subagent.
   - `confirmed` marks the function's units `candidate`; they are excluded from WP.
   - `rejected` / `harness_induced`, with repairs left, creates a `repair` task for you, the parent (up to 2 per module): fix the harness, re-run the module, refresh the scheduler.
   - A gate opens once its candidates are verified and its repairs are done. New candidates (from breakers) or repairs reopen it.
3. **Speculative Interface Architects & Tolerant Header Splice.** One architect per module header ([header_architect_brief.md](./header_architect_brief.md)). It writes baseline contracts in its scratch overlay. A tolerant 3-way AST declaration merger (`splice_architect_header`) cleanly splices non-overlapping function contracts and predicates into headers, enabling provers and architects to work on module headers concurrently.
4. **Function Provers & Sliding-Window Dispatch.** Several functions of the same `.c` or `.h` can be proved at once: each prover edits its own `agents/<id>/scratch/work/`, and the parent splices only that function's spans.
   - Finished provers are merged eagerly or in micro-batches per module (`merge-pending`).
   - Merges re-run the guardrail and WP on the merged tree, with per-function WP re-checks executed in parallel.
   - High-spec machines ($\ge 32$ CPUs, $\ge 64$ CPUs) scale concurrency up to 32 and 64 concurrent agents, while per-process limits remain strictly invariant (`WP_MEMLIMIT_MB=1000`, `FUZZ_RSS_LIMIT_MB=2048`).
5. **Adversarial Breakers.** A prover may iterate `K` times (2 under `quick` or for a `shell_unverifiable_wp` function, 4 under `standard`, 6 under `deep`; the brief states it). Any prover that ends without a full proof gets a breaker ([breaker_brief.md](./breaker_brief.md)). The breaker never blocks the callers. Its seeds and fault hypotheses go through the Crash Verification Gate.
6. **Contract negotiation.** A strengthening request becomes a `negotiate` task as soon as it is ingested, capped per caller/callee pair. The caller is requeued once it resolves. Any merge that changes a contract re-checks the callers already merged (cached).

## Ownership & Isolation Rules

- **Single writer:** the parent is the only writer of `coverage-ledger.json`, `candidates.json`, `findings.json`, `workspace/work/`, `workspace/corpus/`, and `workspace/crashes/`.
- **Locks:** shared state is protected by run-wide locks; merges are journaled, so a killed merge is rolled back by the next one ([resources-and-caching.md](../../docs/resources-and-caching.md), Section 8).
- **Preparation:** the scheduler prepares agents concurrently via a thread pool (`next --prepare` or `step --prepare`).
  - It snapshots `workspace/work/` into `agents/<agent-id>/scratch/work/` under the `merge` lock.
  - The agent's own oracle commands read that copy: their flags put a scratch twin before each include directory of the source tree. `merge-agent` keeps the module's flags, because the parent re-checks the merged tree.
  - It moves the prover's planned units to `in_progress` with a compare-and-set, so a unit that just became a `candidate` is never handed out.
  - It renders `agents/<agent-id>/brief.md` with every template variable filled, including the host paths the agent needs for the wrapper.
  - For a prover, the brief also carries the function's deterministic context: facts from the kernel AST and Eva (`pipeline_make.py run facts`), and a reading slice built from the agent's snapshot and the real compile flags (`agents/<agent-id>/scratch/context/`). The brief keeps only the sections that apply to the function, plus every strict rule. All of it is hints: the proof target stays the real file, and WP stays the only judge. `FRAMAC_PROVER_CONTEXT=off` renders the full brief without this context, for A/B comparisons.
- **Agent outputs:** every subagent writes only under `agents/<agent-id>/scratch/`, writes its final JSON result to `agents/<agent-id>/scratch/result.json` (which `wp_scheduler.py complete --agent-id <agent-id>` reads from disk and validates with `validate_artifacts.py agent-result`), and returns **one JSON object**.
- **References:** `prepare-agent` / `next --prepare` automatically fills the `{references_dir}` placeholder in every brief with the path to `docs/references/` (mounted inside the container at `/opt/framac-pipeline/docs/references`). That folder holds greppable Frama-C manuals (see [README.md](../../docs/references/README.md)), which subagents grep only as a last resort.
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

### Step 2 — The reactive continuous loop (sliding window)

Repeat until `python3 /opt/framac-pipeline/scripts/wp_scheduler.py status` reports `"done": true`:

1. **Atomic step (recommended):** complete finished agents, eagerly merge queued provers, and pull the next ready tasks in a single invocation:
   ```text
   python3 /opt/framac-pipeline/scripts/wp_scheduler.py step --complete <id1> <id2>... --slots auto --prepare
   ```
   - On the first iteration, run with `--slots auto --prepare` without `--complete`.
   - `--slots auto` = `recommend().max_agents` minus running tasks. On high-spec hardware, this scales dynamically up to 32 agents on $\ge 32$ CPUs and 64 agents on $\ge 64$ CPUs.
   - Finished provers merge eagerly without waiting for unrelated module provers, unblocking callers immediately.
   - Newly ready tasks in `next.tasks[]` provide the `agent_id`, `role`, and `brief_file` for newly spawned agents.
   - `next.parent_tasks[]` are `repair` tasks for you, the parent. They take no agent slot:
     1. Record the attempt:
        ```text
        python3 /opt/framac-pipeline/scripts/generate_harness.py --record-repair workspace/harnesses/harness_<mod>.json --reason "<reason>"
        ```
     2. Fix `workspace/harnesses/harness_<mod>.c`, or regenerate it with `--auto-args` / `--entry-style auto_prototype` for an internal multi-argument function.
     3. Run the task's listed `actions`, typically `pipeline_make.py run module-<mod>`.
     4. Then run `wp_scheduler.py refresh --module <mod>`.

2. **Execute or spawn each task** using its rendered `brief_file`. Two kinds carry extra context, which `--prepare` already renders into the brief:
   - **`negotiate`:** a callee prover asked to strengthen its contract. The brief ends with every entry of the task's `requests[]` (the `needed_clause`, the `reason`, the requesting caller). The prover must prove each clause or explain why it does not hold.
   - **`breaker`:** the brief lists the unproven goals from the task's `wp_report`, the stalled prover's own WP report, and names that file.

   Without `--prepare`, render the same briefs with `workspace_overlay.py prepare-agent --request-id <id>` (repeatable) or `--wp-report <path>`.

3. **Granular subcommands (alternative to atomic step):**
   If finer control is needed, the individual subcommands remain available:
   ```text
   python3 /opt/framac-pipeline/scripts/wp_scheduler.py complete --agent-id <id>
   python3 /opt/framac-pipeline/scripts/wp_scheduler.py merge-pending
   python3 /opt/framac-pipeline/scripts/wp_scheduler.py next --slots auto --prepare
   ```
   `complete` reads `agents/<id>/scratch/result.json`, validates it, and dispatches by role:
   - **proven** provers are queued for merging;
   - **stalled or blocked** provers get their WP report ingested, hypotheses/requests recorded, and leave a non-blocking breaker behind;
   - **verifiers** are ingested with their replay report (`ingest-verifier`);
   - **architects** are merged via tolerant header splicing.

4. Run `python3 /opt/framac-pipeline/scripts/validate_artifacts.py run-dir .` after any manual write.

**Recovery:**
- An agent that never returns: `wp_scheduler.py requeue --stale-minutes <N>` (or `--agent-id <id>`) puts its task back and returns its units to `planned`. If its result arrives later anyway, `complete` still accepts it.
- `status` reports `"stuck": true` when nothing is ready or running yet tasks remain. That usually means a gate is waiting on a repair or verify task (see `gates`), or an agent never returned. Resolve it before looping again.
- **Fallback:** `FRAMAC_SCHEDULER=waves` makes `next` hand out tasks wave by wave, with strict barriers between waves. Use it for comparison or debugging.

### Step 3 — Final Record Re-Verification & Diff Export

1. Confirm `python3 /opt/framac-pipeline/scripts/workspace_overlay.py check-acsl-only` passes on `workspace/work/`.
2. In `standard` and `deep` profiles, if any finding record in `findings.json` was upgraded or had its root cause or severity altered during Phase 3, re-verify it with a fresh `crash_verifier_brief.md` subagent.
3. Re-prove every merged function on the final tree: `python3 /opt/framac-pipeline/scripts/pipeline_make.py run wp-sweep`, written exactly so, with the full path. This is the trusted sweep:
   - it does not read the per-run WP cache;
   - it runs WP with no proof cache at all (`--cache-dir off`), so nothing an agent wrote into a cache can answer it;
   - a WP-covered function it cannot re-establish (unproven goals, analysis or ACSL error, unmet limits, no report) has those units `blocked` (`ledger.py ingest-wp --sweep`);
   - it ingests regressions into the ledger;
   - it runs `python3 /opt/framac-pipeline/scripts/ledger.py audit-hypotheses --dag workspace/reports/callgraph_dag.json` (also run first by `pipeline_make.py run report`) to resolve `callee_contract_hypothesis` / `valid_under_hyp` assumptions against the callees' ledger units: a caller is discharged only when every callee is WP-covered with no open hypothesis of its own, transitively down the call graph; otherwise it keeps a `callee_contract_hypothesis` naming the open callees.

   If `workspace/reports/wp-sweep/summary.json` reports `regressions`, those functions' units are now `blocked`. Find out why (usually a later callee contract change) before marking the run complete.
4. Run `python3 /opt/framac-pipeline/scripts/workspace_overlay.py export-diff` to write `workspace/reports/verified_acsl.patch` and copy the contracted `.h` files to `workspace/contracts/`. The patch carries every merged contract; `workspace/contracts/MANIFEST.json` says which are proven, proven under assumptions, or unproven (relied on by other proofs, not established themselves).
