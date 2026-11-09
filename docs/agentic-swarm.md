# Multi-Agent Swarm Architecture & Dual-Oracle Guardrail

This document explains:
- how the pipeline parallelizes verification across as many subagents and tool processes as the machine allows;
- how the **Dual-Oracle Guardrail** prevents LLM hallucination;
- how callers and callees negotiate contracts.

How resources are measured, leased and cached is in [`./resources-and-caching.md`](./resources-and-caching.md).

---

## 1. Levels of Parallelism

Concurrency is never a fixed number:
- The host broker leases CPUs and memory to every container from the measured pool.
- Each tool sizes itself from its lease.
- The scheduler hands out as many agent tasks as `resources.py recommend` allows, recomputed every round.

LLM subagents are used only where judgment is needed.

### Level 1: Module-Level Parallelism without Subagents (Phase 1 `/framac-fuzz` & Phase 2 `/framac-eva`)
Independent harness modules share no internal state during slice verification, and their fuzz and Eva runs need no reasoning. A harness module is a link unit of the build (`libqcbor_a`, the DAG's modules) or a sub-module of one (QCBOR has 8 harnesses inside `libqcbor_a`): a path module (the sources of one directory), a cluster of a unit too large for one Eva run, or a harness scoped by its sidecar's `scope_files` or `sources`. Make targets, reports and corpora are per harness module; the ledger groups functions by link unit (`scripts/module_map.py`).
- A generated Makefile (`pipeline_make.py`) runs them. Each recipe is admitted by CPU and memory inside one container per phase.
- Fuzzing (CPU-bound) and Eva (single-threaded, memory-bound) can run either **sequentially in the foreground** (giving standalone `eva` a writable `rw` `/framac-cache` mount) or **concurrently in the background** as two wrapper calls (where `eva` mounts `/framac-cache` read-only while `fuzz` runs target code). Ingestion keeps the fuzz-then-Eva order.
- Each campaign runs as many LibFuzzer workers as its lease allows. Builds and Eva results are cached by content, so a harness repair re-runs only what changed.

### Level 2: Speculative Header Decoupling (architects)
Bottom-up verification would otherwise have to wait for leaf functions before callers.
- A **Speculative Interface Architect Subagent** per `.h` header named by a harness sidecar (`header`; a unit whose harnesses name two headers gets two architects) ([`../skills/framac-wp/header_architect_brief.md`](../skills/framac-wp/header_architect_brief.md)) writes baseline `requires`, `assigns`, and `ensures` contracts.
- It validates them dynamically against the Phase 1 fuzzer corpus using `run_eacsl_fuzz.py guardrail`.
- Because `frama-c -wp -wp-fct <caller>` trusts the `.h` contract of any function `<callee>` it calls, a caller only waits for its callees' own provers, never for a global wave.

### Level 3: Dependency-Driven Function Provers (no waves)
`wp_scheduler.py` keeps a ready queue instead of global waves. A function's prover is dispatched as soon as all of these are done:
- its callees are merged (recursion cycles become ready together);
- the architects of its own unit and of every callee's unit (a leaf or static function that touches no module header skips them);
- the gate of every fuzz/Eva slice covering its file; a sub-module's open candidates hold only the functions in its own scope, and the callers whose call cone they lie in.

Ordering and merging:
- Functions with the longest chains of callers waiting on them go first, so the critical path starts early.
- Inside each prover's WP run, `-wp-par` follows the lease (min of CPUs and memory at the fixed 1000 MB prover limit).
- Finished provers are merged in micro-batches. Their parent re-checks run in parallel, one WP job per function.

### Level 4: Adversarial Prover-vs-Breaker Dual-Play
When a Function Prover Subagent fails to prove a specific RTE or security assertion after `K` retries (default `K = 4`):
- The scheduler queues an **Adversarial Breaker Subagent** ([`../skills/framac-wp/breaker_brief.md`](../skills/framac-wp/breaker_brief.md)). Callers of the stalled function are released immediately: the breaker never blocks them.
- The Breaker analyzes the exact unproven assertion and synthesizes surgical binary seed inputs for `E-ACSL + LibFuzzer` to trigger a runtime crash at that line.
- A crash becomes a candidate for an independent Crash Verifier. It reopens the gates of the slices it affects, so no further proof work starts on code that may be broken.

---

## 2. The Dual-Oracle Anti-Hallucination Guardrail

A fundamental hazard of using LLMs for formal verification is **vacuous truth**: in classical logic, `False ==> Anything` is `Valid`. An unconstrained LLM trying to satisfy `frama-c -wp` might accidentally write an overly restrictive or contradictory precondition such as:
```c
/*@ requires len == 0; */ // Or: requires len < 0 && len > 0;
```
Under that precondition, `frama-c -wp` will report `100% Valid` on every goal inside the function—even if the function contains a blatant buffer overflow when `len > 0`!

### How the Pipeline Prevents Vacuous Contracts

Every single iteration of the Function Prover Subagent ([`../skills/framac-wp/prover_brief.md`](../skills/framac-wp/prover_brief.md)) and Interface Architect Subagent ([`../skills/framac-wp/header_architect_brief.md`](../skills/framac-wp/header_architect_brief.md)) must pass **two orthogonal oracles** in sequence:

1. **Oracle 1 — The Dynamic E-ACSL Oracle (`run_eacsl_fuzz.py guardrail`):**
   Compiles the newly proposed ACSL annotations (`requires`, `ensures`, `loop invariant`, `assert`) into executable C checks via `e-acsl-gcc` (the same build as Phase 1 fuzzing: instrument with `-n`, full memory tracking, runtime init hook) and replays the module's valid fuzzer corpus (plus 100–200 additional mutations).
   - If *any* real input violates the proposed `requires` or `loop invariant`, the annotation is **immediately rejected as `rejected_overconstrained`**, and the exact failing variable values from the runtime stack trace are fed back to the subagent.
2. **Oracle 2 — The Static Deductive Oracle (`run_wp_function.py`):**
   Only after a contract holds on 100% of real dynamic executions is it passed to `frama-c -wp -wp-rte -wp-fct <fn>` to prove that it holds mathematically across *all* possible inputs.

### The Best Candidate, Not the Last

Both oracles record each iteration in the prover's scratch directory ([`../scripts/prover_candidates.py`](../scripts/prover_candidates.py)). Candidates that pass the guardrail are ranked by fewest unproven goals, then most proved goals. Only those compete, because a stronger `requires` can raise the proof ratio by excluding inputs. Clauses the prover added that hold whatever the code does (`\true`, `x == x`, `0 <= 1`; `acsl_ast.is_trivial_predicate`) earn no credit: a candidate with fewer of them wins a tie, and their goals are subtracted from the proved count (`FRAMAC_CANDIDATE_RANK=legacy` restores the plain count). The tracker tells the prover to stop when an iteration improves neither number. Before a stalled prover's report and partial contract are used, `wp_scheduler.py complete` restores its best candidate.

A candidate that adds a top-level ACSL declaration outside the prover's function (a file-scope `/*@ ghost ... */` function, a `predicate`, a `lemma`) is never ranked: `merge-agent` would refuse the whole patch. The tracker diffs the declarations of `scratch/work` against `scratch/base` after every oracle run and lists them as `scope_violation_pending` in the first `candidate` block, with `next_synthesis_focus: "remove_top_level_acsl_declarations"`. A prover whose goal needs an inductive lemma stops with `proof_gap.reason` starting `inductive lemma required`; the ledger tags it `gap_kind: "inductive_lemma_required"` and `REPORT.md` counts those functions ([`./formal-discovery/tier-3-rule3-ghost-lemma.md`](./formal-discovery/tier-3-rule3-ghost-lemma.md)).

### What a Prover Starts From

The deterministic side prepares what a prover would otherwise have to work out by reading code:

- **Function facts** ([`../scripts/function_facts.py`](../scripts/function_facts.py), Make target `facts`, cached by content):
  - From the Frama-C kernel AST ([`../scripts/kernel_ast.py`](../scripts/kernel_ast.py)): loops with their guard and updated variables, writes and reads in terms of formals and globals, possibly aliased pointer parameters, recursive calls with their decreasing argument, and return paths.
  - From the module's Eva run ([`../scripts/run_eva_slice.py`](../scripts/run_eva_slice.py)): write and read sets, and resolved call targets.
- **A reading slice** ([`../scripts/function_slice.py`](../scripts/function_slice.py)): the target's body, callee prototypes with their current contracts, and only the types, macros and globals the target references, resolved with the real compile flags. It is built from the agent's snapshot and is reading context only. The proof target stays the real file, because a slice can differ from the compiled program.
- **A brief assembled for the function:** string, float, union and pointer-walking guidance, and similar parts, appear only for functions with those features. Every strict rule stays. Without facts, the whole brief is rendered.

These are hints. Eva's locations hold only under the harness (`a[0..15]`, not `out[0 .. n - 1]`), so the prover restates them over the formals, and WP remains the only judge of `assigns`.

---

## 3. Caller-Callee Contract Negotiation

When Caller Function `B` calls Callee Function `A`, `B`'s WP proof may fail because `A`'s `.h` header contract only states:
```c
/*@ ensures \result >= -1; */
int parse_ber_length(const uint8_t *buf, size_t max_len);
```
whereas Caller `B` needs to know that `\result <= (int)max_len` to prove that advancing `buf + \result` stays in bounds.

Instead of allowing Caller Subagent `B` to edit Callee `A`'s contract directly (which could break `A`'s proof or cause race conditions between parallel subagents), `B` lists the clause it needs in the `strengthening_requests` of its result. The parent records it when it completes `B` (`wp_scheduler.py complete`), through [`../scripts/contract_negotiator.py`](../scripts/contract_negotiator.py); the record is equivalent to:

```bash
python3 /opt/framac-pipeline/scripts/contract_negotiator.py request \
  --caller snmpv3_parse_pdu \
  --callee parse_ber_length \
  --callee-file src/snmp/ber_decode.c \
  --header-file include/ber_decode.h \
  --needed-clause "ensures \result <= (int)max_len;" \
  --reason "Required by snmpv3_parse_pdu to prove \valid_read(buf + offset + \result)"
```

As soon as the request is ingested (`wp_scheduler.py complete`), the scheduler emits a `negotiate` task for `A`. Requests are capped per caller/callee pair, and `B` is requeued once the request is resolved:
1. The orchestrator dispatches Callee Subagent `A` to evaluate the requested `ensures \result <= (int)max_len;` clause.
2. Subagent `A` tests the stronger clause against **Oracle 1 (`E-ACSL guardrail`)** and **Oracle 2 (`WP` on `parse_ber_length`)**.
3. **Outcome 1 (True in `A`):** Both oracles pass. Subagent `A` returns the stronger `ensures` clause in its scratch patch; the parent merges it into `include/ber_decode.h`, re-verifies it, marks the request `verified_and_applied`, and requeues Caller `B`.
4. **Outcome 2 (False in `A`):** `parse_ber_length` does *not* actually enforce `\result <= max_len`! That immediately reveals either a missing bounds check inside `parse_ber_length` or a missing bounds check in `snmpv3_parse_pdu`.

A request `A` could not prove (`rejected_by_callee`) is a dead end for every later caller of `A`: the brief of any prover or breaker whose function calls `A` lists it under "Known Dead Ends (Do Not Repeat)" with the callee's note, so no other caller asks for the same clause again ([`../scripts/spec_kb.py`](../scripts/spec_kb.py), `obstructions_section_for`). The scheduler's structural rejections (`not dispatched: ...`: callee not found, caps reached, callee not provable) say nothing about the clause and are not listed. The same section lists the clauses the E-ACSL guardrail refuted on this function in earlier dispatches, which a re-dispatched prover (a fresh agent id) would otherwise not see.

**Seam evidence in the negotiate brief.** Subagent `A` gets more than the raw clause. Under the JSON block of the requests, `workspace_overlay.py prepare-agent` appends `### Why the callers stalled (seam evidence)`: for each caller, the WP report it stalled on (the report promoted from its latest agent, `agents/<id>/artifacts/wp_<caller>.json`, else the canonical `workspace/reports/wp/<caller>.json`) and at most 12 of its unproven goals at the seam (bucket `step_c_caller_precondition` or `step_c_contract_postcondition`, or an annotation naming `A`), each with line, kind, verdict and bucket. Then `### Your function's previous prover run` summarizes `prover_candidates.status` of `A`'s last prover scratch (iterations, best rank, last WP and guardrail statuses), so `A` does not retry a clause its own guardrail already refuted. `wp_scheduler.py` collects both in `_prepare_kwargs` (`_caller_evidence`, `_callee_history`); a missing or corrupt report leaves the caller's goal list empty and never blocks the dispatch, and `next` / `status` show the goal count as `caller_evidence_goals`. `FRAMAC_NEGOTIATE_EVIDENCE=off` drops both subsections for A/B runs. The scheduler's negotiation state machine is unchanged.
