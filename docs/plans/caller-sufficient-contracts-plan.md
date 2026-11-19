# Caller-Sufficient Contracts: Semantic Contract Checks and Brief Context

This plan follows a reading of five papers on 2026-11-17 and keeps only what transfers to the Frama-C agentic verification pipeline ([`../guides/v2-design.md`](../guides/v2-design.md), [`../guides/agentic-swarm.md`](../guides/agentic-swarm.md)). It builds on the contract shape and the residual census of [`./proof-papers-generalization-plan.md`](./proof-papers-generalization-plan.md), both merged.

## Where the ideas come from

| Paper | What is taken | What is left out |
|---|---|---|
| Partial Contracts Suffice (arXiv 2607.10291) | A contract only has to be precise on what callers observe (section IV-A); two contracts are compared by meaning, not by clause count (section IV-D); a syntactic measure of contract strength can be inflated (section IV-D). | Regression verification between two versions of a target. |
| FM-Agent (arXiv 2604.11556) | A contract written from the body alone can describe a bug as intended behaviour; what the callers do with the result says what the function is expected to give (section 2.3). | Reasoning in natural language, which is unsound by the paper's own account. |
| RagVerus (arXiv 2502.05344) | Proven examples from the same repository help more than generic ones (section 5.2). | Embedding retrieval; the call graph already gives the dependencies. |
| Evaluating LLM-Generated ACSL (arXiv 2602.13851) | Timeouts differ a lot between provers on the same goals (tables 3 to 7). The paper's tables disagree with each other on which generator a row belongs to, so no figure from it is used. | Its ranking of annotation generators. |
| NL2ACSL (SSRN 5490609) | Nothing: the pipeline takes no natural-language requirements. | All of it. |

## Premises that constrain the design

- Rule 1 of [`../../skills/framac-wp/prover_brief.md`](../../skills/framac-wp/prover_brief.md) forbids any C token change in the target. Every check below works on a generated probe file outside `workspace/work/`.
- Limits that decide a result stay fixed whatever the machine: the probe runs with a fixed prover timeout.
- Deterministic work is a script; judgment stays with the prover agent. The semantic checks are scripts. What a caller needs is judgment, so the script only shows the call sites and the prover decides.
- A skill describes what the pipeline gives. The brief gains a section only when `prepare_agent` renders it.
- The scheduler stays callee-first. Nothing here changes the dispatch order.

## Step 1: contract refinement probe

**Problem.** `contract_shape` and `is_trivial_predicate` in [`../../scripts/acsl_ast.py`](../../scripts/acsl_ast.py) read names, not meaning. A tautology they cannot see through counts as a functional postcondition, and nothing says whether a contract a prover hands back is weaker than the one already merged.

**Mechanism.** A new script, `scripts/contract_refinement.py`, builds a probe translation unit for one function `f` and runs WP on it without RTE:

- a declaration `f__given` with contract A and no body;
- a definition `f__probe` with contract B whose body is the single call to `f__given` with its own parameters.

If every goal of `f__probe` is proved, A refines B: B's `requires` imply A's, and A's `ensures` and `assigns` imply B's under B's `requires`. Two uses:

1. **Not weaker than before.** A is the new contract, B the previous one. A goal left unproved names the previous clause the new contract no longer gives.
2. **Postconditions that say nothing.** A is the new contract reduced to its `requires` and `assigns`, B the full new contract. An `ensures` of B that is proved here follows from the frame and the precondition alone: it holds for any body, so it tells a caller nothing about this one.

**Verdicts.** `refines`, `weaker` (with the clauses of B left unproved: file, line, kind, text), `undecided` (timeout, a prover gave up on every goal, the probe did not parse, a construct the probe cannot carry such as a variadic prototype). `undecided` is never read as either of the other two.

**Tests.** Unit tests on probe generation (text in, text out) with no Frama-C. One test marked `integration` that runs the probe in the analysis image on three small cases: a refinement, a weakening, a postcondition that follows from `assigns`.

## Step 2: use the probe in the pipeline

- **Verdict limit.** When a function is `all_proven`, `apply_verdict_limits` in [`../../scripts/run_wp_function.py`](../../scripts/run_wp_function.py) records under `limits` which `ensures` clauses follow from the frame alone (use 2). When every `ensures` does, the function is reported with the `safety_only` functions in [`../../scripts/generate_report.py`](../../scripts/generate_report.py), and the report says the reading is semantic. The syntactic `contract_shape` stays as recorded; the new field sits beside it and wins when both are present and decided.
- **Merge re-check.** When a prover's contract replaces a contract already merged for the same function (a negotiation re-run, a re-run after a rejected result), the parent re-check runs use 1 against the merged contract. `weaker` rejects the result with the clauses named, which enforces mechanically what the brief already asks ("Never weaken an existing clause"). `undecided` does not block the merge and is recorded in the WP report. First check in the code how a replaced contract is handled today (whether proven callers are requeued); if they are, record `weaker` and requeue instead of rejecting, and say so in the report to the user.
- **Cost.** One WP run without RTE on a body of one call. Measure it on the integration cases and record the figure in the guide.

## Step 3: call sites in the prover brief

`prepare_agent` in [`../../scripts/workspace_overlay.py`](../../scripts/workspace_overlay.py) renders a section "How the callers use this function": for each direct caller in `callgraph_dag.json`, the call line with a few lines after it, from `workspace/work/`. Capped by a fixed number of callers and lines, with the count of callers left out stated. A function with no caller in the slice (an API entry point) gets a sentence saying so.

The brief then says what to do with it:

- write the `ensures` the callers rely on (the range of a result they index with, the validity of a pointer they dereference, the relation they test);
- a postcondition no caller uses is optional, and a strengthening request will ask for more when a caller needs it;
- when a caller plainly expects something the body does not give, do not write the contract around the body: report it as a hypothesis candidate through the existing channel.

Rule 3 (no `requires` beyond what callers give) is unchanged.

## Step 4: proven examples from the same target

`prepare_agent` adds up to two contracts of functions already `all_proven` in this run, chosen by call-graph distance (direct callees first, then functions sharing a caller), preferring a contract whose shape is `functional`. The contract text is inlined with a fixed line cap. The pointer to the vendored `wp_gallery` examples stays. Nothing is rendered when no function is proven yet.

## Step 5: verdicts by prover in the census

[`../../scripts/wp_residual_census.py`](../../scripts/wp_residual_census.py) counts, for the unproved goals whose cost entry lists provers and per-prover verdicts, how many each prover timed out on and how many it gave up on. It reports only what the reports record and says how many goals had no per-prover data. It changes neither the prover list nor a timeout: the figure is there to decide later whether a prover costs time for nothing.

## Validation

- Unit suite per step (`pytest -n auto`), then `ruff check` and `mypy`. No target run per step.
- At the end, one read-only pass of the probe over the proven contracts of a finished run, written to a scratch directory, to see how many `ensures` clauses follow from the frame alone and how many probes come back `undecided`. A live run is not touched.

## Known limits

- The probe compares contracts, not a contract with the body: a contract can be `functional` by the probe and still describe a bug. Step 3 is the only guard against that, and it is judgment.
- Quantified and pointer-heavy postconditions will often be `undecided`; the paper this comes from could not order about 40% of its comparisons.
- Call sites show direct calls only. A function reached through a pointer shows no caller.

## Documentation to update with the code

[`../guides/agentic-swarm.md`](../guides/agentic-swarm.md) (brief sections, merge re-check), [`../guides/v2-design.md`](../guides/v2-design.md) (`limits`), [`../../skills/framac-wp/prover_brief.md`](../../skills/framac-wp/prover_brief.md) and its mirrors through `tools/sync_skill_mirrors.py`.
