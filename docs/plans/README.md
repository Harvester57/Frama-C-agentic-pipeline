# Engineering Plans, Backlog & Design Archive

- **Documentation Hub:** [`../README.md`](../README.md)
- **Maintenance Rules:** [`../AGENTS.md`](../AGENTS.md)

This directory separates **active engineering plans and open backlog items** from **completed historical redesign and remediation plans** (`./archive/`).

---

## 1. Open Backlog & Active Plans

| Document | Scope | Status |
| :--- | :--- | :--- |
| [`./backlog.md`](./backlog.md) | Master checklist of open verification items, environment gaps (Podman, Slurm, SELinux, NUMA), formal-discovery/papers A/B measurements, and completed hardening follow-ups. | Living backlog |
| [`./open-topics-remediation-plan.md`](./open-topics-remediation-plan.md) | Prioritized open items (`M1`-`M3`, `O1`-`O13`) from the nettle, libpng, libseccomp, and libmnl runs before/around merging `phase1-remediation`. | Active (`O1`-`O5`, `O7`-`O13` done; the steps of 2026-11-17 are landed on `phase1-remediation`, not pushed; `O6` and the rest of `M3` wait for the user) |
| [`./phase1-review.md`](./phase1-review.md) | Read-only coherency review of Phase 1 (`/framac-fuzz`), cataloging defects `F1`-`F17` and design questions `D1`-`D4`. | Active reference for Phase 1 remediation |
| [`./phase1-remediation-plan.md`](./phase1-remediation-plan.md) | Step-by-step execution plan (`S0`-`S14` and validation `V`) resolving the defects in [`./phase1-review.md`](./phase1-review.md). Re-scoped 2026-11-17 (D11): S1–S7, F14, F16 and V gate the merge to `main`. | Active (`phase1-remediation` branch) |
| [`./header-entry-points-plan.md`](./header-entry-points-plan.md) | Functions defined in a library's public headers become API entry points (`H1`), with a report of the unexecuted ones in the dynamic reach gate (`R1`) and the ordering against S5 and S6b of the Phase 1 remediation plan. From the QCBOR run-6 gap: 383 of 440 public header functions never ran. | Active (`H1` and `R1` merged into `phase1-remediation` on 2026-11-17, `H1` after S6b; `H2` and the end validation open) |
| [`./templates-and-stubs-improvement-plan.md`](./templates-and-stubs-improvement-plan.md) | Hardening plan across `templates/` (dual harnesses, `fc_stubs/`, `workspace/stubs/` overlay, E-ACSL runtime/canary, MetAcsl templates, `pipeline.mk`). | Active (many `S*`/`M*`/`H*` steps landed; remaining items tracked) |
| [`./regex-hardening-plan.md`](./regex-hardening-plan.md) | Follow-up workstreams (`A`-`E`) from the repository-wide regex audit: replacing fragile log/ACSL regexes with structured CSV/AST parsers and fail-closed matchers. | Active |
| [`./papers-assessed.md`](./papers-assessed.md) | Ledger of every research paper assessed for pipeline improvements, with its verdict (`yields`, `decision`, `watch`, `nothing`, `triaged`) and the plan that holds the details. Read and extended by the [`paper-assessment`](../../skills/paper-assessment/SKILL.md) skill. | Living ledger |
| [`./papers-generalization-plan.md`](./papers-generalization-plan.md) | Assessment and ranked implementation tiers (Eva loop-head states, Heurix, verifier decision points, rejection evidence basis, Houdini loop seeds). | Active (code landed for Tiers 3-4, loop seeds, reopen; A/B measurements open) |
| [`./proof-papers-generalization-plan.md`](./proof-papers-generalization-plan.md) | Assessment of five proof-workflow papers (ProofCoder, VeriGen-C, Dafny workflow, verified optimization in Lean, formal methods and fuzzing) and ranked tiers: per-goal solver cost and verdict kind, a census of residual WP goals followed by a Rocq trial, contract shape in the report, and a decision on functional oracles in Phase 1. | Proposal (not implemented) |
| [`./harness-and-spec-papers-generalization-plan.md`](./harness-and-spec-papers-generalization-plan.md) | Assessment of three papers (SpecAgent, AutoSOUP, SemScan) and ranked tiers: the precondition and its authority on a `harness_induced` rejection, a measurement of strengthening requests against contract shape before any strength feedback, an offline check of trace steps against the function they name, and a decision on external benchmark sets. | Proposal (not implemented). Tier 1 closed by its Step 0 on 2026-11-18 (stop; census in the plan's Section 5); Tier 2 stopped by its Step 0 on 2026-11-18 (the data cannot answer; counts in Section 6), no signal from the stalled provers of libmodbus run-1 and QCBOR run-6 the same day (Section 7), waiting for new runs; Tier 3 closed by its Step 0 the same day (stop: no mismatch in 432 sites); Decision D1 open |
| [`./frama-c-34-option-review.md`](./frama-c-34-option-review.md) | Every Frama-C 34 kernel and plugin option against what the pipeline uses; ranked candidates (E-ACSL `--temporal`, `--libc-replacements`, `--validate-format-strings`, `-wp-auto`, Instantiate, JSON outputs, ...). | Active (candidates 1-4 tried 2026-11-14: libc/format E-ACSL flags adopted; `-wp-auto` second pass open; `--temporal` blocked upstream) |
| [`./fuzz-budget-design.md`](./fuzz-budget-design.md) | Larger Phase 1 fuzz budgets from the c-ares run-1 observations: campaigns blinded by false positives, builds kept out of fuzz leases and a build cache key that survives a slow dependency scan, the sanitizer engine exploring and E-ACSL judging by replay in its own Make stage, raised `standard`/`deep` budgets with sublinear caps for large units, coverage-over-time measurement, a per-case floor pass before the shared campaign, fuzz memory reserved from measured peaks, several arguments for program harnesses, a report-only join of Phase 1's results with Eva's Unknown alarms, and offline batch symbolization (`P1`-`P10`; `P4`, fuzzing alongside Eva, rejected). | Proposal (not implemented; open design points in its section 6) |
| [`./formal-discovery-plan.md`](./formal-discovery-plan.md) | Assessment and 7-tier plan porting formal-discovery mechanisms onto the pipeline, with per-tier specs in `./formal-discovery/`. | Tiers 1-6 implemented (A/B benchmarks & Tier 7 open) |

### Formal-Discovery Per-Tier Plans (`./formal-discovery/`)

- [`./formal-discovery/tier-1-dead-end-ledger.md`](./formal-discovery/tier-1-dead-end-ledger.md) — Dead-end & obstruction ledger (`spec_kb.py`)
- [`./formal-discovery/tier-2-negotiate-evidence.md`](./formal-discovery/tier-2-negotiate-evidence.md) — Caller goal & callee history seam evidence in negotiate briefs
- [`./formal-discovery/tier-3-rule3-ghost-lemma.md`](./formal-discovery/tier-3-rule3-ghost-lemma.md) — Prover brief Rule 3 / ghost-lemma scope alignment
- [`./formal-discovery/tier-4-trivial-stub-mutant.md`](./formal-discovery/tier-4-trivial-stub-mutant.md) — Trivial-stub mutant and corrected mutation rejection criterion
- [`./formal-discovery/tier-5-trivial-aware-rank.md`](./formal-discovery/tier-5-trivial-aware-rank.md) — Trivial-annotation-aware prover candidate ranking
- [`./formal-discovery/tier-6-proof-carry-forward.md`](./formal-discovery/tier-6-proof-carry-forward.md) — Cross-run WP proof carry-forward (`proof_carry.py`)

---

## 2. Completed Historical Plans (`./archive/`)

These plans have been executed and merged. They remain as historical design records explaining why specific invariants, schemas, and architecture choices exist.

| Archived Document | Scope | Completed |
| :--- | :--- | :--- |
| [`./archive/remediation-plan.md`](./archive/remediation-plan.md) | Workflow coherency audit across skills, briefs, Make recipes, ledger, and container mounts (`C1`-`C5`, `H1`-`H10`, `M1`-`M12`, `L1`-`L6`). | 2026-11-07 (all items Fixed) |
| [`./archive/phase0-redesign.md`](./archive/phase0-redesign.md) | Design for build-derived link-unit inventory, Frama-C kernel AST call graph, trust propagation, and two-image snapshot architecture. | 2026-11-08 |
| [`./archive/phase0-implementation-plan.md`](./archive/phase0-implementation-plan.md) | Implementation steps `I0`-`I10` delivering the Phase 0 redesign on `main`. | 2026-11-08 |
| [`./archive/phase0-downstream-effects.md`](./archive/phase0-downstream-effects.md) | Audit of Phase 0 artifact contracts (`build_capture.json`, `phase0_model.json`, `callgraph_dag.json`, `security_props.json`) and downstream Phase 1-3 consumers. Sections 1-2 remain a detailed artifact-field reference. | 2026-11-08 |
| [`./archive/phase0-remediation-plan.md`](./archive/phase0-remediation-plan.md) | Post-merge Phase 0 remediation steps `R1`-`R10` (gates, schemas, trust, sub-module gating, capture snapshot). | 2026-11-08 |
