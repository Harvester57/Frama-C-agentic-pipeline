# Pipeline v2 Design: Evidence Discipline Ported from security-audit

This document records the v2 architecture of the Frama-C pipeline. It ports the evidence, coverage, isolation, and verification discipline of the `security-audit` skill (reconnaissance, coverage ledger, independent validation, schema-validated records, target-neutral reporting) onto the existing Frama-C phases (slice, fuzz, Eva, WP).

The phases and tools do not change. What changes is how results are classified, who is allowed to write what, how coverage is claimed, and what the final report is allowed to say.

---

## 1. Product of a Run

A run is **findings-first**:

- The headline is the set of `confirmed` bugs, each with a reproducer, source location, and severity.
- Everything else in scope is reported as coverage evidence: units proven unconditionally, units proven under listed open assumptions, blocked units, and deferred or out-of-scope units with reasons.
- A run ends in exactly one of two terminal states: `complete` (all phases done, every candidate has an independent verdict, validators pass) or `incomplete` with an exact `incomplete_reason`. Partial reports state their incompleteness in the first section.

---

## 2. Run Directory and Write Ownership

Runs live **outside the target** by default:

```text
~/framac-pipeline/<repo>/run-<N>/
├── run-metadata.json          # run id, target, source ref, profile, scope, budget, status
├── coverage-ledger.json       # the coverage claim (parent-owned)
├── candidates.json            # unverified candidates awaiting an independent verdict
├── findings.json              # verdict records: confirmed / needs_validation / rejected
├── REPORT.md                  # derived, never hand-edited
├── FINDINGS-DETAIL.md         # derived
├── NEEDS-VALIDATION.md        # derived
├── report.sarif               # verdict records only
├── workspace/                 # former .framac-workspace (baseline, work, harnesses, corpus, crashes, contracts, reports)
├── state/                     # former .framac-state (checkpoints)
└── agents/<agent-id>/{scratch,artifacts}
```

- In the container the target is mounted **read-only** at `/target` and the run directory read-write at `/framac-run` (the working directory).
- A run directory inside the target is allowed only on explicit request and only when version control ignores it.
- `--in-place` becomes a separate host-side apply step that runs after the final report.
- The **parent** (orchestrator) is the only writer of `run-metadata.json`, `coverage-ledger.json`, `candidates.json`, `findings.json`, the shared work tree, and the shared corpus. Subagents write only into `agents/<agent-id>/scratch/` and return exactly one JSON object (Section 7).

---

## 3. Execution Safety

Two layers, of which only the first is an isolation boundary:

1. **Outer container** (wrappers): the sole isolation boundary. `--network none`, `--cap-drop ALL`, `--security-opt no-new-privileges`, Docker's default seccomp and AppArmor profiles (neither is relaxed), CPU/memory/PID limits, target read-only, only the run directory writable, environment limited to an explicit allowlist. `SYS_PTRACE` is removed. The legacy `-NoInnerSandbox` / `-AllowDegradedSandbox` (`--no-inner-sandbox` / `--allow-degraded-sandbox`) flags fail hard with exit code 2.
2. **Inner resource layer** ([`../scripts/sandbox_exec.py`](../scripts/sandbox_exec.py)): every target-controlled binary (LibFuzzer campaigns, guardrail replays, reproducers, later target builds) runs with a cleared environment plus allowlist, rlimits on CPU, file size, open files, and processes (optional address space; core dumps disabled), and a wall-clock timeout that SIGKILLs the whole process group. Runs record `sandbox: "rlimits"`. This layer provides no filesystem or namespace isolation inside the container.

**Residual risk.** Target-controlled binaries can write anywhere in `/framac-run` that the container user can write, including `coverage-ledger.json`, `candidates.json`, and `findings.json`. Authoritative state is schema-validated and fingerprinted on phase transitions, so tampering surfaces as validation failure or fingerprint mismatch rather than silent corruption, but it is not prevented. This is acceptable for auditing non-adversarial production code; deliberately hostile targets are out of scope.

---

## 4. Verdict Model

| Verdict | Meaning | Severity |
|---|---|---|
| `confirmed` | A reproduced E-ACSL failure through the module harness, with the fault in target code and the harness respecting the entry function's declared or documented contract. | Yes |
| `needs_validation` | A specific, source-grounded fault hypothesis that could not be reproduced: Eva `Invalid` without a concrete witness, or a prover/breaker hypothesis (input condition + predicate + why it was not reproduced). Lists exact blockers and a validation plan. | No |
| `rejected` | A candidate disproved by verification: harness-induced crash, dead code, toolchain artifact, contract over-constraint mistaken for a bug. Retained so later runs do not repeat it. | No |

Rules:

- A WP stall is **not** a finding. It is a `blocked` ledger unit with its unproven goals, attempts, and the residual E-ACSL guard. It becomes a `needs_validation` candidate only when a concrete `fault_hypothesis` (`input_condition`, `predicate`, `why_not_reproduced`) is stated. When a goal stalls due to a WP/SMT limitation (for example `<stdlib.h>` dynamic allocation predicates `\freeable` / `allocates`, nonlinear arithmetic, or an unreachable branch established by caller invariants) rather than a suspected bug, the prover or breaker records `"proof_gap": {"predicate": "...", "reason": "..."}` instead (`status = "blocked"` in the ledger, with no candidate created).
- `Invalid_but_dead` Eva statuses are dead-code evidence, never a candidate.
- **Reachability** is a recorded field: `untrusted_surface` (the harness entry corresponds to an untrusted input surface identified by reconnaissance) or `internal_api`. It caps severity.
- **Severity anchors** (confirmed only, never above the demonstrated effect):
  - `critical`: untrusted_surface + out-of-bounds write / control-flow corruption, or Layer 4 authentication bypass.
  - `high`: untrusted_surface out-of-bounds read of secrets, Layer 6 secret leak, Layer 5 injection into a security-relevant sink.
  - `medium`: untrusted_surface DoS / non-termination, untrusted_surface arithmetic undefined behavior (signed integer overflow, divide-by-zero, invalid shift) that bypasses validation logic, corrupts state, or feeds invalid parameters into subsequent APIs, or internal_api memory corruption.
  - `low`: untrusted_surface arithmetic undefined behavior that is strictly localized (e.g. fractional scaling) with no memory safety, bypass, or DoS effect; internal_api read or UB with no shown effect.
- **Fingerprint**: `<rel-file>#<function>::<property-kind>::<hash10>` where `hash10` is the first 10 hex digits of SHA-256 over the normalized failing predicate. No line numbers, input bytes, wave, agent, or verdict. Multiple crash inputs and Eva/WP/E-ACSL hits on the same predicate collapse into one record with all reproducers attached; the verifier may split or merge with a stated reason.

### Crash verification gate (M2)

Crash verification runs right after Phases 1 and 2, before WP:

- Confirmed: the function's units become `candidate` and are excluded from WP.
- Rejected as harness-induced: the parent fixes the harness, the module is re-fuzzed, and its units stay queued.
- Breaker crashes in Phase 3 go through the same verifier before the prover is stopped.
- In `standard` and `deep`, a final record re-verification runs before reporting. Any material replacement (verdict upgrade, changed root cause, changed severity) goes to another fresh verifier.

---

## 5. Coverage Ledger

Unit = **function x obligation class**. ID: `<rel-file>#<function>::<class>` with class in `rte`, `l2_termination`, `l3_frame`, `l4_auth`, `l5_output`, `l6_secret`. Using the file in the ID keeps same-named `static` functions in different files distinct.

Seeding:

- `rte` for every function; `l2_termination` only for functions with loops; `l3`-`l6` only where reconnaissance or inference assigns them.
- Work that the profile or tier does not schedule is seeded as `deferred` or `out_of_scope` with a reason. Nothing is silently omitted.
- The coverage critic may propose missing `l3`-`l6` units.

State table (validator-enforced):

| Status | `agent_id` | `evidence` | `result_fingerprints` | `unresolved` |
|---|---|---|---|---|
| `planned` | null | earlier-phase evidence allowed | empty | empty |
| `in_progress` | required | any | empty | empty |
| `blocked` | any | non-empty | empty | non-empty |
| `covered` | any | non-empty, at least one discharging entry | empty | empty |
| `candidate` | any | non-empty | non-empty | optional |
| `deferred`, `out_of_scope`, `not_applicable` | null | empty | empty | non-empty reason |

Evidence entries name their phase (`fuzz`, `eva`, `wp`, `audit`, `verifier`), producer (script or agent id), result, and the run-relative tool output path.

**Assumptions.** A `covered` unit carries an explicit `assumptions` list: `requires` clauses whose call sites are not verified (linked to those call sites' units), stub contracts relied on, and `Valid_under_hyp` goals whose hypotheses are callee contracts. In per-function WP (`-wp-fct`), `Valid_under_hyp` is expected: callee contracts are hypotheses proven in their own sessions. They are only acceptable when every hypothesis is a callee contract whose own unit is `covered`. The proof audit (M3) resolves this; until then they are listed as open assumptions. The report separates "proven unconditionally" from "proven under N open assumptions". Verifying a caller later discharges its assumption automatically.

**Layer naming convention.** WP goals map to obligation classes by name: RTE goals -> `rte`; `loop variant` / `decreases` -> `l2_termination`; `assigns` / `\separated` goals -> `l3_frame`; named clauses `L4_*`, `L5_*`, `L6_*` (for example `ensures L5_no_crlf: no_crlf_or_nul(out, \result);`) -> the matching layer. Unnamed security clauses cannot be credited to a layer unit.

**Projected frame skeletons (AutoFraming-style, arXiv:2610.29046v1).** `function_facts.py` projects each function's frame information (kernel-AST writes/reads/loops, `may_alias` pairs, Eva `-deps` footprints) into a deterministic `frame_skeleton` in the facts JSON (schema 2): `requires \separated(rho_p, rho_q);` for interfering pointer pairs only (aliasing that can change a caller-visible write; type-compatible pointees only, so `int *` vs `double *` is never separated), and `assigns L \from r1, ..., rm;` per caller-visible write (loop-indexed writes normalized to their whole range; `\from \nothing` when nothing influences the write). The skeleton is rendered into the prover brief as a REQUIRED minimum — provers may strengthen, never delete or weaken — and `workspace_overlay.py` enforces it mechanically at merge time (`acsl_ast.check_frame_preserved` rejects a candidate whose contract drops a projected clause; fail-open when facts are missing). `FRAMAC_FRAME_SKELETON=off` disables the projection for A/B runs. `run_wp_function.py` reports a `frame_summary` (missing-assigns warning, assigns-VC status, `l3_frame` goal counts) so an `l3_frame` unit is frame-error-free only when WP discharges every assigns/loop-assigns/separated goal and no missing-assigns warning fired — a full proof with a missing frame clause does not count.

---

## 6. Proof Audit (M3)

A function's proof-side units are `covered` only after audit:

- **Deterministic audit checks (implemented):**
  - `ledger.py audit-hypotheses --dag workspace/reports/callgraph_dag.json` (run automatically during `pipeline_make.py run wp-sweep` and `report`) resolves `callee_contract_hypothesis` / `valid_under_hyp` assumptions against callee `rte` and `l3_frame` units in the ledger (`status: "discharged"` when every non-external callee is `covered`, `"refuted"` when any callee is `blocked`/`candidate`, or `"open"` otherwise).
  - **Verdict limits:** a passing verdict states what it covered, and a verdict that cannot does not count. `run_wp_function.py` writes `limits` into every report, `ledger.py ingest-wp` copies them onto the discharging evidence, `validate_artifacts.py` rejects discharging WP evidence without them, and `REPORT.md` lists what was not established.
    - `limits.vacuity`: after an `all_proven` result, a separate contract-only pass runs `-wp-smoke-tests`. A doomed `requires` (`contradictory`) turns the proof into `unsound_proof`. `consistent` means no prover refuted the contract within its timeout, not that it is satisfiable; `inconclusive` opens an assumption. Doomed dead-code and dead-call goals are only counted, because correct defensive code triggers them.
    - `limits.missing_spec_callees`: a called prototype with no contract fails the proof (Tier B), since WP would otherwise trust Frama-C's generated default.
    - `limits.classes_without_real_clause`: an L4-L6 class whose every clause holds whatever the function does (`\true`, `x == x`) is not credited. The check is syntactic, so a tautology it cannot see through (a predicate call, a quantifier) stays credited.
    - `limits.dynamic_oracle`: added by the parent re-check from the guardrail's `reach` (libFuzzer `-print_coverage`). A function no input reached is still merged, because WP alone can prove code the corpus misses, but the proof carries an open assumption.
  - `run_wp_function.py --smoke-tests` adds the raw smoke goals to a proof run, for inspection. It also fails on correct defensive branches, so it is not the gate.
  - Mechanical lexical checks (`acsl_ast.py` / `workspace_overlay.py check-acsl-only`) reject `admit`, `axiom`, `axiomatic`, `inductive`, vacuous `\false` clauses, and any non-ACSL token changes.
- **Entry-function rule (implemented in briefs and parent re-checks):** on `untrusted_surface` entry functions, `requires` may only state memory shape (validity, separation, non-null for non-attacker pointers) and environment facts recorded as boundary assumptions. Any value constraint on attacker-controlled bytes or lengths fails the audit and the unit becomes `blocked`.
- **LLM auditor (planned roadmap):** a separate fresh LLM auditor agent for Layer 4-6 contracts and boundary-assumption plausibility.

---

## 7. Agents and Structured Results

Implemented roles in [`../schemas/agent-result.schema.json`](../schemas/agent-result.schema.json): `header_architect`, `prover`, `breaker`, `crash_verifier` (with `recon`, `proof_auditor`, and `coverage_critic` reserved on the M3/M4 roadmap). Each returns exactly one JSON object validated against [`../schemas/agent-result.schema.json`](../schemas/agent-result.schema.json). A malformed or prose-wrapped result is discarded, not repaired, and the task is rerun with a fresh agent if the budget allows.

- **Write isolation (M2, implemented):** each prover, breaker, or architect works in its own scratch overlay and returns an annotation-only patch plus evidence. The parent applies patches serially or in micro-batches (`merge-agent` / `merge-batch`), re-runs the kernel check, guardrail, and WP on the merged tree, and then commits. Breaker seeds are promoted from scratch into the shared corpus by the parent.
- **Annotation-only rule (M2, implemented):** after stripping ACSL comments, the C token stream of the work tree must equal the baseline. Confirmed findings carry remediation text and an optional separate fix patch that is never merged into the work tree.
- **Coverage critic (M4, planned roadmap):** a deterministic gap script (Eva-unreached code from `-metrics-eva-cover`, unstubbed external callees, units closed without evidence, recursion cycles broken arbitrarily, function-pointer calls) feeding a fresh LLM critic per phase.

---

## 8. Reconnaissance and Call Graph (M4)

- **Current implementation:** `build_callgraph_dag.py` uses a C/ACSL lexical token stream (`tokenize_c_acsl`), Tarjan's SCC algorithm for recursion cycles, `compile_commands.json` flag extraction, and structural signature/body classification (`verifiability`, `wp_blockers`, `wp_notes`, risk tiers, and Layers 2-6 property inference).
- **Planned M4 roadmap:**
  - Parallel recon agents (entry surfaces and untrusted inputs; principals, authentication, and secret handling; build and harness feasibility) returning structured facts to override the baseline module table with source-backed reasons.
  - Authoritative Frama-C kernel AST call graph merged with Eva-resolved function-pointer edges after Phase 2. The extraction exists and is shared with the prover facts: `kernel_ast.call_graph()` gives the kernel's direct edges, indirect call sites and recursion cycles, and `run_eva_slice.py` reports Eva-resolved edges (`flows.call_edges`). `build_callgraph_dag.py` does not use them yet: its `callgraph_source` stays `regex`.
  - A C/ACSL companion file giving each vulnerability class a hunting move, ACSL property pattern, and validation rules.

---

## 9. Profiles, Budget, Modes, Incremental Runs (M5)

| Profile | Scope |
|---|---|
| `quick` | Phases 0-2 + crash verification (60 CPU-s fuzz budget, 600 s prover wall budget); WP only on Tier 1A entry chains; remaining unscheduled WP units closed via `ledger.py close-remaining`. |
| `standard` | All phases on Tier 1A, 1B, and Tier 2 validators (120 CPU-s fuzz budget, 900 s prover wall budget); final record re-verification before reporting. |
| `deep` | Extended budgets (900 CPU-s fuzz budget, 1800 s prover wall budget, higher retry limit `K`); Tier 3 `rte` units scheduled instead of deferred. |

- Profiles change breadth, never the evidence bar.
- **Budget** (optional, in agent invocations or wall-clock budgets via `FRAMAC_PROVER_WALL_BUDGET_S`) bounds prover/breaker execution. Exhaustion sets `run_status: incomplete` with a reason.
- **Guidance mode (implemented):** focused requests ("help me prove this function", "why does WP fail here") use the relevant brief and tooling on a scratch copy with no run directory, ledger, or report. Full mode runs on an explicit pipeline request or when artifacts are requested.
- **Cross-run caching and carry-forward:** content-addressed shared caches (`/framac-cache`, populated by trusted `build`, `eva`, `ingest`, and end-of-run `wp-sweep` steps; see [`./resources-and-caching.md`](./resources-and-caching.md#5-caches), Section 5) reuse E-ACSL builds, Eva reports, evolved fuzz corpora, and WP proofs across `run-<N>` directories. Run-directory snapshot manifests (`run_metadata.py snapshot` / `validate_artifacts.py snapshot`) record cryptographic digests of prior run artifacts; full per-unit ledger carry-forward across runs remains on the M5 roadmap.

---

## 10. Outputs

- `findings.json` and `coverage-ledger.json` are the only sources of truth. `candidates.json` holds unverified candidates; a run with unverified candidates is `incomplete`.
- `REPORT.md`: run status, profile, scope, and source ref first; confirmed table; needs-validation table; assurance summary (unconditional vs conditional proofs, boundary assumptions); coverage counts; hardening notes.
- `FINDINGS-DETAIL.md` and `NEEDS-VALIDATION.md`: per-record detail.
- `report.sarif`: verdict records only (`confirmed` = error, `needs_validation` = warning, fingerprint in `partialFingerprints`). Raw Eva/WP SARIF stays in `workspace/reports/` as tool output.

---

## 11. Anti-patterns

1. Reporting a harness-induced crash as a bug.
2. Proving a function under a `requires` that excludes attacker-controlled values at the trust boundary.
3. Counting `Valid_under_hyp` as unconditional proof.
4. Treating `Invalid_but_dead` as a bug.
5. Treating a WP stall as a finding, or hiding it as covered.
6. Agents editing shared headers, the shared corpus, or ledgers directly.
7. Executable C changes in the ACSL work tree.
8. Running target-controlled binaries outside `sandbox_exec.py` (rlimits, env allowlist, timeout) or outside the hardened container.
9. Writing report prose that disagrees with `findings.json`, or writing it before verification.
10. Claiming complete coverage from a profile, tier, or budget cut.

---

## 12. Milestones

| Milestone | Status | Content |
|---|---|---|
| **M1 Foundation** | Implemented | Run directory outside the target; hardened wrappers + `sandbox_exec.py` resource layer (rlimits, env allowlist, timeout); findings, candidates, ledger, metadata, and agent-result schemas; stdlib-only validators with pytest; fingerprints; status-classification fixes (fuzz outcomes, guardrail RTE vs contract, Eva dead/assumed buckets, CSV column normalization); ledger seeding and phase ingestion; report and SARIF derived from findings + ledger. |
| **M2 Verification & Isolation** | Implemented | Crash verifier brief ([`../skills/framac-wp/crash_verifier_brief.md`](../skills/framac-wp/crash_verifier_brief.md)) + gate (`ledger.py ingest-verifier` & `ingest-agent-hypothesis`); per-agent scratch overlays (`workspace_overlay.py init-agent`) and structural function-span patch merge + re-verification (`merge-agent`, `merge-batch`); safe artifact/seed/crash promotion (`promote_artifact.py`); lexical pure-ACSL annotation-only check (`acsl_ast.py`); harness legitimacy (exact-size `malloc(size)` + `size == 0` sentinel buffers and `harness_<mod>.json` sidecars). |
| **M3 Proof Audit** | Partial (deterministic checks implemented; LLM auditor planned) | Implemented: `ledger.py audit-hypotheses`, `run_wp_function.py --smoke-tests`, lexical `admit`/`axiom`/`\false` rejection, `proof_gap` vs `fault_hypothesis` distinction, and entry-function `requires` rules. Planned: standalone LLM proof-auditor subagent for L4-L6 contracts. |
| **M4 Recon & Critics** | Planned | Recon subagents and [`./architecture.md`](./architecture.md) overrides; Frama-C kernel AST call graph + Eva function-pointer edges; C/ACSL companion file; per-phase coverage critic subagents. |
| **M5 Profiles, Caches & Carry-Forward** | Partial (profiles, guidance mode, shared caches & snapshots implemented; ledger carry-forward planned) | Implemented: `quick` / `standard` / `deep` profiles, Guidance Mode, content-addressed per-run and cross-run caches (`cache.py`, `wp-sweep`), warm-start corpora, and snapshot manifests (`run_metadata.py snapshot`). Planned: automated per-unit ledger carry-forward across runs. |
