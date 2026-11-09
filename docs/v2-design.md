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
   The same hardening applies to every image the wrapper selects: the build image (the target's build and tests), the analysis image (everything else) and the optional CodeQL image.
2. **Inner resource layer** ([`../scripts/sandbox_exec.py`](../scripts/sandbox_exec.py)): every target-controlled binary (LibFuzzer campaigns, guardrail replays, reproducers, the target's build under `bear`, its test suite during seed recording) runs with a cleared environment plus allowlist, rlimits on CPU, file size, open files, and processes (optional address space; core dumps disabled), and a wall-clock timeout that SIGKILLs the whole process group. Runs record `sandbox: "rlimits"`. This layer provides no filesystem or namespace isolation inside the container.

**Residual risk.** Target-controlled binaries can write anywhere in `/framac-run` that the container user can write, including `coverage-ledger.json`, `candidates.json`, and `findings.json`. Authoritative state is schema-validated on every write and cross-checked by `validate_artifacts.py run-dir` (linked units exist, finding fingerprints appear on their units, confirmed reproducers match their sha256 and size), so tampering that breaks those invariants surfaces as a validation failure. It is not prevented, and a tamper that keeps every file schema-valid and consistent is not detected: fingerprints are not recomputed from their predicates. This is acceptable for auditing non-adversarial production code; deliberately hostile targets are out of scope.

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
- **Reachability** is a recorded field: `untrusted_surface` (the harness entry is a trust-boundary function in the Phase 0 model's `trust`: library API, input path or the threat model's input sources) or `internal_api`. The sidecar records where it came from (`reachability_source`). It caps severity.
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
- In `standard` and `deep`, the parent re-verifies before reporting any finding record that Phase 3 upgraded or whose root cause or severity changed, with a fresh verifier (`framac-wp` Step 3). This is an instruction to the parent: no script detects such a change.

---

## 5. Coverage Ledger

Unit = **function x obligation class**. ID: `<rel-file>#<function>::<class>`. Using the file in the ID keeps same-named `static` functions in different files distinct. The classes:

- `rte` and `l2_termination`;
- `l3_frame`, and the MetAcsl classes `l4_auth_state`, `l4_auth_required`, `l5_sanitized`, `l6_wiped` and `l6_no_leak` ([`./security-properties.md`](./security-properties.md)).

A clause a prover names `L4_*`, `L5_*` or `L6_*` by hand gets no class of its own (see the layer naming convention below).

Seeding (`ledger.py seed`, from the DAG of the Phase 0 model):

- One unit per function a non-test link unit compiles, grouped by link unit. Functions found only in test units get none.
- `rte` for every function; `l2_termination` only for functions with loops.
- From `workspace/reports/security_props.json` (`security_props.py run`): `l3_frame` for every function that writes through a pointer, and the MetAcsl classes where the threat model puts a property instance. Without a threat model only `l3_frame` is seeded.
- Header `static inline` functions no entry point of the build reaches are seeded `deferred` (`header_unreached`).
- Units of a function on the GCC call-graph fallback carry `bookkeeping.callgraph_fallback`; units of a concurrent link unit carry `bookkeeping.concurrent`, and the report says their Eva and WP results assume sequential execution.
- Work that the profile or tier does not schedule is seeded as `deferred` or `out_of_scope` with a reason. Nothing is silently omitted.
- The coverage critic may propose missing `l3`-`l6` units.

**Module mapping.** A harness module (its reports, corpus, candidates) is a link unit or a sub-module of one. Ingest maps each report to its unit through `module_map.py`, so a sub-module's report credits its unit's functions. Eva rows go to the function whose line range holds them. A unit keeps one Eva verdict per harness module, and is `covered` only with at least one `valid` and no `invalid` or `unknown` from any module.

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

**Layer naming convention.** WP goals map to obligation classes by name: RTE goals -> `rte`; `loop variant` / `decreases` -> `l2_termination`; `assigns` / `\separated` goals -> `l3_frame`; goals of the generated MetAcsl annotations (`L4_auth_state_*`, `L4_auth_required_*`, `L5_sanitized_*`, `L6_wiped_*`, `L6_no_leak_*`, annotated `<property>: meta:`) -> the property's class; everything else -> `rte` (`run_wp_function.goal_obligation_class`). A clause a prover names `L4_*`, `L5_*` or `L6_*` by hand is classed by its kind like any other clause (`rte`, or `l3_frame` for a frame clause), so only the generated goals credit a Layer 4-6 unit.

**Projected frame skeletons (AutoFraming-style, arXiv:2610.29046v1).** `function_facts.py` projects each function's frame information (kernel-AST writes/reads/loops, `may_alias` pairs, Eva `-deps` footprints) into a deterministic `frame_skeleton` in the facts JSON (schema 2): `requires \separated(rho_p, rho_q);` for interfering pointer pairs only (aliasing that can change a caller-visible write; type-compatible pointees only, so `int *` vs `double *` is never separated), and `assigns L \from r1, ..., rm;` per caller-visible write (loop-indexed writes normalized to their whole range; `\from \nothing` when nothing influences the write). The skeleton is rendered into the prover brief as a REQUIRED minimum — provers may strengthen, never delete or weaken — and `workspace_overlay.py` enforces it mechanically at merge time (`acsl_ast.check_frame_preserved` rejects a candidate whose contract drops a projected clause; fail-open when facts are missing). `FRAMAC_FRAME_SKELETON=off` disables the projection for A/B runs. `run_wp_function.py` reports a `frame_summary` (missing-assigns warning, assigns-VC status, `l3_frame` goal counts) so an `l3_frame` unit is frame-error-free only when WP discharges every assigns/loop-assigns/separated goal and no missing-assigns warning fired — a full proof with a missing frame clause does not count.

**Loop templates and loop dependency graph (SESpec/InvWeaver-style, facts schema 3).** Each loop's variables are classified into unchanged / non-inductive / inductive (`_classify_loop_vars`, from the kernel dump's writes/reads/RHS values), and rendered as per-loop ACSL skeleton templates with `PLACE_HOLDER`s, including the loop-skip conditional `!(guard) ==> v == \at(v, Pre);` that pure LLMs systematically miss. A loop-level dependency graph (`_loop_graph`) records state-transition edges (nesting, sequential order) and verification-dependency edges (inner provability -> outer preservation; earlier provability -> later establishment), rendered as a per-loop "Loop dependency context" (assumption/obligation). `run_wp_function.py` turns a failed loop-preservation goal into a dependency-slice hint naming the inner/predecessor loop whose exit summary is the likely missing fact (fail-open without facts). `FRAMAC_LOOP_TEMPLATES=off` disables templates and the graph for A/B runs.

**Specification quality by mutation testing (COINS 2608.13077v1 / KBSpec C@All).** `scripts/mutation_check.py` (opt-in, evaluative only — never touches `workspace/work/`) runs on functions whose parent WP report is `all_proven` and writes `workspace/reports/mutation.json`: contract mutants (drop an `ensures`, flip `<=`→`<`, `ensures \true;`) measure **completeness** (a mutant that still proves is equivalent → the spec is too weak), implementation mutants (flip `<`→`<=` in a guard, change a return constant) measure **precision** (an `ensures`/`behavior` goal coming back Invalid → the spec rejects the wrong code, REJECT-style). `generate_report.py` renders a "Specification quality" section and splits open units into **prover-limited** (analysis_error, allocation/macro-loop limits, all-timeout) vs **spec-limited** (genuine unproven goals, missing-assigns) — the evaluation duality COINS warns about. `benchmark.py` carries the per-target `mutation` totals in the run file (schema: `benchmark-run.schema.json`).

**Specification knowledge base (KBSpec-style, arXiv:2606.21339v2).** `scripts/spec_kb.py` maintains a dual-source ACSL knowledge base per run under `workspace/reports/kb/`: a seed KB sliced from the reference manuals via `INDEX.md` section lines (built once per run), and an evolved KB of (error -> fix) repair items mined from finished prover tasks (`spec_kb.py mine --run-dir ...`), scored with KBSpec's helpfulness triplet (helpful on `all_proven`, harmful on a stall; a verified trajectory's fix wins) and pruned to top-L. Retrieval is deterministic keyword overlap (ACSL built-ins + identifiers) against a query built from the function's features, frame skeleton and loop classes. The prover brief gets a "Retrieved ACSL Knowledge" section at dispatch (`<!-- spec-kb -->` sentinel in `prover_brief.md`), and `run_wp_function.py` turns failed goals into repair-pattern hints from the evolved KB. A third store, `obstructions.json` (also filled by `spec_kb.py mine`), records dead ends: clauses the E-ACSL guardrail refuted on a corpus input (`rejected_overconstrained`, from `agents/*/scratch/candidates/c*/guard_*.json`; `code_fault` is a code defect candidate and is excluded) and strengthening requests a callee prover tried and rejected (`rejected_by_callee` without the scheduler's `not dispatched:` prefix). It has no helpfulness triplet, so the evolved KB's top-L pruning never drops it (capped at 500 items, oldest first). At dispatch, prover and breaker briefs get a "Known Dead Ends (Do Not Repeat)" section (at most 10 items) with the refutations on the function, those of earlier prover dispatches of the same function read live from their scratch (`prover_candidates.refuted_clauses`), and the rejected requests on its callees (also read live from `strengthen_requests.json`). A refutation where the annotation evaluated an undefined term (`annotation_rte`) is worded as "guard it with `==>`", not as a false clause. `FRAMAC_SPEC_KB=off` disables it for A/B runs.

**Failure-kind repair strategy (SESpec Alg. 4 / InvWeaver).** `run_wp_function.py` maps each unproven loop goal to a repair strategy by its WP name: `_established` -> weaken (or add a `requires` holding at loop entry), `_preserved` -> adjust (inductiveness / `loop assigns`), failing both -> regenerate (invalid invariant; largest valid subset), provability-only -> strengthen, `loop_variant`/`decreases` -> fix the measure or add a progress guard. The hint is emitted with the WP report, and the prover brief's Step B states the same taxonomy. `prover_candidates.py` ranks candidates by `(failed, invalid, -proved)`: among equal failed counts, a candidate whose failures are only provability outranks one carrying invalid invariants.

---

## 6. Proof Audit (M3)

A function's proof-side units are `covered` only after audit:

- **Deterministic audit checks (implemented):**
  - `ledger.py audit-hypotheses --dag workspace/reports/callgraph_dag.json` (run at the end of every `pipeline_make.py run wp-sweep` and first in `report`) resolves `callee_contract_hypothesis` / `valid_under_hyp` assumptions against the callees' ledger units, transitively: a caller is discharged (`hypotheses_discharged` evidence) only when every callee is WP-covered with no open hypothesis of its own; otherwise it keeps one `callee_contract_hypothesis` naming the open callees.
  - **Verdict limits:** a passing verdict states what it covered, and a verdict that cannot does not count. `run_wp_function.py` writes `limits` into every report, `ledger.py ingest-wp` copies them onto the discharging evidence, `validate_artifacts.py` rejects discharging WP evidence without them, and `REPORT.md` lists what was not established.
    - `limits.vacuity`: after an `all_proven` result, a separate contract-only pass runs `-wp-smoke-tests`. A doomed `requires` (`contradictory`) turns the proof into `unsound_proof`. `consistent` means no prover refuted the contract within its timeout, not that it is satisfiable; `inconclusive` opens an assumption. Doomed dead-code and dead-call goals are only counted, because correct defensive code triggers them.
    - `limits.missing_spec_callees`: a called prototype with no contract fails the proof (Tier B), since WP would otherwise trust Frama-C's generated default.
    - `limits.classes_without_real_clause`: an L4-L6 class whose every clause holds whatever the function does (`\true`, `x == x`) is not credited. The check is syntactic, so a tautology it cannot see through (a predicate call, a quantifier) stays credited.
    - `limits.dynamic_oracle`: added by the parent re-check from the guardrail's `reach` (libFuzzer `-print_coverage`). A function no input reached is still merged, because WP alone can prove code the corpus misses, but the proof carries an open assumption. Batch merges measure reach too. `limits.guardrail_corpus` (`total`, `replayed`, `sampled`, `empty`) says what the guardrail replayed: promoted seeds and crash inputs always, the rest a deterministic sample; an empty corpus counts as not exercised.
  - `run_wp_function.py --smoke-tests` adds the raw smoke goals to a proof run, for inspection. It also fails on correct defensive branches, so it is not the gate.
  - Mechanical lexical checks (`acsl_ast.py` / `workspace_overlay.py check-acsl-only`) reject `admit`, `axiom`, `axiomatic`, `inductive`, vacuous `\false` clauses, and any non-ACSL token changes.
- **Entry-function rule (mechanical at merge):** on `untrusted_surface` entry functions, `requires` may only state memory shape (validity, separation, non-null for non-attacker pointers) and environment facts recorded as boundary assumptions. `acsl_ast.entry_requires_violations` checks it lexically in `merge-agent` and `merge-batch`; a value constraint on an attacker-controlled parameter or the bytes it points to rejects the merge (`trust-boundary check failed (untrusted_surface entry requires): ...`).
- **Unsound models:** a WP proof under a memory model with `cast` is never credited (`unsound_proof`), whoever chose the model.
- **Eva statuses:** `Inconsistent` or unrecognized Eva statuses are exported as `other_properties` and keep the unit open.
- **LLM auditor (planned roadmap):** a separate fresh LLM auditor agent for Layer 4-6 contracts and boundary-assumption plausibility.

---

## 7. Agents and Structured Results

Implemented roles in [`../schemas/agent-result.schema.json`](../schemas/agent-result.schema.json): `architect` (the header architect), `prover` (also used for `negotiate` tasks), `breaker`, `crash_verifier`, and `critic` (defined in the schema for the M4 coverage critic, with no brief or consumer yet; `recon` and a proof auditor remain on the M3/M4 roadmap). Each returns exactly one JSON object validated against [`../schemas/agent-result.schema.json`](../schemas/agent-result.schema.json). A malformed or prose-wrapped result is discarded, not repaired, and the task is rerun with a fresh agent if the budget allows.

- **Write isolation (M2, implemented):** each prover, breaker, or architect works in its own scratch overlay and returns an annotation-only patch plus evidence. The parent applies patches serially or in micro-batches (`merge-agent` / `merge-batch`), re-runs the kernel check, guardrail, and WP on the merged tree, and then commits. Breaker seeds are promoted from scratch into the shared corpus by the parent.
- **Annotation-only rule (M2, implemented):** after stripping ACSL comments, the C token stream of the work tree must equal the baseline. Confirmed findings carry remediation text and an optional separate fix patch that is never merged into the work tree.
- **Coverage critic (M4, planned roadmap):** a deterministic gap script (Eva-unreached code from `-metrics-eva-cover`, unstubbed external callees, units closed without evidence, recursion cycles broken arbitrarily, function-pointer calls) feeding a fresh LLM critic per phase.

---

## 8. Reconnaissance and Call Graph (M4)

- **Current implementation** (Phase 0; [`./phase0-implementation-plan.md`](./phase0-implementation-plan.md)):
  - **Build capture** (`build_capture.py`): the target's own build under `bear`, in the build image, from a recipe the user gave or confirmed. It gives link units, per-file flags, test units, the API (exports, public headers, `main`, an executable's embedded API) and a snapshot of the target's headers and libraries. A target that does not build stops with `needs_build_recipe`; there is no inventory without a build.
  - **Frama-C model** (`phase0_model.py` with `phase0_dump.ml`): one parse per distinct set of sources and flags. Functions are named as Eva and WP name them (`file#name`), with direct calls, indirect calls matched by signature against address-taken functions, thread spawns, callbacks, macro aliases, loops and cyclomatic complexity. Every fact carries its source. A unit Frama-C cannot parse gets GCC's `-fcallgraph-info` edges (`callgraph_source: gcc_callgraph`), flagged with Frama-C's first error. Alias narrowing of indirect edges is optional and off by default: it was measured and found unsound for reassigned global pointers.
  - **Trust** (`trust.py`): library API and functions reached from input readers are untrusted; the structured threat model (`schemas/threat_model.schema.json`) adds input sources and trusted callers. Optional CodeQL facts (`codeql_trust.py`, open-source targets only) can add untrusted marks, never remove one.
  - **DAG view** (`build_callgraph_dag.py`): link units as modules, Tarjan's SCC for recursion cycles, bottom-up waves, tiers from trust (`tiers.py`), and the split of units too large for one Eva run (`unit_split.py`).
- **Planned M4 roadmap:**
  - Parallel recon agents (entry surfaces and untrusted inputs; principals, authentication, and secret handling; build and harness feasibility) returning structured facts to override the baseline module table with source-backed reasons.
  - Eva-resolved function-pointer edges merged into the call graph after Phase 2. `run_eva_slice.py` reports them (`flows.call_edges`), but the DAG keeps the model's signature-matched edges.
  - A C/ACSL companion file giving each vulnerability class a hunting move, ACSL property pattern, and validation rules.

---

## 9. Profiles, Budget, Modes, Incremental Runs (M5)

| Profile | Scope |
|---|---|
| `quick` | Phases 0-2 + crash verification (60 CPU-s fuzz budget per harness case, at most 480 per link unit; 600 s prover wall budget); Tier 3 deferred (`scripts/tiers.py`): Make leaves out whole Tier 3 modules (no fuzzing or Eva for them), and the ledger seeds every Tier 3 function's units `deferred` (no WP). A Tier 3 function inside a module of a higher tier is still analysed by that module's fuzz and Eva runs, but Eva results on its deferred units are skipped, except an Invalid, which makes the unit a `candidate`; WP only on Tier 1A entry chains; remaining unscheduled WP units closed via `ledger.py close-remaining`. |
| `standard` | All phases on Tier 1A, 1B, and Tier 2 validators (120 CPU-s fuzz budget per harness case, at most 1200 per link unit; 900 s prover wall budget); the parent re-verifies changed finding records before reporting. |
| `deep` | Extended budgets (900 CPU-s fuzz budget per harness case, at most 7200 per link unit; 1800 s prover wall budget; higher retry limit `K`). Tier 3 `rte` units are scheduled in `standard` and `deep`, deferred only in `quick` (step I8). |

- Profiles change breadth, never the evidence bar.
- **Budget** (optional, in agent invocations or wall-clock budgets via `FRAMAC_PROVER_WALL_BUDGET_S`) bounds prover/breaker execution. Exhaustion sets `run_status: incomplete` with a reason.
- **Guidance mode (implemented):** focused requests ("help me prove this function", "why does WP fail here") use the relevant brief and tooling on a scratch copy with no run directory, ledger, or report. Full mode runs on an explicit pipeline request or when artifacts are requested.
- **Cross-run caching and carry-forward:** content-addressed shared caches (`/framac-cache`, populated by trusted `build`, `eva` and `ingest` steps; see [`./resources-and-caching.md`](./resources-and-caching.md#5-caches), Section 5) reuse E-ACSL builds, Eva reports and evolved fuzz corpora across `run-<N>` directories. WP proofs are not shared yet: the end-of-run `wp-sweep` runs without any proof cache and publishes nothing. Run-directory snapshot manifests (`run_metadata.py snapshot` / `validate_artifacts.py snapshot`) record cryptographic digests of prior run artifacts; full per-unit ledger carry-forward across runs remains on the M5 roadmap.

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
| **M4 Recon & Critics** | Partial (Phase 0 build capture, Frama-C call graph, trust and threat model implemented; recon agents and critics planned) | Implemented: build-derived inventory and link units, the Frama-C model's call graph with signature-matched indirect edges, trust from the build and the structured threat model. Planned: recon subagents and [`./architecture.md`](./architecture.md) overrides; Eva function-pointer edges in the DAG; C/ACSL companion file; per-phase coverage critic subagents. |
| **M5 Profiles, Caches & Carry-Forward** | Partial (profiles, guidance mode, shared caches & snapshots implemented; ledger carry-forward planned) | Implemented: `quick` / `standard` / `deep` profiles, Guidance Mode, content-addressed per-run and cross-run caches (`cache.py`), warm-start corpora, and snapshot manifests (`run_metadata.py snapshot`). Planned: automated per-unit ledger carry-forward across runs, and publishing swept WP proofs. |
