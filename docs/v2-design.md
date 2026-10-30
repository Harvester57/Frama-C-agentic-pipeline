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
2. **Inner resource layer** (`scripts/sandbox_exec.py`): every target-controlled binary (LibFuzzer campaigns, guardrail replays, reproducers, later target builds) runs with a cleared environment plus allowlist, rlimits on CPU, file size, open files, and processes (optional address space; core dumps disabled), and a wall-clock timeout that SIGKILLs the whole process group. Runs record `sandbox: "rlimits"`. This layer provides no filesystem or namespace isolation inside the container.

**Residual risk.** Target-controlled binaries can write anywhere in `/framac-run` that the container user can write, including `coverage-ledger.json`, `candidates.json`, and `findings.json`. Authoritative state is schema-validated and fingerprinted on phase transitions, so tampering surfaces as validation failure or fingerprint mismatch rather than silent corruption, but it is not prevented. This is acceptable for auditing non-adversarial production code; deliberately hostile targets are out of scope.

---

## 4. Verdict Model

| Verdict | Meaning | Severity |
|---|---|---|
| `confirmed` | A reproduced E-ACSL failure through the module harness, with the fault in target code and the harness respecting the entry function's declared or documented contract. | Yes |
| `needs_validation` | A specific, source-grounded fault hypothesis that could not be reproduced: Eva `Invalid` without a concrete witness, or a prover/breaker hypothesis (input condition + predicate + why it was not reproduced). Lists exact blockers and a validation plan. | No |
| `rejected` | A candidate disproved by verification: harness-induced crash, dead code, toolchain artifact, contract over-constraint mistaken for a bug. Retained so later runs do not repeat it. | No |

Rules:

- A WP stall is **not** a finding. It is a `blocked` ledger unit with its unproven goals, attempts, and the residual E-ACSL guard. It becomes a `needs_validation` candidate only when a concrete fault hypothesis is stated.
- `Invalid_but_dead` Eva statuses are dead-code evidence, never a candidate.
- **Reachability** is a recorded field: `untrusted_surface` (the harness entry corresponds to an untrusted input surface identified by reconnaissance) or `internal_api`. It caps severity.
- **Severity anchors** (confirmed only, never above the demonstrated effect):
  - `critical`: untrusted_surface + out-of-bounds write / control-flow corruption, or Layer 4 authentication bypass.
  - `high`: untrusted_surface out-of-bounds read of secrets, Layer 6 secret leak, Layer 5 injection into a security-relevant sink.
  - `medium`: untrusted_surface DoS / non-termination, or internal_api memory corruption.
  - `low`: internal_api read or UB with no shown effect.
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

---

## 6. Proof Audit (M3)

A function's proof-side units are `covered` only after audit:

- **Deterministic audit script**: no unexplained `Valid_under_hyp`; `-wp-smoke-tests` clean (no vacuous preconditions or dead branches); every added `requires` either proven at all verified call sites or recorded as an assumption; no axioms or admits introduced by agents; the contract diff against the last locked version shows no weakened security clause.
- **Entry-function rule**: on `untrusted_surface` entry functions, `requires` may only state memory shape (validity, separation, non-null for non-attacker pointers) and environment facts recorded as boundary assumptions. Any value constraint on attacker-controlled bytes or lengths fails the audit and the unit becomes `blocked`.
- **LLM auditor** (fresh agent) only for Layer 4-6 contracts and the plausibility of boundary assumptions.

---

## 7. Agents and Structured Results

Roles: recon, header architect, prover, breaker, crash verifier, proof auditor, coverage critic. Each returns exactly one JSON object validated against `schemas/agent-result.schema.json`. A malformed or prose-wrapped result is discarded, not repaired, and the task is rerun with a fresh agent if the budget allows.

- **Write isolation (M2)**: each prover, breaker, or architect works in its own scratch overlay and returns an annotation-only patch plus evidence. The parent applies patches serially, re-runs the kernel check, guardrail, and WP on the merged tree, and then commits. Breaker seeds are promoted from scratch into the shared corpus by the parent.
- **Annotation-only rule (M2)**: after stripping ACSL comments, the C token stream of the work tree must equal the baseline. Confirmed findings carry remediation text and an optional separate fix patch that is never merged into the work tree.
- **Coverage critic (M4)**: a deterministic gap script (Eva-unreached code from `-metrics-eva-cover`, unstubbed external callees, units closed without evidence, recursion cycles broken arbitrarily, function-pointer calls) feeds one fresh LLM critic per phase. The critic returns missing units and reassignments; the parent accepts or rejects them.

---

## 8. Reconnaissance and Call Graph (M4)

- Parallel recon agents (entry surfaces and untrusted inputs; principals, authentication, and secret handling; build and harness feasibility) return structured facts. The parent writes a capped `architecture.md` and a module table (entry functions, input shape, tier, assigned L3-L6 classes, reachability) that overrides the regex baseline. Each override records a source-backed reason.
- The Frama-C kernel call graph, built from the AST parsed with `compile_commands.json` flags, is authoritative. Eva-resolved function-pointer edges are merged after Phase 2. The regex script remains only as a fallback, and units derived from it are flagged in the ledger.
- A C/ACSL companion file (adapted from security-audit's memory-safety classes plus Layers 2-6) gives each class a hunting move (breakers, recon), an ACSL property pattern (provers, architects), and validation rules (verifiers). Ledger units record which blocks were selected or excluded and why; prompts copy blocks verbatim.

---

## 9. Profiles, Budget, Modes, Incremental Runs (M5)

| Profile | Scope |
|---|---|
| `quick` | Phases 0-2 + crash verification; WP only on Tier 1A entry chains; one critic pass; merged verifier/auditor. |
| `standard` | All phases; a critic per phase; separate crash verifier and proof auditor. |
| `deep` | More fuzz time and a higher retry limit K; Tier 3 `rte` units assigned instead of deferred; final-clean critic; second auditor on L4-L6. |

- Profiles change breadth, never the evidence bar.
- **Budget** (optional, in agent invocations) reserves critic and verifier/auditor calls before any prover or breaker is launched. Exhaustion sets `run_status: incomplete` with a reason.
- **Guidance mode**: focused requests ("help me prove this function", "why does WP fail here") use the relevant brief and tooling on a scratch copy with no run directory, ledger, or report. Full mode only on an explicit pipeline request or when artifacts are requested.
- **Carry-forward** across `run-<N>`: each unit stores hashes of its preprocessed body, its own contract, the callee contracts it relies on, the stubs it uses, and toolchain versions. A prior `covered` unit carries forward only on a full match plus a cheap WP replay. The replay is cheap because the trusted end-of-run `wp-sweep` fills the shared proof cache; see `docs/resources-and-caching.md`, Section 5. Prior `confirmed` findings re-run their reproducer. Prior `needs_validation`, `deferred`, and `blocked` units become current work. A prior `rejected` record suppresses only the identical fingerprint.

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

| Milestone | Content |
|---|---|
| **M1 Foundation** | Run directory outside the target; hardened wrappers + `sandbox_exec.py` resource layer (rlimits, env allowlist, timeout); findings, candidates, ledger, metadata, and agent-result schemas; stdlib-only validators with pytest; fingerprints; status-classification fixes (fuzz outcomes, guardrail RTE vs contract, Eva dead/assumed buckets, CSV column normalization); ledger seeding and phase ingestion; report and SARIF derived from findings + ledger. |
| **M2 Verification & Isolation** | Crash verifier brief (`crash_verifier_brief.md`) + gate (`ledger.py ingest-verifier` & `ingest-agent-hypothesis`); per-agent scratch overlays (`workspace_overlay.py init-agent`) and structural function-span patch merge + re-verification (`merge-agent`); safe artifact/seed/crash promotion (`promote_artifact.py`); lexical pure-ACSL annotation-only check (`acsl_ast.py`); harness legitimacy (exact-size `malloc(size)` + `size == 0` sentinel buffers and `harness_<mod>.json` sidecars). |
| M3 | Deterministic proof audit, `-wp-smoke-tests`, entry-function `requires` rule, assumption resolution, LLM auditor for L4-L6. |
| M4 | Recon agents and `architecture.md`; Frama-C call graph; C/ACSL companion file; coverage critic. |
| M5 | Profiles and budget; hash-gated carry-forward; guidance mode. |
