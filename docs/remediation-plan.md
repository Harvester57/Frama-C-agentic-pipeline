# Remediation Plan: Workflow Coherency Audit (2026-11-07)

This plan comes from a read-only coherency audit of the skills, briefs, Make layer, scripts, wrappers and docs. Each defect has an ID, a class, a priority and a remediation. Priorities:

- **P0 Critical**: the pipeline can credit a unit as `covered` (or as unconditionally proven) without the evidence that claim implies. This breaks the evidence discipline of `docs/v2-design.md`.
- **P1 High**: a path where the workflow cannot terminate correctly, loops, loses findings, or weakens isolation.
- **P2 Medium**: silent degradation, or an instruction that does not match the code.
- **P3 Low**: documentation drift.

Classes: `soundness` (overstated assurance), `workflow` (termination, resume, loops), `recall` (findings lost), `isolation`, `degradation` (a feature silently does less), `doc` (drift).

---

## P0 Critical

| ID | Class | Defect | Remediation | Status |
|---|---|---|---|---|
| C1 | soundness | `ledger.py audit-hypotheses` checks callees one level deep: a callee that is `covered` but itself conditional (open `callee_contract_hypothesis` / `valid_under_hyp`) counts as proven, so a caller above a blocked leaf is reported unconditional. | Treat a callee as proven only when it is `covered` with WP evidence **and** carries no open hypothesis assumption; iterate to a fixpoint so conditionality propagates up the call graph (cycles stay conditional). | Fixed |
| C2 | soundness | `report` does not run `audit-hypotheses` (contrary to `framac-wp` SKILL and `v2-design.md` §6); `wp-sweep` runs it only when some unit already has a hypothesis, so speculative callers can keep a stale status. | Run `audit-hypotheses` in the `report` target before validation, and unconditionally at the end of `wp-sweep`. | Fixed |
| C3 | soundness | A prover can pass `--wp-model Typed+cast` (the unsound model per the WP manual) to `run_wp_function.py`; `infer_prover_wp_flags` carries it into the parent re-check and the sweep, and `ingest-wp` credits the proof. | `run_wp_function.py` records an unsound model as a Tier-B soundness issue (so `all_proven` becomes `unsound_proof`); `infer_prover_wp_flags` never propagates a `cast` model; `ingest-wp` refuses to credit a report whose model contains `cast`. | Fixed |
| C4 | soundness | Eva properties whose status is `Inconsistent`, or any status string not in `framac_common._STATUS_MAP`, fall into an unexported `Other` bucket while the function still counts as having properties, so `ingest` marks it `covered`. | Export the bucket (`other_properties`, `other_count`) in the Eva report and keep a function with any such property `planned` with explicit evidence. | Fixed |
| C5 | soundness | `wp-sweep` backstop holes: an `analysis_error` / `acsl_syntax_error` re-proof leaves the unit `covered`; sweep rows that are missing are not ingested. | A trusted re-proof that cannot run downgrades the unit to `blocked` (`sweep_reproof_failed`); missing sweep rows are reported as regressions. | Fixed |

## P1 High

| ID | Class | Defect | Remediation |
|---|---|---|---|
| H1 | workflow | In the `quick` profile the scheduler only creates prove tasks for the Tier 1A entry chain, but `_is_done` requires no `planned` units, so Phase 3 ends `stuck`. | When the profile is `quick`, have `wp_scheduler.py` close off-chain planned units as `deferred` (`quick_profile_wp_not_scheduled`) at `init`/`_sync`; align `framac-verify` SKILL. |
| H2 | workflow | A Phase 3 crash (breaker, reproduced hypothesis) can never be `confirmed`: `ingest-verifier` needs a parent replay report, but replay only runs in Phase 2 and the verifier's `attempt_*.json` is never passed. | On `complete` of a verifier for a candidate without a replay report, run `run_eacsl_fuzz.py replay-candidates` for that fingerprint (parent-side, sandboxed) before `ingest-verifier`; fix the brief. |
| H3 | workflow | The prover brief prescribes `blocked` with `unproven_goals: []` for `code_fault` / repeated `analysis_error`, but `validate_artifacts.py` requires a non-empty list for any non-`all_proven` result, so those results are discarded and the task ends `invalid_result`. | Allow an empty list when `blocked` carries `code_fault`, `analysis_error` or `proof_gap`; align brief example. |
| H4 | workflow | Regenerating a harness rewrites `repair_attempts: 0`, so the 2-repair cap never triggers. | `generate_harness.py` preserves `repair_attempts` / `repair_history` from an existing sidecar. |
| H5 | workflow | Resume is broken: Setup runs `run_metadata.py init` before the resume check (init refuses an existing run); no command writes `phase_done` 2/3; slice Step 5 runs `checkpoint.py init` unconditionally and rewinds progress. | Reorder Setup; add `checkpoint.py save-phase` calls (or Make hooks) after ingest and after the scheduler reports `done`; guard `checkpoint init` like Make's `seed`. |
| H6 | workflow | `wp_scheduler.py baseline` (Make `wp-baseline`, undocumented) closes every prove task it attempts as `done` regardless of WP result. | Close only `all_proven` tasks; leave others `pending` for a prover; document or remove the target. |
| H7 | recall | Eva `Invalid` alarms in deferred / unseeded functions are dropped at ingest; fuzz crashes in the same functions are kept. | Mirror the fuzz path: link deferred units, create unlinked candidates otherwise. |
| H8 | recall | A guardrail `code_fault` never becomes a candidate; `boundary_assumptions` (prover, architect) and `suggested_requires` (breaker) are never read. | Ingest `code_fault` as a candidate with the guardrail report as reproducer source; record boundary assumptions on the units the proof credits. |
| H9 | soundness | The dual-oracle guardrail is weaker than documented: only the first 64 corpus files by name are replayed (promoted `seed-*` sort last); the normal merge path passes `module=None`, so reach is never measured and `limits.dynamic_oracle` never recorded; no mechanical trust-boundary check of `requires` on `untrusted_surface` entries. | Sample the corpus deterministically including seeds; pass module/sources on merge so reach is measured; add a lexical check rejecting value constraints on attacker-controlled parameters in entry-function `requires`. |
| H10 | isolation | `pipeline_make.py run minimize` is classed static though it runs target code (`resources.py` `_DYNAMIC_MAKE_TARGETS`). | Add `minimize` to the dynamic targets. |

## P2 Medium

| ID | Class | Defect | Remediation |
|---|---|---|---|
| M1 | degradation | Auto-dictionary described in `framac-fuzz` SKILL (and `--no-auto-dict`) is not implemented. | Implement in `run_eacsl_fuzz.py campaign`, or remove from the skill. |
| M2 | degradation | Eva tuning is lost: `eva-<mod>` does not reproduce the per-obligation combination; a stale settings digest silently falls back to base; `run eva`, `module-<mod>` and `flamegraph-<mod>` overwrite the combined report. | Make `eva-<mod>` replay `eva-tune` when a current decision exists; warn on stale digest; decouple `flamegraph-<mod>` from `eva-%`. |
| M3 | recall | Fuzz and Eva fingerprints can disagree on the alarm kind (`normalize_kind` scans the predicate before the label). | Prefer the label kind when present on both sides. |
| M4 | degradation | Skill command lines miss the rw-cache allowlist (`run ingest replay wp-queue`) or use `$S`. | Split the commands as in `framac-verify`; replace `$S`. |
| M5 | degradation | `FRAMAC_FRAME_SKELETON`, `FRAMAC_LOOP_TEMPLATES`, `FRAMAC_SPEC_KB` are not forwarded by either wrapper. | Add to both knob lists. |
| M6 | isolation | The PowerShell wrapper and docker-compose run the container as root; the POSIX wrapper sets `--user`. | Set `--user` on Linux hosts in PS1 and in compose. |
| M7 | doc | Quick-profile prover wall budget: brief 300 s, scheduler 600 s. | Use one constant. |
| M8 | doc | Gate granularity: call-cone gating only applies to modules without a sidecar; exhausted repairs block only linked units. | Align SKILL text (or implement cone gating). |
| M9 | workflow | Final record re-verification (standard/deep) is described but not implemented. | Add a scheduler step or remove the claim. |
| M10 | soundness | `covered` from a pre-repair harness survives a repair that widens reached contexts. | On `refresh --module`, re-plan Eva-covered units of the module. |
| M11 | degradation | `docs/references` is not in the image (mounted only by wrappers). | Copy into the image. |
| M12 | degradation | The Eva guidance command omits `--no-warn-unsigned-downcast`. | Add the flag to the skill. |
| M13 | doc | `wp-sweep` is said to feed the shared proof cache; it runs with `--cache-dir off`. | Fix the docs or publish swept proofs. |
| M14 | doc | Tamper-evidence via fingerprints (`v2-design.md` §3) is not implemented. | Recompute fingerprints in `validate_artifacts.py`, or reword. |
| M15 | soundness | `export-diff` copies unproven headers into the "verified" contracts output. | Copy only headers whose contracts back covered units, or rename the output. |

## P3 Low (documentation drift)

- Agent cap: "capped by `FRAMAC_MAX_AGENTS` (16)" — the default is 16/32/64 by CPU count, and the env var replaces it.
- Skill argument hints with no command behind them: `framac-wp` `--max-retries`, `--function`; `framac-verify` `--module`, `--fuzz-time`, `--max-agents`.
- K is 2/4/6 by profile; breakers spawn on any non-proven result.
- Role names in `v2-design.md` (`header_architect`, `coverage_critic`) vs schema (`architect`, `critic`).
- `agentic-swarm.md` negotiation flow (caller-driven) vs implementation (parent-driven).
- `eva-tune` under quick: Eva SKILL says skip, `framac-verify` runs it, the code does not gate.
- Fuzz status `insufficient_memory` is undocumented.
- Every Make Eva-covered unit gets a misleading "recursive or missing assigns" assumption text because `-no-warn-unsigned-downcast` counts as a reduced check.
- README lists 5 schemas (6 exist), omits `python-*` skills, describes skill mirrors as symlinks (the working tree now has copies, which `tests/test_extract_references.py` rejects).
- `architecture.md` mentions `phase0..3.json` checkpoint files.
- `docker-compose.yml` sets no `FRAMAC_RUN_ID`, so `run_metadata.py init` rejects its run directory name.
- Unused Make variable `PROFILE`; `_node_deps("wp-queue")` omits `facts`.

---

## Order of work

1. P0 (C1–C5) — done in this change, with tests.
2. P1 workflow blockers H1–H6 (each independent; H2 and H3 touch `wp_scheduler.py` / `validate_artifacts.py`).
3. P1 recall and isolation H7–H10.
4. P2, then a single doc pass for P3.
