# Tier 1: Dead-End & Obstruction Ledger

Self-contained implementation plan. Parent document: [`../formal-discovery-plan.md`](../formal-discovery-plan.md) (Section 3, Tier 1). Independent of every other tier.

## Goal

Provers and breakers today never learn which clauses were already refuted on this function or which strengthening requests on their callees already failed. Record both kinds of dead end from artifacts that already exist in the run directory, and render them into the agent brief as a short "do not repeat" list. The paper's analogue is the wiki's `ideas/` notes labelled *dead-end* with their concrete obstruction (Shirobokov et al., Appendix C).

Everything is gated by the existing `FRAMAC_SPEC_KB` switch (`spec_kb.enabled()`), so no new environment flag is needed.

## Facts the implementer must know (verified 2026-11-09)

- **Guardrail refutations.** `scripts/run_eacsl_fuzz.py` returns, for a refuted candidate, a dict with `status: "rejected_overconstrained"`, a `reason` string, and `failure`: the dict `parse_eacsl_failure` builds, with keys `file`, `line`, `function`, `kind`, `alarm_kind`, `is_rte`, `label`, `predicate`, and optionally `annotation_rte: true` (the annotation evaluated an undefined term; this is *not* a false clause). `status: "code_fault"` means an RTE check failed on a real input (a code defect candidate, never evidence against the contract).
- **Where candidate reports live.** `scripts/prover_candidates.py` stores each oracle run under `agents/<id>/scratch/candidates/c<n>/guard_<fn>.json` and `wp_<fn>.json` (`_report_name`, `CANDIDATES_DIR`), and the state in `agents/<id>/scratch/candidates/state.json` (`STATE_FILE`, `SCHEMA_VERSION = 1`). `_oracle_summary("guardrail", report)` keeps only `{"status": ...}`. `GUARDRAIL_REFUTATIONS = {"rejected_overconstrained", "code_fault"}`.
- **Strengthening requests.** `workspace/reports/strengthen_requests.json` (`scripts/contract_negotiator.py`) holds `{"requests": [...]}`; each request has `id`, `status` (`pending`, `verified_and_applied`, `rejected_by_callee`), `caller_function`, `callee_function`, `callee_file`, `header_file`, `needed_clause`, `reason`, `resolution_note`. The scheduler (`scripts/wp_scheduler.py`, `_emit_negotiations`) writes `rejected_by_callee` with a `resolution_note` starting with `not dispatched:` for structural reasons (callee not found, self-request, callee has a candidate unit or is `shell_unverifiable_wp`, caps reached). Only `_resolve_negotiation` writes a `rejected_by_callee` that means the negotiating prover tried and could not prove the clause; its note is the prover's own text.
- **Spec KB.** `scripts/spec_kb.py`: `enabled()`, `KB_SENTINEL = "<!-- spec-kb -->"`, `KB_SCHEMA = 1`, `kb_dir_of(overlay) -> <overlay>/reports/kb`, `mine_run(run_dir, kb_path=None, top_l=50)` (CLI `spec_kb.py mine --run-dir D [--out F]`), `kb_section_for(overlay, record)`. `mine_run` prunes `evolved.json` to the top-L items by `helpful - harmful`; obstruction items have no triplet and must therefore live in their own file.
- **Brief rendering.** `scripts/workspace_overlay.py::prepare_agent(run_dir, agent_id, role, ..., function, c_file, module, wp_report, requests)`; roles are `architect`, `prover`, `breaker`, `verifier`. For `role == "prover"` it computes `kb_section = spec_kb.kb_section_for(overlay, record)` with `record = _load_function_facts(overlay, module, norm_c_file, function)` and then does `rendered.replace(spec_kb.KB_SENTINEL + "\n\n", kb_section and kb_section + "\n")`. The sentinel exists in `skills/framac-wp/prover_brief.md` (line 22) but **not** in `skills/framac-wp/breaker_brief.md`.
- **Callees of a function.** The scheduler computes `task["callees"]` (keys `file#fn`) in `_compute_deps`, but `prepare_agent` does not receive them. The callgraph DAG at `<overlay>/reports/callgraph_dag.json` has `functions[<key>]` records with `internal_callees` / `direct_callees` / `callees` (see `ledger.cmd_audit_hypotheses` for the resolution rules); `dag_function_record(dag_fns, function, norm_c_file)` already returns the function's record inside `prepare_agent`.

## Changes

### 1. `scripts/prover_candidates.py`

- `_oracle_summary(oracle, report)`: for `oracle == "guardrail"`, return `{"status": ..., "reason": report.get("reason"), "failure": <failure dict or None>}` when `report.get("status") in GUARDRAIL_REFUTATIONS`; otherwise keep `{"status": ...}`. Keep only the keys `function`, `line`, `kind`, `label`, `predicate`, `annotation_rte`, `is_rte` of `failure` (drop `file` paths to keep `state.json` small). No schema bump: readers use `.get`.
- New `refuted_clauses(scratch: Path) -> list[dict]`: walk `state["candidates"]`, collect every guardrail summary with `status == "rejected_overconstrained"` and a `failure` with a non-empty `predicate`; return one item per distinct `(predicate, annotation_rte)` as `{"predicate", "label", "line", "kind", "annotation_rte", "candidate": <id>}`, sorted by candidate id. Fall back to reading `candidates/c<n>/guard_<fn>.json` when a summary predates this change (no `failure` key). Never raise on a malformed state (return `[]`).
- Expose it in `status(scratch)` as `"refuted_clauses": refuted_clauses(scratch)`.

### 2. `scripts/spec_kb.py`

- New constants: `OBSTRUCTIONS_FILE = "obstructions.json"`, `OBSTRUCTION_SCHEMA = 1`, `MAX_OBSTRUCTIONS_RENDERED = 10`, `STRUCTURAL_REJECTION_PREFIX = "not dispatched:"`.
- New `mine_obstructions(run_dir: Path, out_path: Path | None = None) -> dict`, called at the end of `mine_run` (same CLI entry point, no new hook). Output `<overlay>/reports/kb/obstructions.json`:

  ```json
  {"schema": 1, "updated_at": "...", "items": [
    {"id": "guard:<function>:<sha1(predicate)[:12]>", "kind": "guardrail_refutation",
     "function": "...", "file": "...", "predicate": "...", "label": "...", "line": 12,
     "annotation_rte": false, "source": "<agent_id>", "candidate": 3, "seen": 2},
    {"id": "req:<request id>", "kind": "rejected_strengthening",
     "callee_function": "...", "callee_file": "...", "caller_function": "...",
     "needed_clause": "...", "resolution_note": "...", "source": "<request id>", "seen": 1}
  ]}
  ```

  Sources: (a) every `agents/*/scratch/candidates/c*/guard_*.json` with `status == "rejected_overconstrained"` and a `failure.predicate` (resolve `function` from the report's `failure.function`, else from the agent's `.prover_budget.json` `function`; `file` from the budget's `file`); (b) every request in `workspace/reports/strengthen_requests.json` with `status == "rejected_by_callee"` whose `resolution_note` does **not** start with `STRUCTURAL_REJECTION_PREFIX`. Merge by `id`, incrementing `seen`. Items are never pruned by helpfulness; cap the file at 500 items, oldest dropped. Never raise on a malformed run dir.
- New `obstructions_for(overlay: Path, function: str | None, callees: list[str] | None) -> list[dict]`: load `obstructions.json`; return guardrail items whose `function == function` plus rejected-strengthening items whose `callee_function` is in `callees` (plain names; compare on the name after `#` when a key is given). Order: guardrail items first (most recent candidate first), then requests. Cap at `MAX_OBSTRUCTIONS_RENDERED`.
- New `obstructions_section_for(overlay: Path, function: str | None, callees: list[str] | None) -> str`: `""` when disabled or nothing matches; otherwise

  ```
  ## Known Dead Ends (Do Not Repeat)

  Clauses below were refuted on real inputs or rejected by their callee in this run. Do not write them again; if you believe one is needed, say so in `unproven_goals` instead.

  - `<predicate>` (line N, label `L`): failed under E-ACSL on a corpus input (candidate 3 of agent a-12).
  - `<predicate>`: evaluated an undefined term at runtime (guard it with `==>`), not a false clause.
  - Callee `parse_hdr`: `ensures \result <= 64` was requested by `read_pkt` and could not be proven ("<resolution_note[:160]>").
  ```

  Mark `annotation_rte` items with the second wording: they are not refutations and the prover should guard the term instead of dropping the clause.

### 3. `scripts/workspace_overlay.py`

- In `prepare_agent`, after `kb_section` is computed for provers, and also for `role == "breaker"`: compute `callees` from `fn_meta` (`internal_callees` or `direct_callees` or `callees`, names after `#`), then `kb_section += spec_kb.obstructions_section_for(overlay, function, callees)` when `spec_kb.enabled()`. For breakers `kb_section` was never set before: initialise it to `""` for every role.
- Add the line `<!-- spec-kb -->` to `skills/framac-wp/breaker_brief.md` where the breaker's context section ends (right before its first numbered rule), so the same `replace` call works for both roles. Keep the sentinel on its own line followed by a blank line, as in the prover brief.
- Also pass the current agent's own `refuted_clauses` (from `prover_candidates.status(agent_root / "scratch")`) into the same section when the prover is re-dispatched into an existing scratch (`dispatches > 1`); first dispatch has none.

### 4. Skill text

- `skills/framac-wp/prover_brief.md`: one sentence under the KB paragraph (near the sentinel): "A `Known Dead Ends` section, when present, lists clauses already refuted on this function or rejected by a callee; never re-add them."
- `skills/framac-wp/breaker_brief.md`: same sentence; the breaker uses refuted clauses as hints for inputs that violate the current contract.
- Do not edit `.agents/skills` or `.claude/skills` (gitignored mirrors).

### 5. Docs

- `docs/v2-design.md`, the "Specification knowledge base" paragraph (around line 132): add the obstruction store and what it feeds.
- `docs/agentic-swarm.md` Section 3: note that rejected strengthening requests are surfaced to later callers.
- `docs/backlog.md`: tick the item.

## Tests (`-n auto`)

- `tests/test_prover_candidates.py`: a `rejected_overconstrained` guardrail report with a `failure` keeps `reason` and the trimmed `failure` in `state.json`; `refuted_clauses` deduplicates by predicate, ignores `code_fault`, and returns `[]` on a missing or malformed state.
- `tests/test_spec_kb.py`: `mine_obstructions` on a synthetic run dir (two agents, one refutation each on the same predicate → one item with `seen == 2`; one `code_fault` ignored; one `annotation_rte` kept and marked) and a `strengthen_requests.json` with one structural rejection (`not dispatched: ...`, excluded) and one real rejection (kept). `obstructions_for` filters by function and by callee name; cap respected. `obstructions_section_for` returns `""` with `FRAMAC_SPEC_KB=off` (monkeypatch env) and renders both wordings.
- `tests/test_workspace_overlay.py`: `prepare_agent` for a prover and for a breaker renders the section when `obstructions.json` matches, and leaves no sentinel text behind in either brief; nothing is rendered when the store is absent.
- Existing tests must stay green; `mine_run`'s evolved-KB behaviour is unchanged.

## Verification

```powershell
$env:PYTHONIOENCODING="utf-8"
python -m pytest tests/test_prover_candidates.py tests/test_spec_kb.py tests/test_workspace_overlay.py -n auto
python -m pytest tests -n auto
python -m ruff check scripts tests
python -m mypy scripts tests
```

Acceptance on a target run: after `spec_kb.py mine --run-dir .`, `workspace/reports/kb/obstructions.json` exists, and a re-dispatched prover's `agents/<id>/brief.md` contains `## Known Dead Ends` listing its earlier refuted clause. Compare a benchmark run against the previous baseline with `benchmark.py compare <baseline> <run.json>`; no `regression` rows.

## Out of scope

Changing how `mine_run` scores repair items; any scheduler change; cross-run persistence of obstructions (a later tier may publish them to the shared cache).
## Implementation notes (2026-11-09)

Plan facts that turned out wrong when checked against the code, and what was done instead:

- **Re-dispatch never reuses a scratch.** `wp_scheduler._assign_agent` gives every dispatch a fresh agent id (`prove-<slug>-<n>`) and never reuses an `agents/<id>/` directory, so "the prover's own `refuted_clauses` when `dispatches > 1`" would always be empty. `prepare_agent` instead collects `refuted_clauses` from every other agent whose `.prover_budget.json` names the same function and file (`_earlier_refutations`) and passes them to `obstructions_section_for(..., extra=...)`.
- **Nothing runs `spec_kb.py mine`.** No script, Make target or skill calls `mine_run`, so `obstructions.json` (like `evolved.json`) is only written by hand. `obstructions_for` therefore also reads rejected requests live from `<overlay>/reports/strengthen_requests.json`. Recorded as an open pipeline bug in `docs/troubleshooting.md` Section 5.
- **`load_json_optional` raises on a malformed file**, so the "never raises" functions use their own quiet loader.
- An `annotation_rte` item and a false-clause item with the same predicate text are different lessons, so the guard item id carries a `:rte` suffix for the former; `seen` counts distinct sources (agents or requests), so re-mining the same run does not inflate it.
