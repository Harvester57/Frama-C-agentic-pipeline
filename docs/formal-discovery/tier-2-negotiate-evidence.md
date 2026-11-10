# Tier 2: Evidence in the Negotiate Brief

Self-contained implementation plan. Parent document: [`../formal-discovery-plan.md`](../formal-discovery-plan.md) (Section 3, Tier 2). Independent of every other tier.

## Goal

When a caller's proof stalls on a callee's contract, the scheduler dispatches a `negotiate` task to a prover on the callee. That prover today receives only the raw strengthening requests. Give it the evidence the paper's conference critiques carry (Shirobokov et al., Fig. S5: the exact seam that fails): the caller's unproven goals at the call site and the callee's own candidate history. No scheduler state-machine change; no change to when `negotiate` is dispatched.

New A/B switch: `FRAMAC_NEGOTIATE_EVIDENCE` (`off` disables the extra sections; default on).

## Facts the implementer must know (verified 2026-11-09)

- `scripts/wp_scheduler.py`:
  - `_prepare_kwargs(task)` for `kind == "negotiate"` returns `{"module", "function", "c_file", "header_file", "requests": [<request dicts>]}`; `requests` are looked up by id from `_requests()` (the strengthening ledger). `task["callers"]` holds the caller task ids (`prove:<file>#<fn>`).
  - A breaker task carries `task["wp_report"]`, the stalled prover's promoted WP report (`agents/<id>/artifacts/wp_<fn>.json`, set in `_ensure_breaker` from `_promote_agent_wp`). Prove tasks keep `task["parent_wp_report"]` after a merge; a stalled prove task has no promoted report path stored on it, but `_promote_agent_wp` writes `agents/<agent_id>/artifacts/wp_<fn>.json` and the canonical `workspace/reports/wp/<fn>.json` may be stale.
  - `_describe(task)` renders `requests` and `callers` for `negotiate` tasks in `--prepare` / `status` output.
  - Dispatch calls `DEPS.prepare_agent(Path.cwd(), task["agent_id"], ROLE_BY_KIND[task["kind"]], **_prepare_kwargs(task))` (around line 2301). Extra kwargs must be accepted by `workspace_overlay.prepare_agent`.
- `scripts/workspace_overlay.py::prepare_agent(..., wp_report=None, requests=None)` appends, when `requests` is non-empty, a section `## Contract Negotiation Requests` with instructions and `json.dumps(requests, indent=2)`. The CLI `prepare-agent` accepts `--request-id` (repeatable) and resolves ids against `workspace/reports/strengthen_requests.json`.
- WP report shape (`scripts/run_wp_function.py`): top-level `function`, `file`, `status`, `proven_count`, `proven_under_hyp_count`, `unproven_count`, `unproven_goals: [{"file","function","line","kind","status","annotation", "diagnostic_bucket", ...}]`. Goals at a call site of callee `g` have `annotation` naming the callee's property instance (WP names them like `typed_<caller>_call_<g>_pre` / `..._requires` for preconditions; postcondition uses of the callee appear as hypotheses of the caller's own `ensures` goals, so those stay unproven under `step_c_contract_postcondition`). `diagnostic_bucket` is one of `step_a_assigns`, `step_b_loop_invariant`, `step_c_rte_obligation`, `step_c_caller_precondition`, `step_c_contract_postcondition`.
- Candidate history of the callee: `prover_candidates.status(scratch)` returns `{"agent_id","function","iterations","best","best_rank","highest_proved","history":[...]}` for `agents/<id>/scratch`. The callee's last prover agent id is on its prove task (`task["agent_id"]` of `prove:<file>#<callee>` after completion, or its `history`/`dispatch` records; use whatever field the scheduler keeps for the last assigned agent, falling back to scanning `agents/*/scratch/.prover_budget.json` for `function == callee`).

## Changes

### 1. `scripts/wp_scheduler.py`

- New helper `_caller_evidence(state, task) -> list[dict]` for a `negotiate` task: for each caller id in `task["callers"]`, locate the caller's most recent WP report in this order: the caller task's `wp_report` if set, else `agents/<caller agent_id>/artifacts/wp_<caller fn>.json`, else `workspace/reports/wp/<caller fn>.json`. Load it with `_load_report`; keep goals where `diagnostic_bucket in ("step_c_caller_precondition", "step_c_contract_postcondition")` or whose `annotation` contains the callee name. Return
  `[{"caller": "<fn>", "caller_file": "<file>", "report": "<path>", "goals": [{"line","kind","status","annotation","diagnostic_bucket"}, ...]}]`, at most 12 goals per caller.
- New helper `_callee_history(task) -> dict | None`: find the callee's last prover scratch and return `prover_candidates.status(scratch)` trimmed to `{"agent_id","iterations","best_rank","highest_proved","last_wp_status","last_guardrail_status"}` (the last two from the final `history` entries). `None` when no scratch exists.
- `_prepare_kwargs` for `negotiate` adds `"caller_evidence": _caller_evidence(...)` and `"callee_history": _callee_history(...)` when `os.environ.get("FRAMAC_NEGOTIATE_EVIDENCE", "on").lower() != "off"`.
- `_describe` for `negotiate` adds `"caller_evidence_goals": <total goal count>` so `status` output shows the evidence was found.
- Keep `_prepare_kwargs` tolerant: evidence collection must never raise (wrap in `_try` or catch and record in `out["errors"]`), and a missing report yields an entry with `"goals": []` and `"report": None`.

### 2. `scripts/workspace_overlay.py`

- `prepare_agent(..., requests=None, caller_evidence: list[dict] | None = None, callee_history: dict | None = None)`.
- Extend the `## Contract Negotiation Requests` section. After the JSON block, when `caller_evidence` is non-empty, append:

  ```
  ### Why the callers stalled (seam evidence)

  - `read_pkt` (`src/pkt.c`, report `agents/a-7/artifacts/wp_read_pkt.json`):
    - line 88, `requires` instance of `parse_hdr`: Unknown (`step_c_caller_precondition`)
    - line 102, ensures `len_ok`: Unknown (`step_c_contract_postcondition`)
  ```

  and, when `callee_history` is present:

  ```
  ### Your function's previous prover run

  Agent `a-3` ran 4 iterations; best rank: failed 1, proved 17, invalid 0; last WP status `unproven_goals_remain`, last guardrail `passed_dynamic_oracle`. Its scratch is read-only to you; do not copy clauses the guardrail refuted.
  ```

  Then one instruction sentence: "Prove the requested clauses first; if a requested clause is exactly what the caller's goal needs but cannot hold, say which caller goal would remain open."
- CLI: add `--caller-evidence-json <path>` and `--callee-history-json <path>` (optional) to `prepare-agent` so a human can reproduce a brief; the scheduler passes Python objects directly.

### 3. Flag plumbing

`FRAMAC_NEGOTIATE_EVIDENCE` must be added to: `wrappers/framac-docker.ps1` (allowlist near line 624), `wrappers/framac-docker.sh` (near line 385), `docker-compose.yml` (environment list, near line 69), `tests/test_remediation_p2_container.py` (`AB_SWITCHES` tuple and the `env.update(...)` at line 152), and `docs/resources-and-caching.md` Section 4 knob list.

### 4. Skill text and docs

- `skills/framac-wp/prover_brief.md`: no template change needed (the section is appended), but the paragraph describing negotiation should mention the two new subsections.
- `docs/agentic-swarm.md` Section 3 (Caller-Callee Contract Negotiation): describe the evidence the negotiating prover receives.
- `docs/backlog.md`: tick the item.

## Tests (`-n auto`)

- `tests/test_wp_scheduler.py`: with a fake state holding one `negotiate` task, two callers, one with a promoted report containing three goals (two call-site, one `rte`), `_prepare_kwargs` returns evidence with exactly the two call-site goals and the report path; a caller without any report yields `goals: []`; `FRAMAC_NEGOTIATE_EVIDENCE=off` omits both keys; a corrupted report file does not raise.
- `tests/test_workspace_overlay.py`: `prepare_agent(role="prover", requests=[...], caller_evidence=[...], callee_history={...})` renders both subsections after the JSON block; with `caller_evidence=[]` and `callee_history=None` the brief is byte-identical to today's output.
- Existing negotiate tests unchanged.

## Verification

```powershell
$env:PYTHONIOENCODING="utf-8"
python -m pytest tests/test_wp_scheduler.py tests/test_workspace_overlay.py tests/test_remediation_p2_container.py -n auto
python -m pytest tests -n auto
python -m ruff check scripts tests
python -m mypy scripts tests
```

Acceptance on a target run: a `negotiate` brief under `agents/<id>/brief.md` contains `### Why the callers stalled` with at least one goal line whenever the caller's report exists. Benchmark comparison against the previous baseline shows no `regression`.

## Out of scope

Holding `negotiate` until sibling callers finish (rejected in the parent document); changing request caps (`MAX_NEGOTIATIONS_PER_PAIR`, `MAX_NEGOTIATION_ROUNDS_PER_CALLEE`); any change to `contract_negotiator.py`.
## Implementation notes (2026-11-09)

Implemented on branch `claude/fd-tier2-negotiate-evidence-4298b4`. Where the facts above turned out imprecise:

- `_prepare_kwargs(task)` and `_describe(task, ctx)` had no access to the schedule, which the evidence needs (caller tasks, agent history). Both now take an optional `state`; `cmd_next` passes the schedule the dispatch snapshot was taken from. Without a state the caller name and file are parsed from the caller task id.
- The reliable record of a task's agents is `state["agents"]` (agent id -> task id, in assignment order). `task["agent_id"]` survives `_finish` but `_reopen` clears it. Caller reports are looked up in this order: the caller task's `wp_report`, `agents/<id>/artifacts/wp_<fn>.json` for its agents newest first, the caller's breaker task `wp_report`, then `workspace/reports/wp/<fn>.json`. A report whose `function` differs is skipped; a corrupt one falls through to the next path.
- The callee history is taken from the newest agent of `prove:<callee>` or of the negotiate task itself (an earlier round), excluding the agent being prepared, and only when its scratch has `candidates/state.json`. The fallback scan of `agents/*/scratch/.prover_budget.json` also matches the budget's `file`, so a same-named static in another file is not used.
- `step_c_contract_postcondition` is the fallback bucket of `run_wp_function.classify_unproven_goal` (anything that is not assigns, loop, `rte:` or requires/precondition), so the evidence can include caller goals unrelated to the callee, such as plain `assert`s. Annotation matching on the callee name uses identifier boundaries.
- `skills/framac-wp/prover_brief.md` had no paragraph on negotiation, only the `strengthening_requests` bullet; a bullet for the callee side was added after it. `docs/backlog.md` had no item to tick; a section 1c was added.
- Benchmark acceptance (`benchmark.py` / `benchmark_compare.py`) was not run.
