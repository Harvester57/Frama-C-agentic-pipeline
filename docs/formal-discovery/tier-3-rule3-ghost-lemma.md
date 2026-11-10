# Tier 3: Rule 3 / Ghost-Lemma Remediation

Self-contained implementation plan. Parent document: [`../formal-discovery-plan.md`](../formal-discovery-plan.md) (Section 3, Tier 3). Independent of Tiers 1, 2, 4, 5, 6; must land **before** Tier 7, which supersedes it.

## Goal

The prover brief tells provers to write a file-scope `/*@ ghost ... */` lemma function; the merge splicer rejects exactly that block. Make the brief and the splicer agree, make the prover find out on its first iteration instead of at merge, and count the resulting gaps so the loss is visible per target. Troubleshooting entry: [`../troubleshooting.md`](../troubleshooting.md), Section 5, "A Prover's Merge Is Refused ... After It Added a Ghost Lemma Function" (currently **Open**).

No new environment flag: this is a bug fix.

## Facts the implementer must know (verified 2026-11-09)

- `skills/framac-wp/prover_brief.md` lines 96–100 (inside `<!-- if: loops or recursion -->`): Rule 3 "Inductive Lemmas Without Coq (Ghost Lemma Functions)" says never write an unproven global `lemma`, and instead write a recursive `/*@ ghost ... */` C function with `requires`, `decreases n;`, `assigns \nothing;`, `ensures`.
- `scripts/acsl_ast.py`:
  - `locate_function_span(source, fn, is_header)` → `Span(start_byte, end_byte, start_line, end_line, text)`; `_compute_span_start` walks back over the declarator and the contract but stops at any token for which `_is_top_level_acsl_token(tok)` is true. `_TOP_DECL_KWS = {"predicate","logic","lemma","type","axiomatic","inductive","ghost"}`; a `ghost` block followed by a parenthesised signature is a top-level declaration (see the parser around line 1242).
  - `splice_prover_changes(base, agent, current, fn, is_header, path, contract_only)` first runs `verify_acsl_only(base, agent)` (passes for a pure-ACSL ghost block), then raises `ScopeViolationError("...agent modified content outside assigned function '<fn>'")` when the text before or after the span differs.
  - `extract_top_level_acsl_declarations(source, path) -> list[dict]` parses top-level declarations; each dict has at least a `kind` and a `name` (check the exact keys before use).
  - Reproduction (2026-11-09): base = contract + `int f(int n) { return n; }`; agent = a `/*@ ghost /@ requires n >= 0; decreases n; assigns \nothing; ensures n >= 0; @/ void lem(int n) {...} */` block above it. `verify_acsl_only` → `[]`; span starts at the contract (line 5); `splice_prover_changes` → `ScopeViolationError`.
- `scripts/run_wp_function.py`: under `-wp-fct <fn>` only `<fn>`'s goals are generated; a called ghost function's contract is a hypothesis (`valid_under_hyp`). Unproven global `lemma`s are detected (`unproven lemma(s) in scope` → `soundness.tier_b_unsound`, `soundness.ok = False`); an unproven *ghost function* is not detected by anything.
- `scripts/prover_candidates.py`: after every oracle run on a scratch file, `note_oracle(out_json, oracle, report, digest_before)` runs (via `add_candidate_block`, printed in the oracle's stdout `candidate` block). It knows the scratch (`_scratch_of`), the budget (`.prover_budget.json` with `file`, optional `header`, `function`) and reads the tracked files (`_read_tracked`). `agents/<id>/scratch/base/` is the pristine snapshot of `workspace/work/` (`init_agent_overlay`).
- `scripts/ledger.py` (`ingest-agent-result` path, around line 1795): a prover result with `proof_gap: {"predicate", "reason"}` adds `proof_gap` evidence to the function's units, sets them `blocked`, and appends `proof_gap: <predicate>: <reason>` to `unresolved`.
- `scripts/generate_report.py::spec_quality_section` renders "Open units: prover-limited vs spec-limited" from `mutation_check.classify_open_unit(wp_report)`.
- `scripts/workspace_overlay.py check-acsl-only --overlay W [--work-dir D] [--file F ...]` → `check_acsl_only(overlay, work_dir, files)` returns `{"ok": bool, ...}`.

## Changes

### 1. Brief: make Rule 3 truthful (`skills/framac-wp/prover_brief.md`)

Replace the two bullets of Rule 3 with:

- "Never write a global `lemma` and never write a file-scope `/*@ ghost ... */` function. An unproven `lemma` makes the proof `unsound_proof`; a ghost function sits outside your function's span and `merge-agent` refuses the whole patch (`ScopeViolationError`), and nothing proves the ghost function's own contract under `-wp-fct`."
- "When a goal needs an inductive argument that WP cannot do inline (a `loop invariant` over a recursively defined quantity, a lemma about a `predicate`), stop with `status: "stalled_after_k_retries"` and `proof_gap: {"predicate": "<the goal's predicate>", "reason": "inductive lemma required: <one line>"}`. Do not work around it with `axiomatic`, `admit`, a ghost function inside the body, or a weaker clause."
- Keep the surrounding `<!-- if: loops or recursion -->` conditional. Keep Step B's ghost *variable* guidance (`/*@ ghost size_t idx = 0; */` inside the body is a statement, not a declaration, and stays allowed).
- Add to the `candidate` block description (around line 244): "`scope_violation_pending` lists top-level ACSL declarations you added outside your function; remove them before the next iteration, the merge will refuse them."

### 2. Early signal in the prover loop (`scripts/prover_candidates.py`)

- New `top_level_additions(scratch: Path, budget: dict) -> list[str]`: for each tracked rel (`_tracked_rels(budget)`), read `scratch/base/<rel>` and `scratch/work/<rel>`, call `acsl_ast.extract_top_level_acsl_declarations` on both, and return the `kind name` strings present in work but not in base (compare on `(kind, name)`; for anonymous blocks compare normalised text). Fail-open: any exception → `[]`.
- In `note_oracle`, compute `pending = top_level_additions(scratch, budget)` and add `"scope_violation_pending": pending` to the returned block (and to the `history` entry). The block is what the prover sees in the oracle's stdout.
- When `pending` is non-empty, force `next_action` to `"continue"` even for an `all_proven` candidate (the candidate is unmergeable), and add `"next_synthesis_focus": "remove_top_level_acsl_declarations"` to the block. `_install_best` must not install such a candidate: treat it as ineligible in `_is_eligible` via a new `scope_ok` field on the WP summary (set in `note_oracle` before `_evaluate`).

### 3. Make the merge error self-explanatory (`scripts/acsl_ast.py`)

- In `splice_prover_changes`, when the prefix or suffix differs, compute `extract_top_level_acsl_declarations(agent) − extract_top_level_acsl_declarations(base)`; if non-empty, raise `ScopeViolationError(f"{path}: agent added top-level ACSL declaration(s) outside '{fn}': {names}; file-scope ghost functions, predicates and lemmas are not mergeable by a prover (see prover brief Rule 3)")`. Otherwise keep the current message.

### 4. Count the gap (`scripts/generate_report.py`, `scripts/ledger.py`)

- `ledger.py`: when `proof_gap.reason` starts with `inductive lemma required`, add `"gap_kind": "inductive_lemma_required"` to the evidence record (keep everything else as is).
- `generate_report.py::spec_quality_section`: after the prover-limited / spec-limited split, add a line `- **inductive lemma required**: N function(s): f, g, ...` counting units whose evidence has `gap_kind == "inductive_lemma_required"`. This number is the input to the Tier 7 go/no-go decision.

### 5. Troubleshooting

Update the Section 5 entry: status **fixed**, name the three code changes (brief rule, `scope_violation_pending`, splicer message) and keep the symptom line for runs made before the fix.

## Tests (`-n auto`)

- `tests/test_acsl_ast.py`: (a) ghost function block above the function → `ScopeViolationError` whose message names the declaration (`ghost lem`); (b) a top-level `predicate` added in a `.c` file → same; (c) unchanged behaviour for a contract-only edit (splices) and for a C-token edit outside the span (old message).
- `tests/test_prover_candidates.py`: with a scratch whose `work/<file>` adds a ghost function over `base/<file>`, `note_oracle` returns `scope_violation_pending == ["ghost lem"]`, `next_action == "continue"` even when the WP report is `all_proven` and the guardrail passed, and `best` stays `None`; with no additions the block is unchanged (byte-compare against the current expected output).
- `tests/test_workspace_overlay.py` (brief rendering): the rendered prover brief for a function with loops contains "never write a file-scope" and `proof_gap`, and no longer contains "write a `/*@ ghost ... */` recursive C function".
- `tests/test_report.py`: a ledger unit with `gap_kind == "inductive_lemma_required"` produces the new line.
- Optional but recommended: a test that parses every ACSL snippet in `skills/framac-wp/prover_brief.md` code fences with `acsl_ast.tokenize_c_acsl` to catch syntax errors in the brief (see the memory note on gap 4 in `docs/v2-design.md` Section 6).

## Verification

```powershell
$env:PYTHONIOENCODING="utf-8"
python -m pytest tests/test_acsl_ast.py tests/test_prover_candidates.py tests/test_workspace_overlay.py -n auto
python -m pytest tests -n auto
python -m ruff check scripts tests
python -m mypy scripts tests
```

Acceptance: the reproduction above now fails with the new message; a scratch with a ghost function shows `scope_violation_pending` in the first oracle's `candidate` block; `REPORT.md` of a run with such a stall shows the "inductive lemma required" count.

## Out of scope

Allowing provers to contribute lemmas (Tier 7); changing `verify_acsl_only`; changing `-wp-fct` scoping in `run_wp_function.py`.