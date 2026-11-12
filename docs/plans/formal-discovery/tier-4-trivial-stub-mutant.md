# Tier 4: Trivial-Stub Mutant and Corrected Rejection Criterion

Self-contained implementation plan. Parent document: [`../formal-discovery-plan.md`](../formal-discovery-plan.md) (Section 3, Tier 4). Independent of every other tier.

## Goal

`scripts/mutation_check.py` measures specification *precision* by mutating the implementation and asking whether WP rejects the mutant. Two defects make the metric unreliable, and one mutant is missing:

1. A mutant counts as rejected only when an `ensures` / behavior goal comes back **Invalid**. A false postcondition usually comes back **Unknown** (no counter-model found), so real rejections are missed and precision is under-reported.
2. A mutant whose WP run fails (`status: "error"`, for example a parse error) counts as *not rejected*, which looks like an imprecise spec.
3. No mutant asks the paper's question (Shirobokov et al., Appendix I.1): does the specification reject the program that does nothing? Functions without relational operators or constant returns get no implementation mutant at all (`precision: None`).

The check stays evaluative: it writes `workspace/reports/mutation.json`, never touches `workspace/work/`, and gates nothing.

New A/B switch: `FRAMAC_MUTATION_STUB` (`off` disables the stub mutant only; the corrected criterion is a bug fix and always applies).

## Facts the implementer must know (verified 2026-11-09)

- `mutation_check.check_function(c_file, fn, cppflags, out_dir, wp_runner=None, max_mutants=6)`: locates the span, splits contract (`_acsl_text_of_span`) and body (`span.text[brace:]` with `brace = _find_body_brace_offset(span.text)`), builds `spec_mutants(contract, n)` and `impl_mutants(body, n)`, writes each mutant to a temp file and calls `runner(mut_file, fn, out_dir, cppflags=cppflags)`; default runner `run_wp_function.run_wp_on_function` (signature includes `counter_examples: bool = False`, `cache_dir="auto"`). Per-function result keys: `function, file, spec_mutants, equivalent, impl_mutants, rejected, completeness, precision, details[]` with `details` entries `{"mutant","kind","rejected"|"equivalent","status"}`.
- `_is_rejection(report)`: `True` iff some entry of `report["unproven_goals"]` has `"invalid" in status.lower()` and a `kind` not starting with `rte`. `_is_equivalent(report)`: `report["status"] == "all_proven"`.
- `impl_mutants(body, n)`: flips the first occurrence of each relational operator in `_REL_OP_FLIP` and bumps literal `return <int>;` constants (`_RETURN_CONST_RE`).
- `run_mutation_check(...)` runs only on functions whose parent report `workspace/reports/wp/<fn>.json` is `all_proven`; totals: `functions, spec_mutants, equivalent, impl_mutants, rejected, completeness, precision` (`precision` is the mean of per-function precisions).
- WP report: `unproven_goals` contains only goals that are not Valid (statuses Unknown, Invalid, Invalid under hyp, Never tried; `status` holds WP's raw status string), each with `kind` (`rte_*` kinds for RTE guards) and `annotation`. Timeouts appear as Unknown. `proven_count` / `unproven_count` are integers.
- `generate_report.spec_quality_section` renders totals and per-function lines from `mutation.json`.

## Changes

### 1. Corrected rejection criterion (`scripts/mutation_check.py`)

- `_is_rejection(report) -> tuple[bool, str]`: returns `(True, "invalid")` when a non-RTE goal has `invalid` in its status; `(True, "unknown")` when a non-RTE goal is otherwise unproven (any entry in `unproven_goals` whose `kind` does not start with `rte`); `(False, "proved")` when `status == "all_proven"`; `(False, "not_applicable")` when `status` is `error` / `analysis_error` / missing. Rationale recorded in the module docstring: the original function is `all_proven` with the same budget, so a mutant goal the solvers can no longer prove is evidence the spec distinguishes the mutant; a timeout is possible but rare at equal budget, and the `verdict` field keeps the two cases apart for anyone auditing the number.
- `check_function`: for impl mutants, `rejected, verdict = _is_rejection(report)`; `details` entries gain `"verdict": verdict`. Mutants with `verdict == "not_applicable"` increment a new `impl_not_applicable` counter and are **excluded** from `impl_mutants` (the denominator). Same `not_applicable` handling for spec mutants whose run errors (`spec_not_applicable`, excluded from `spec_mutants`).
- Pass `counter_examples=True` to the default runner when it accepts the kwarg (`inspect.signature`), so an `invalid` verdict carries a model in the WP report for auditing. Injected test runners keep working.

### 2. Trivial-stub mutant

- New `trivial_stub_mutant(span_text: str, brace_offset: int) -> tuple[str, str] | None`:
  - Take the declarator text `span_text[:brace_offset]`, drop ACSL blocks and line annotations (`acsl_ast.tokenize_c_acsl`, keep `c_token`s), drop `static`, `inline`, `extern`, `__attribute__((...))`, and take the tokens before the function name as the return type.
  - `void` with no `*` → `("trivial-noop-body", "{ }")`.
  - Contains `struct` or `union` with no `*` → `None` (a scalar `return 0;` would not compile; record as `not_applicable`).
  - Otherwise (integer, floating, enum, `_Bool`, any pointer) → `("trivial-zero-body", "{ return 0; }")`.
  - Unparseable declarator → `None`.
- `check_function`: when `os.environ.get("FRAMAC_MUTATION_STUB", "on").lower() != "off"`, prepend the stub mutant to the impl mutants (it does not count against `max_mutants`). Record `"trivial_body_rejected": bool | None` on the function result (`None` when no stub was produced) and the verdict in `details` as the other mutants.
- `run_mutation_check` totals: add `trivial_body_checked`, `trivial_body_accepted` (count of functions where the stub was **not** rejected) and `trivial_body_accepted_functions: [names]`.
- Note on `assigns`: a stub body writes nothing, so `assigns` goals are trivially valid and only `ensures` / behavior goals can reject it. A contract whose only output constraint is `assigns` therefore accepts the stub; that is the intended signal (the spec says nothing about results).
- Note on `requires \false`-style vacuity: already caught by `--wp-smoke-tests`; the stub mutant does not re-check it.

### 3. Report (`scripts/generate_report.py`)

In `spec_quality_section`, after the totals line, when `trivial_body_checked` is present:

```
- Trivial-stub check: N functions checked, M accept a body that does nothing: `f`, `g` (their contracts constrain no result)
```

Per-function lines append `, trivial stub rejected: yes|no|n/a`. Nothing else changes.

### 4. Flag plumbing

`FRAMAC_MUTATION_STUB` goes into `wrappers/framac-docker.ps1` (allowlist near line 624), `wrappers/framac-docker.sh` (near line 385), `docker-compose.yml` (near line 69), `tests/test_remediation_p2_container.py` (`AB_SWITCHES` and the `env.update` at line 152), and the knob list in `docs/resources-and-caching.md` Section 4.

### 5. Docs

- `docs/v2-design.md`: the mutation-check paragraph gains the stub mutant and the corrected criterion.
- `docs/backlog.md`: update the COINS/KBSpec item (the Invalid-only criterion is listed there as implemented; note the correction).
- `benchmark.py` already carries per-target `mutation` totals; `benchmark_compare.py` should treat a change in `precision` as `changed` (not `improvement`) on the first run after this change, since the metric's definition moved. Add a one-line note in `docs/benchmark.md`.

## Tests (`-n auto`, all with an injected `wp_runner`)

- `tests/test_mutation_check.py`:
  - `_is_rejection`: Invalid non-RTE goal → `(True, "invalid")`; Unknown non-RTE goal → `(True, "unknown")`; only `rte_*` goals unproven → `(False, ...)`; `status: "error"` → `(False, "not_applicable")`.
  - `trivial_stub_mutant`: `void f(int *p)` → noop body; `static inline int g(void)` → zero body; `char *h(void)` → zero body; `struct s k(void)` → `None`; `struct s *m(void)` → zero body; declarator with a preceding ACSL block is handled.
  - `check_function` on a void function whose contract has only `assigns`: `trivial_body_rejected is False`, counted in totals; on a function with `ensures \result == a + b`: stub rejected with verdict `unknown` when the fake runner returns an Unknown goal; a runner raising for the stub → `not_applicable`, excluded from the denominator, `precision` computed over the remaining mutants.
  - `FRAMAC_MUTATION_STUB=off` (monkeypatch): no stub mutant, `trivial_body_rejected` absent.
- `tests/test_report.py`: the new line renders with and without accepted functions.

## Verification

```powershell
$env:PYTHONIOENCODING="utf-8"
python -m pytest tests/test_mutation_check.py tests/test_remediation_p2_container.py -n auto
python -m pytest tests -n auto
python -m ruff check scripts tests
python -m mypy scripts tests
```

Acceptance on a target run: `python scripts/mutation_check.py --run-dir <run>` writes `mutation.json` with `trivial_body_checked > 0`; `REPORT.md` lists the functions whose contracts accept the stub; precision values are higher than before for the same run (more rejections counted) and every `details` entry carries a `verdict`.

## Implementation notes (2026-11-09)

Implemented on branch `claude/fd-tier4-stub-mutant-978a2d`. Facts that differed from the list above, and decisions taken:

- `run_wp_function.run_wp_on_function` never returns `status: "error"`; its failure statuses are `analysis_error`, `acsl_syntax_error` and `wp_aborted` (`"error"` only comes from `check_function`'s own exception handler). `_is_rejection` therefore treats every status other than `all_proven` / `unproven_goals_remain` as `not_applicable`.
- A run with only `rte_*` goals unproven returns `(False, "rte_only")` (the contract accepts the mutant; RTE guards are not spec goals). Goals without a `kind` are skipped, as before.
- Spec-mutant details carry `verdict` too (`equivalent` / `distinguished` / `not_applicable`), so every `details` entry has one.
- A struct/union return gets a `details` entry `{"mutant": "trivial-stub", "verdict": "not_applicable", ...}` without a WP run; it is not counted in `impl_not_applicable` (which counts failed runs). A typedef'd struct return cannot be recognised from the declarator: its `return 0;` stub fails to compile and is recorded as `not_applicable` through the failed run.
- `benchmark_compare.py` does not compare the `mutation` totals at all, so there was nothing to downgrade from `improvement` to `changed`; `docs/benchmark.md` says the pre-change `precision` is not comparable. `schemas/benchmark-run.schema.json` lists the new totals.
- Benchmark measurement (Section 3 "Measurement") was not run with this change.

## Out of scope

Gating `all_proven` credit on precision or on the stub result; new spec mutants; running the check inside the prover loop.