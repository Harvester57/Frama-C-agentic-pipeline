# Public header functions as API entry points

- **Why:** on a library whose public API is defined in its headers, the harness and both reach
  gates see only the exported functions behind it. See "Public API Functions Defined in a Header"
  in [`../troubleshooting/harnesses-and-seeds.md`](../troubleshooting/harnesses-and-seeds.md).
- **Evidence (QCBOR `dev` `9bd0845`, run-6, module `libqcbor_a`):** 171 entry points, 171
  reached, 171 executed, both gates passed. 440 functions are defined in the public headers; 383
  of them never ran (3,334 lines, no loop). 224 of the 383 are map variants (`...InMapN`,
  `...ToMapN`), 112 have 10 lines or more, 25 call nothing, and 2 are the only route to an entry
  point the generator skipped (`QCBORDecode_GetItemsInMap*` to `QCBORDecode_Private_MapSearch`).
- **Found:** 2026-11-17, while checking laurencelundblade/QCBOR#454 against run-6.

## What exists already

The first sketch of this work had three steps. Two of them meet work that is already planned:

| First sketch | What it meets | Result |
| :--- | :--- | :--- |
| 1. Report unexecuted public header functions in the reach gate | `harness_reach.run_dynamic` and `schemas/harness_reach_dynamic.schema.json` belong to S5 of [`./phase1-remediation-plan.md`](./phase1-remediation-plan.md), which is in work on `p1/s5-dynamic-gate` | **R1** below, after S5 is merged |
| 2. Lift the 255-case limit | It is **S6b** of the same plan (D7, D20): the `identity16` selector, fully specified. The user moved it after the merge to `main` on 2026-11-17. The silent defects are already fixed in `45c7a5f` (2026-11-15): the selector no longer shifts when a case is added, and more than 256 cases is refused | Not planned again here. **H1 lands after S6b** |
| 3. Public header functions become entry points | Nothing | **H1** below |

## Decisions

| # | Question | Decision |
| :--- | :--- | :--- |
| HD1 | Which functions. | A function the Phase 0 model records with `static` and `header`, whose file is one of the public headers the build capture found for the unit (`public.files`). Library units only (static and shared); not test units, not executables. No naming rule: `_Private_` helpers defined in a public header count too. |
| HD2 | Where it is computed. | In `phase0_model.py`, as a per-unit list `header_api`, next to `entry_points` and `embedded_api`. The build capture cannot see these functions: they have no global symbol. `build_callgraph_dag.py` adds them to the unit's `candidate_entry_points`, after the global ones. |
| HD3 | Reached, and trust. | `model_api()` includes `header_api`: a header function takes the caller's input like an exported one. **Corrected by the H1 review:** `model_api()` decides the DAG's `reached` flag, not trust. A reached header function gets an active ledger unit where it was `header_unreached` (deferred) before. Trust and tiers do not move, because `trust.py` (rule 1) reads only `entry_points` and `embedded_api`. Whether trust should count `header_api` is **H2**, open. |
| HD4 | Case order. | The generated cases of the global entry points keep their index. Header cases come after them. Where the hand-written `--dispatch-case` cases sit after the generated ones, their index moves; the step reports whether it does, since the identity selector then orphans their seeds. |
| HD5 | More entry points than cases. | Unchanged: `api_harness.py` records the overflow in `api_skipped` (`more than 255 cases`), which the static reach gate reports as gaps. On QCBOR, 171 + 440 entry points against 255 cases would fail the gate, so **H1 does not land before S6b**. A test fixes this behavior. |
| HD6 | Opt-out. | None. An entry point that cannot be driven from bytes is exempted with `harness_reach.py exempt` and a reason, as today. |
| HD7 | Fuzz budget. | Not changed here. A module's budget is shared by its cases, so more cases give each case a smaller share (QCBOR: about a third). The per-case floor pass of [`./fuzz-budget-design.md`](./fuzz-budget-design.md) (P6a) is the answer to that, and it is a proposal. The end validation measures the effect. |
| HD8 | E-ACSL and RTE selection. | A header entry point the harness calls is added to the `-rte-select` / `-e-acsl-functions` list through the existing name filter of `fuzz_build.py` (Frama-C aborts on an unknown name). Unverified on a real build until the end validation. |
| HD9 | Seeds. | The seed recorder wraps global symbols (`-Wl,--wrap`), so it cannot record a header function. It skips them without an error, and their cases start without recorded seeds. |

## Review of H1 (2026-11-17)

H1 is implemented on `feat/header-entry-points` (seven commits, `e4ed2c3` to `da4f35c`). Checked
again on the branch: `ruff check` and `mypy` pass, the new tests and the neighbouring test files
pass (263 passed, 18 skipped), and a dry merge into `phase1-remediation` at `7e431a6` (S5, S6a
and S12 merged meanwhile) has no conflict. `ruff format --check` reports 48 files, all of them
already at the base; the only one H1 touches is `scripts/api_harness.py`, at a line H1 did not
change. The full suite was run by the implementing agent only (5888 passed, 218 skipped).

**Measured offline on the recorded QCBOR run-6 model** (the branch's `header_api()` and
`build_callgraph_dag.py` on a copy of `phase0_model.json` and `build_capture.json`; no target run):

| | Before | With H1 |
| :--- | :--- | :--- |
| Entry points of `libqcbor_a` | 171 | 611 (440 from 13 public headers, 9 of them `_Private_`) |
| Header functions `reached` | 88 of 470 | 470 of 470 |
| Tiers | 342 Tier 1A, 8 Tier 1B, 4 Tier 2, 401 Tier 3 | the same |
| Harness modules | 1 (`libqcbor_a`) | 10 cluster sub-modules: the entry points now reach more than 400 functions, so `unit_split.py` splits the unit. The largest has 280 entry points and 402 functions |

What this means, beyond "more cases":
- **Phase 3 and Eva get the header functions.** In run-6 the ledger holds 410 `deferred` units
  under `inc/` (of 480): those functions were analyzed by no phase. With H1 they are reached, so
  they are planned.
- **QCBOR becomes ten harnesses, ten Eva runs and ten campaigns** in place of one. That is the
  designed answer to a large unit, but it was calibrated on exported entry points; the clusters
  and their cost need the end validation.
- **S6b is still needed** (HD5): the largest cluster has 280 entry points against 255 cases. The
  other nine fit.
- **Hand-written `--dispatch-case` cases move** behind the header cases (HD4), and with the split
  they belong to another module anyway. A run's harness repairs have to be redone.

Open after H1, each recorded in the troubleshooting entry:
- **H2, trust:** public header functions stay Tier 3 ("no untrusted path"). A sub-module scoped
  to source files is then not held to them, and the unit's own gate row asks only for Tier 1 and
  2 entry points. Needs `scripts/trust.py`, which H1 did not own.
- **Shared libraries only:** the build capture computes `public_headers` only when the build has
  a static library, so such a target gets no `header_api`.
- **A scope with header entry points only** fails in `api_harness.generate` before the layout
  probe can make their cases.
- **The static reach gate follows header wrappers**, so a header entry point that only another
  header entry point calls is never a gap.
- **HD8 on a real build:** whether Frama-C keeps the plain name of the header copy the harness
  compiles. The legacy `e-acsl-gcc.sh` path has no retry for an unknown name.

## Steps

### H1. Header functions are entry points (M)

- **Branch:** `feat/header-entry-points`, cut from `phase1-remediation` at `3369898` or later, in
  its own worktree. Not merged and not pushed by the step.
- **Rules:** "Rules for every step" of [`./phase1-remediation-plan.md`](./phase1-remediation-plan.md)
  (D15: unit and fixture tests only; the standard checks), and `CLAUDE.md`.
- **Owns:** `scripts/phase0_model.py` (`header_api`), `schemas/phase0_model.schema.json`,
  `scripts/build_callgraph_dag.py` (`model_api`, `candidate_entry_points`), `scripts/api_harness.py`
  (the entry loop: a header `static` entry is callable), `scripts/fuzz_build.py` (the function
  list), `scripts/seed_harvest.py` (only if it fails on a header entry point), the tests named
  below, `skills/framac-slice/SKILL.md` (what an entry point is), this plan's Status table, and the
  troubleshooting entries it closes.
- **Must not touch:** `scripts/harness_reach.py` (`run_dynamic` is S5's, `_artifact_first_byte` is
  S6b's), `scripts/phase0_gates.py`, `scripts/generate_report.py`, `scripts/ledger.py`,
  `templates/pipeline.mk`, `schemas/harness_reach_dynamic.schema.json`,
  `docs/guides/architecture.md`, `docs/plans/phase1-remediation-plan.md`, and `MAX_CASES` in
  `api_harness.py` (S6b's). If one of them needs a change, the step stops and reports it.
  `harness_reach.py` should need none: `built_entries` drops only `model_only` functions, and
  `ModuleMap.scope_entry_points` passes `candidate_entry_points` through.
- **Work**, one commit each, in this order:
  1. **Model.** `header_api` per library unit (HD1, HD2), in the model and its schema.
  2. **DAG.** `candidate_entry_points` gains the unit's `header_api`, after the global entry
     points and only for functions the unit compiles.
  3. **Trust.** `model_api()` includes `header_api` (HD3).
  4. **Harness.** `api_harness.py` builds a case for a header `static` entry point that the layout
     probe saw declared (`visible`), instead of skipping it as
     `static: not callable from the harness`. Order as HD4. A `static` entry point that is not in
     a header stays skipped.
  5. **Build.** The function list (HD8).
  6. **Seeds.** Only what HD9 needs.
  7. **Docs and skills.** The troubleshooting entries, this plan's Status, the slice skill, then
     `python tools/sync_skill_mirrors.py`. Last, so that it can be redone after S5 and S6b, which
     share `skills/framac-slice/SKILL.md`.
- **Tests** (new files; no module-level constant another test module defines):
  - `tests/test_header_entry_points.py`: a fixture library with one exported function, one
    function defined in its public header, one defined in a private header, and one `static` in a
    source file. The model lists only the public header function in `header_api`; the DAG puts it
    in `candidate_entry_points` after the exported one; a test unit gets none; `model_api()`
    contains it.
  - `tests/test_api_harness_header_entries.py`: the public header function gets a case after the
    exported function's case, whose index is unchanged; a `static` in a source file is still
    skipped; with more entry points than cases, the overflow is in `api_skipped` with
    `more than 255 cases` and header functions overflow first (HD5); the generated harness
    compiles when host clang is present, as the existing API harness tests do.
  - `tests/test_harness_reach_header_entries.py`: without changing `harness_reach.py`, the static
    gate reports a header entry point the harness does not call as a gap, and the dynamic gate
    reports one with `executions: 0` as a gap.
  - The function list of HD8, and the seed recorder of HD9, each with one test next to the
    existing tests of those modules.
- **Acceptance:** the standard checks of the remediation plan, and the tests above.

### R1. Report unexecuted public header functions (S, after S5 is merged)

- **Why it stays:** H1 lands after the merge and after S6b, so until then a passing dynamic gate
  still reads "the API ran". R1 is small and can land right after S5, before the validation run.
- **Work:** `harness_reach.run_dynamic` adds to each module row the number of public header
  functions (HD1) and how many have `executions: 0`, with the first names. No gate decision
  depends on it. The schema gains the two fields. The run report prints them next to the entry
  point counts.
- **After H1:** the header functions are entry points and the gate holds the module to them; R1's
  numbers then cover only exempted ones.
- **Written (2026-11-17)** on `feat/header-coverage-report`, cut from `phase1-remediation` at
  `fe9775f`: H1's model commit cherry-picked (`header_api`), then `feat(reach)` and `docs`. A row
  gains `header_api_functions` (a count) and `header_api_unexecuted` (`count`, and the first 20
  names, sorted). A row measured by its crashes, or with partial coverage, keeps only the count.
  The run report prints one line per module that has unexecuted ones.
- **Review (2026-11-17):**
  - Re-run on the branch: `ruff check`, `mypy scripts tests`, and the tests around the change
    (77 passed). The agent's own full run: 5922 passed, 218 skipped.
  - Applied offline to the recorded QCBOR run-6 coverage, with `header_api` added to a copy of the
    model: the `libqcbor_a` row keeps `passed: true` with 171 entry points and no gap, and reports
    383 of 440 public header functions never executed. That is the number counted by hand from
    the same coverage report before this step existed. Nothing was written to the run.
  - Dry merges: clean into `phase1-remediation` (`b540121`) and into `p1/s6b-wide-selector`. A
    rebase of `feat/header-entry-points` onto this branch skips the cherry-picked model commit and
    stops on one conflict, the status lines both branches add to the same troubleshooting entry.
  - **Open, split units:** a sub-module row counts only the header functions in its scope
    (`ModuleMap.scope_functions`). A file-scoped sub-module scopes source files, so it counts
    none. A cluster sub-module counts those its anchors reach, so a header function nothing calls
    is in no row. On a split unit the numbers are therefore a lower bound. This is read from the
    code: no split unit was run, and QCBOR is one module before H1. A count per unit over all of
    its modules' coverage would close it.
  - On the branch itself the reviewer did not re-run the whole suite. It was run on the merge
    (next bullet).
  - **Merged (2026-11-17)** on `integ/r1-merge`, which `phase1-remediation` fast-forwards to. The
    checks ran on the merge with the tip `6632b74` (after the mpack run-3 supervisor fixes):
    `ruff check`, `mypy scripts tests`, the generated-text check and the skill mirror check pass,
    and the whole suite gives 6042 passed, 221 skipped. The tip then gained one commit of
    documents only (`6fd8634`); on the merge with it, the generated-text check and the docs
    structure test were run again.
  - **After H1, corrected:** the list is made from coverage only, so a header entry point that a
    crash proved executed is still listed.
  - `feat/header-entry-points` (H1) has to be rebased onto the merge, not merged: both branches
    add `tests/test_header_entry_points.py`. The rebase also meets the R1 row of the Status table
    below and the R1 status line in the troubleshooting entry.

### S6b. Two-byte selector

As specified in [`./phase1-remediation-plan.md`](./phase1-remediation-plan.md). Not changed by
this plan. H1 needs it before it lands (HD5).

Started early on 2026-11-17, on the user's decision, in parallel with S5 and H1:
- **Base:** S5 is not merged yet, so the branch is cut from the `phase1-remediation` tip and must
  be rebased over S5. Both change `scripts/harness_reach.py` and `scripts/run_eacsl_fuzz.py`.
- **Scope beyond the remediation plan's list:** every reader and writer of the selector is
  checked, including Eva sharding (`scripts/eva_shards.py`), which that list does not name.
- **Commits:** two, not one: code and tests, then skills and docs, because S5 and H1 edit the
  same skills.
- **With H1:** S6b owns `MAX_CASES` in `scripts/api_harness.py`; H1's overflow test is written
  against that constant, not the number 255.

## Not in this plan

These decide how much the new cases find. Each needs a design of its own.

- **Accessors that need an entered map or array.** A generated case calls the accessor on a fresh
  context and gets `QCBOR_ERR_MAP_NOT_ENTERED` ("Generated Cases for the `*InMap*` Spiffy
  Accessors" in the troubleshooting file). 224 of QCBOR's 383 functions are of this kind.
- **Caller-built arguments.** A sentinel-terminated array of structs (`QCBORDecode_GetItemsInMap`'s
  item list) cannot be built from bytes. Its case lands in `api_skipped`, becomes a reach gap, and
  the architect writes it by hand.
- **Seeds for header functions** (HD9).

## Order and landing

- **Now:** H1 on its branch, in parallel with S5, S6a and S7. It shares no file with them except
  `skills/framac-slice/SKILL.md`, which it edits last.
- **After S5 is merged:** R1.
- **After the merge to `main`:** S6b, then H1 rebased onto it.
- **End validation (user-triggered, once):** regenerate Phase 0 for QCBOR `dev` `9bd0845` with H1
  and S6b. Expected: the header functions are entry points; `QCBORDecode_GetItemsInMap` has a case
  or is a reach gap; the E-ACSL build accepts the function list (HD8); the campaign report shows
  the per-case budget (HD7). Then the same on v2.0-alpha-6, to see whether a hand-written
  `GetItemsInMap` case reaches the two behaviors of #454.

## Status

| Step | Size | When | Status |
| :--- | :--- | :--- | :--- |
| H1 | M | now, on `feat/header-entry-points`; lands after S6b | implemented 2026-11-17 on `feat/header-entry-points` (`e4ed2c3`..`e360071` and the docs commit), not merged. HD3 only moves `reached`: trust and tiers stay as they were, since `trust.py` does not read `header_api`; a sub-module scoped to the sources is then not held to the header entry points (both open, see the troubleshooting entry). HD8 unverified until the end validation |
| H2 | S | with H1 | open: decide whether `trust.py` counts `header_api` (see "Review of H1") |
| R1 | S | after S5 is merged | merged 2026-11-17: the reach row and the run report list them, no gate reads them; open: on a split unit the numbers are a lower bound |
| S6b | M | after the merge to `main` (remediation plan, D20) | open, tracked there |
