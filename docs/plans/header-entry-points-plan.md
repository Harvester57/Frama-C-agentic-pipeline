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
| HD3 | Trust. | `model_api()` includes `header_api`: a header function takes the caller's input like an exported one. This feeds the risk tiers of every target, so it is its own commit with its own test, and the commit message states what changes. |
| HD4 | Case order. | The generated cases of the global entry points keep their index. Header cases come after them. Where the hand-written `--dispatch-case` cases sit after the generated ones, their index moves; the step reports whether it does, since the identity selector then orphans their seeds. |
| HD5 | More entry points than cases. | Unchanged: `api_harness.py` records the overflow in `api_skipped` (`more than 255 cases`), which the static reach gate reports as gaps. On QCBOR, 171 + 440 entry points against 255 cases would fail the gate, so **H1 does not land before S6b**. A test fixes this behavior. |
| HD6 | Opt-out. | None. An entry point that cannot be driven from bytes is exempted with `harness_reach.py exempt` and a reason, as today. |
| HD7 | Fuzz budget. | Not changed here. A module's budget is shared by its cases, so more cases give each case a smaller share (QCBOR: about a third). The per-case floor pass of [`./fuzz-budget-design.md`](./fuzz-budget-design.md) (P6a) is the answer to that, and it is a proposal. The end validation measures the effect. |
| HD8 | E-ACSL and RTE selection. | A header entry point the harness calls is added to the `-rte-select` / `-e-acsl-functions` list through the existing name filter of `fuzz_build.py` (Frama-C aborts on an unknown name). Unverified on a real build until the end validation. |
| HD9 | Seeds. | The seed recorder wraps global symbols (`-Wl,--wrap`), so it cannot record a header function. It skips them without an error, and their cases start without recorded seeds. |

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

### S6b. Two-byte selector

As specified in [`./phase1-remediation-plan.md`](./phase1-remediation-plan.md). Not changed by
this plan. H1 needs it before it lands (HD5).

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
| H1 | M | now, on `feat/header-entry-points`; lands after S6b | dispatched 2026-11-17 |
| R1 | S | after S5 is merged | open |
| S6b | M | after the merge to `main` (remediation plan, D20) | open, tracked there |
