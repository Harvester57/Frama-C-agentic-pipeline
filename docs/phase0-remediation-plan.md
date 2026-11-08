# Phase 0 remediation plan

This plan covers what the 2026-11-08 audits of Phase 0 left open after the pre-merge fixes:

- **Defects 9–14** of [`phase0-downstream-effects.md`](phase0-downstream-effects.md) §8. Defects 1–8 and 15–20 are fixed (commits `cf9c2cd`..`fc25f85`).
- **The audits' lower-priority findings:** gate edges, resume, threat-model handling, version tolerance, schemas, dead reads.
- **What the step notes of [`phase0-implementation-plan.md`](phase0-implementation-plan.md) left open.**
- **Stale docs, briefs and comments.**

Known limits of the design (Alias, seeds, MetAcsl, one configuration per shared file) are listed under [Backlog](#backlog-not-planned) and are not part of the steps.

Locations come from the audits and were checked on `phase0-redesign` at `fc25f85`. Line numbers drift: search for the named function.

## Decisions (2026-11-08)

Taken by the user as recommended. The steps below follow them.

| # | Question | Options | Decision |
| :--- | :--- | :--- | :--- |
| D1 | When does `phase0-redesign` merge to `main`? | (a) Run the validation benchmark on today's tree, merge, then land these steps; (b) hold the merge until R1–R9 are in. | **(a).** Today's tree carries I0–I10 and 20 fixes; nothing below blocks using it. The steps stay small and land one by one. |
| D2 | GCC-fallback units: the implementation plan says Eva and WP are "reported blocked"; the code seeds them `deferred` (`unresolved: callgraph_fallback: …`). | (a) Keep `deferred` and reword the decision; (b) make them `blocked`, which `validate_artifacts` only accepts with evidence. | **(a),** with a report section that lists fallback units and their first Frama-C error (R4). |
| D3 | The trust rule for input readers applies to every unit, not only executables. | (a) Keep and document; (b) restrict to executables. | **(a).** It is more conservative, and libraries that read files are real. |
| D4 | The "scalar helper → Tier 3" rule is not in the plan. | (a) Keep and document; (b) drop. | **(a).** It is what keeps parameterless getters out of Tier 1. |
| D5 | Defect 14: one configuration per source file shared by several units (qlz's four executables). | (a) One parse per (file, configuration) and per-unit DAG views; (b) document as a limit. | **(b) now.** qlz is the only benchmark target with the shape. Revisit with (a) when a target needs it (R10 records it). |
| D6 | `poc/phase0/` | (a) Remove; (b) keep as history. | **(a),** after `benchmark_seeded.CORPUS` points at `tests/fixtures/phase0/seeded/`. The two copies differ only in the README and in `s08_wellformed_input/truth.json`, which gained the `trust` truth. Check the scorer accepts the fixture copy first (R9). |
| D7 | The manifest's unused `compile_commands` field and CryptoLib's `compile_commands.json` asset | (a) Remove with the next baseline; (b) keep. | **(a),** in the same change as the baseline re-record, because both feed `harness_digest`. |
| D1′ (2026-11-08, evening) | D1 revisited: the API-reach work (`c5a8381`..`684052f`) landed after V, so the validated tree is no longer the head. | (a) Merge `c5ee34e` now, the rest after a second V; (b) land R1–R10 on the branch, one V on the result, then merge everything. | **(b).** One validation covers today's work and the R steps; `main` stays untouched until it passes. V re-records the baseline as `phase0-r2`. |
| D8 | Must ledgers from before I9 (with its three hand-named Layer 4-6 classes) still load? | (a) No: drop the classes; (b) yes: keep them in the schema enums and the report. | **(a).** A pre-redesign run directory cannot be resumed with the new DAG and units anyway. R2, R4 and R10 drop them everywhere. |
| D9 | Open items the steps left to the implementer | — | Taken as the steps recommend: R4 keeps a model or DAG field only if the report or the benchmark shows it and drops the rest (as done: the model drops `included`; the DAG drops `provable_functions`, `shell_unverifiable_functions`, `indirect_callees`, `cross_module_callees` and `entry_trust`, the last three in `f0cbf3c` after `27f443d` had kept them for the skill; `thread_entries`, `parse_jobs` and `alias` stay for the benchmark and the report); R5 writes and keeps `scope_files` (also through `--api`); R7 drops the DAG's never-produced `header`/`headers`/`skipped` reads; R8 documents the pinned-digest alignment of the two base stages. |

## Rules for every step

These are the same as the implementation plan's rules:
- **Ownership:** each step owns the files it lists, and parallel steps own disjoint files.
- **Checks:** `ruff`, `ruff format --check`, `mypy scripts tests` (clean since `f008516`) and the full pytest suite pass.
- **Docs and skills:** they change in the same step as the behavior, and `skills/` is mirrored into `.claude/skills/`.
- **Pipeline runs:** no step needs one to land. Unit tests with recorded fixtures cover each item, and the validation run (V) checks them together when the user says so.

## Steps

### R1. Make, gates and resume (M)

- **Goal:** a resumed or partial run never skips a gate, and Phase 0 is recorded as done only once its last gate passed.
- **Work:**
  - **Phase 0 checkpoint after build-check:**
    - `seed` stops recording phase 0 (`pipeline.mk:84`);
    - `pipeline_make.py build-check` records it when it passes (`checkpoint.py save-phase --phase 0`, after `init` when the state is new);
    - a resume whose `phase_done` is unset re-runs `gen` and `build-check`.
  - **Skill order:**
    - `framac-verify` Phase 0 lists the seed, then `gen`, then `build-check`;
    - the `framac-slice` Step 5 checkpoint moves after `build-check`;
    - Step 3 runs `security_props.py run` once per run, not inside the per-module list.
  - **Guidance-mode commands:**
    - in `framac-fuzz` (the `campaign` command) and `framac-eva` (`run_eva_slice.py`), the gate check `phase0_gates.py check --module <mod>` comes first;
    - `run_eva_slice.py` refuses a module whose gate failed when the run directory has a stamp. R6 does the same for `campaign`.
  - **The reach gate and the DAG (defect 12, gate half):** the reach stamp records the DAG's digest. A DAG rebuilt after the check fails the gate until `harness_reach.py check` runs again. The `harness_digest` check stays.
  - **Exemptions:** the static gate matches exemptions by DAG key (`harness_reach.py`, `check_module`), and the dynamic gate also by plain name (`run_dynamic`, `apply_dynamic`). Both should take the key and a unique plain name.
  - **`build_check.json`:**
    - a module the reach gate stopped records `not_built` with the gate's reason;
    - `sweep_list`'s fallback to a same-named record (a stale DAG without the callee's record) warns.
  - **Fuzz budget** (`allocate_fuzz_budgets`):
    - a `params.json` budget above the unit's cap is kept, with a tuning warning;
    - when the 30 s minimum per module pushes a unit over its cap, `gen` warns rather than exceeding it silently.
- **Owns:** `templates/pipeline.mk`, `scripts/pipeline_make.py`, `scripts/phase0_gates.py`, `scripts/harness_reach.py`, `scripts/run_eva_slice.py` (gate check), `skills/framac-slice`, `skills/framac-verify`, `skills/framac-fuzz`, `skills/framac-eva`.
- **Tests:**
  - the phase 0 checkpoint is absent after `seed` and present after a passing `build-check`;
  - a DAG rewritten after the check fails the gate;
  - plain-name and key exemptions behave the same in both gates;
  - budget warnings;
  - the recipe tests in `test_phase0_make_recipes.py` and `test_phase0_gates.py`.
- **Acceptance:** no path in the skills, Make or the scripts reaches fuzz, Eva or WP while a gate fails or is stale.

### R2. Ledger seed and fuzz ingest (M)

- **Goal:** re-seeding follows the current DAG, and fuzz verdicts land on renamed statics as Eva verdicts do.
- **Work:**
  - **Defect 11:**
    - `ingest-fuzz` places a candidate's location on its unit by line range (`_dag_line_index`, as Eva ingest does);
    - the model's `kernel_names` maps a kernel-renamed static (`f_0`) back to its `file#name`;
    - the name is used only for a location without a line.
  - **Defect 12, seed half:** `ledger.py seed --refresh` re-derives the units with no evidence from the current DAG: planned, deferred and out of scope. It:
    - adds the new functions and classes;
    - marks units whose function left the DAG `out_of_scope` with a reason;
    - never touches a unit with evidence;
    - reports what changed.

    Plain `seed` keeps its "never rewind" behavior.
  - **The seed checks its inputs:**
    - it refuses when the reach gate failed (`phase0_gates.check(need=("reach",))`), as `wp_scheduler.py init` does since `60107a9`;
    - it refuses when `security_props.json` is missing while the model has a threat model, rather than seeding without the MetAcsl classes.
  - **Stale-DAG fallbacks:** `audit-hypotheses` warns when it falls back to the first same-named record (a callee key with no DAG record).
  - **Old classes:** drop the dead maps of the pre-I9 Layer 4-6 classes (`LAYER_TO_CLASS`, `ledger.py:81`, `:84`, `:1474`). The ledger schema enums keep them while old ledgers may be read (decided in R10; D8 then dropped them everywhere).
- **Owns:** `scripts/ledger.py`, `schemas/coverage-ledger.schema.json`.
- **Tests:**
  - fuzz ingest of a `f_0` candidate;
  - `--refresh` after a DAG change (added function, removed function, unit with evidence untouched);
  - the seed refuses a failed gate and a missing `security_props.json`.
- **Acceptance:** a re-run of Phase 0 on a changed target needs no new ledger; the tests above pass.

### R3. Trust, threat model and security properties (S, after R4's version helper)

- **Goal:** trust and the MetAcsl properties come from the same threat model, and a bad threat model stops the run outside the skill too.
- **Work:**
  - **Defect 9:**
    - `acsl_ast.is_trust_boundary` already takes a `file`, but its callers in `workspace_overlay.py` (the merge's trust-boundary check and `prepare_agent`'s reachability) pass only the name;
    - pass the file, and make sure the records `function_trust_records` and `trust.py` build are keyed per `file#name`;
    - same-named functions keep their own trust.
  - **Invalid threat model:** `security_props.py run` exits non-zero when the model records `invalid_threat_model`, so Make's `security-props` and the benchmark stop with the errors. A missing one stays `no_threat_model` with Layer 3 only.
  - **One threat model:**
    - `security_props.py` and `trust.py run` (CodeQL re-runs) read the path and sha256 the model recorded (`model.trust.threat_model`), not `find_threat_model` again;
    - a file whose sha256 changed since the model was built stops them, with a message to re-run the model.
  - **Validation:** `trust.py run` validates the model it rewrites. `security_props.py` follows R5's policy on its own schema errors.
  - **Version checks:** adopt R4's model-feature helper in `trust.py` and `security_props.py`, replacing their own field sniffing.
- **Owns:** `scripts/trust.py`, `scripts/security_props.py`, `scripts/workspace_overlay.py`, `scripts/acsl_ast.py`, `scripts/codeql_trust.py`.
- **Tests:**
  - two same-named functions with different trust;
  - an invalid threat model makes `security_props.py run` exit non-zero;
  - an edited threat model is refused until the model is rebuilt;
  - `--threat-model` outside the search order is honored downstream.

### R4. Model, DAG and versions (M)

- **Goal:** old artifacts are recognized the same way everywhere, and a stopped model is resumable.
- **Work:**
  - **`no_unit_parsed` in the checkpoint:** `phase0_model.py` records it as `needs_build_recipe` is recorded (`checkpoint.py` status), and a resume shows the units' errors and restarts at the model.
  - **GCC paths:**
    - `gcc_callgraph` and `macro_aliases` resolve the paths GCC prints against the compile's `cwd`, then the tree (`phase0_model.py`, `tree_rel` callers);
    - a test uses `-I../include` from a subdirectory.
  - **Versions:**
    - the model's `schema_version` goes to 2;
    - a helper `model_features(model)` reports `external_calls`, `formals`, `writes`, `trust` and `kernel_names`;
    - `build_callgraph_dag.py` warns in the DAG's `warnings` when a feature is missing, rather than silently dropping the `dynamic_allocation` blocker, Tier 2 and format/write detection;
    - the DAG gets its own `schema_version`, and `block_fallback_units` stamps it, so consumers can tell a DAG that predates defect 6.
  - **Fallback report (D2):** `generate_report.py` lists GCC-fallback units with their first Frama-C error and what was deferred, next to the trust table.
  - **Unread fields:** decide per field and record it in the schema description: `included`, `thread_entries`, `parse_jobs`, `alias`, and the DAG module fields `cross_module_callees`, `provable_functions`, `shell_unverifiable_functions`, `tier_counts`, `recommended_strategy`, `deferred_profiles`, `entry_trust`, and function `indirect_callees`. Keep a field the report or the benchmark should show, and drop the rest.
  - **Old classes:** drop them from `generate_report.CLASSES` once R10 decides on old ledgers.
- **Owns:** `scripts/phase0_model.py`, `schemas/phase0_model.schema.json`, `scripts/build_callgraph_dag.py`, `scripts/checkpoint.py`, `scripts/generate_report.py`.
- **Tests:**
  - resume after `no_unit_parsed`;
  - GCC paths from a subdirectory compile;
  - a model without `external_calls` gives a DAG warning;
  - the report lists a fallback unit.

### R5. Contracts and validation (M, after R1–R4)

- **Goal:** every Phase 0 artifact has a schema, and one place checks them.
- **Work:**
  - **New schemas:**
    - `callgraph_dag.json` (modules, `submodules`, `lexer_modules`, functions, `callgraph_fallback`, `eva_wp_blocked`, `fuzz_engine`);
    - harness sidecars;
    - `build_check.json`;
    - the dynamic reach report.
  - **`validate_artifacts.py run-dir`** also validates `build_capture.json`, `phase0_model.json`, `security_props.json` and the DAG when present. `make seed` already runs it.
  - **One self-validation policy:** producers write their artifact and record schema problems as warnings; `validate_artifacts run-dir` fails on them. Today `build_capture` and `phase0_model` warn, `security_props` exits 2, and `trust.py run` does not validate. R3 aligns `security_props` and `trust`.
  - **Sidecar `scope_files`:** `module_map.py` reads it and the slice skill documents it, but `generate_harness.py` never writes it, and a regeneration drops it. Either `generate_harness.py` writes and keeps it (`--scope-file`), or the read and the doc go. Recommendation: write it, because sub-module scope is otherwise only the lexer module or the sources.
  - **`infer_unit`:** vote by DAG key, not plain name (`module_map.py`).
  - **Since the API-reach work (`c5a8381`..`684052f`):** the sidecar schema covers `api_harness`, `api_cases` (each case's `selector`, `kind`, `calls`, `slots`, `rest`, `entry`) and `api_skipped`; a schema for `seed_harvest.json` (with `source`, `executables`, `runs`, `traces`) and one for the lines of `workspace/seed_records/traces.jsonl`; `scope_files` survives a regeneration through `generate_harness.py --api` too.
- **Owns:** `schemas/` (new files), `scripts/validate_artifacts.py`, `scripts/module_map.py`, `scripts/generate_harness.py`, `scripts/api_harness.py` (sidecar writing only).
- **Tests:**
  - each schema accepts the producer's output on the recorded fixtures and rejects a broken one;
  - `validate run-dir` catches a DAG with a wrong shape;
  - `scope_files` survives a regeneration.

### R6. Fuzz side (S)

- **Goal:** coverage counts only target code, and every replay path builds the right harness.
- **Work:**
  - **Defect 10:** add the snapshot root (`workspace/snapshot/root/`) to `COVERAGE_EXTERNAL_PREFIXES` (`run_eacsl_fuzz.py`), so snapshot headers no longer count as target code.
  - **Defect 8's fallback path:** `_sidecar_build_spec`, used when `pipeline_make` cannot be imported, takes the candidate's file and function through `harness_module_for_function`.
  - **Gate in guidance mode:** `campaign` refuses a module whose gate failed when the run directory has a stamp (R1 does `run_eva_slice.py`).
- **Owns:** `scripts/run_eacsl_fuzz.py`.
- **Tests:**
  - a coverage report with snapshot paths;
  - the fallback spec for a sub-module candidate;
  - `campaign` refused on a failed gate.

### R7. WP side (M)

- **Goal:** each harness's header gets its architect, and gating follows sub-module scope.
- **Work:**
  - **Defect 13:**
    - `wp_scheduler.py` keeps one header task per harness sidecar's `header`, not one per unit from the merged sidecar's first header (`header`, `merged_sidecar`);
    - gating moves from the unit to the sub-module scope (`contributors`, `inert`) where a sub-module's candidates only concern its own functions.
  - **Dead reads:** the DAG module `header`/`headers` and `skipped` (`header`, `inert`) are never produced. Drop them, or produce `header` from the sidecars in R5's sidecar schema.
  - **Old class names:** `run_wp_function.py:75-76`, `skills/framac-wp/prover_brief.md:155`, and `breaker_brief.md:29` (`g_sec_auth_verified` from the deleted Layer 4 template).
- **Owns:** `scripts/wp_scheduler.py`, `scripts/run_wp_function.py`, `skills/framac-wp`.
- **Tests:**
  - a unit with two harnesses and two headers gets two architect tasks;
  - a sub-module's candidate does not gate another sub-module's functions.

### R8. Capture, images and tooling (M)

- **Goal:** the build capture and the images do what I2, I3b and I10c meant, without manual steps.
- **Work:**
  - **Capture timeout:** a build that times out is retried once, serially, on a fresh copy, as a non-zero exit already is (`build_capture.py`, the `timed_out` branch; CryptoLib stalled under `bear` without the broker).
  - **Generated headers:** `config.h` and the other headers generated in the build tree reach the analyses. Add the build tree's generated-header directories from the capture to the snapshot include path (`target_env.py`, `framac_common.augment_framac_cppflags`). No benchmark target needs it yet, so it needs a fixture.
  - **Resource classes:** `resources.py` infers classes for `build_capture.py run` and `seed_harvest.py record` (`phase-dynamic`) and `codeql_trust.py run`, so callers stop passing them.
  - **Images:**
    - create `/framac-scratch` (mode 1777) in both images, and drop the wrappers' `chmod` and compose's manual step;
    - CI runs `image_toolchain.py` on both images (same gcc and glibc), the E-ACSL canary, and a snapshot check on the analysis image. The image build keeps only the model selftest.
    - The decision table's "common base stage" stays aligned by pinned digests: document that, or add a shared stage if the two Debian bases can be one.
  - **`pyproject.toml`:** add the 19 missing script modules to `known-first-party`.
- **Owns:** `scripts/build_capture.py`, `scripts/target_env.py`, `scripts/framac_common.py` (include path only), `scripts/resources.py`, `Dockerfile`, `.github/workflows/`, `wrappers/`, `docker-compose.yml`, `pyproject.toml`.
- **Tests:**
  - a timed-out build retried serially (recorded runner);
  - a generated header on the include path;
  - class inference;
  - wrapper tests without `chmod`;
  - Docker-backed: the scratch directory exists for a non-root user.

### R9. Benchmark (M)

- **Goal:** the benchmark runs the Phase 0 sequence the skill runs, and its baselines keep every replay.
- **Work:**
  - **Stages:**
    - both benchmarks run `coverage` and `reach-dynamic` before ingest, as `framac-verify` does;
    - `benchmark.py` stops a target after a failed capture or model, as `benchmark_seeded.py` does, rather than relying on the DAG's exit 2;
    - the phase 0 checkpoint follows R1 (after `build-check`).
  - **Baseline merge:** `merge_runs` merges a bug's replays per target instead of replacing the bug entry, so a later per-target run keeps the other target's replay.
    - This explains QCBOR-02/03 reading `retained (partial)` with qcbor-dev's `ieee754` replay `not_run` in every baseline since `phase0-i5a`.
    - Re-check those two bugs on qcbor-dev in V.
  - **D7:** remove the manifest's `compile_commands` and CryptoLib's asset, with the baseline re-record.
  - **D6:** `CORPUS` points at `tests/fixtures/phase0/seeded/`, then the tracked files of `poc/phase0/` go (`git rm`). `poc/phase0/out/` is the benchmark's untracked work directory (checkouts, runs, results) and stays; move the default work directory out of `poc/` only if nothing else points at it.
  - **`docs/benchmark.md`:**
    - the latest baseline;
    - `--compare default`, whose `default.json` is the pre-redesign `dagfix-2`;
    - CRYPTOLIB-01, retained since `bdba3fa`.
- **Owns:** `scripts/benchmark.py`, `scripts/benchmark_seeded.py`, `benchmark/manifest.json`, `benchmark/assets/`, `benchmark/baselines/` (merge only), `docs/benchmark.md`, `poc/`.
- **Tests:**
  - `merge_runs` keeps both targets' replays;
  - the stage list includes coverage and reach-dynamic;
  - a failed model stops the target;
  - the seeded scorer on the fixture copy.

### R10. Cleanup and records (S, last)

- **Goal:** the docs, briefs and comments describe the code as it is, and the accepted deviations are recorded.
- **Work:**
  - **Stale docs** from `phase0-downstream-effects.md` §8:
    - `skills/framac-eva`:
      - Step 4 states the old "all Valid → covered" rule;
      - lines 67 and 74 use the Layer 6 `\tainted` idiom;
      - Step 1 says nothing about units.
    - `skills/framac-fuzz:96` lacks `--extra-corpus`.
    - `docs/troubleshooting.md:217` recommends `Typed+cast`.
    - `docs/resources-and-caching.md`: the toolchain id without `+snapshot`, and the target table lacks `reach-gate`, `seeds` and `reach-dynamic`.
    - `docs/v2-design.md:185` (Tier 3 and Eva).
    - `docs/agentic-swarm.md:22` (directory module names).
    - `docs/phase0-implementation-plan.md` (`--no-model` in the I5a note: mark it historical).
  - **Comments** that say the DAG is keyed by plain name, or that a missing model gives lexer modules: `module_map.py`, `wp_scheduler.py`, `workspace_overlay.py`, `harness_reach._module_entries`, `pipeline_make.py`. This step goes after R1–R7 have merged, since it touches their files.
  - **Test fixture:** `tests/test_wp_scheduler.py` builds an old-shape DAG (plain keys, `name_collisions`, no link units). Move it to the link-unit shape.
  - **Old classes:** decide whether ledgers from before I9 must still load. If not, drop the pre-I9 Layer 4-6 classes from the schemas and `generate_report`, with R2 and R4 (decided: D8).
  - **Records:**
    - the decisions D2–D5 go into the implementation plan's decision table;
    - a short glossary in `phase0-downstream-effects.md` §3: `unit` is a capture path in `modules[*].unit` and `indirect_sites[].unit`, but a DAG module name in `submodules[*].unit` and sidecars;
    - defect 14 recorded as a limit (D5).
- **Owns:** `docs/`, comments in the files above (after their steps), `tests/test_wp_scheduler.py` fixtures.

### V. Validation run and baseline (user-triggered)

- **When:** only when the user asks. Per D1, once on today's tree before the merge, and again after R1–R9.
- **Runs:**
  - the full benchmark, all sets;
  - the seeded set;
  - `FRAMAC_DOCKER_TESTS=1 python -m pytest`, which covers the reproducers' truth, including the model changes of defects 17 and 20.
- **Check the expected changes:**
  - WP refused on stale harnesses (defect 16);
  - more `shell_unverifiable` functions (defect 2);
  - `l3_frame` units (defect 5);
  - fallback deferrals (defect 6);
  - the `harness_module` field in replay results (defect 8);
  - reached header functions and seeds through embedded API on tweetnacl (defect 19);
  - remapped-id warnings (defect 20);
  - QCBOR-02/03 on qcbor-dev (R9).
- **Then:** re-record the baseline (`phase0-r1`) with every unit-count change explained, and merge.

## Order and parallelism

```text
R1 ─┐
R2 ─┤
R4 ─┼─▶ R3 ─┐
R6 ─┤       ├─▶ R5 ─▶ R10 ─▶ V
R7 ─┤       │
R8 ─┤       │
R9 ─┴───────┘
```

- **R1, R2, R4, R6, R7, R8 and R9** own disjoint files and can run in parallel, as subagents or sessions.
- **R3** needs R4's `model_features` helper only for its last item, so it can start in parallel and finish after R4.
- **R5** writes schemas for the shapes R1–R4 settle, so it comes after them.
- **R10** edits comments in files the other steps own, so it comes last.
- **Two coordination points:**
  - R1 and R9 both move the phase 0 checkpoint after `build-check` (Make and the benchmark);
  - R1 and R6 both add a gate check to a guidance-mode script.

## Backlog (not planned)

These are known limits of the design, recorded in the step notes. None is a defect of the implementation. Each would be its own step, with a measurement.

- **Trust of header inline API:** a public header's `static inline` functions count as untrusted only when the threat model lists them (`trust.py`). Worth promoting: it decides tiers and the reach gate for QCBOR-style APIs.
- **L3 over-approximation:** a libc writer call counts as a pointer write even into a local, which creates frame obligations WP must discharge (`security_props.py`). Worth promoting if Phase 3 time on `l3_frame` units shows up in V.
- **Alias:** trust narrowing on pointers read from `const` globals only (I4 follow-up); it covers all of x509-parser's narrowed sites.
- **Seeds:**
  - calls through header inlines;
  - the encoder harnesses;
  - struct members deeper than one `{ptr, len}` level.
- **MetAcsl:**
  - `L5_no_crlf` on string literals;
  - `memset` wipes under Typed;
  - indirect leaks (copies need Eva taint);
  - `return`-kind secrets (warning only).
- **CodeQL:** facts outside the model (CMake probes) are counted as unmatched rather than filtered.
- **Mechanical dispatch** (seeded set): cases with undeclared callees or gcrypt types are not filtered.
- **Pre-I7 models:** a warning only. R4's version helper makes this uniform.
- **One configuration per shared source file (defect 14, D5):** a file compiled by several units with different flags is parsed, analysed and proved only in the first unit's configuration, so the other units' `#if` branches and `-D` values go unchecked. qlz's four executables are the only benchmark target with the shape. The fix, when a target needs it: one parse per (file, configuration) and per-unit DAG views.

## Status

| Step | Size | Status |
| :--- | :--- | :--- |
| R1 | M | done, `c689c1b` |
| R2 | M | done, `ea9be7b` |
| R3 | S | done, `152970e` |
| R4 | M | done, `27f443d` + `f0cbf3c` (the three DAG fields D9 drops) |
| R5 | M | done, `630e09e` |
| R6 | S | done, `b3298c1` |
| R7 | M | done, `3c68074` |
| R8 | M | done, `47d7c89` |
| R9 | M | done, `28101de` |
| R10 | S | done |
| V | — | first run done on the pre-R tree (`docs/progress/validation-r1-2026-11-08.md`, baseline `phase0-r1`); the second, pending, runs after R1–R10 (D1′) and records `phase0-r2` |
