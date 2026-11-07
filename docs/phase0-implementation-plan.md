# Phase 0 implementation plan

This plan turns the target Phase 0 in [`phase0-redesign.md`](phase0-redesign.md) into implementation steps. The proof of concept in `poc/phase0/` validated the core of that design.

## Decisions (2026-11-07)

| Question | Decision |
| :--- | :--- |
| How the work lands | Everything stays on `phase0-redesign` and merges to `main` once, at the end. `main` is merged into the branch regularly, starting with `156adfa`. |
| Image dependencies | MetAcsl, the CodeQL CLI (downloaded at image build, off by default) and `strace` (for test-input harvesting) may be added. |
| Target does not build | Phase 0 **stops**. It records `needs_build_recipe` with diagnostics, and the parent agent asks the user for a build command, packages or flags. There is no inventory from the lexer. |
| Frama-C cannot parse a unit | The GCC call-graph fallback runs, flagged in the ledger and the report. Fuzzing with sanitizers still runs; Eva and WP on that unit are reported blocked. Phase 0 stops only if no unit parses. |
| The lexer | Deleted at the end. `build_callgraph_dag.py` keeps only the DAG-view writer. |
| Seed inputs from tests | The project's test suite runs inside the sandbox with file-access tracing. The data files the tests read become seed inputs. |
| Threat model | A structured, machine-readable block in `THREAT_MODEL.md` (input sources, secrets, auth gates, output sinks). If it is missing, Phase 0 records `no_threat_model` rather than guessing. |
| Benchmark baseline | Re-recorded at each step that changes units, after review. Recall of known bugs must never drop, and every change in unit counts is explained in the step's notes. |

Defaults taken where nothing was asked (open to change):

- **Header `static inline` functions** get a ledger unit only when reached from an entry point.
- **Test executables** are units marked `test`. They get no harness and no ledger unit.
- **Libraries compiled straight into an executable:** the globals declared in project headers are their API.
- **Unit split threshold:** calibrated on the benchmark. The starting guess is 150 functions or 5k lines.
- **Fuzz budget** scales with the number of harness cases, up to a cap per unit set by the profile.

## Rules for every step

- **Ownership.** Each step lists the files it owns. Steps that can run in parallel own disjoint files.
- **Tests.**
  - Unit tests go in `tests/`, stdlib only, with recorded fixtures.
  - Docker-backed integration tests carry the `integration`/`slow` markers.
  - The 9 reproducers and the 7 seeded projects move to `tests/fixtures/phase0/` in I0 and become the integration fixtures.
- **Acceptance gates for every step, besides its own:**
  - `ruff`, `ruff format --check`, `mypy scripts tests` and the full pytest suite pass;
  - the reproducers score 1.00 wherever the step touches inventory;
  - no known bug is lost on the benchmark.
- **Docs and skills** change in the step that changes behavior, never later.

## Steps

### I0. Branch groundwork

- **Goal:** start from current `main` with the PoC's assets usable as test fixtures.
- **Work:**
  - merge `main` (`156adfa`) into `phase0-redesign`;
  - copy `poc/phase0/reproducers/` and `poc/phase0/seeded/` to `tests/fixtures/phase0/`;
  - add a pytest helper that runs a fixture through Docker (skipped when Docker is absent);
  - record a branch benchmark baseline with qcbor-dev included now that it passes Phase 0.
- **Owns:** `tests/fixtures/phase0/`, `tests/conftest.py` helpers, `benchmark/baselines/`.
- **Acceptance:** the suite passes, and the baseline is recorded with all 10 targets.

### I1. Phase 0 gates become Make dependencies

- **Goal:** the reach gate and build-check can no longer be skipped. This step needs no new analysis.
- **Work:**
  - `pipeline.mk`: `seed` and `gen` depend on `reach-gate` (`harness_reach.py check`) and `build-check`;
  - `pipeline_make.py`: `gen` refuses modules that failed either gate, unless the module is exempted;
  - `validate_artifacts.py` checks both reports;
  - update the slice and verify skills.
- **Owns:** `templates/pipeline.mk`, `scripts/pipeline_make.py` (gate wiring only), `scripts/validate_artifacts.py`, `skills/framac-slice`, `skills/framac-verify`.
- **Acceptance:** a run with a reach gap or an E-ACSL fallback stops before seeding. The benchmark is unchanged.

### I2. Build recipe and build capture

- **Goal:** Phase 0 knows exactly what the build compiles, links and exports, or stops and asks.
- **Work:**
  - **Build recipe:** `run-metadata.json` gets a `build` block (command, packages, environment, working directory). It is set by the user or proposed by the agent and confirmed by the user, and recorded for resume.
  - **`scripts/build_capture.py`,** promoted from `phase0b.py`'s capture code:
    - runs the build under `bear intercept` in a scratch copy, through `sandbox_exec.py` (`phase-dynamic`);
    - parses compile, link and archive steps;
    - drops build-system probes;
    - derives link units, marks test units, and reads per-file flags (`-I -D -U -include -imacros -iquote -isystem -std`);
    - takes exports from `nm -D` and version scripts, and public headers from `make install DESTDIR=` with a fallback to headers outside the source directories.
  - **Output:** `workspace/reports/build_capture.json`, with a schema.
  - **Stop and ask:** a failed build writes `phase0.status = needs_build_recipe` with the first error, missing headers and candidate `-dev` packages. The slice skill tells the agent to ask the user.
- **Owns:** `scripts/build_capture.py`, `schemas/build_capture.schema.json`, `scripts/run_metadata.py` (build block), `skills/framac-slice` (recipe section).
- **Tests:**
  - unit tests on recorded `bear` event files (compile+link in one command, `ar`, `-l` resolution, probes, joined vs. separate flags);
  - integration tests on all reproducers (units and entry points as in their truth files).
- **Acceptance:**
  - reproducer units and entry points match their truth files 100%;
  - the benchmark targets build, CryptoLib with its packages;
  - a target with a broken build stops with a usable diagnostic.

### I3. Frama-C model

- **Goal:** one Frama-C parse per link unit gives the inventory and the call graph, named as Eva and WP will name them.
- **Work:**
  - **`scripts/phase0_dump.ml`,** promoted from `p0_dump.ml`, reports:
    - definition locations, storage and signatures;
    - direct calls, indirect call sites and address-taken functions;
    - functions passed as arguments (threads, callbacks);
    - loops.
  - **`scripts/phase0_model.py`:**
    - parses each unit with its per-file flags and saves the session (`workspace/framac/<unit>.sav`);
    - collects metrics (`-metrics -metrics-by-function`: lines, cyclomatic complexity);
    - extracts macro aliases (`gcc -E -dM` per translation unit, keeping `#define a b` where `b` is a defined function);
    - marks thread entries and concurrent units;
    - links header `static inline` functions to the units that compile them.
  - **GCC fallback:** for a unit Frama-C cannot parse, `-fcallgraph-info`, flagged with the first Frama-C error.
  - **Output:** `workspace/reports/phase0_model.json` with a schema. Every fact carries its source.
- **Owns:** `scripts/phase0_model.py`, `scripts/phase0_dump.ml`, `schemas/phase0_model.schema.json`.
- **Tests:**
  - unit tests on recorded dumps (static collisions, aliases, thread spawns, header inline functions);
  - integration tests on all reproducers;
  - a forced parse failure to exercise the GCC fallback.
- **Acceptance:**
  - reproducers score 1.00 on every class;
  - all benchmark targets parse;
  - the GCC fallback produces edges and a flag on the forced failure.

### I4. Narrowing function-pointer edges with Alias (parallel with I5)

- **Goal:** fewer spurious indirect edges, without losing true ones.
- **Work:** run `-alias` in the I3 parse and intersect its targets with the signature match. Measure on the benchmark targets (x509-parser has 163 indirect edges) and on the reproducers and seeded projects. Adopt it only if precision rises with recall unchanged on fixtures where indirect edges are exact (r03, r08, r09, s02).
- **Owns:** the Alias part of `scripts/phase0_model.py` (coordinate with I5 on the model schema only).
- **Acceptance:** a measured report in `docs/phase0-redesign.md`. Alias is adopted or rejected with the numbers.

### I5. Switch the pipeline to the model

- **Goal:** every Phase 0 consumer reads the model. Modules become link units.
- **Work:**
  - **`build_callgraph_dag.py`** writes the DAG view from the model:
    - modules = units, or sub-modules after I9;
    - `required_sources` = unit sources plus the sources of linked libraries;
    - `cppflags` per unit;
    - API entry points, aliases, and provenance per function.

    The lexer code stays until I12, unused.
  - **Harness sub-modules:** a sidecar may name a harness module inside a unit (`unit` field), so a unit can have several harnesses, as QCBOR's 8 harnesses do today. `pipeline_make.py` maps each sidecar to its unit's sources and flags.
  - **`ledger.py seed`:**
    - units only for functions in non-test units;
    - header `static inline` functions only when reached;
    - `callgraph_source` per unit, and fallback units flagged.
  - **`harness_reach.py`:** checks units, API entry points and aliases.
  - **`generate_harness.py`:** resolves aliases and uses the unit flags, including `-include`.
  - **`wp_scheduler.py` and `audit-hypotheses`:** use indirect edges.
  - **Benchmark manifest:** module names move to unit or sub-module names. Recall is checked, and the baseline re-recorded.
  - **Seeded benchmark:** joins `scripts/benchmark.py` as a `phase0` set, using the PoC's mechanical harness policy as a deterministic check.
- **Owns:** `scripts/build_callgraph_dag.py`, `scripts/ledger.py` (seed), `scripts/harness_reach.py`, `scripts/generate_harness.py` (aliases, unit flags), `scripts/pipeline_make.py` (modules), `scripts/wp_scheduler.py` (edges), `benchmark/manifest.json`, `scripts/benchmark.py`.
- **Acceptance:**
  - benchmark recall unchanged;
  - Eva-analysed functions with no ledger unit: 0 on every target;
  - the seeded set finds 7/7 bugs and fires 0 decoys;
  - baseline re-recorded with the unit changes explained.

### I6. Hand-off to Phase 1 (parallel with I7 and I8)

- **Goal:** fuzzing starts from real inputs and gets a fair budget, and Phase 1 coverage reaches back into Phase 0.
- **Work:**
  - **Test-input harvesting:**
    - run the project's tests (`make test`/`check`, `ctest`, or a command in the build recipe) in the sandbox under `strace -f -e trace=openat`;
    - keep the regular files the tests open for reading inside the target tree, excluding sources, objects and binaries, capped by size and count;
    - store them in `workspace/seeds/<unit>/`.
  - **Seed adaptation:** each harness gets the seeds in its own format. A dispatch harness gets one copy per buffer-taking case, prefixed with that case's selector byte. They are passed to `campaign` through `--extra-corpus`, which exists but is not wired.
  - **Dictionary:** `fuzz_dictionary.py` adds integer and string values of macros from the unit's `gcc -E -dM`.
  - **Fuzz budget:** set per harness case, capped per unit and profile.
  - **Dynamic reach gate:** after `coverage-<mod>`, an API entry point with zero executions reopens the reach gate (`reach-dynamic` target). The parent then repairs the harness or records an exemption.
  - **Image:** add `strace`.
- **Owns:** `scripts/seed_harvest.py` (new), `scripts/fuzz_dictionary.py`, `templates/pipeline.mk` (fuzz and coverage recipes), `scripts/pipeline_make.py` (budget), `scripts/harness_reach.py` (dynamic mode), `Dockerfile` (strace), `skills/framac-fuzz`.
- **Acceptance:**
  - on minmea and QCBOR, seeds come from their tests;
  - coverage per entry point after a quick campaign is at least today's;
  - a seeded fixture whose bug needs a structured input is found with seeds and missed without;
  - an unreached entry point reopens the gate.

### I7. Performance and reuse of the parse (parallel with I6 and I8)

- **Goal:** Phase 0 costs about what the build costs, and later phases stop re-parsing.
- **Work:**
  - parse each source once per flag set;
  - parse units in parallel under the resource broker (new class `parse`);
  - skip test units;
  - Eva, WP, `kernel_ast.py` and `function_facts.py` load the saved session when the digest of sources and flags matches, and parse otherwise.
- **Owns:** `scripts/phase0_model.py` (scheduling), `scripts/resources.py` (class), `scripts/run_eva_slice.py`, `scripts/run_wp_function.py`, `scripts/kernel_ast.py`, `scripts/function_facts.py` (load path only).
- **Acceptance:**
  - Phase 0 wall time ≤ build time + 2× the lexer's on every benchmark target;
  - Eva and WP parse time measurably lower;
  - results identical with and without the saved session.

### I8. Trust boundary (parallel with I6 and I7)

- **Goal:** `untrusted_surface` is derived from evidence, not a default.
- **Work:**
  - **Threat-model schema:** the structured `THREAT_MODEL.md` block (`input_sources`, `secrets`, `auth_gates`, `output_sinks`) with a validator. A missing block records `no_threat_model` on every unit.
  - **Input-path pass** on the model:
    - **input functions:** `read`, `recv`, `recvfrom`, `fread`, `fgets`, `getline`, `getenv`, argv of `main`, plus the threat model's `input_sources`;
    - **untrusted:** the API functions and callers on a call path to an input function, and every API function of a unit the threat model marks as exposed;
    - **output:** `trust` per function in the model.
  - **CodeQL (optional):**
    - downloaded at image build;
    - enabled per run in `run-metadata.json` when the user declares the target open-source;
    - its source-to-sink facts refine `trust` and never widen it silently, recorded with `source: codeql`.
  - **Consumers:**
    - the sidecar's `reachability` defaults from `trust`;
    - the trust-boundary check in `acsl_ast.py` reads it;
    - the report shows the trust source per entry point.
- **Owns:** `scripts/trust.py` (new), `schemas/threat_model.schema.json`, `Dockerfile` (CodeQL), `scripts/generate_harness.py` (reachability default only), `scripts/acsl_ast.py` (trust lookup only), `scripts/generate_report.py` (trust column).
- **Acceptance:** the reproducers and seeded projects get a `trust` truth field, which matches; CodeQL off changes nothing; CodeQL on adds `source: codeql` facts on minmea.

### I9. Tiers and unit split (after I8)

- **Goal:** tiers that tell units apart, and units small enough for Eva.
- **Work:**
  - **Per-function tier** from trust and complexity:
    - untrusted and complex → 1A or 1B, depending on input or output;
    - heap or recursive and untrusted → 2;
    - no untrusted path → 3.
  - **Module tier:** the highest of its functions'. Tier 3 is deferred under quick.
  - **Unit split:** split units above the threshold by call-graph clustering, anchored on entry points (each cluster is an entry point's reachable set, merged where they overlap above 50%). The clusters become sub-modules for Eva and harnesses.
  - Calibrate the threshold on CryptoLib and QCBOR Eva times.
- **Owns:** `scripts/tiers.py` (new), `scripts/unit_split.py` (new), `scripts/build_callgraph_dag.py` (view fields), `skills/framac-slice` (tier table).
- **Acceptance:**
  - Tier 3 is non-empty and justified on the benchmark;
  - quick profile time drops with recall unchanged;
  - Eva converges on CryptoLib's largest unit after the split.

### I10. Security layers via MetAcsl (after I8)

- **Goal:** L3–L6 obligations come from what the threat model requires, not from what the code already does.
- **Work:**
  - **Image:** install MetAcsl at a pinned version.
  - **Property generation**, from the structured threat model:
    - **L4:** auth gates become "only gate functions write the auth state, and privileged functions require it";
    - **L5:** output sinks become sanitization properties on writers;
    - **L6:** secrets become "wiped before release" and "never flows to output sinks".
  - **L3:** a frame (`assigns`) obligation for every function that writes through a pointer.
  - **Ledger:** new obligation classes keyed to the properties.
  - **Phase 3 briefs:** say which MetAcsl-generated annotations a prover must discharge.
  - Retire the per-function pattern matching of the old L5/L6 inference.
- **Owns:** `scripts/security_props.py` (new), `templates/metacsl/`, `Dockerfile` (MetAcsl), `scripts/ledger.py` (classes), `skills/framac-wp` (briefs).
- **Acceptance:**
  - a fixture with a secret that is never wiped produces an unproven L6 unit;
  - a fixture with a correct wipe proves it;
  - the existing L5/L6 templates are covered or explicitly dropped.

### I11. Mechanical harness contract check (after I5)

- **Goal:** harness-induced crashes are caught before they reach crash verifiers.
- **Work:**
  - before fuzzing, build each harness with E-ACSL checking the entry functions' `requires` clauses, taken from contract notes, existing ACSL and the I10 properties;
  - replay the corpus;
  - a precondition violation in a case is reported as a harness defect (`harness_contract_violation`), not a candidate, and sent back to the parent agent.
- **Owns:** `scripts/run_eacsl_fuzz.py` (new `contract-check` mode), `templates/pipeline.mk` (target), `skills/framac-fuzz`.
- **Acceptance:** the seeded decoys built to crash only outside their contract (`be16_at`, `load_be32`), when harnessed directly, are reported as harness defects. No real bug is reclassified.

### I12. Lexer removal, docs, and the single merge

- **Goal:** one Phase 0, documented, on `main`.
- **Work:**
  - delete the lexer analysis from `build_callgraph_dag.py`, its tests and its schema fields;
  - update the docs: `architecture.md`, `v2-design.md`, `troubleshooting.md`, the README, and the slice, verify and fuzz skills;
  - final full run: benchmark (all sets), reproducers and seeded set;
  - merge `phase0-redesign` into `main`.
- **Owns:** everything touched above, for cleanup only.
- **Acceptance:**
  - every gate above passes on the merged tree;
  - the remediation-style status table in this file is complete;
  - `poc/phase0/` is kept as history or removed (decide then).

## Order and parallelism

```text
I0 ─▶ I1 ─▶ I2 ─▶ I3 ─▶ I5 ─┬─▶ I6 ─────────────┐
                    │         ├─▶ I7 ─────────────┤
                    └─▶ I4    ├─▶ I8 ─┬─▶ I9 ─────┤
                              │       └─▶ I10 ────┤
                              └─▶ I11 ────────────┴─▶ I12
```

- **I1** is independent of the analysis work and comes first because it is small and protects everything after it.
- **I4** can run next to I5; it touches only the Alias part of the model.
- **I6, I7 and I8** own disjoint files once I5 is in, and can be parallel subagent or session work.
- **I11** needs I5. It improves once I10 provides more `requires` clauses, but doesn't depend on it.

## Risks

- **Build recipes for real targets.** Stop-and-ask moves effort onto the user for targets that don't build out of the box. Mitigation: candidate packages in the diagnostic, and the recipe recorded for resume and reuse.
- **Running test suites inside the sandbox** runs more target code, and some suites need a network or services. Mitigation: a time and resource cap, no network, and failures are non-fatal (seeds are an improvement, not a requirement).
- **The harness format change in I5** touches every benchmark harness spec. Mitigation: sub-modules keep today's harness granularity; the manifest is migrated by script, not by hand.
- **MetAcsl and CodeQL versions:** pin both, and add a selftest like the E-ACSL canary.
- **Frama-C upgrades** can break the dump module. Mitigation: a selftest (as `kernel_ast.py selftest`) runs at image build.

## Status

| Step | Status |
| :--- | :--- |
| I0–I12 | not started |
