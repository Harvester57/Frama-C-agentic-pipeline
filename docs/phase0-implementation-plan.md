# Phase 0 implementation plan

This plan turns the target Phase 0 in [`phase0-redesign.md`](phase0-redesign.md) into implementation steps. The proof of concept in `poc/phase0/` validated the core of that design.

Revised on 2026-11-07 after a review against the code:

- **Gates (I1):** the gates now produce a stamp the later targets require. Making `gen` depend on build-check was circular.
- **Saved-parse reuse:** the plan claimed Eva and WP could load Phase 0's saved parse. They can't, because they parse the harness or spliced contracts too. The remaining performance work moved into I3, and the old I7 is gone.
- **Seed inputs (I6):** they come from recording the API calls the tests make. Our targets' test inputs are inline literals, not files.
- **Trust boundary (I7):** library API is untrusted by default, and the input-path pass applies to executables. Threat models are written for three benchmark targets.
- **Contract check:** the old I11 is dropped. It relied on `requires` clauses that only exist after Phase 3.
- **I5 split:** I5a switches the inventory with modules held fixed. I5b makes link units the modules and maps sub-module reports back to their unit at ingest.
- **Added:**
  - build recipes for the benchmark;
  - all image changes in I0, with a MetAcsl feasibility test;
  - a selftest for the dump module;
  - concurrency in the report;
  - a size estimate per step.
- **CodeQL:** later the same day, it moved to its own image, keeping the main image free of it.
- **Two images:** a build image runs the target's build and tests. The Frama-C image runs everything else and no longer needs target packages: it uses a snapshot of the target's headers and libraries exported by the build. The new step I3b does the switch. The monolith stays until I10.

## Decisions (2026-11-07)

| Question | Decision |
| :--- | :--- |
| How the work lands | Everything stays on `phase0-redesign` and merges to `main` once, at the end. `main` is merged into the branch at the start of each step, starting with `156adfa`. |
| Images | Two images on a common base (same Debian release, same gcc), defined in one multi-stage Dockerfile. **Build image:** build systems, `bear`, `strace`, common `-dev` libraries, and per-target packages through small derived images. It runs the target's own build and its tests. **Frama-C image:** Frama-C, MetAcsl, the provers, and the compilers instrumented builds need (gcc, clang, libFuzzer), with no target packages. It runs everything else: parse, Eva, WP, E-ACSL and sanitizer builds, fuzzing, replay, coverage. **Snapshot:** the target's headers and libraries reach the Frama-C image through a snapshot the build exports. **CodeQL** gets its own image derived from the build image, off by default. The monolithic image stays until I10. |
| Target does not build | Phase 0 **stops**. It records `needs_build_recipe` with diagnostics, and the parent agent asks the user for a build command, packages or flags. There is no inventory from the lexer. |
| Frama-C cannot parse a unit | The GCC call-graph fallback runs, flagged in the ledger and the report. Fuzzing with sanitizers still runs; Eva and WP on that unit are reported blocked. Phase 0 stops only if no unit parses. |
| The lexer | Deleted at the end. `build_callgraph_dag.py` keeps only the DAG-view writer. |
| Seed inputs from tests | The project's test suite runs inside the sandbox. The arguments the tests pass to the API are recorded as seeds, and the data files they read are kept as a secondary source. |
| Threat model | A structured, machine-readable block in `THREAT_MODEL.md` (input sources, secrets, auth gates, output sinks). If it is missing, Phase 0 records `no_threat_model` rather than guessing. |
| Benchmark baseline | Re-recorded at each step that changes units, after review. Recall of known bugs must never drop, and every change in unit counts is explained in the step's notes. |

Defaults taken where nothing was asked (open to change):

- **Header `static inline` functions** get a ledger unit only when reached from an entry point.
- **Test executables** are units marked `test`. They get no harness and no ledger unit.
- **Libraries compiled straight into an executable:** the globals declared in project headers are their API.
- **Unit split threshold:** calibrated on the benchmark. The starting guess is 150 functions or 5k lines.
- **Fuzz budget** scales with the number of harness cases, up to a cap per unit set by the profile.

## Rules for every step

- **Ownership.** Each step lists the files it owns. Steps that run in parallel own disjoint files. The Dockerfile belongs to I0 only.
- **Size.** S is about a day of focused work, M a few days, L a week or more.
- **Tests.**
  - Unit tests go in `tests/`, stdlib only, with recorded fixtures.
  - Docker-backed integration tests carry the `integration`/`slow` markers.
  - The 9 reproducers and the 7 seeded projects become the integration fixtures in I0.
- **Acceptance gates for every step, besides its own:**
  - `ruff`, `ruff format --check`, `mypy scripts tests` and the full pytest suite pass;
  - the reproducers score 1.00 wherever the step touches inventory;
  - no known bug is lost on the benchmark.
- **Docs and skills** change in the step that changes behavior, never later.

## Steps

### I0. Branch groundwork and image (M)

- **Goal:** start from current `main` with the fixtures and every image dependency in place, and know whether MetAcsl can be used.
- **Work:**
  - merge `main` (`156adfa`) into `phase0-redesign`;
  - copy `poc/phase0/reproducers/` and `poc/phase0/seeded/` to `tests/fixtures/phase0/`;
  - add a pytest helper that runs a fixture through Docker (skipped when Docker is absent);
  - **images**, as stages of one multi-stage Dockerfile, while the monolithic image stays the default:
    - **base:** Debian release, gcc, Python, the hardening user;
    - **build image** (`framac-build`): base plus make, CMake, Meson, Ninja, `bear`, `strace`, `pkg-config` and a set of common `-dev` libraries;
    - **Frama-C image** (`framac-analysis`): base plus Frama-C, the provers, clang and libFuzzer, without build systems or target packages;
    - check that both report the same `gcc -dumpfullversion` and the same glibc;
  - **CodeQL image** (`Dockerfile.codeql`, tag `framac-codeql`):
    - built `FROM` the build image, adding the CodeQL CLI and the C/C++ query packs at pinned versions;
    - CodeQL extracts C by tracing the build, so it needs exactly what the build image has, and neither the main image nor the Frama-C image ever contains it;
    - it runs through the existing wrapper with `-Image` / `FRAMAC_DOCKER_IMAGE`, with the same mounts, hardening and disabled network;
    - unused until I7;
    - **MetAcsl feasibility test,** in the Frama-C image: build the release that targets Frama-C 34, or the development branch, against the image's `34.0~~dev` kernel, and run it on a 20-line example through WP and E-ACSL. Record go or no-go for I9;
  - record a branch benchmark baseline with qcbor-dev included, now that it passes Phase 0.
- **Owns:** `Dockerfile`, `Dockerfile.codeql`, `tests/fixtures/phase0/`, `tests/conftest.py` helpers, `benchmark/baselines/`.
- **Acceptance:**
  - the monolithic, build and Frama-C images build, with identical gcc and glibc in the last two;
  - no image other than the CodeQL image contains CodeQL;
  - the CodeQL image builds from the build image and answers `codeql version`;
  - the MetAcsl result is recorded in this file;
  - the suite passes, and the baseline covers all 10 targets.

### I1. Phase 0 gates that cannot be skipped (S, parallel with I2)

- **Goal:** fuzzing, Eva and Phase 3 never start on harnesses that failed the reach gate or the E-ACSL build check.
- **Work:**
  - **Stamp:** `harness_reach.py check` and `pipeline_make.py build-check` each write their result to `workspace/reports/phase0_gates.json`.
  - **`pipeline.mk`:**
    - `seed` depends on the reach gate (it runs after harness generation and needs no Makefile);
    - `fuzz`, `eva` and `wp-queue` depend on a passing stamp;
    - build-check stays after `gen`, as today, because it builds through the generated Makefile.
  - **`pipeline_make.py gen`:** the per-module `fuzz-`/`eva-` targets of a module that failed either gate print why and exit non-zero, unless the module is exempted.
  - **Benchmark:** `inner_phase0` calls the reach gate before `ledger.py seed`. The manifest records the exemptions its pinned harnesses need, each with a reason.
  - `validate_artifacts.py` checks the stamp. Update the slice and verify skills.
- **Owns:** `templates/pipeline.mk` (gate targets), `scripts/pipeline_make.py` (stamp and gate checks), `scripts/harness_reach.py` (stamp), `scripts/validate_artifacts.py`, `scripts/benchmark.py` (`inner_phase0` gate call), `benchmark/manifest.json` (exemptions), `skills/framac-slice`, `skills/framac-verify`.
- **Acceptance:**
  - a run with a reach gap or an E-ACSL fallback stops before fuzzing;
  - the benchmark passes with its exemptions listed;
  - recall is unchanged.

### I2. Build recipe and build capture (L, parallel with I1)

- **Goal:** Phase 0 knows exactly what the build compiles, links and exports, or stops and asks.
- **Work:**
  - **Build recipe:**
    - `run-metadata.json` gets a `build` block: command, packages, environment, working directory, and the test command used in I6;
    - it is set by the user, or proposed by the agent and confirmed by the user;
    - the checkpoint records `needs_build_recipe`, so a resumed run starts again at the capture.
  - **`scripts/build_capture.py`,** promoted from `phase0b.py`'s capture code, runs in the **build image**. It:
    - runs the build under `bear intercept` in a scratch copy on a per-run named Docker volume, through `sandbox_exec.py` (`phase-dynamic`). A named volume, not a host bind mount, because file I/O on a Windows/OneDrive mount made the PoC's QCBOR extraction 7× slower;
    - parses compile, link and archive steps;
    - drops build-system probes;
    - derives link units, marks test units, and reads per-file flags (`-I -D -U -include -imacros -iquote -isystem -std`);
    - takes exports from `nm -D` and version scripts, and public headers from `make install DESTDIR=` with a fallback to headers outside the source directories;
    - **exports a snapshot** of what the analysis side needs from the target's environment, with a digest:
      - **headers:** every header the compiler's dependency lists (`gcc -M`) name outside the project and outside libc. libc headers are told apart with `dpkg -S` (`libc6-dev`, `linux-libc-dev`), because Frama-C's own libc replaces them;
      - **libraries:** the static and shared libraries the link steps resolved (`-l` through `gcc -print-file-name`), plus the shared libraries those need (`ldd` on the built artifacts);
      - **generated headers** (`config.h` from configure or CMake) stay in the build tree on the volume.
  - **Wrappers** (PowerShell, sh, compose): create and mount the per-run volume, and pick the build image for build steps and the monolithic image for the rest. That changes in I3b.
  - **Output:** `workspace/reports/build_capture.json`, with a schema; the snapshot under `snapshot/` on the volume.
  - **Stop and ask:** a failed build writes `needs_build_recipe` with the first error, missing headers and candidate `-dev` packages. The slice and verify skills tell the agent to ask the user and resume.
  - **Benchmark:** every target gets a `build` recipe in the manifest:
    - tweetnacl's Makefile is a symlink stub on a Windows checkout, so it gets an explicit `cc` command;
    - CryptoLib gets CMake plus its packages;
    - minmea gets CMake with tests enabled and the `check` package.
- **Owns:** `scripts/build_capture.py`, `schemas/build_capture.schema.json`, `scripts/run_metadata.py` (build block), `scripts/checkpoint.py` (status), `wrappers/` and `docker-compose.yml` (volume, build image), `benchmark/manifest.json` (recipes), `scripts/benchmark.py` (recipe passing), `skills/framac-slice` (recipe section).
- **Tests:**
  - unit tests on recorded `bear` event files (compile+link in one command, `ar`, `-l` resolution, probes, joined vs. separate flags);
  - integration tests on all reproducers (units and entry points as in their truth files).
- **Acceptance:**
  - reproducer units and entry points match their truth files 100%;
  - all 10 benchmark targets build from their recipes;
  - a target with a broken build stops with a usable diagnostic and resumes after the recipe is fixed.

### I3. Frama-C model (L)

- **Goal:** one Frama-C parse per link unit gives the inventory and the call graph, named as Eva and WP will name them, at about the cost of the build.
- **Work:**
  - **`scripts/phase0_dump.ml`,** promoted from `p0_dump.ml`, reports:
    - definition locations, storage and signatures;
    - direct calls, indirect call sites and address-taken functions;
    - functions passed as arguments (threads, callbacks);
    - loops.
  - **`scripts/phase0_model.py`:**
    - parses each unit with its per-file flags, each source once per flag set, units in parallel under the resource broker (new class `parse`), test units skipped;
    - finds the target's headers in the snapshot (`-idirafter`) and the generated headers in the build tree, so the parse runs in the Frama-C image without target packages;
    - collects metrics (`-metrics -metrics-by-function`: lines, cyclomatic complexity);
    - extracts macro aliases (`gcc -E -dD` per translation unit, keeping `#define a b` where `b` is a defined function and the definition is in a project file);
    - marks thread entries and concurrent units;
    - links header `static inline` functions to the units that compile them.
  - **GCC fallback:** for a unit Frama-C cannot parse, `-fcallgraph-info`, flagged with the first Frama-C error.
  - **Dump selftest** (like `kernel_ast.py selftest`), run at image build and by the slice skill's setup.
  - **Output:** `workspace/reports/phase0_model.json` with a schema. Every fact carries its source.
- **Owns:** `scripts/phase0_model.py`, `scripts/phase0_dump.ml`, `schemas/phase0_model.schema.json`, `scripts/resources.py` (class `parse`).
- **Tests:**
  - unit tests on recorded dumps (static collisions, aliases, thread spawns, header inline functions);
  - integration tests on all reproducers;
  - a forced parse failure to exercise the GCC fallback.
- **Acceptance:**
  - reproducers score 1.00 on every class;
  - all benchmark targets parse;
  - the GCC fallback produces edges and a flag;
  - Phase 0 wall time ≤ build time + 2× the lexer's time on every benchmark target.

### I3b. The Frama-C image without target packages (L, after I3, parallel with I4 and I5a)

- **Goal:** one Frama-C image for every target. Target packages live only in the build image.
- **Why a snapshot, not a split by job:** Make runs inside a single container, and every Make target is phony. A recipe therefore cannot switch to another image partway through (that would need Docker inside the container, which is ruled out). So every stage that needs Frama-C (E-ACSL builds, the guardrail, Phase 3) stays whole in the Frama-C image and gets the target's environment from the snapshot.
- **Work:**
  - **Builds** (`run_eacsl_fuzz.py`: E-ACSL, sanitizer and coverage builds; the guardrail):
    - compile with `-idirafter <snapshot>/include`;
    - link against `<snapshot>/lib` with an rpath, so fuzzing, replay and the guardrail run the binaries without installed packages;
    - use the generated headers from the build tree.
  - **Analyses:** Eva (`run_eva_slice.py`), WP (`run_wp_function.py`), `kernel_ast.py` and `function_facts.py` parse with the same snapshot include path.
  - **Selftest:** the E-ACSL canary and a snapshot check run on the bare Frama-C image.
  - **Cache keys** (`cache.py`): the snapshot digest replaces the derived-image identity, so a target's Eva and WP results stay reusable while its headers and libraries are unchanged.
  - **Wrappers:** the Frama-C image becomes the default for every non-build step. Derived `framac-pipeline:<repo>` images are no longer built; derived images exist only for the build image.
  - **Seed harvesting (I6)** runs the target's tests in the build image, where they were built.
- **Owns:** `scripts/run_eacsl_fuzz.py` (snapshot flags), `scripts/run_eva_slice.py`, `scripts/run_wp_function.py`, `scripts/kernel_ast.py`, `scripts/function_facts.py` (include path only), `scripts/cache.py` (key), `wrappers/` and `docker-compose.yml` (image choice).
- **Acceptance:**
  - CryptoLib, which needs packages, runs Phases 0–2 on the bare Frama-C image, with results identical to the monolith;
  - the E-ACSL canary passes on the bare image;
  - no derived Frama-C image is built for any benchmark target.

### I4. Narrowing function-pointer edges with Alias (S, parallel with I5a)

- **Goal:** fewer spurious indirect edges, without losing true ones.
- **Work:** run `-alias` in the I3 parse and intersect its targets with the signature match. Measure on the benchmark targets (x509-parser has 163 indirect edges) and on the reproducers and seeded projects. Adopt it only if precision rises with recall unchanged on r03, r08, r09 and s02, where the indirect edges are exact.
- **Owns:** the Alias option of `scripts/phase0_model.py`.
- **Acceptance:** a measured report in `docs/phase0-redesign.md`. Alias is adopted or rejected with the numbers.

### I5a. Switch the inventory, modules held fixed (M)

- **Goal:** the bookkeeping gains the A/B showed, with low risk. Every function the build compiles gets a ledger unit under its real name. Modules don't change yet.
- **Work:**
  - **`build_callgraph_dag.py`** writes the DAG from the model, as the PoC's `dag_view.py` held-module view does:
    - functions, edges (direct and indirect) and macro aliases from the model;
    - modules, tiers and per-function analysis still from the lexer.
  - **`ledger.py seed`:**
    - no units for functions only in test units;
    - header `static inline` functions only when reached;
    - `callgraph_source` per function, and fallback units flagged.
  - **Aliases:** `generate_harness.py` and `harness_reach.py` resolve macro aliases, so harness code naming `crypto_hash` still resolves.
  - **Indirect edges:** `wp_scheduler.py` and `audit-hypotheses` use them.
- **Owns:** `scripts/build_callgraph_dag.py`, `scripts/ledger.py` (seed), `scripts/generate_harness.py` (aliases), `scripts/harness_reach.py` (aliases), `scripts/wp_scheduler.py` (edges).
- **Acceptance:**
  - on the benchmark, Eva-analysed functions with no ledger unit reach 0 on every target;
  - recall is unchanged;
  - the baseline is re-recorded with the unit changes explained, matching the PoC's A/B.

### I5b. Link units as modules (L, after I1, I3b and I5a)

- **Goal:** modules are the build's link units, and harnesses are written against units and their API.
- **Work:**
  - **DAG view:**
    - modules = units, or sub-modules after I8;
    - `required_sources` = unit sources plus the sources of linked libraries;
    - per-unit flags;
    - API entry points.
  - **Harness sub-modules:** a sidecar may name a harness module inside a unit (`unit` field), so a unit keeps several harnesses, as QCBOR's 8 do today. `pipeline_make.py` maps each sidecar to its unit's sources and flags.
  - **Ingest mapping:** `ledger.py ingest-eva` and `ingest-fuzz`, candidate linking and `wp_scheduler.py` resolve a report's module to its unit through the sidecar. Today they match `unit.module == report.module` (`ledger.py:442`, `:679`), which would credit nothing for a sub-module report.
  - **Concurrency:** units that start threads are marked in the ledger. The report says their Eva and WP results assume sequential execution.
  - **Benchmark manifest:** a script migrates module names to unit and sub-module names.
  - **Seeded benchmark:** the seeded set joins `scripts/benchmark.py` as a `phase0` set, with the PoC's mechanical harness policy as a deterministic check.
  - **Slice skill:** its harness section (step 4) targets link units and their API entry points.
- **Owns:** `scripts/build_callgraph_dag.py` (modules), `scripts/pipeline_make.py` (modules), `scripts/ledger.py` (ingest mapping, concurrency), `scripts/wp_scheduler.py` (module map), `scripts/generate_report.py` (concurrency), `benchmark/manifest.json`, `scripts/benchmark.py`, `skills/framac-slice`.
- **Acceptance:**
  - benchmark recall unchanged;
  - every sub-module report credits its unit's functions;
  - the seeded set finds 7/7 bugs and fires 0 decoys;
  - baseline re-recorded.

### I6. Hand-off to Phase 1 (L, parallel with I7)

- **Goal:** fuzzing starts from realistic inputs and gets a fair budget, and Phase 1 coverage reaches back into Phase 0.
- **Work:**
  - **Seeds from recorded API calls** (`scripts/seed_harvest.py`):
    - rebuild the test executables with `-Wl,--wrap=<api_fn>` recorders, generated from the model's API and signatures;
    - run the recipe's test command in the sandbox (no network, capped time);
    - record the buffers and scalars each API call receives;
    - write them in each harness's case format, selector byte included.
  - **Where it runs:** test builds and test runs happen in the build image, where the target's packages are.
  - **Secondary seeds:** data files the tests open for reading inside the target tree (`strace -f -e trace=openat`), capped by size and count.
  - **Corpus wiring:** seeds go to `workspace/seeds/<module>/` and reach `campaign` through `--extra-corpus`, which exists but is not wired.
  - **Dictionary:** `fuzz_dictionary.py` adds integer and string values of macros from the unit's preprocessed sources.
  - **Fuzz budget:** set per harness case, capped per unit and profile.
  - **Dynamic reach gate:** after `coverage-<mod>`, an API entry point with zero executions reopens the reach gate (`reach-dynamic` target). The parent then repairs the harness or records an exemption.
- **Owns:** `scripts/seed_harvest.py` (new), `scripts/fuzz_dictionary.py`, `templates/pipeline.mk` (fuzz and coverage recipes), `scripts/pipeline_make.py` (budget), `scripts/harness_reach.py` (dynamic mode), `skills/framac-fuzz`.
- **Acceptance:**
  - on minmea (79 inline test sentences) and QCBOR (347 inline test arrays), seeds are recorded from the test runs;
  - coverage per entry point after a quick campaign is at least today's;
  - a seeded fixture whose bug needs a well-formed input is found with seeds and missed without;
  - an unreached entry point reopens the gate.

### I7. Trust boundary (M, parallel with I6)

- **Goal:** `untrusted_surface` follows a stated rule and the threat model, not a default buried in harness generation.
- **Work:**
  - **Threat-model schema:** the structured `THREAT_MODEL.md` block (`input_sources`, `secrets`, `auth_gates`, `output_sinks`) with a validator. A missing block records `no_threat_model` on every unit.
  - **Rules:**
    - **library units:** every API function is untrusted unless the threat model marks the library, or specific functions, as called only by trusted code;
    - **executables:** functions reached in the call graph from an input reader are untrusted. Input readers are `read`, `recv`, `recvfrom`, `fread`, `fgets`, `getline`, `getenv`, `main` with argv, and the threat model's `input_sources`;
    - **output:** `trust` per function in the model, with its source (`default`, `call_graph`, `threat_model`, `codeql`).
  - **CodeQL (optional):**
    - enabled per run in `run-metadata.json` when the user declares the target open-source;
    - runs in the CodeQL image: database creation replays the build recipe under CodeQL's tracer, then the taint queries write `workspace/reports/codeql_trust.json`;
    - a target with packages gets a CodeQL image derived from its derived build image (`framac-codeql:<repo>`), built by the wrapper;
    - its source-to-sink flows can mark additional internal functions untrusted;
    - it never removes a default or a threat-model decision.
  - **Consumers:**
    - the sidecar's `reachability` defaults from `trust`;
    - the trust-boundary check in `acsl_ast.py` reads it;
    - the report shows the trust source per entry point.
  - **Threat models** for minmea, QCBOR and x509-parser, stored as benchmark assets, so I7–I9 can be measured on real code.
- **Owns:** `scripts/trust.py` (new), `scripts/codeql_trust.py` (new), `wrappers/` (CodeQL image derivation), `schemas/threat_model.schema.json`, `benchmark/assets/*/THREAT_MODEL.md`, `scripts/generate_harness.py` (reachability default), `scripts/acsl_ast.py` (trust lookup), `scripts/generate_report.py` (trust column).
- **Acceptance:**
  - the reproducers and seeded projects get a `trust` truth field, which matches;
  - CodeQL off changes nothing;
  - CodeQL on adds `source: codeql` facts on minmea without removing any.

### I8. Tiers and unit split (M, after I7)

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

### I9. Security layers via MetAcsl (L, after I7, only if I0's test passed)

- **Goal:** L3–L6 obligations come from what the threat model requires, not from what the code already does.
- **Work:**
  - **Property generation**, from the structured threat model:
    - **L4:** auth gates become "only gate functions write the auth state, and privileged functions require it";
    - **L5:** output sinks become sanitization properties on writers;
    - **L6:** secrets become "wiped before release" and "never flows to output sinks".
  - **L3:** a frame (`assigns`) obligation for every function that writes through a pointer.
  - **Ledger:** new obligation classes keyed to the properties.
  - **Phase 3 briefs:** say which MetAcsl-generated annotations a prover must discharge.
  - Retire the per-function pattern matching of the old L5/L6 inference.
  - **If I0 recorded no-go:** generate the same properties as plain per-function ACSL templates from the threat model. L4 then loses its program-wide form.
- **Owns:** `scripts/security_props.py` (new), `templates/metacsl/`, `scripts/ledger.py` (classes), `skills/framac-wp` (briefs).
- **Acceptance:**
  - a fixture with a secret that is never wiped produces an unproven L6 unit;
  - a fixture with a correct wipe proves it;
  - the benchmark threat models produce properties on their targets;
  - the existing L5/L6 templates are covered or explicitly dropped.

### I10. Lexer removal, docs, and the single merge (M)

- **Goal:** one Phase 0, documented, on `main`.
- **Work:**
  - delete the lexer analysis from `build_callgraph_dag.py`, its tests and its schema fields;
  - retire the monolithic image: the build and Frama-C images become the only ones, plus CodeQL's;
  - update the docs: `architecture.md`, `v2-design.md`, `troubleshooting.md`, the README, and the slice, verify and fuzz skills;
  - final full run: benchmark (all sets), reproducers and seeded set;
  - merge `phase0-redesign` into `main`.
- **Owns:** everything touched above, for cleanup only.
- **Acceptance:**
  - every gate above passes on the merged tree;
  - the status table below is complete;
  - `poc/phase0/` is kept as history or removed (decide then).

## Order and parallelism

```text
I0 ─┬─▶ I1 ───────────────────────────┐
    └─▶ I2 ─▶ I3 ─┬─▶ I3b ──────────┐  ▼
                  ├─▶ I4             ▼
                  └─▶ I5a ─────────▶ I5b ─┬─▶ I6 ──────────────┐
                                          └─▶ I7 ─┬─▶ I8 ──────┤
                                                  └─▶ I9 ──────┴─▶ I10
```

- **I1 and I2** are independent, and I1 must land before I5b changes harness modules.
- **I3b, I4 and I5a** run side by side after I3. Their files are disjoint: I3b covers build flags, analysis include paths, cache keys and wrappers; I4 the Alias option; I5a the DAG, the ledger seed and aliases.
- **I6 and I7** own disjoint files once I5b is in, and can be parallel subagent or session work. So can I8 and I9.

## Risks

- **Build recipes for real targets.** Stop-and-ask moves effort onto the user for targets that don't build out of the box. Mitigation: candidate packages in the diagnostic, and the recipe recorded for resume and reuse.
- **Running test suites inside the sandbox** runs more target code, and some suites need a network or services. Mitigation: a time and resource cap, no network, and failures are non-fatal (seeds are an improvement, not a requirement).
- **API-call recording** with `-Wl,--wrap` only catches calls that cross object files. Calls inside a library's own object, or inlined under LTO, are not recorded. Tests call the API from their own objects, so this covers the intended case; it is measured in I6.
- **The harness format change in I5b** touches every benchmark harness spec. Mitigation: sub-modules keep today's harness granularity, and the manifest is migrated by script.
- **MetAcsl against a development Frama-C:** I0 decides go or no-go before any I9 work.
- **CodeQL image:** it is pinned, has its own selftest, and is never pushed or shared. Because it is built `FROM` the main image, it must be rebuilt whenever the main image changes; the wrapper checks the base image digest.
- **Frama-C upgrades** can break the dump module. Mitigation: the I3 selftest runs at image build.
- **An incomplete snapshot.** Some libraries load plugins or data files at run time (`dlopen`, certificate stores), which `ldd` doesn't see. Mitigation: the I3b acceptance run on CryptoLib, a replay of every crash candidate on the build image when the snapshot is suspect, and an explicit `snapshot_extra` list in the build recipe.
- **Drift between the two images.** A different gcc or glibc would change which `#if` branches are taken or break the E-ACSL runtime. Mitigation: a common base stage, and the I0 check of compiler and glibc versions run as a selftest on every image build.
- **A long-lived branch:** `main` keeps moving (for example `156adfa`). Mitigation: merge `main` at the start of each step and run the gates after the merge.

## Status

| Step | Size | Status |
| :--- | :--- | :--- |
| I0 | M | not started |
| I1 | S | not started |
| I2 | L | not started |
| I3 | L | not started |
| I3b | L | not started |
| I4 | S | not started |
| I5a | M | not started |
| I5b | L | not started |
| I6 | L | not started |
| I7 | M | not started |
| I8 | M | not started |
| I9 | L | not started |
| I10 | M | not started |
