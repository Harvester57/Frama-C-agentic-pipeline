# Overnight progress: I5a, I5b and onward (2026-11-08)

Branch `phase0-redesign`, all commits local (not pushed).

## Report 1

### I5a: the cross-module Eva fix is in, benchmark run 4 running

Commits so far for I5a:

| Commit | What |
| :--- | :--- |
| `b8e36a2` | DAG from the Phase 0 model; seed, aliases, key indexing |
| `2eb3bc9` | Eva ingest: header units kept, kernel-renamed copies (`f_0`) mapped |
| `9d88f9f` | Unreached header functions seeded `deferred`, re-planned when Eva reaches them |
| `22f276f` | No Eva evidence on a header unit that stays unreached |
| `3d6f38a` | **The fix you approved:** Eva status from every module's report, rows placed by line range |

What `3d6f38a` does:
- Each Eva row goes to the DAG function whose line range holds it, which is exact for renamed copies and inlined rows. The name is used only when a row has no line.
- A unit gets evidence from every report that analysed its function, and records one verdict per module (`bookkeeping.eva_verdicts`). A module's newer report replaces its old verdicts.
- Covered is decided once, from all verdicts: some module proves every obligation, and none leaves one Unknown, Invalid or unclassified. The boundary assumption names every proving module, and the result no longer depends on report order.
- The benchmark has a new `covered_with_unknown` metric, and `compare` counts a new entry there as a regression.
- Tests: `tests/test_eva_cross_module.py` (7 cases: both orders, incremental ingest, superseding report, line placement, header reached from another module), plus compare tests. Suite: 1885 passed. ruff is clean, and mypy shows only the 18 errors that predate this work.

Run 4 (all 10 targets, about 45 minutes) is going. If it is clean I record `phase0-i5a`, finish the notes and commit.

### I5b: started

Surveying how module names flow through the pipeline (harness sidecars, `pipeline_make`, ledger, scheduler, manifest) before the change.

## Report 2

### I5a

Run 4 has done minmea, qcbor-dev and qcbor-master so far (all exit 0). CryptoLib is running now: it is the slowest target.

### I5b: the design is in place, the consumers are being changed

The work is in a separate worktree, `frama-c-i5b` on branch `phase0-i5b`. The benchmark mounts the main checkout's scripts while it runs, so I5b can't be edited there.

Done so far:
- **The DAG's modules are the build's link units** (`build_callgraph_dag.unit_view`). There is one module per non-test library or executable, libraries first. Each one carries its own sources plus those of the libraries it links, its compile flags, its API entry points and `concurrent`.
  - **Tiers don't change:** each function keeps its lexer module's tier, and a unit takes the most demanding one. Tiers change in I8.
  - **Checked on all 10 targets:** every manifest harness module maps to a unit. For example, QCBOR's 8 harnesses map to `libqcbor_a` and CryptoLib's 5 map to `libcryptolib_so`.
- **Harness modules keep their names** and become sub-modules of their unit (`scripts/module_map.py`). A sidecar records its `unit`. Reports, corpora and candidates stay keyed by the harness module, and each one credits its unit.
- **Benchmark changes:**
  - `migrate-units` writes each harness module's unit into the manifest, read from a link-unit DAG.
  - Phase 0 stops if the DAG puts a module in a different unit than the manifest says.
  - `modules_without_harness` counts a unit as harnessed when one of its sub-modules has a harness.
- **Slice skill:** steps 2, 4 and 4b are updated.
- **Tests:** 9 new tests for the unit view and the module map, and 2 for the benchmark.

Three agents are working on disjoint files:
- **Make layer, gates and reach check:** `pipeline_make`, `phase0_gates`, `harness_reach`, fuzz build specs.
- **Ledger, WP scheduler, overlay and report:** ingest through `unit_of`, the concurrency mark, and a sequential-execution note in the report.
- **The seeded-bug set as a benchmark set:** `scripts/benchmark_seeded.py`.

**Next:** review and merge their work, run the full benchmark plus the seeded set, then commit I5b.
## Report 3

### I5a: done (`3813532`)

Baseline `phase0-i5a` comes from run 4:
- Eva-analysed functions with no ledger unit: 0 on every target.
- `covered_with_unknown`: 0 on every target.
- Recall: 7/7.

Against `phase0-i0`, `compare` shows one regression, and it is the soundness fix working. On qcbor-dev, `UsefulInputBuf_GetBytes` and `IEEE754_AssembleDouble` used to count as covered because one module proved them. Other modules' Eva runs leave Unknowns in them, so they are no longer covered. For example, `UsefulInputBuf_GetBytes` is valid from `UsefulBuf` but unknown from 4 decode modules.

### I5b: merged into `phase0-redesign`, benchmark running

The three agents' work is reviewed and merged (`f6733b8`, merge `03225f6`). The suite passes: 1937 tests.

Fixes I made while integrating:
- **Model flags:** they came as split tokens (`-I inc`), which produced a stray `-I`. They are now single tokens, and force includes are kept apart.
- **Conflicting macros:** the lexer's Makefile `-D` flags could contradict the build's own (`-DFAST` alongside `-DLEGACY`). A unit now uses the build's macros plus the lexer's include directories, and a sub-module uses its unit's flags.
- **CryptoLib `sa`:** the unit's exported API adds 2 entry points to its scope that the pinned harness doesn't drive. They are recorded as accepted gaps, the same as for the other pinned modules.
- **`-Dmain` rename:** now a valid identifier for module names that contain `-`, which affected x509.

What the agents' end-to-end check on qcbor-dev showed:
- all 8 sub-module reports credit `libqcbor_a`;
- re-ingesting changes nothing;
- the lexer-module path gives identical results.

**Seeded set:** `benchmark.py seeded` runs it, and its first project, s01, passed (bug found, decoy quiet). The full set (7 projects) and the 10-target benchmark (`i5b1-*`) are running now.

### I4: done, Alias not adopted (branch `phase0-i4`, `dbd0e38`; merged after the I5b runs)

On r03, r08, r09 and s02 the type match is already exact, so precision has no room to rise, and the adoption rule can't be met.
- **x509-parser:** indirect edges go from 163 to 122. All 41 dropped edges are spurious mix-ups between fields of the same type in its `const` tables.
- **The catch:** Alias narrows a global function pointer to its initializer even when another function reassigns it. A new fixture shows a true edge lost this way.
- **The option stays off by default.** Worth a follow-up: trust Alias only for pointers read from `const` globals.
- **Cost:** at most 1.5 s per parse.

### I6 and I7: started

They run in parallel, each in its own worktree with its own agent:
- **I6:** seeds from recorded test API calls, the dictionary, per-case budgets, and the dynamic reach gate.
- **I7:** threat-model schema, trust rules, optional CodeQL, and threat models for minmea, QCBOR and x509.
## Report 4

### I5b: seeded set passes, benchmark on round 3

- **Seeded set: 7/7 bugs found, 0/4 decoys fired (PASS).**
  - The first full run found 6/7. s04_force_include was missed because the build's `-include config.h` never reached the harness.
  - Fix: unit flags and force includes are now relative to the run directory, and generate_harness applies the force includes.
- **10-target benchmark, rounds 1 and 2:** each round exposed a way the build's own unit flags, newly fed into harnesses by I5b, break something. All are fixed on `phase0-i5b` and merged:
  - **CryptoLib, quoted macro:** `-DMC_LOG_PATH="log.txt"` lost its quotes, so E-ACSL and Eva failed. The pipeline splits and re-joins flag strings in several places, so the fix is to leave quoted `-D` values and `-std=` out of DAG-merged harness flags. The harness spec states such flags itself.
  - **semver, `-std=c89`:** the build's flag rejects the generated (C99) harness.
  - **x509-parser, sources:** a callee pulled in its whole unit's sources, including `x509-parser.c`, whose Frama-C-only `main` includes `__fc_builtin.h`. Callees bring their lexer module's closure again.
  - **x509-parser, `-Dmain` rename:** with the identifier fix, the `x509-parser` module runs Eva for the first time since I0. Round 2 has 200 failed units there, where it used to record a tool failure.
- **Round 2 otherwise:**
  - 0 functions without a unit and 0 covered-with-Unknown on every target.
  - QCBOR and minmea recall: 6/6.
- **Round 3** (all fixes) is running with CryptoLib and semver first.

### I6 and I7: done on their branches, not merged yet

- **I6** (`phase0-i6`):
  - **Seeds from the test suites:** minmea gives 214 unique API calls (64 seeds); qcbor-dev gives 3821 calls (708 seeds per decode harness).
  - **Coverage:** never lower than before.
  - **New fixture s08:** its bug needs a well-formed checksum. It is found with seeds and missed without.
  - **Dynamic reach gate:** it reopens three QCBOR modules whose entry points never execute.
  - **Also:** a per-case fuzz budget, and macro values added to the dictionary.
- **I7** (`phase0-i7`):
  - **Threat models:** a threat-model schema, plus threat models for minmea, qcbor-dev and x509-parser.
  - **Trust rules:** library API, input-reader reachability, and `trusted_callers`.
  - **Truth:** 16/16 fixtures match their new `trust` truth field.
  - **CodeQL** runs fully offline (`framac-codeql:minmea`): it adds `codeql` sources to 12 minmea functions and removes nothing. With it off, nothing changes.

### I8 and I9: started

Both run from the I7 branch, in their own worktrees:
- **I8:** trust- and complexity-based tiers, and unit split.
- **I9:** MetAcsl security properties from the threat model. I0 recorded MetAcsl as a go.

**Next:**
- Accept I5b on round 3.
- Merge I6 and I7, then run the merged benchmark.
- Merge I8 and I9 when they report.
## Report 5

### I5b accepted, I4/I6/I7/I8/I9 merged

- **I5b done:** baseline `phase0-i5b` (rounds 3 and 4).
  - Recall 7/7. Seeded set 7/7 bugs, 0/4 decoys.
  - 0 regressions against I5a. x509-parser's `x509-parser` module now completes Eva.
  - jsmn, qlz and semver relied on Makefile macros the library build doesn't use; their harness specs now state them.
- **I4 (Alias):** measured, not adopted, off by default. The exact projects already score 1.00, and Alias is unsound with reassigned globals.
- **Merged into `phase0-redesign`**, in order:
  - I4;
  - I6 (seeds from tests, dynamic reach gate, s08);
  - I7 (trust, threat models, CodeQL);
  - I8 (tiers from trust, unit split);
  - I9 (MetAcsl security properties).
- **Conflicts:** only in the plan document and in four code hunks. The redesign's I5b harness-flag rules won over I8's older cherry-picks, and `phase0_model` keeps both `--alias` and `--threat-model`. s08 got its trust truth, which I7 added for the other fixtures.
- **Gates on the merged tree:**
  - ruff clean;
  - pytest 2047 passed, 100 skipped;
  - mypy: one error, already there on Nov 7 (`run_eacsl_fuzz.py:1352`).
- **Running now:** the full 10-target benchmark plus the seeded set on the merged tree (`i9m1-*`, `seeded-i9m1`). Next: compare with `phase0-i5b` and record the baseline.

### I10 started in two worktrees

- **I10a (`phase0-i10a`):** deletes the regex lexer, so the DAG comes from the model only.
  - The path-based module partition stays, because the benchmark's harness modules are named after it.
  - Acceptance: identical DAG views on the saved benchmark runs, or each difference explained.
- **I10b (`phase0-i10b`):** brings the docs and the slice, verify and fuzz skills up to date with I0–I9.
- **Left for you:**
  - retiring the monolithic image (the tests' Docker image is still `framac-pipeline:latest`);
  - the single merge of `phase0-redesign` into `main`.

## Report 6

### The merged tree holds up

- **`phase0-i9`** (merged I4–I9, runs `i9m1-*`) against `phase0-i5b`:
  - 0 regressions, every known bug retained;
  - CryptoLib `mc_initialize` newly covered;
  - seeded set: **8/8 bugs, 0/4 decoys**, now including s08 from I6.
- **The I6 dynamic reach gate** didn't block any benchmark stage: all 10 targets finished with rc=0.

### I10: lexer gone, docs updated

- **Lexer removal (I10a):**
  - `build_callgraph_dag.py` went from 2,764 to 971 lines. The DAG now comes from the Frama-C model only. With no model it stops with `needs_build_recipe`.
  - The file-path module partition is kept, so harness names don't change.
  - On every saved run, rebuilding the DAG gives identical link units, sub-modules, entry points, sources and waves. Every other difference is explained in the plan's I10a note.
- **Docs (I10b):** the README, architecture, v2-design, troubleshooting, onboarding, benchmark and security-properties docs, and the slice, verify and fuzz skills, now describe Phase 0 as built.
- **Baseline `phase0-i10`** (runs `i10m1-*`) against `phase0-i9`:
  - 0 regressions; seeded set 8/8, 0/4.
  - **One warning, explained: CryptoLib `mc` Eva checks 43 properties, down from 689.** The lexer's guesses had pulled 19 sources into that harness. The model's edges need its 3 own files, and Eva now has 0 undeclared functions, against 1. The old properties were mostly in unreachable code. Ledger coverage is unchanged.
- **Two tier changes I accepted; please glance:** the model sees real types, so CryptoLib's 13 `get_*_interface` getters go from Tier 3 to 1A, and `main(int, char **)` goes from 1B to 1A.
- **Gates:**
  - ruff clean;
  - pytest 2045 passed, 100 skipped;
  - mypy: only the Nov 7 error.

### Running now

- **I10c**, in its own worktree: retiring the monolithic image. The Docker tests still default to `framac-pipeline:latest`.

### Left for you

- **The single merge of `phase0-redesign` into `main`.** Everything is local; nothing is pushed.
- **Keep or remove `poc/phase0/`.**
- **The manifest's unused `compile_commands` asset.** I kept it so the harness digests don't change.
