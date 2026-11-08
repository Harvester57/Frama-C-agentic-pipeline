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