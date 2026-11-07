# Phase 0 redesign: proof of concept

A sandbox for the design in [`docs/phase0-redesign.md`](../../docs/phase0-redesign.md). Nothing here is
imported by the pipeline, and nothing in `scripts/` changes: the current extractor
(`scripts/build_callgraph_dag.py`) is only run, read-only, for comparison.

## Contents

| File | Role |
| :--- | :--- |
| `phase0b.py` | The new extractor: build under `bear intercept`, link units from link/archive steps, Frama-C per unit with per-file flags, GCC `-fcallgraph-info` fallback, entry points from exports and public headers, thread entries. Writes `model.json`. |
| `p0_dump.ml` | Frama-C kernel module loaded by `phase0b.py`: defined functions (definition location, storage, signature), direct calls, indirect call sites with their signature, address-taken functions, functions passed as arguments. |
| `score.py` | Runs both extractors and scores them: against `truth.json` on the reproducers, and on the benchmark targets against the known bugs of `benchmark/manifest.json`. |
| `reproducers/` | Nine small buildable projects, one per defect, each with an exact `truth.json` (see its README). |
| `targets.json` | Build command of each benchmark target. |
| `dag_view.py` | Writes the model as a `callgraph_dag.json` the current pipeline reads. It holds modules, tiers and the lexer's per-function analysis fixed, and changes only the inventory and the edges. |
| `ab.py`, `ab_inner.py` | The A/B. It runs the benchmark's own Phases 0–2 twice per target, once on the lexer DAG and once on the `dag_view.py` view, with the manifest's harnesses unchanged. It then compares the ledgers, Eva coverage, the Phase 3 queue and the known bugs. The command is `python -I poc/phase0/ab.py run [--target ID] [--fuzz]`, and results go to `out/ab/`. |
| `run.ps1`, `run.sh` | Run everything in `framac-pipeline:latest`, repository mounted read-only, network off. Results go to `out/` (ignored by git). |

## Running

```powershell
.\poc\phase0\run.ps1 reproducers                     # out/reproducers/results.md
.\poc\phase0\run.ps1 fetch                           # clone the benchmark targets (host, network)
.\poc\phase0\run.ps1 targets                         # out/targets/results.md
.\poc\phase0\run.ps1 extract -Target <dir> -Build "make"   # one project, out/extract/<name>/model.json
```

`run.sh` takes the same modes on Linux and macOS. Add `-Only <name>` (PowerShell) or names after the
mode (sh) to run a subset.

## Iterating

- **A new defect:** add `reproducers/rNN_<name>/` with a `Makefile` and a `truth.json` (schema in
  `reproducers/README.md`), then run `reproducers -Only rNN_<name>`.
- **A real project:** `extract -Target <dir> -Build "<build command>"` and read
  `out/extract/<name>/model.json`; per-unit Frama-C logs are in `out/extract/<name>/framac/`.
- **A new benchmark target:** add it to `targets.json` with its build command.

## `model.json`

| Field | Content |
| :--- | :--- |
| `build` | Build command, status, time, log tail on failure. |
| `units` | Per link artifact: `kind` (`executable`, `shared_lib`, `static_lib`, `unlinked`), `files`, `links`, `entry_points`, `frama_c` (status, time, first error), `gcc_fallback` when used. |
| `functions` | `<file>#<name>` → file, name, definition line, `static`, signature, units, `source` (`frama-c-kernel` or `gcc-callgraph-info`). |
| `edges` | caller, callee, `kind` (`direct`, `indirect`), `sources` (`frama-c-kernel`, `type-match`, `thread-spawn`, `callback-arg`, `gcc-callgraph-info`). |
| `indirect_sites` | Each function-pointer call with its signature and candidate targets. |
| `externals`, `entry_points`, `thread_entries` | As named. |
| `cg_overapprox_extra_edges` | Edges Frama-C's `-cg` adds beyond the direct calls (its own function-pointer over-approximation), for comparison with `type-match`. |
