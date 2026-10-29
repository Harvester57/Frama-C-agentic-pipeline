---
name: framac-eva
description: >-
  Phase 2 of the Frama-C verification pipeline. Runs whole-slice Abstract
  Interpretation (Frama-C Eva + RTE) from each module's eva_main() harness
  inside the hardened framac-pipeline container. Automatically discharges
  80-90% of RTE obligations via value/octagon/symbolic-location domains,
  separates Invalid (red), Unknown (orange), dead, and assumed statuses, emits
  per-slice SARIF, and records results in the coverage ledger, including the
  queue of surviving Unknown functions for Phase 3 (/framac-wp).
argument-hint: "<target-dir> --run-dir <dir> [--module <name>] [--slevel <N>]"
---

# /framac-eva

Module-level Abstract Interpretation stage that prunes the vast majority of RTE proof obligations automatically with **zero loop invariants** required from the user or LLM.

## Step 1 — Select Module Slices

Read `workspace/reports/callgraph_dag.json` and `workspace/harnesses/`. If Phase 0 has not been run yet, execute `/framac-slice <target-dir>` first.

---

## Step 2 — Parallel Module Eva Execution

One run per module slice, in parallel:

```powershell
$env:PYTHONIOENCODING="utf-8"
& "C:\Users\Florian\OneDrive\Documents\Dev\frama-c\wrappers\framac-docker.ps1" `
  -TargetDir "<target-dir>" -RunDir "<run-dir>" `
  "python3 /opt/framac-pipeline/scripts/run_eva_slice.py --module <mod> --sources workspace/work/src/<mod>/*.c workspace/harnesses/harness_<mod>.c --main eva_main --out-dir workspace/eva/<mod> --slevel <slevel_or_100> --cppflags '-Iworkspace/work/include -I/opt/framac-pipeline/templates/acsl' --out-json workspace/reports/eva/<mod>.json"
```

A Frama-C failure is reported as `status: "analysis_error"` (exit code 1), never as zero alarms.

### Tuning Eva Precision When Needed
If a `Tier 1A` or `Tier 1B` module has an unusually low discharge rate (< 70% Valid) due to loop widening:
- Re-run `run_eva_slice.py` with higher `--slevel 250` or add `/*@ loop pragma UNROLL 64; */` above bounded fixed-size header loops in `workspace/work/`.
- If Layer 6 (Secret Non-Interference / Taint) properties are active on the module, enable `-eva-domains taint` to verify `!\tainted(...)` assertions at network emission sinks.

---

## Step 3 — Status Buckets

`workspace/reports/eva/<mod>.json` partitions every property:

1. **`Valid` (green):** proven for every calling context reachable from `eva_main`. This is a proof relative to the harness context, which is recorded as an assumption on the unit.
2. **`Invalid` (red):** Eva claims a runtime error whenever the statement is reached. Without a concrete witness input this is a `needs_validation` candidate, not a confirmed bug.
3. **`Unknown` (orange):** surviving proof obligations for WP.
4. **`Dead` (`Invalid_but_dead`, `Valid_but_dead`, `Unknown_but_dead`):** the statement is unreachable from `eva_main`. Neither a bug nor a proof; it indicates a harness gap.
5. **`Assumed` (`Considered valid`):** libc or stub specifications taken as given. Recorded as assumptions, never counted as proven.

## Step 4 — Ingest and Queue WP Work

```text
python3 /opt/framac-pipeline/scripts/ledger.py ingest-eva workspace/reports/eva/*.json
python3 /opt/framac-pipeline/scripts/validate_artifacts.py run-dir .
```

- Functions whose RTE obligations are all Valid become `covered` (with the harness-context assumption).
- Each Invalid alarm becomes a fingerprinted candidate (same fingerprint as an E-ACSL crash on the same predicate) and its unit becomes `candidate`.
- Functions with Unknown obligations stay `planned` with Eva evidence attached. Intersect them with the waves in `callgraph_dag.json` and write the ordered WP queue to `workspace/reports/wp_queue.json` for `/framac-wp`.
