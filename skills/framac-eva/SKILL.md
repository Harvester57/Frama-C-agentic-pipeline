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

## Step 2 — Run Eva on Every Module with Make (no subagents)

Eva runs need no judgment, so they run from the generated Makefile (`docs/resources-and-caching.md`), not from one LLM subagent per module. Eva is single-threaded. Make runs modules side by side, admitting each by memory, and the probe's history learns each module's peak memory. `S=/opt/framac-pipeline/scripts`.

1. If `/framac-fuzz` has not done it yet, generate the Makefile once: `python3 $S/pipeline_make.py gen`.
2. Run every module **in the background**, at the same time as the `fuzz` target: `python3 /opt/framac-pipeline/scripts/pipeline_make.py run eva`. Results with status `ok` are cached by content, so an unchanged module is not re-analyzed. Write this command exactly as shown, with the full path: only this exact command line may also fill the shared cross-run cache (`docs/resources-and-caching.md`, Section 5).

For a single module in guidance mode, the underlying command is:

```text
python3 $S/run_eva_slice.py --module <mod> --sources <sidecar sources> workspace/harnesses/harness_<mod>.c --main eva_main --out-dir workspace/eva/<mod> --slevel <slevel_or_100> --cppflags='<sidecar cppflags> -I/opt/framac-pipeline/templates/acsl' --out-json workspace/reports/eva/<mod>.json
```

- A Frama-C failure is reported as `status: "analysis_error"` (exit code 1), never as zero alarms.
- A run that exceeds the profile's wall-clock limit (`--timeout`) is reported as `status: "analysis_timeout"`.

`run_eva_slice.py` runs `-rte -then -eva` on purpose. Eva's own alarms would find the same errors, but RTE supplies the full list of obligations, which Eva then marks Valid, Unknown, Invalid or Dead. The ledger's `covered` rule and the Dead (harness-gap) bucket depend on that list. Do not drop `-rte` from this phase, and do not add `-rte-initialized`: Eva already reports uninitialized reads (see `docs/references/README.md`, "Key facts").

### Tuning Eva Precision When Needed
Tuning is your judgment call. Make applies it: record per-module parameters in `workspace/build/params.json`, then re-run the `eva` target (or `module-<mod>`).
- **Low discharge rate:** if a `Tier 1A` or `Tier 1B` module discharges unusually little (< 70% Valid) because of loop widening:
  - raise the slevel: `python3 $S/pipeline_make.py params set --module <mod> --eva-slevel 250`;
  - or add `/*@ loop pragma UNROLL 64; */` above bounded fixed-size header loops in `workspace/work/`.
- **Taint:** if Layer 6 (Secret Non-Interference / Taint) properties are active on the module, enable the taint domain with `params set --module <mod> --eva-taint`. It adds `taint` to `-eva-domains`, so `!\tainted(...)` assertions at network emission sinks get verified.
- For any other precision lever, or an alarm or message you do not understand, grep the Eva manual through [`docs/references/`](../../docs/references/README.md) rather than reading it: loops §6.4, case splitting and partitioning §6.5, domains §6.7, what each alarm checks §3.2, log messages §3.3, FAQ §10.

---

## Step 3 — Status Buckets

`workspace/reports/eva/<mod>.json` partitions every property:

1. **`Valid` (green):** proven for every calling context reachable from `eva_main`. This is a proof relative to the harness context, which is recorded as an assumption on the unit.
2. **`Invalid` (red; Frama-C 33 reports it as `Invalid or unreachable`):** Eva claims a runtime error whenever the statement is reached. Without a concrete witness input this is a `needs_validation` candidate, not a confirmed bug. It gets the same fingerprint as an E-ACSL crash on the same property, so the two merge into one candidate.
3. **`Unknown` (orange):** surviving proof obligations for WP.
4. **`Dead` (`Dead`, `Invalid_but_dead`, `Valid_but_dead`, `Unknown_but_dead`):** the statement is unreachable from `eva_main`. Neither a bug nor a proof; it indicates a harness gap.
5. **`Assumed` (`Considered valid`):** libc or stub specifications taken as given. Recorded as assumptions, never counted as proven.

## Step 4 — Ingest and Queue WP Work

After both `fuzz` and `eva` have finished:

```text
python3 /opt/framac-pipeline/scripts/pipeline_make.py run ingest replay wp-queue
```

**`ingest`:**
- Ingests new fuzz reports, then new Eva reports. Expected modules without a report are recorded, never skipped.
- Then validates the run directory. Results:
  - Functions whose RTE obligations are all Valid become `covered` (with the harness-context assumption).
  - Each Invalid alarm becomes a fingerprinted candidate (same fingerprint as an E-ACSL crash on the same predicate) and its unit becomes `candidate`.
  - Functions with Unknown obligations stay `planned` with Eva evidence attached.

**`replay`:** replays every unverified candidate's reproducers into `workspace/reports/replay/`, so the crash verifiers start from facts.

**`wp-queue`:** runs `wp_scheduler.py init`. That builds the Phase-3 task graph from the planned units, the call graph and the candidates, and writes `workspace/reports/wp_queue.json`. Nothing is written by hand.
