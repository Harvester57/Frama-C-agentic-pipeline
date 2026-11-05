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

1. If `/framac-fuzz` has not done it yet, generate the Makefile once: `python3 /opt/framac-pipeline/scripts/pipeline_make.py gen`.
2. Run every module: `python3 /opt/framac-pipeline/scripts/pipeline_make.py run eva` (run in the foreground after `fuzz` so `eva` gets a writable `rw` `/framac-cache` mount, or concurrently in the background with `ro` cache if your host harness supports background wrapper calls). Results with status `ok` are cached by content, so an unchanged module is not re-analyzed. Write this command exactly as shown, with the full path: only this exact command line may also fill the shared cross-run cache (`docs/resources-and-caching.md`, Section 5).
3. Tune every module that still has Unknowns, before ingesting: `python3 /opt/framac-pipeline/scripts/pipeline_make.py run eva-tune` (Step 2a). Each surviving Unknown costs a prover task in Phase 3, so this pays for itself. Skip it only when the budget allows no extra Eva runs at all, as under the `quick` profile.

For a single module in guidance mode, the underlying command is:

```text
python3 /opt/framac-pipeline/scripts/run_eva_slice.py --module <mod> --sources <sidecar sources> workspace/harnesses/harness_<mod>.c --main eva_main --out-dir workspace/eva/<mod> --slevel <slevel_or_100> --cppflags='<sidecar cppflags> -I/opt/framac-pipeline/templates/acsl' --out-json workspace/reports/eva/<mod>.json
```

- A Frama-C failure is reported as `status: "analysis_error"` (exit code 1), never as zero alarms.
- A run that exceeds the profile's wall-clock limit (`--timeout`) is reported as `status: "analysis_timeout"`.

`run_eva_slice.py` runs `-rte -then -eva` on purpose. Eva's own alarms would find the same errors, but RTE supplies the full list of obligations, which Eva then marks Valid, Unknown, Invalid or Dead. The ledger's `covered` rule and the Dead (harness-gap) bucket depend on that list. Do not drop `-rte` from this phase, and do not add `-rte-initialized`: Eva already reports uninitialized reads (see `docs/references/README.md`, "Key facts").

---

## Step 2a — Tune Eva with Make (no judgment, no subagents)

`run eva-tune` searches for a better configuration of each module. It is deterministic and cached: do not try options by hand first.

1. It runs the module's own settings as the **base run**. A module with no Unknown left stops there.
2. Otherwise it runs a fixed **ladder** of configurations, side by side, each changing one concern: `slevel`, `unroll`, `history`, `values`, `relational`, `returns`, plus the all-round `precision`. They are not nested, because no knob helps every program.
3. A **guard** rejects any run that did not complete, turned any obligation Dead, gave one an inconsistent status, reached fewer functions, lost the entry function, made a function non-terminating, degenerated, or analysed different inputs. A collapse in coverage removes alarms too, so a low alarm count alone proves nothing.
4. **Selection** takes the fewest functions with an Unknown, then the fewest Unknowns, then ladder order. Elapsed time plays no part.
5. **Per-loop analysis:** for loops in functions that still have Unknowns, it unrolls one loop nest at a time on a scratch mirror (never in `workspace/work/`) and keeps the annotation only if Unknowns fall and no obligation turns Dead.
6. **Combination:** an obligation any admissible run proves counts as proved, because a Valid status means no execution can violate that property first (`docs/resources-and-caching.md`, Section 6). Invalid from any complete run always reaches the report, and Dead never counts as proof.

The result replaces `workspace/reports/eva/<mod>.json`, with a `tuning` block saying what was tried, what was rejected and why. The decision goes into `workspace/build/params.json`, so `run eva` uses it from then on and another machine's `run eva-tune` replays only the recorded runs. A machine that finishes fewer runs leaves more units `planned`.

To search again, for example after changing what a loop does: `python3 /opt/framac-pipeline/scripts/pipeline_make.py params set --module <mod> --eva-retune`. A change to the sources or to the module's other Eva settings already triggers a new search.

### Tuning Eva by Hand
`eva-tune` covers precision. These are the choices it cannot make, because they depend on what you know about the target. Record them in `workspace/build/params.json`, then re-run the `eva` target (or `module-<mod>`).
- **An option the ladder does not try:** `python3 /opt/framac-pipeline/scripts/pipeline_make.py params set --module <mod> --eva-option min-loop-unroll=8` (repeatable; `name=` clears it). Only the allowlist in `scripts/eva_options.py` is accepted: `min-loop-unroll`, `auto-loop-unroll`, `widening-delay`, `partition-history`, `slevel`, `ilevel`, `plevel`, `subdivide-non-linear`, `split-return`, `remove-redundant-alarms`, `octagon-through-calls`, `equality-through-calls`, `context-depth` (never below its default of 2), `precision`, and `domains=multidim`. None of them reduces what is checked. `context-depth` changes the initial state rather than precision, so a run with another value is another analysis and is never combined with this one.
- **Dynamic memory allocation (`Tier 2` heap/tree parsers):** by default, Eva merges dynamic allocations (`malloc`/`calloc`/`realloc`) at the same callstack (`-eva-mlevel 0`) into weak bases (`__malloc_w_*`), causing spurious aliasing on loop/tree/list/JSON/ASN.1 allocations. Unroll allocation sites per callstack with `params set --module <mod> --eva-mlevel 4` (or `--mlevel <K>` on `run_eva_slice.py`).
- **Recursive call cycles without `assigns` specs (`Tier 2`):** if Eva aborts on a mutually recursive call cycle (`assigns:missing`), enable the recursion fallback for that module with `params set --module <mod> --eva-recursion-fallback` (which passes `--allow-incomplete-recursion-specs` / `-eva-warn-key assigns:missing=warning` and records the assumption in `reduced_checks`).
- **Taint:** if Layer 6 (Secret Non-Interference / Taint) properties are active on the module, enable the taint domain with `params set --module <mod> --eva-taint`. It adds `taint` to `-eva-domains`, so `!\tainted(...)` assertions at network emission sinks get verified.
- **A loop `eva-tune` should not unroll, or one it missed:** a hand-written `//@ loop unroll N;` in `workspace/work/` (ACSL-only, so it passes the merge checks) is left alone by the search. Do not write the older `loop pragma UNROLL`: the kernel rejects it (`unexpected token 'pragma'`) and the whole run fails.
- For any other precision lever, or an alarm or message you do not understand, grep the Eva manual through `docs/references/` (see `docs/references/README.md`) rather than reading it: loops §6.4, case splitting and partitioning §6.5, domains §6.7, what each alarm checks §3.2, log messages §3.3, FAQ §10.

---

## Step 3 — Status Buckets

`workspace/reports/eva/<mod>.json` partitions every property:

1. **`Valid` (green):** proven for every calling context reachable from `eva_main`. This is a proof relative to the harness context, which is recorded as an assumption on the unit.
2. **`Invalid` (red; Frama-C 33 reports it as `Invalid or unreachable`):** Eva claims a runtime error whenever the statement is reached. Without a concrete witness input this is a `needs_validation` candidate, not a confirmed bug. It gets the same fingerprint as an E-ACSL crash on the same property, so the two merge into one candidate.
3. **`Unknown` (orange):** surviving proof obligations for WP.
4. **`Dead` (`Dead`, `Invalid_but_dead`, `Valid_but_dead`, `Unknown_but_dead`):** the statement is unreachable from `eva_main`. Neither a bug nor a proof; it indicates a harness gap.
5. **`Assumed` (`Considered valid`):** libc or stub specifications taken as given. Recorded as assumptions, never counted as proven.

## Step 4 — Ingest and Queue WP Work

After `fuzz`, `eva` and `eva-tune` have finished:

```text
python3 /opt/framac-pipeline/scripts/pipeline_make.py run ingest replay wp-queue
```

`wp-queue` first runs `facts`: per-function facts for the prover briefs, from the kernel AST and the read and write sets in each Eva report (`workspace/reports/facts/<mod>.json`, cached by content). They are hints, and a failure only means briefs without them. Write `python3 /opt/framac-pipeline/scripts/pipeline_make.py run facts` as its own step after `eva` when you want them to fill the shared cross-run cache.

**`ingest`:**
- Ingests new fuzz reports, then new Eva reports. Expected modules without a report are recorded, never skipped.
- Then validates the run directory. Results:
  - Functions whose RTE obligations are all Valid become `covered` (with the harness-context assumption, and a second one when the proof relied on combining tuning runs).
  - Each Invalid alarm becomes a fingerprinted candidate (same fingerprint as an E-ACSL crash on the same predicate) and its unit becomes `candidate`.
  - Functions with Unknown obligations stay `planned` with Eva evidence attached.

**`replay`:** replays every unverified candidate's reproducers into `workspace/reports/replay/`, so the crash verifiers start from facts.

**`wp-queue`:** runs `wp_scheduler.py init`. That builds the Phase-3 task graph from the planned units, the call graph and the candidates, and writes `workspace/reports/wp_queue.json`. Nothing is written by hand.
