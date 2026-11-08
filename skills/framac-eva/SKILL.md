---
name: framac-eva
description: >-
  Phase 2 of the Frama-C verification pipeline. Runs whole-slice Abstract
  Interpretation (Frama-C Eva + RTE) from each module's eva_main() harness
  inside the hardened analysis container. Automatically discharges
  80-90% of RTE obligations via value/octagon/symbolic-location domains,
  separates Invalid (red), Unknown (orange), dead, and assumed statuses, emits
  per-slice SARIF, and records results in the coverage ledger, including the
  queue of surviving Unknown functions for Phase 3 (/framac-wp).
argument-hint: "<target-dir> --run-dir <dir> [--module <name>] [--slevel <N> (params set --eva-slevel)]"
---

# /framac-eva

Module-level Abstract Interpretation stage that prunes the vast majority of RTE proof obligations automatically with **zero loop invariants** required from the user or LLM.

## Step 1 — Select Module Slices

Read `workspace/reports/callgraph_dag.json` and `workspace/harnesses/`. If Phase 0 has not been run yet, execute `/framac-slice <target-dir>` first.

Two kinds of module meet here:
- **Link units** are the DAG's modules (`module_kind: "link_unit"`, for example `libqcbor_a`). The ledger's `module` is the unit.
- **Harness modules** are what Eva runs on: one `workspace/harnesses/harness_<mod>.c` and its sidecar `harness_<mod>.json` each. A harness module is a whole unit, or a sub-module of one: a path module (the DAG's `lexer_modules`, the sources grouped by directory), a cluster of a split unit (the DAG's `submodules`), or any other harness, scoped by its sidecar's `scope_files` (else its `sources`). The sidecar's `unit` names its link unit.

Make targets (`eva-<mod>`), Eva reports (`workspace/reports/eva/<mod>.json`) and the `--module` of the commands below use harness module names. Ingest maps a report to the units of its link unit (`ModuleMap.unit_of`), so never compare the two names directly. A unit whose harnesses are all sub-modules has no `eva-<unit>` target of its own.

---

## Step 2 — Run Eva on Every Module with Make (no subagents)

Eva runs need no judgment, so they run from the generated Makefile (`docs/resources-and-caching.md`), not from one LLM subagent per module. Eva is single-threaded. Make runs modules side by side, admitting each by memory, and the probe's history learns each module's peak memory. `S=/opt/framac-pipeline/scripts`.

1. If `/framac-fuzz` has not done it yet, generate the Makefile once: `python3 /opt/framac-pipeline/scripts/pipeline_make.py gen`.
2. Run every module: `python3 /opt/framac-pipeline/scripts/pipeline_make.py run eva` (run in the foreground after `fuzz` so `eva` gets a writable `rw` `/framac-cache` mount, or concurrently in the background with `ro` cache if your host harness supports background wrapper calls). Results with status `ok` are cached by content, so an unchanged module is not re-analyzed. Write this command exactly as shown, with the full path: only this exact command line may also fill the shared cross-run cache (`docs/resources-and-caching.md`, Section 5).
3. Tune every module that still has Unknowns, before ingesting: `python3 /opt/framac-pipeline/scripts/pipeline_make.py run eva-tune` (Step 2a). Each surviving Unknown costs a prover task in Phase 3, so this pays for itself. Skip it only when the budget allows no extra Eva runs at all, as under the `quick` profile.

For a single module in guidance mode, check the module's Phase 0 gate first, then run the underlying command:

```text
python3 /opt/framac-pipeline/scripts/phase0_gates.py check --module <mod> --need reach
python3 /opt/framac-pipeline/scripts/run_eva_slice.py --module <mod> --sources <sidecar sources> workspace/harnesses/harness_<mod>.c --main eva_main --out-dir workspace/eva/<mod> --slevel <slevel_or_100> --no-warn-unsigned-downcast --cppflags='<sidecar cppflags> -I/opt/framac-pipeline/templates/acsl' --out-json workspace/reports/eva/<mod>.json
```

- The gate check exits 1 with the reasons when the module failed the reach gate, or its harness or the DAG changed since the check: repair the harness and re-run `harness_reach.py check` (`/framac-slice` Step 4b); never analyse around it. `run_eva_slice.py --module <mod>` enforces the same check itself whenever the run directory has a gate stamp (`workspace/reports/phase0_gates.json`): it prints `status: "gate_failed"` with the reasons, exits 1 and writes no report. A scratch copy without a stamp is not gated.
- A Frama-C failure is reported as `status: "analysis_error"` (exit code 1), never as zero alarms.
- A run that exceeds its wall-clock limit (`--timeout`, from `params set --eva-timeout`; otherwise the broker's fixed Eva job limit) is reported as `status: "analysis_timeout"`. When the limit is at least 120 s and the run uses the default precision and domains, it first retries with cheaper settings; a retry that finishes is reported `ok` with `timeout_fallback` naming the settings used, and is less precise than the base run (more Unknowns).
- Either way the report carries `cost_profile`: the five functions with the largest share of the run's time on their own (`self`) and with their callees (`inclusive`), read from `flamegraph.txt`. `run` says which run it describes: `timed_out` (the run that hit the limit; a killed run still leaves its profile) or `fallback` (when the timed-out run left none). Start any slow-run fix there: tune (Step 2a) or stub the functions it names, before rendering the full flamegraph.

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

The result replaces `workspace/reports/eva/<mod>.json`, with a `tuning` block saying what was tried, what was rejected and why. The decision goes into `workspace/build/params.json`. While it is current (same module settings, same inputs as the last base run), `eva-<mod>` — and so `run eva` and `module-<mod>` — replays it instead of running Eva once: the base run, the recorded rungs and loop trials (all cached by content), then the same per-obligation combination, so the report is the one `run eva-tune` writes (`tuning.mode: "replay"`) and the decision is never re-recorded. Another machine's `run eva-tune` also replays only the recorded runs. A machine that finishes fewer runs leaves more units `planned`.

When the decision no longer applies, `gen` and `run` print a warning (`<mod>: Eva tuning: ...`, in the top-level `warnings` and the module's own): after a change to the module's Eva settings, `eva-<mod>` falls back to the base options; when the sources changed, or there is no base run yet, it runs the selected options once, without the combination. If the base run of a replay shows the sources changed, the report is that base run's (`tuning.mode: "skipped"`). In every case, `run eva-tune` tunes again.

To search again, for example after changing what a loop does: `python3 /opt/framac-pipeline/scripts/pipeline_make.py params set --module <mod> --eva-retune`. A change to the sources or to the module's other Eva settings already triggers a new search.

### Tuning Eva by Hand
`eva-tune` covers precision. These are the choices it cannot make, because they depend on what you know about the target. Record them in `workspace/build/params.json`, then re-run the `eva` target (or `module-<mod>`).
- **An option the ladder does not try:** `python3 /opt/framac-pipeline/scripts/pipeline_make.py params set --module <mod> --eva-option min-loop-unroll=8` (repeatable; `name=` clears it). Only the allowlist in `scripts/eva_options.py` is accepted: `min-loop-unroll`, `auto-loop-unroll`, `widening-delay`, `widening-period`, `partition-history`, `partition-value`, `slevel`, `ilevel`, `plevel`, `subdivide-non-linear`, `unroll-recursive-calls`, `split-return`, `remove-redundant-alarms`, `octagon-through-calls`, `equality-through-calls`, `context-depth` (never below its default of 2), `context-width`, `precision`, `default-loop-unroll`, `interprocedural-history`, `interprocedural-splits`, `reduce-on-logic-alarms`, `hierarchical-convergence`, `descending-iteration`, `join-results`, `alloc-returns-null`, `all-rounding-modes-constants`, `domains=multidim`, the per-function overrides `slevel-function=f:1000` (repeatable as a comma list, also `partition-history-function`, `equality-through-calls-function`, `subdivide-non-linear-function`, `split-return-function`, `domains-function=octagon:f+`), and `builtin`/`use-spec` (comma-separated function lists, to stub externals inside Eva — see `docs/upstream/sources/use_spec.i`). None of them reduces what is checked. `context-depth` changes the initial state rather than precision, so a run with another value is another analysis and is never combined with this one. The `perfn` ladder rung already applies `slevel-function` to the functions with the most surviving Unknowns.
- **Dynamic memory allocation (`Tier 2` heap/tree parsers):** by default, Eva merges dynamic allocations (`malloc`/`calloc`/`realloc`) at the same callstack (`-eva-mlevel 0`) into weak bases (`__malloc_w_*`), causing spurious aliasing on loop/tree/list/JSON/ASN.1 allocations. Unroll allocation sites per callstack with `params set --module <mod> --eva-mlevel 4` (or `--mlevel <K>` on `run_eva_slice.py`).
- **Recursive call cycles without `assigns` specs (`Tier 2`):** if Eva aborts on a mutually recursive call cycle (`assigns:missing`), enable the recursion fallback for that module with `params set --module <mod> --eva-recursion-fallback` (which passes `--allow-incomplete-recursion-specs` / `-eva-warn-key assigns:missing=warning` and records the assumption in `reduced_checks`).
- **Taint:** the pipeline generates no taint annotation. Layer 6 is the MetAcsl `L6_wiped_*` / `L6_no_leak_*` properties, checked by WP in Phase 3, and the no-leak check sees direct flows only (`docs/security-properties.md`). To follow an indirect flow of a secret by hand, `params set --module <mod> --eva-taint` adds `taint` to `-eva-domains`; Eva then checks the `//@ taint ...;` and `//@ assert !\tainted(...);` annotations you write yourself (Eva manual, taint domain).
- **A loop `eva-tune` should not unroll, or one it missed:** a hand-written `//@ loop unroll N;` in `workspace/work/` (ACSL-only, so it passes the merge checks) is left alone by the search. Do not write the older `loop pragma UNROLL`: the kernel rejects it (`unexpected token 'pragma'`) and the whole run fails.
- For any other precision lever, or an alarm or message you do not understand, grep the Eva manual through `docs/references/` (see `docs/references/README.md`) rather than reading it: loops §6.4, case splitting and partitioning §6.5, domains §6.7, what each alarm checks §3.2, log messages §3.3, FAQ §10.

### Observability and repair hints in every Eva report
- Every run writes `flamegraph.txt` (`-eva-flamegraph`) and `nonterm.log` (`-nonterm`) in its output directory; the report (`workspace/reports/eva/<mod>.json`) carries them as `flamegraph_file`, `nonterm_log_file`, and the parsed `nonterm` warnings. A plain `eva-<mod>` writes them in `workspace/eva/<mod>/`; a tuned module's runs are under `workspace/eva/<mod>/tune/<run>/`, and `eva-tune` (or its replay) copies the `flamegraph.txt` of the run the report rests on to `workspace/eva/<mod>/flamegraph.txt`. For a slow or hanging run, render it with `python3 /opt/framac-pipeline/scripts/pipeline_make.py run flamegraph-<mod>` (or `scripts/eva_flamegraph.py --dir workspace/eva/<mod>`) and read the widest bars — they name the functions where Eva spends its time. `flamegraph-<mod>` never runs Eva, so it cannot replace the module's report: it fails, saying so, when `workspace/eva/<mod>/flamegraph.txt` does not exist yet (run `eva-<mod>` or `eva-tune` first), and in one `run` it comes after `eva` and `eva-tune`.
- The report's `repair_hints` field ports upstream `make-wrapper` log patterns (`docs/upstream/sources/make_wrapper_tips.md`): a `recursive_call` hint means patch/stub/specify the recursive call or use `--eva-recursion-fallback`; a `missing_spec` hint names the function and points at the defining file (via `build_callgraph_dag.py`'s index) or `templates/acsl/external_stubs.h`.
- Upstream reference examples worth reading when tuning by hand are vendored in `docs/upstream/sources/`: `loopinv.c` (`-eva-slevel-function`), `partitioning-annots.c` (`//@ loop unroll N;`, `-eva-partition-value/-history`), `use_spec.i` (`-eva-use-spec` to override a function with a spec inside Eva), `taint.c`/`multi_taint.c` (taint-domain annotations, for the indirect flows the MetAcsl no-leak check does not see).

---

## Step 3 — Status Buckets

`workspace/reports/eva/<mod>.json` partitions every property:

1. **`Valid` (green):** proven for every calling context reachable from `eva_main`. This is a proof relative to the harness context, which is recorded as an assumption on the unit.
2. **`Invalid` (red; Frama-C 34 reports it as `Invalid`, 33 as `Invalid or unreachable` — both spellings map to the same bucket in `framac_common.py`):** Eva claims a runtime error whenever the statement is reached. Without a concrete witness input this is a `needs_validation` candidate, not a confirmed bug. It gets the same fingerprint as an E-ACSL crash on the same property, so the two merge into one candidate.
3. **`Unknown` (orange):** surviving proof obligations for WP.
4. **`Dead` (`Dead`, `Invalid_but_dead`, `Valid_but_dead`, `Unknown_but_dead`):** the statement is unreachable from `eva_main`. Neither a bug nor a proof; it indicates a harness gap.
5. **`Assumed` (`Considered valid`):** libc or stub specifications taken as given. Recorded as assumptions, never counted as proven.

## Step 4 — Ingest and Queue WP Work

After `fuzz`, `eva` and `eva-tune` have finished:

```text
python3 /opt/framac-pipeline/scripts/pipeline_make.py run ingest
python3 /opt/framac-pipeline/scripts/pipeline_make.py run replay wp-queue
```

`wp-queue` first runs `facts`: per-function facts for the prover briefs, from the kernel AST and the read and write sets in each Eva report (`workspace/reports/facts/<mod>.json`, cached by content). They are hints, and a failure only means briefs without them. Write `python3 /opt/framac-pipeline/scripts/pipeline_make.py run facts` as its own step after `eva` when you want them to fill the shared cross-run cache.

**`ingest`:**
- Ingests new fuzz reports, then new Eva reports. Expected modules without a report are recorded, never skipped.
- Then validates the run directory. Results:
  - Each harness module's report gives each function's `rte` unit one verdict, kept per module in `bookkeeping.eva_verdicts`; a module's newer report replaces its verdicts. A module whose report reaches the function's obligations and finds them all Valid gives `valid`; one Invalid, Unknown or unclassified status gives `invalid`, `unknown` or `other`; obligations that are only Dead (the harness never reached them), or no property at all, give `dead` or `none`.
  - A unit becomes `covered` when at least one module's verdict is `valid` and none is `invalid`, `unknown` or `other`; `dead` and `none` neither prove nor block. It carries the harness-context assumption naming the modules whose harnesses proved it (and a second one when the proof relied on combining tuning runs). A report from another unit's harness counts too ("another module's harness").
  - When a later report leaves an obligation open, a unit that only Eva covered goes back to `planned` (`eva_cover_withdrawn`).
  - Each Invalid alarm becomes a fingerprinted candidate (same fingerprint as an E-ACSL crash on the same predicate) and its unit becomes `candidate`.
  - Units with Unknown obligations stay `planned` with Eva evidence attached. `deferred` units (Tier 3 under `quick`, GCC-fallback units) get no verdict, but an Invalid alarm in one still makes it a `candidate`; an unreached header function, deferred until then, becomes `planned` again once a report gives it properties.

**`replay`:** replays every unverified candidate's reproducers into `workspace/reports/replay/`, so the crash verifiers start from facts.

**`wp-queue`:** runs `wp_scheduler.py init`. That builds the Phase-3 task graph from the planned units, the call graph and the candidates, and writes `workspace/reports/wp_queue.json`. Nothing is written by hand.
