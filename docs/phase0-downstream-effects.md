# Phase 0 redesign: what it means for the other phases

Read this before you change Phase 1 (fuzzing), Phase 2 (Eva), the Pre-WP crash gate, Phase 3 (WP), the report, the Make flow or the benchmark. It records what Phase 0 now produces, what each later phase reads from it, what changed downstream, the traps, and the defects known today.

- **State described:** branch `phase0-redesign` at `2cfaa48` (2026-11-08), with steps I0–I10 of [phase0-implementation-plan.md](phase0-implementation-plan.md) done. It is not yet merged into `main`.
- **Sources:** a read of the code in four areas (Phase 1, Eva and the ledger, the WP gate and Phase 3, orchestration), and the plan's step notes. Line numbers are as of that commit. Each defect in §8 was checked in the code.
- **Background:** [phase0-redesign.md](phase0-redesign.md) explains why, and the plan's "Step notes" say what each step did.

## 1. The redesign in one table

| | Before | Now | Where |
| :--- | :--- | :--- | :--- |
| Inventory | Regex lexer over the sources | Frama-C kernel model on the build's own flags, with a GCC fallback per unit | `scripts/phase0_model.py` |
| Target that doesn't build | Lexer guess | Phase 0 stops with `needs_build_recipe` | `scripts/build_capture.py`, `state/progress.json` |
| Function identity | Plain name; collisions lost a definition | Model id `file#name`; DAG key is the plain name, or `file#name` when the name collides | `build_callgraph_dag._model_key_of` |
| Indirect calls | Mostly missed | Type-matched edges (Alias narrowing exists, off) | model `indirect_sites` |
| DAG modules | Directories | Link units (`module_kind: link_unit`) | `build_callgraph_dag.unit_view` |
| Harness modules | Same as DAG modules | A unit, or a sub-module of one: path module or I8 cluster | `scripts/module_map.py` |
| Entry points | Name guesses | The unit's exported API, `main`, the embedded API | build capture |
| Flags | Lexer Makefile scan | The build's flags per unit, `force_includes` apart | `unit_cppflags` |
| Tiers | Regex patterns per module | Per function, from trust and structure; units take the highest | `scripts/tiers.py` |
| Big units | Not handled | Split into clusters above 400 functions or 15k lines | `scripts/unit_split.py` |
| Fuzz corpus | Empty | Seeds recorded from the target's tests | `scripts/seed_harvest.py` |
| Reach gate | Static only | Static, then reopened by coverage (`reach-dynamic`) | `scripts/harness_reach.py` |
| Trust | None | `untrusted`/`trusted` plus `boundary` per function, from the API, input readers and the threat model; optional CodeQL | `scripts/trust.py`, `scripts/codeql_trust.py` |
| Security properties | `templates/acsl/layer4/5/6` | MetAcsl properties from a structured threat model | `scripts/security_props.py`, `templates/metacsl/` |
| Images | One monolith | Build image (`framac-build[:<repo>]`) and analysis image (`framac-analysis`), plus CodeQL; a snapshot carries the target's headers and libraries | `Dockerfile`, `wrappers/` |

## 2. What Phase 0 hands over

| Artifact | Main fields | Read by |
| :--- | :--- | :--- |
| `workspace/reports/build_capture.json` | units (files, links, flags, entry points, embedded API), `cc -M` header lists, status | `phase0_model.py`, `build_callgraph_dag.py` (unit `-I`), `seed_harvest.py`, `benchmark.py` |
| `workspace/snapshot/manifest.json` and `root/` | digest, headers, libraries | `target_env.py`: `-idirafter`, `-L`, RPATH; `cache.toolchain_id` (`+snapshot:<digest>`) |
| `workspace/reports/phase0_model.json` | `functions` (`file#name`, signature, formals, `external_calls`, `indirect_sites`, trust), `units[].parse.status`, `trust` | the DAG, `trust.py`, `security_props.py`, `seed_harvest.py`, `generate_report.py`, `acsl_ast.py` |
| `workspace/reports/callgraph_dag.json` | `module_kind`; `modules{tier, run_eacsl_fuzz, run_eva, required_sources, cppflags, force_includes, candidate_entry_points, concurrent}`; `lexer_modules`, `unit_of_lexer_module`; `submodules`; `functions{name, file, module, lexer_module, tier, tier_reasons, untrusted_path, trust, wave, header, reached, callgraph_source, callgraph_fallback, internal_callees, indirect_callees, verifiability, wp_blockers, wp_notes, security_properties}`; `tiers` | `pipeline_make.py`, `module_map.py`, `ledger.py`, `wp_scheduler.py`, `workspace_overlay.py`, `run_wp_function.py`, `harness_reach.py`, `benchmark.py` |
| `workspace/reports/security_props.json` | `obligations["file#name"]` (class, property) | `ledger.py` seed, `run_wp_function.py`, `workspace_overlay.py` (prover brief) |
| `workspace/harnesses/harness_<mod>.json` (sidecar) | `unit`, `sources`, `cppflags`, `ldflags`, `include_source`, `dispatch_cases`, `max_input_size`, `reach_exempt`, `entry_fn`, `reachability` | `module_map.py`, `pipeline_make.py`, `run_eacsl_fuzz.py`, `harness_reach.py`, `workspace_overlay.py` |
| `workspace/seeds/<mod>/` | seed inputs | `fuzz-%` and `coverage-%` through `--extra-corpus` (`templates/pipeline.mk`) |
| `workspace/reports/phase0_gates.json` | reach (passed, gaps, `harness_digest`), `build_check` (ok, `fuzz_engine`) | `phase0_gates.check` from `pipeline.mk`; `validate_artifacts.py` |

The names `lexer_modules`, `lexer_module` and `unit_of_lexer_module` are kept for compatibility. They now mean **path modules**: files grouped by directory (`src/<dir>/…` → `<dir>`, `src/f.c` → `f`), with header functions placed by vote. There is no lexer behind them.

## 3. Concepts every phase must handle

### 3.1 Units and harness modules

- **The ledger's `module` is the link unit** (for example `libqcbor_a`). Report names, Make targets, corpus directories, crash directories and candidates use **harness module** names (for example `qcbor_decode`).
- **Map through `ModuleMap`, never compare names directly:**
  - `unit_of(module)` gives the unit of a harness module;
  - `submodules(unit)` gives the harness modules inside a unit;
  - `harness_module_for(unit)` gives the unit's own harness, else its *first* sub-module;
  - `harness_module_for_function` gives the harness whose scope holds a function;
  - `scope_functions` gives what a harness answers for;
  - `tier_of` and `run_flags` give a harness module's run settings.
- **A unit whose harnesses are all sub-modules gets no Make target under its own name.** Its WP flags are the union of its sub-modules' flags.
- **Scope:**
  - a path module answers for its own functions;
  - a cluster answers for its cluster's functions;
  - any other harness module answers for its `scope_files`, else its `sources`;
  - an empty scope means the whole unit.

### 3.2 Function identity

- **Model ids are always `file#name`.** DAG keys are the plain name, unless two functions share it, and then `file#name`. Code that indexes the DAG by plain name silently misses colliding functions (§8).
- **Ledger units are `file#function::class`.** They are matched by (file, plain name), and a unique name is the fallback.
- **Crash fingerprints are `normalized_file#plain_function::kind::digest`.**
- **Kernel renames:** Frama-C renames colliding statics (`f_0`). Eva ingest maps rows back by file and line range; fuzz ingest does not.

### 3.3 Flags and sources

- **The sidecar is the source of truth for build flags.** `pipeline_make` checks the sidecar's `cppflags` against an allowlist. The DAG's flags only feed the `dag_cppflags_missing` warning. New unit flags reach a build only when the harness is regenerated.
- **What the harness generator merges from the DAG:**
  - the unit's `-I`, `-D`, `-U` flags and its `force_includes` (`generate_harness._merge_dag_module_cppflags`);
  - **not** `-D` values with quotes, spaces or backslashes, nor `-std=`, because later stages split and re-join flag strings. The harness spec must state these itself.
- **One configuration per file:** a file compiled by several units with different flags is analysed only in the first unit's configuration. qlz's four executables are the known case.
- **Header `static inline` functions** have one DAG record, homed in the first unit that compiles them. They are analysed, credited and proved under that unit only.
- **Source closures are smaller and exact:**
  - a path module's `required_sources` is the closure of model edges from its own functions;
  - a callee brings its path module's closure, not its whole unit.
  - Example: CryptoLib `mc` went from 19 source files to 3, and Eva from 689 properties to 43, with 0 undeclared functions.

### 3.4 Tiers and profiles

- **Tiers are per function** (`tier`, `tier_reasons`, `untrusted_path`). A unit or cluster takes its highest tier.
  - Without trust (a model before I7), only structure decides, and `tiers.source` is `structure`.
- **Values moved with real types.** CryptoLib's 13 `get_*_interface` getters went from 3 to 1A, and `main(int, char **)` from 1B to 1A. 1A and 1B share run flags.
- **The quick profile defers Tier 3:**
  - Make excludes whole Tier 3 modules;
  - the ledger seeds Tier 3 functions `deferred`;
  - the benchmark doesn't count them;
  - Eva results on deferred units are skipped, but an Invalid still makes the unit a `candidate`.

### 3.5 Trust and the threat model

- **Each function has a trust record:**
  - `trust.value`: `untrusted` or `trusted`;
  - `trust.sources`: `default`, `input_reader`, `threat_model`, `codeql`, …;
  - `trust.boundary`.
- **A target without a structured `THREAT_MODEL.md` records `no_threat_model`.** Only the library API is untrusted then. Today only minmea, qcbor and x509-parser have threat models.
- **What uses trust today:**
  - tiers;
  - the harness sidecar's `reachability`;
  - the WP merge check on boundary contracts (`acsl_ast.is_trust_boundary`);
  - the report's "Trust boundary" section.

### 3.6 Security properties (MetAcsl)

- **Classes:** `l3_frame`, `l4_auth_state`, `l4_auth_required`, `l5_sanitized`, `l6_wiped` and `l6_no_leak`, beside `rte` and `l2_termination`.
  - The old classes `l4_auth`, `l5_output` and `l6_secret` stay in the schemas and `generate_report.CLASSES`.
  - The DAG emits only Layer 2 now, so the seed never creates the old classes.
- **`security_props.json` must exist before `ledger.py seed`.**
  - If it appears later, WP produces meta goals with no ledger unit.
  - An unproven meta goal blocks `all_proven`.
- **The `security-props` Make target runs `security_props.py run`,** and `seed` depends on it; the benchmarks run it as a stage before `seed` (fixed defect 5, §8).
- **Known limits (I9 notes):**
  - `L5_no_crlf` on string literals doesn't prove;
  - `memset` wipes don't prove under Typed;
  - no-leak sees direct flows only.

### 3.7 Images, snapshot, gates

- **Images:** the build image runs the target's build, tests, capture and seed recording. The analysis image runs everything else. `-Image` only renames one of the two.
- **Snapshot:** the target's headers and libraries reach the analysis image through `workspace/snapshot/`.
  - The RPATH is fixed to `/framac-run/workspace/snapshot/root/…`, so the binaries only run where the run directory is mounted there.
  - Host runs need `FRAMAC_SNAPSHOT_DIR`.
  - Module flags may not carry `-Wl,`; the link flags are added inside `run_eacsl_fuzz.py`.
- **Two different "snapshots":** the target snapshot (`workspace/snapshot/manifest.json`), and the overlay snapshot (`state/snapshot-manifest.json`), which `run-metadata.json`'s `snapshot_digest` refers to.
- **Gates (`pipeline.mk`):**
  - `build-%`, `coverage-%` and `eva-%` check `reach`;
  - `fuzz-%` checks `reach` and `build_check`;
  - `seed` depends on `reach-gate`;
  - `reach-dynamic-%` runs after `coverage-%`, and reopens the gate for an entry point no input executed.
- **The gate digest covers only the harness `.json` and `.c`.**
  - A rebuilt DAG with new entry points doesn't invalidate a passed gate, so run `reach-gate` again after it.
  - Any sidecar edit clears that module's dynamic gaps.

## 4. Phase 1: fuzzing, coverage, replay

**What it reads:**
- the sidecar: sources, flags, `dispatch_cases`, `max_input_size`, `reach_exempt`;
- the DAG record through `ModuleMap`: tier, run flags;
- the seeds;
- the snapshot flags.

`run_eacsl_fuzz.py` itself reads no DAG for compilation.

**What changed:**
- **One campaign per harness module.** Reports, corpus, crashes, dictionaries and seeds are all keyed by the harness module name. Renaming a harness module loses its corpus warm start (`cache.warm_start_corpus`).
- **Budget per case:**
  - 60, 120 or 900 CPU-seconds per case (quick, standard, deep);
  - capped per unit at 480, 1200 or 7200, scaled down in proportion with at least 30 each;
  - recorded as `fuzz_budget_source`.
- **Seeds:** `fuzz-%` writes `workspace/seeds/<mod>` and passes it as `--extra-corpus`, and so does `coverage-%`. The single-module command in `skills/framac-fuzz/SKILL.md` leaves this out.
- **Dynamic reach gate:** an entry point with 0 executions reopens the gate. The gap stays until the harness digest changes. It reads only the sidecar's exemptions, not `reach_exempt_modules.json`.
- **Ingest:** clean or error evidence goes only to units in the harness module's scope, and candidates name the report's harness module.
- **Replay** of a candidate that names a unit builds `harness_module_for(unit)`, which is the first sub-module. The ledger picks a candidate's harness by the scope of the crashing function, so the two can disagree (§8).

**Watch out:**
- **E-ACSL still uses the old tokenizer:** its `-rte-select` list and crash-to-function resolution go through `c_definitions.extract_functions_from_code`, not the model.
- **Concurrency:** E-ACSL detects it by scanning sources (`slice_has_pthread`), not from the DAG's `concurrent`.
- **GCC-fallback units:** the DAG gives them `fuzz_engine: sanitizers`, which the Make plan applies, so `build_check` accepts them without a manual `params set` (defect 6).
- **Coverage:** `COVERAGE_EXTERNAL_PREFIXES` doesn't list the snapshot root, so code in snapshot headers counts as target code.
- **Colliding names:** seed records are keyed by plain name and pooled across units, and link repair (`_dag_symbol_files`) takes the first file per name.

**Not used yet:** trust, `untrusted_path`, `security_props` (MetAcsl properties are never checked at run time), `no_threat_model`, and the fallback flag.

## 5. Phase 2: Eva and the coverage ledger

**What it reads:**
- `run_eva_slice.py` reads no Phase 0 artifact. Make gives it sources, flags and `-Dmain=__framac_module_main_<ident>` from the sidecar and the DAG record.
- The ledger seed reads the DAG: `module_kind`, the module's `tier` and `concurrent`, and per function `name`, `file`, `module`, `tier`, `wave`, `header`, `reached`, `callgraph_source`, `callgraph_fallback`, `has_loops`, `security_properties`, `verifiability`, `wp_blockers` and `wp_notes`. It also reads `security_props.json` and the profile.
- Eva ingest reads the DAG's `line`, `end_line`, `file` and `name` per function, to place rows by line range.

**What changed:**
- **Verdicts per harness module:** each harness module keeps one verdict in `bookkeeping.eva_verdicts`, and a newer report replaces it.
- **When a unit is covered:** at least one `valid` verdict and no `invalid`, `unknown` or `other`. `dead` and `none` neither prove nor block.
  - An Eva-only cover is withdrawn (`eva_cover_withdrawn`) when a blocking verdict appears.
  - A failed Eva run records evidence but no verdict, so it never blocks.
- **Cross-module verdicts:** a report credits other modules' units it has rows for, under "another module's harness".
- **Header functions:**
  - An unreached header function is seeded `deferred` (`HEADER_UNREACHED`). It becomes `planned` again once a report gives it properties.
  - Kernel copies like `f_0` land on the right unit by line range.
- **Concurrency:** a unit gets `bookkeeping.concurrent` and a report note saying its Eva and WP results assume sequential execution. Covering ignores it.
- **Recorded results:** `mc_initialize` is newly covered, and x509-parser's `x509-parser` module completes Eva.

**Watch out:**
- **Ingest order:** fuzz before Eva.
- **A report's `module` must be the harness module.** The units it may credit are those of `ModuleMap.unit_of(report module)`. Header files are owned even when absent from the report's `sources`.
- **Re-seeding only adds units.** Existing units keep their module, tier, status and fallback fields, and units of vanished functions stay. After a Phase 0 change, use a fresh ledger or a new run.
- **Ingest is keyed by the digest of the report bytes.** A `ModuleMap` change does not re-attribute reports already ingested.
- **Old run directories:** a ledger with `callgraph_source: regex` fails validation, so `generate_report` aborts on such a run. The enum is now `frama_c` or `gcc_callgraph`.
- **`concurrent` comes from a header function's home unit only.** Other concurrent units that compile it are missed.
- **`bookkeeping` is free-form in the schema.** Only tests pin `eva_verdicts`.

**Not used yet:**
- trust, `untrusted_path` and `no_threat_model`;
- the "fallback unit blocked" decision: those units stay `planned` with only `bookkeeping.callgraph_fallback`;
- Eva's own `flows.call_edges`, which are never merged back into the DAG;
- MetAcsl classes in Eva ingest, which handles `rte` only.

## 6. Pre-WP gate and Phase 3: WP

**What it reads:**
- **`wp_scheduler.py`:**
  - indexes DAG functions by `(file, name)` and by plain name, so it takes both key forms;
  - takes call edges from `internal_callees` only;
  - recomputes recursion groups and waves itself (Tarjan), ignoring the DAG's `wave` and `recursion_cycles`;
  - reads `verifiability` and `wp_blockers` from the DAG, falling back to the ledger's `bookkeeping`.
- **The quick chain** takes the per-function ledger tier and seeds from every Tier 1A function.
- **The overlay and prover briefs** go through `ModuleMap`, `merged_sidecar` and `harness_module_for_function`. Each brief also reads that function's MetAcsl obligations from `security_props.json`.
- **The trust-boundary merge check** uses `acsl_ast.is_trust_boundary`.

**What changed:**
- **Fewer WP blockers.**
  - Before, `irreducible_goto`, `container_of` and `volatile_or_asm` made a function `shell_unverifiable_wp`. The lexer removal dropped them, and only harness entry, variadic and dynamic allocation remain.
  - So such functions now get full prover budgets and fail at run time: a non-natural loop is a Tier-A abort, and casts hit the cast probe.
  - The pointer-cast, unsigned-wrap and macro-loop notes are gone from `wp_notes`.
  - This is a regression (§8).
- **More indirect edges:**
  - more `needs_calls_annotation` functions;
  - more dependencies, possibly spurious recursion groups, and a bigger quick chain. On x509-parser, about 41 of 163 type-matched edges are spurious, since Alias narrowing is off.
- **Coarser gating:**
  - any open verify task of any sub-module blocks every prover in the unit;
  - there is one header architect per unit, and it covers the first sub-module's header only.
- **More prove tasks:** one per function with any planned unit. With `security_props.json`, `l3_frame` units queue functions whose RTE work Eva already covered (198 on qcbor-dev).
- **Trust boundary from trust:**
  - harness entries not at the boundary become `internal_api` and escape the boundary check;
  - boundary functions with no harness are added.
- **Header functions** are proved under their home unit's flags only, with the `.h` file as `--file`.

**Watch out:**
- **Keys:** obligations and MetAcsl instances are `file#name` with the model's paths, matched by suffix, while ledger units use the DAG's `file` and `name`. Keep the paths consistent.
- **Meta classes are credited by goal name.** An agent clause named like `L6_wiped_x` would match one.
- **Architect merges check only harness `entry_fn`s.** A value constraint an architect adds to a boundary function no harness enters is not caught.
- **The brief and the merge check disagree.** The brief marks every function of a unit `untrusted_surface` when any sidecar has no `entry_fn`; the merge check skips such sidecars.
- **Gate and repair:** they must go through `ModuleMap`. A verify task's module is a harness module, not the unit.
- **GCC-fallback units** have no signatures, so they get no `internal_variadic` blocker, and their WP parse will probably fail again.
- **`Typed+cast`:** a proof under it never counts (`run_wp_function.py:1519`), yet `docs/troubleshooting.md:217` still recommends it. That was stale before the redesign too.

**Not used yet:**
- trust and `untrusted_path` for priority (the queue orders by chain height, then Eva Unknowns);
- `concurrent`;
- the fallback flag;
- `no_threat_model`.

## 7. Orchestration, report, cache, benchmark

- **The Make plan:**
  - one record per harness module;
  - a sub-module takes its path module's record, with its own tier and run flags;
  - deferral by tier.
  - `pipeline_make` never reads the model, the capture, trust or `security_props.json`.
- **Report:**
  - new: a "Trust boundary" section (with the `no_threat_model` reason), concurrency notes, and the MetAcsl classes;
  - not yet: fallback units, tiers, seeds, the security-props summary, the build recipe, the unit split, dynamic reach gaps;
  - SARIF is unchanged.
- **Cache:** the toolchain id carries `+snapshot:<digest>`. Unit flags reach cache keys through the sidecar, and headers through the dependency manifest. No key holds a model or capture digest, and none is needed while the sidecar holds the flags.
- **Schemas:**
  - new: `build_capture`, `phase0_model`, `threat_model`, `security_props`;
  - the ledger, agent-result and findings schemas gained five classes;
  - `run-metadata` gained `build` and `codeql`;
  - `regex` left the ledger's `callgraph_source` enum.
  - `validate_artifacts` doesn't schema-check the model, the capture or `security_props.json`.
- **Wrappers:**
  - the default image is `framac-analysis:latest`;
  - `-BuildImage` runs `framac-build[:<repo>]`;
  - `-TargetPackages` only derives the build image;
  - `-Scratch`, `-RemoveScratch` and `-CodeQL` were added.
- **Benchmark:**
  - baselines `phase0-i5a`, `phase0-i5b`, `phase0-i9`, `phase0-i10` (latest);
  - `benchmark.py seeded` runs the 8 seeded projects;
  - `harness_digest` leaves out the recipe, threat model, seeds and security props, so `compare` doesn't flag changes to those;
  - it still hashes the now-unused `compile_commands` asset, which was kept so digests don't change.

## 8. Known defects and gaps

All of these were checked in the code. Defects 1-8 and 15-20 are fixed on `phase0-redesign` (commit in the Status column); 9-14 stay open. Defects 15-20 came from a second audit of Phase 0 (2026-11-08). The fixes were unit-tested only: no pipeline or benchmark run has checked them yet.

| # | Severity | Where | Problem | Fix direction | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | Broken | `templates/pipeline.mk:57-60` `slice-init` | Passes `--emit-compile-commands`, which I10a removed: the target fails, and it runs no capture or model step. No test runs the recipe. | Rewrite `slice-init` as capture → model → DAG, or drop it and document the skill's sequence; add a test that runs the recipe. | Fixed, `cf9c2cd`: `slice-init` only creates the overlay; a new `dag` target builds the DAG. Capture and model stay agent steps (they need the confirmed recipe). `test_phase0_make_recipes.py` runs the recipes. |
| 2 | Regression | `build_callgraph_dag.py` `wp_facts` | goto, `container_of`, volatile and inline-asm functions are no longer WP blockers, so WP spends full budgets on them. | Get these facts from the kernel model (Frama-C knows gotos, volatile accesses and asm), restore the blockers, and add a test. | Fixed, `516bea0`: `source_facts` tokenizes each function's body from the model's line span and restores `irreducible_goto`, `container_of` and `volatile_or_asm`. |
| 3 | Soundness | `ledger.py:2580-2622` `audit-hypotheses` | Callees are looked up by plain function name. A colliding callee's DAG key is `file#name`, matches nothing and is dropped, so a caller can be discharged unconditionally over an unproven callee. | Resolve callees by `(file, name)` the way `wp_scheduler.resolve` does; add a `file#name` test. | Fixed, `5eb31ff`. |
| 4 | Wrong brief | `workspace_overlay.py:2429-2562` `prepare_agent` | `dag_fns.get(function)` by plain name finds nothing for colliding names. The brief then gets every L2 property of the module and `wave_index=0`. It also reads `is_entry`, which nothing produces. | Look up by `file#name` first; drop `is_entry`. | Fixed, `5eb31ff`: `dag_function_record`. |
| 5 | Not wired | Make and benchmark | `security_props.py run` is never called, so MetAcsl obligations exist only when an agent runs it before `ledger.py seed`. | Add a `security-props` target before `seed`, and to the benchmark stages. | Fixed, `cf9c2cd`. |
| 6 | Decision not enforced | `phase0_model.py:875-889`, ledger, Make | "Stop if no unit parses": the model stays `ok` when every unit fell back to GCC. "Fallback unit: Eva and WP blocked": only `bookkeeping.callgraph_fallback` is set. No automatic sanitizer fallback either. | Model status `no_unit_parsed`; mark fallback units blocked in the ledger and report; set `fuzz_engine: sanitizers` for them. | Fixed, `5e89cfc`: model status `no_unit_parsed`, exit 4; fallback units get `run_eva`/`run_wp_full` false and `fuzz_engine: sanitizers`; the seed defers their functions' Eva/WP units with `callgraph_fallback: <reason>`, which report section 6 groups. |
| 7 | Missing flags | `generate_harness._merge_dag_module_cppflags` | An I8 cluster (in `submodules`, not `lexer_modules`) or a freely named harness gets neither its unit's flags nor its `force_includes`. | Resolve the unit through `ModuleMap.unit_of` or the `--unit` argument. | Fixed, `188dfdb`. |
| 8 | Inconsistent | `run_eacsl_fuzz.py:2997`, `ledger.py:1510` | Replay builds a unit's first sub-module. The ledger picks the harness whose scope holds the crashing function. | Replay through `harness_module_for_function`. | Fixed, `85ef0a9`: replay, minimize and the benchmark replay build the harness holding the candidate's function. |
| 9 | Imprecise | `trust.py:508-535`, `workspace_overlay.py:1408` | The boundary check passes the name without the file, so same-named functions merge, with "untrusted wins". Conservative, but noisy. | Pass the file. |
| 10 | Imprecise | `run_eacsl_fuzz.py:135` | Snapshot headers count as target code in coverage. | Add the snapshot root to `COVERAGE_EXTERNAL_PREFIXES`. |
| 11 | Imprecise | fuzz ingest | Kernel-renamed statics (`f_0`) are not mapped back, unlike in Eva ingest. | Reuse the line-range placement. |
| 12 | Stale state | `ledger.py:416-418`, `phase0_gates.py:45-55` | Re-seeding never refreshes existing units, and the reach-gate digest ignores the DAG. | Document it (done here); consider a DAG digest in the gate key and a `--refresh` seed. |
| 13 | Coarse | `wp_scheduler.py:673-679`, `:1367` | One header architect per unit, for the first sub-module's header only; gating is per unit. | Per-harness headers; gate per sub-module scope. |
| 14 | Limit | flags | One configuration per file shared by several units (qlz). | Run each unit's configuration (I8 split, or a later step). |
| 15 | Broken | `pipeline_make.build_check`, `validate_artifacts.validate_phase0_gates` | A plan with nothing to fuzz recorded `build_check.ok: false` with no modules, which failed validation and `wp-queue`: an Eva-only run could not finish. | Pass a plan with modules but nothing to fuzz; keep failing a plan with no module. | Fixed, `60107a9`. |
| 16 | Gate bypass | `phase0_gates.check` (whole run), `wp_scheduler.py init`, `benchmark.py` | The whole-run gate trusted the stored reach flag (a harness changed since passed) and the recorded build rows (a module build-check never built passed). `wp_scheduler.py init` checked no gate, and the benchmark checkpointed Phase 2 whatever `wp-queue` returned. | Check digests run-wide; `wp-queue` passes the plan's `MODULES` and `FUZZ_MODULES`; `init` checks the gates; drop the benchmark's checkpoint. | Fixed, `60107a9`. |
| 17 | Lost facts | `phase0_model.ModelBuilder.add_function` | The first parse to see a function kept its record, so a function also compiled by an earlier-sorting GCC-fallback unit lost its signature, formals, loops and writes (and with them its L2/L3 units and WP blockers). | A Frama-C record replaces a GCC one. | Fixed, `f43368a`. |
| 18 | Name lookup | `pipeline_make.sweep_list`, `generate_harness._merge_dag_harness_sources` | Plain-name lookups of DAG keys, as in defect 3: a colliding Eva-only callee was left out of the WP sweep, and a colliding callee's sources were not merged into a harness. | Resolve keys through their DAG record; for harness sources, the definition in the harness's sources, else the only external one. | Fixed, `2747d3f`. |
| 19 | Missing API | `build_callgraph_dag` (`reached`), `seed_harvest.plan_recorder` | The model's top-level `entry_points` leaves out `embedded_api`, so header functions reached only from it were deferred as unreached, and it was never recorded for seeds. | `model_api`: entry points plus the non-test units' embedded API. | Fixed, `b440e1e`. |
| 20 | Silent drop | `phase0_model` (capture ids) | A function defined in a `#include`d `.c`, or a header function without `-g`, has another id in the capture than in the model; trust, the unit view and the reach gate dropped it without a warning. | `reconcile_api_ids` maps it to the unit's only external function of that name, or warns. | Fixed, `003be49`. |

**Stale docs and briefs:**
- `skills/framac-eva/SKILL.md`:
  - Step 4 states the old "all Valid → covered" rule;
  - lines 67 and 74 point to Layer 6 `\tainted`, an idiom I9 dropped;
  - Step 1 never mentions units.
- `skills/framac-fuzz/SKILL.md:96`: the campaign command has no `--extra-corpus workspace/seeds/<mod>`.
- `skills/framac-wp/breaker_brief.md:29`: uses `g_sec_auth_verified` from the deleted Layer 4 template.
- `skills/framac-wp/prover_brief.md:155` and `run_wp_function.py:75-76`: name the old classes `l4_auth`, `l5_output` and `l6_secret`.
- `docs/troubleshooting.md:217`: recommends `Typed+cast`.
- `docs/resources-and-caching.md`:
  - line 251 documents `slice-init`;
  - line 189 gives the toolchain id without `+snapshot`;
  - its target table lacks `reach-gate`, `seeds` and `reach-dynamic`.
- `docs/benchmark.md`:
  - names `phase0-i5b` the latest baseline;
  - documents `--compare default` (`default.json` is the pre-redesign run `dagfix-2`).
- `docs/v2-design.md:185`: says Tier 3 gets no Eva, but only whole Tier 3 modules are skipped, and only under quick.
- `docs/agentic-swarm.md:22`: uses directory module names.
- Comments that still say the DAG is keyed by plain name, or that a missing model gives lexer modules:
  - `module_map.py:12-16`;
  - `wp_scheduler.py:537`;
  - `workspace_overlay.py:2429`;
  - `harness_reach._module_entries`;
  - `pipeline_make.py:459-461`.
- `tests/test_wp_scheduler.py:99-127`: builds an old-shape DAG (plain keys, `name_collisions`, no link units).

## 9. Phase 0 information nobody uses yet

These are opportunities, not defects:
- **Trust and `untrusted_path`:** they could set the order of the WP queue, the fuzz budgets and the seed choice.
- **`concurrent`:** E-ACSL could take it instead of rescanning the sources, and Eva could switch on its concurrency options or report a limit.
- **`no_threat_model`:** today it is a single line in REPORT.md. It could be a run-metadata field and a warning.
- **Eva's call edges:** they could be merged back into the DAG, to narrow indirect sites the way Alias would.
- **The report:** it could cover fallback units, tiers and their reasons, the seeds, the unit split and dynamic reach gaps.
- **Alias narrowing:** it removes about a quarter of x509-parser's type-matched edges, but is unsound with reassigned globals. A sound version would cut WP dependencies and spurious recursion.

## 10. Checklist when you change a downstream phase

1. **Names:** map every module name through `ModuleMap`. The ledger holds units; reports and Make hold harness modules.
2. **Functions:** look them up by `(file, name)` or the DAG key, never by plain name alone. Test with a colliding static (fixtures r01, s07).
3. **Flags:** take them from the sidecar. If the DAG's flags matter, regenerate the harness; don't merge at build time.
4. **Header functions:** expect one home unit per header function and one configuration per file.
5. **Old runs:** after changing what Phase 0 emits, start from a new run or a fresh ledger, and rerun `reach-gate`.
6. **Security properties:** `security_props.json` must exist before `ledger.py seed`. Make's `seed` depends on `security-props`; a manual sequence must keep that order.
7. **Images:** build and tests run in the build image, everything else in the analysis image. No `framac-pipeline:<tag>` image exists any more.
8. **Benchmark:**
   - compare against `phase0-i10`;
   - recall must not drop;
   - explain every unit-count change;
   - run `benchmark.py seeded` when you touch inventory, harnesses, ingest or gates.
9. **Docs and skills:** update them in the same change. Mirror `skills/` into `.claude/skills/`; `test_framac_skills_mirror_is_in_sync` checks this.

## 11. Tests that pin the Phase 0 contracts

| Area | Tests |
| :--- | :--- |
| Units, `ModuleMap`, flags, force includes | `test_unit_view.py`, `test_dag_model_view.py` |
| Make plan, budgets, gates, replay | `test_pipeline_make.py` (link units and budgets from line 1469), `test_phase0_gates.py`, `test_harness_reach.py` |
| Ingest and verdicts | `test_link_unit_ingest.py`, `test_eva_cross_module.py`, `test_ledger.py`, `test_ledger_p1.py` |
| Fuzz side | `test_seed_harvest.py`, `test_target_env.py`, `test_fuzz_subcommands.py`, `test_fuzz_coverage.py`, `test_fuzz_link_repair.py`, `test_fuzz_dictionary.py` |
| WP side | `test_wp_scheduler.py`, `test_wp_continuous_loop.py`, `test_workspace_overlay.py`, `test_acsl_only_and_merge.py`, `test_prover_context.py`, `test_c_definitions.py` |
| Tiers, split, trust, properties | `test_tiers.py`, `test_unit_split.py`, `test_trust.py`, `test_security_props.py` |
| Report, validation, cache | `test_report.py`, `test_validators.py`, `test_cache.py` |
| Images and wrappers | `test_build_capture.py`, `test_image_toolchain.py`, `test_remediation_p2_container.py` |
| Benchmark | `test_benchmark.py`, `test_benchmark_compare.py`, `test_benchmark_seeded.py` |

The defect 1-8 fixes added tests for the `slice-init`, `dag` and `security-props` recipes (`test_phase0_make_recipes.py`), stopping when no unit parses (`test_phase0_model.py`), source WP blockers and blocking a fallback unit (`test_dag_model_view.py`, `test_pipeline_make.py`), `audit-hypotheses` with `file#name` callees (`test_ledger.py`), `prepare_agent` with `file#name` keys (`test_workspace_overlay.py`), cluster flags (`test_unit_view.py`) and replay on a sub-module (`test_pipeline_make.py`).

**Not covered by any test:** `_check_internal_variadic`.
