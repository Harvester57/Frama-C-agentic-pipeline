---
name: framac-slice
description: >-
  Phase 0 of the Frama-C verification pipeline. Initializes the run's
  workspace/ shadow overlay from the read-only target, captures the target's
  own build from a user-confirmed recipe (stops and asks when it does not
  build), parses every link unit with Frama-C into the Phase 0 model
  (functions, direct and indirect call edges, API entry points, GCC fallback
  for units Frama-C cannot parse), records seed inputs from the target's tests,
  imports the fuzz targets and corpora the target ships,
  marks the trust boundary from the build and the structured threat model,
  writes the call-graph DAG (link units as modules, bottom-up waves, risk tiers
  from trust, unit split), generates the MetAcsl security properties (Layers
  3-6), generates per-module dual-use harnesses (Eva + E-ACSL LibFuzzer), gates
  them on reachability and on a working E-ACSL build, and seeds the coverage
  ledger.
argument-hint: "<target-dir> [--run-dir <dir>]"
---

# /framac-slice

Turns a C codebase into link-unit modules, module harnesses and per-function topological waves inside the run directory, then seeds the coverage ledger.

All commands run through the wrapper with the run directory as working directory (`/framac-run`) and the target mounted read-only at `/target`:

```powershell
# Windows (PowerShell)
$env:PYTHONIOENCODING="utf-8"
& ".\wrappers\framac-docker.ps1" `
  -TargetDir "<target-dir>" -RunDir "<run-dir>" -BuildIfMissing `
  "<command>"
```

```bash
# Linux / macOS (POSIX)
./wrappers/framac-docker.sh \
  --target "<target-dir>" --run-dir "<run-dir>" --build-if-missing \
  -- "<command>"
```

Always use full `/opt/framac-pipeline/scripts/<script>.py` paths inside `"<command>"` so host PowerShell does not expand `$S`.

**Images.** Commands run in the analysis image (`framac-analysis:latest`: Frama-C, MetAcsl, the provers, clang and libFuzzer, no target packages) unless a step says otherwise. `-BuildImage` (`--build-image`) runs in the build image (`framac-build`), which runs the target's own build and tests. `-CodeQL` (`--codeql`) runs in the optional CodeQL image. There is no other image.

## Step 1 — Initialize the Shadow Overlay Workspace

```text
python3 /opt/framac-pipeline/scripts/workspace_overlay.py init --target /target --overlay workspace
```

The target is never modified. If the overlay already exists and the target changed since it was captured, `init` fails: start a new run directory instead of resuming.

Pipeline output kept inside the target (a folder holding `run-metadata.json`, `coverage-ledger.json`, or `overlay_meta.json`, such as a previous run's results) is not source. `init` does not copy it and lists it in `overlay_meta.json` as `skipped_pipeline_output`. If it reports one, tell the user so they can move it out of the target tree.

### Step 1b — Build Recipe and Build Capture

Phase 0 needs the target's own build: what it compiles, links and exports. A target that does not build stops Phase 0 until the user gives a working recipe. There is no fallback inventory.

1. **Recipe.** Read `build` in `run-metadata.json` (`run_metadata.py show`). If it is missing, propose one (`python3 /opt/framac-pipeline/scripts/build_capture.py propose` reads the build files) and ask the user to confirm or correct it:
   - the build command and its working directory;
   - the Debian packages it needs;
   - extra environment or flags;
   - the command that runs the tests (it gives the seeds of Step 1e).

   Never record a recipe the user has not given or confirmed. Then record it:

   ```text
   python3 /opt/framac-pipeline/scripts/run_metadata.py set-build --command "<cmd>" [--workdir <dir>] [--package <pkg>]... [--env KEY=VALUE]... [--test-command "<cmd>"] [--install-command "<cmd>"] [--snapshot-extra <abs path>]... [--origin user|agent_confirmed]
   ```

2. **Capture.** Run it in the build image, on the run's scratch volume, sized as `phase-dynamic`. Pass the recipe's packages as target packages, so the wrapper builds the derived build image `framac-build:<repo>`:

   ```powershell
   & ".\wrappers\framac-docker.ps1" -TargetDir "<target-dir>" -RunDir "<run-dir>" -BuildImage -Scratch `
     [-TargetPackages "<pkg1> <pkg2>"] "python3 /opt/framac-pipeline/scripts/build_capture.py run"
   ```

   ```bash
   ./wrappers/framac-docker.sh --target "<target-dir>" --run-dir "<run-dir>" --build-image --scratch --class phase-dynamic \
     [--target-packages "<pkg1> <pkg2>"] -- "python3 /opt/framac-pipeline/scripts/build_capture.py run"
   ```

   The build runs under `bear` through `sandbox_exec.py`, in a copy of the target on the volume. A build that fails with parallel jobs is retried once with one job. The result is `workspace/reports/build_capture.json`:
   - **units:** link units (libraries and executables) with their files, the project units they link, per-file flags (`-I -D -U -include -imacros -iquote -isystem -std`) and API entry points. Exports come from `nm -D` and version scripts, public headers from `make install DESTDIR=` or headers outside the source directories. An executable's entry point is `main`; a library compiled straight into an executable gets `embedded_api`. Test executables are marked `test`. Each unit lists the libraries it links from outside the project (`external_libs`).
   - **compiles:** per compile, the project headers it includes, whether it includes `setjmp.h` (`includes_setjmp_h`), and the functions its object defines (`defined_functions`, from `nm`). Step 2 compares those functions with the model's.
   - **snapshot:** the headers and libraries outside the project and libc, copied to the run's `workspace/snapshot/` with a digest. The analysis image has none of the target's packages: Frama-C, E-ACSL, the sanitizer and coverage builds read the target's headers from there (`-idirafter`, searched last) and link its libraries from there (with an RPATH, so the fuzz binaries run without the packages). Do not pass `-TargetPackages` to any step other than the capture, the seed recording and CodeQL: the wrapper ignores it in the analysis image.

   Run the capture before Step 1c, and again after a recipe change.

3. **Stop and ask.** Exit code 3 and `"status": "needs_build_recipe"` mean the build failed, built no C file, or has no recipe. The checkpoint records the same status. Show the user `diagnostics`:
   - `first_error`;
   - `missing_headers`;
   - `candidate_packages` (a heuristic);
   - `packages_not_installed`.

   Ask for a corrected command, packages or flags, record them with `set-build`, and run the capture again. A successful capture clears the status, and Phase 0 continues.

### Step 1c — Frama-C Model

Parse every non-test link unit of the capture with Frama-C, on the same scratch volume, in the analysis image:

```powershell
& ".\wrappers\framac-docker.ps1" -TargetDir "<target-dir>" -RunDir "<run-dir>" -Scratch -Class phase-static `
  "python3 /opt/framac-pipeline/scripts/phase0_model.py run"
```

```bash
./wrappers/framac-docker.sh --target "<target-dir>" --run-dir "<run-dir>" --scratch --class phase-static \
  -- "python3 /opt/framac-pipeline/scripts/phase0_model.py run"
```

How it runs:
- Units with the same sources and flags share one parse.
- Each parse takes a `parse` lease from the broker (`--no-broker` skips it, `--jobs N` caps the parallel parses).
- Target headers come from the capture's snapshot, and so do the headers the build generated (`config.h`): the capture copies them into the snapshot's `generated/` and every analysis adds that directory with `-idirafter`.
- `python3 /opt/framac-pipeline/scripts/phase0_model.py selftest` checks the dump module against the image's kernel. The image build runs it; run it again if the model fails to load its module.

The result is `workspace/reports/phase0_model.json`, validated against `schemas/phase0_model.schema.json`. Every fact carries its source:
- **functions:** keyed `file#name`, so same-named statics stay apart. Each has its lines, loops, cyclomatic complexity, storage, formals, the pointers and globals it writes, the units that contain it, and the Frama-C kernel name per unit. `param_sizes` gives, per argument index, the bytes of the objects the parsed callers pass there when the call site shows them (`buf`, `&buf[4]`, `buf + 4`, `&key`): `min`, `max` and the number of sites. The API harness and the seed recorder size fixed-size buffers passed without a length (keys, nonces) from it. `static inline` functions in headers belong to every unit that compiles them.
- **edges:** direct calls; indirect calls matched by signature against the address-taken functions of the same program; thread spawns (`pthread_create`, `thrd_create`); callbacks passed to external functions. Each edge carries its sources.
- **macro_aliases:** `#define a b` chains in project files that end at a defined function.
- **thread_entries**, units marked `concurrent`, `externals`, and each function's unresolved callees (`external_calls`).
- **trust:** each function's trust (Step 1d).

**Alias (off by default).** `phase0_model.py run --alias` narrows each indirect site's type match with Frama-C's Alias plugin, and records per site `narrowing`, `narrowing_reason` and `dropped`. It was measured and not adopted: it is unsound for a global function pointer that has an initializer and is reassigned elsewhere. Leave it off unless the user asks.

Read `units.<name>.parse.status`:
- `ok`: Frama-C parsed the unit.
- `gcc_fallback`: Frama-C could not parse the unit. Its functions and edges come from GCC's `-fcallgraph-info`, without loops, complexity or signatures, and `parse.error` holds Frama-C's first error. Its harnesses are fuzzed with the sanitizers (E-ACSL needs the Frama-C parse), and Eva and WP are blocked on it: the ledger seeds its units `deferred` with a `callgraph_fallback:` reason (Step 2, Step 5). Report every fallback unit to the user with that error.
- `skipped_test` (a test unit) and `no_sources` (no compiled source of its own).

If no unit parses with Frama-C, the model's `status` is `no_unit_parsed` and the command exits 4: stop Phase 0 and report each unit's `parse.error` to the user. Exit 1 means the capture is missing, the scratch volume is not mounted, or the dump module did not compile (`kernel_ast.py`): fix that before going on. Step 2 needs a model whose `status` is `ok`.

### Step 1d — Trust Boundary

The model already holds each function's `trust` (`scripts/trust.py`, run by `phase0_model.py`):
- `value`: `untrusted` or `trusted`;
- `source`: the deciding rule;
- `boundary`: attacker data reaches the parameters directly.

The rules:
- **Library API:** every API function of a library unit, and an executable's embedded API, is untrusted (`default`, boundary).
- **Input path:** input roots are functions calling an input reader (`read`, `recv`, `recvfrom`, `fread`, `fgets`, `getline`, `getenv` and close relatives), `main` with argv, and the threat model's `input_sources`. Every function they reach in the call graph is untrusted (`call_graph`).
- **Threat model:** `trusted_callers` marks functions (or a unit's API) called only by trusted code. It wins over the other rules and keeps what it overrode under `overridden`.
- **Everything else** is trusted (`default`).

The threat model is the fenced `framac-threat-model` JSON block of THREAT_MODEL.md, validated against `schemas/threat_model.schema.json`. Its fields are `input_sources`, `trusted_callers`, `secrets`, `auth_gates` and `output_sinks`. It is read from `workspace/THREAT_MODEL.md`, else the target's own. Check it before the model runs:

```text
python3 /opt/framac-pipeline/scripts/trust.py check-threat-model [PATH]
```

- Exit 0: valid.
- Exit 1: no file or no block. Every unit records `no_threat_model`. Report it to the user: the default rules then decide alone, and Step 3 generates only Layer 3.
- Exit 2: invalid. Fix the listed errors.

The model looks for the threat model once, in the order above (`phase0_model.py run --threat-model PATH` names another file), and records its path and sha256 under `trust.threat_model`. `trust.py run` and `security_props.py run` read that recorded file and never search again, so trust and the security properties always come from the same threat model. They stop when the file changed, went missing, or appeared since the model was built. After changing the threat model, re-run the model (or `trust.py run --threat-model PATH`, which annotates the model with that file and records it), then rebuild the DAG (Step 2) and the security properties (Step 3).

Each function's trust belongs to its `file#name`: two same-named statics keep their own trust in the model, the DAG and the contract trust-boundary check of a merge.

**CodeQL (optional, off by default).** CodeQL may add untrusted marks (`codeql`); it never removes one. It runs only when the user declares the target open source, because CodeQL's licence covers open-source code only. Ask the user; never assume it. Then:

```powershell
& ".\wrappers\framac-docker.ps1" -TargetDir "<target-dir>" -RunDir "<run-dir>" -Class phase-static `
  "python3 /opt/framac-pipeline/scripts/run_metadata.py set-codeql --enable --open-source --declared-by user"
& ".\wrappers\framac-docker.ps1" -TargetDir "<target-dir>" -RunDir "<run-dir>" -Scratch -CodeQL -TargetPackages "<pkgs>" `
  "python3 /opt/framac-pipeline/scripts/codeql_trust.py run && python3 /opt/framac-pipeline/scripts/trust.py run"
```

(sh: `--codeql`.) `-CodeQL` runs in `framac-codeql:<repo>`: the target's derived build image plus the CodeQL CLI copied from `framac-codeql:latest`. It is built locally and never pushed. `codeql_trust.py` replays the build recipe under CodeQL's tracer and writes `workspace/reports/codeql_trust.json`. Then `trust.py run` merges its facts.

Consumers of trust:
- the harness sidecar's `reachability` (`untrusted_surface` at a boundary, else `internal_api`; `reachability_source` records `trust:<rule>`);
- the contract trust-boundary check, for every boundary function;
- the tiers (Step 2);
- the report, which lists the trust source of each entry point.

### Step 1e — Seeds From the Tests

Record the arguments the target's own programs pass to the API. With a test command these are the tests; without one, the project's non-test executables (demos, tools). Run it in the build image, on the same scratch volume, after the model:

```powershell
& ".\wrappers\framac-docker.ps1" -TargetDir "<target-dir>" -RunDir "<run-dir>" -BuildImage -Scratch `
  [-TargetPackages "<pkg1> <pkg2>"] "python3 /opt/framac-pipeline/scripts/seed_harvest.py record"
```

```bash
./wrappers/framac-docker.sh --target "<target-dir>" --run-dir "<run-dir>" --build-image --scratch --class phase-dynamic \
  [--target-packages "<pkg1> <pkg2>"] -- "python3 /opt/framac-pipeline/scripts/seed_harvest.py record"
```

It relinks each test executable with `-Wl,--wrap` recorders for the model's API functions, runs the test command in the sandbox (no network, capped time) under `strace`, and keeps what is listed below. Without a test command it relinks each non-test executable that defines API functions instead and runs it once, with no arguments, empty stdin and a 60 s cap. The report's `source` says which (`test_command` or `executables`), and `runs` gives each executable's exit status. It keeps:
- the arguments of each outermost API call, in `workspace/seed_records/calls.jsonl` (deduplicated; a lone pointer whose callers pass a known-size object, per the model's `param_sizes`, is recorded with that many bytes);
- each process's calls in order, with each pointer argument's address and the bytes recorded per argument, in `workspace/seed_records/traces.jsonl` (processes with more than one call; same-shaped traces once). `--api` turns calls that share an address (a key pair, then the box that uses it) into sequence cases;
- up to 64 small data files the tests opened inside the target tree.

The report is `workspace/reports/seed_harvest.json`. A failing test suite is a warning, not an error: seeds are an improvement, never a requirement. Calls through header `static inline` functions are not recorded. The fuzz recipes turn the records into seeds in each harness's own format (`/framac-fuzz`).

Remove the scratch volume once the capture, the model, CodeQL and the seed recording are done: run the wrapper with `-RemoveScratch` (`--remove-scratch`) and no command. Later steps read the snapshot from the run directory, not the volume.

### Step 1f — The Target's Own Fuzz Targets and Corpora

Many projects ship libFuzzer fuzz targets (files defining `LLVMFuzzerTestOneInput`, often under `fuzz/`, `tests/fuzz/` or `.clusterfuzzlite/`, and often not built by default) and corpora for them. A shipped corpus usually holds far more coverage than a Phase 1 campaign can build from scratch. Find and import them in the analysis image, after the overlay (Step 1a):

```text
python3 /opt/framac-pipeline/scripts/fuzz_assets.py discover
python3 /opt/framac-pipeline/scripts/fuzz_assets.py map --corpus <id> --fuzzer <id>              # or:
python3 /opt/framac-pipeline/scripts/fuzz_assets.py map --corpus <id> --function <fn> [<fn>...]
python3 /opt/framac-pipeline/scripts/fuzz_assets.py map --corpus <id> --ignore --reason '<why>'
python3 /opt/framac-pipeline/scripts/fuzz_assets.py import
```

`discover` reads the target without following symlinks and writes `workspace/reports/fuzz_assets.json`. It finds:
- **fuzzers:** C and C++ files that define `LLVMFuzzerTestOneInput`, whether they also define `LLVMFuzzerInitialize`, and the functions they call with their input (`direct_api_calls`). C++ fuzzers are `unsupported` (E-ACSL is C only), but their corpora can still be mapped to functions;
- **corpora:** `*_seed_corpus.zip` files, and directories named with `corpus`, `seed` or `fuzz` that hold data files;
- **libFuzzer files:** `<fuzzer>.dict` and `<fuzzer>.options` (`max_len`);
- **corpora from outside the target:** each folder under `<run-dir>/inputs/corpora/<name>/`. Put a corpus the user has elsewhere (a ClusterFuzz backup, an earlier campaign) there, one folder per corpus; a folder named as a fuzzer id is paired with that fuzzer.

Only the OSS-Fuzz names pair automatically: `<fuzzer>_seed_corpus.zip` (or the unzipped `<fuzzer>_seed_corpus/`), `corpus/<fuzzer>/`, `<fuzzer>_corpus/`, `<fuzzer>.dict`, `<fuzzer>.options`. Every other corpus is unmapped, and pairing it is your call. `direct_api_calls` only sees calls whose arguments name the fuzzer's input parameters: a fuzzer that copies its input into a local first (c-ares's name fuzzer) lists helpers only, so its corpus reaches the unit's own harness cases only through its `tf_` module. Read the fuzzer source, a few corpus files, and the build or test scripts that use the folder (c-ares feeds `test/fuzzinput/` to `ares-test-fuzz.c` and `test/fuzznames/` to `ares-test-fuzz-name.c`). Then:
- map it to a **fuzzer** when its files are that fuzzer's input;
- map it to **functions** when its files are whole inputs of API functions that no shipped C fuzzer wraps, such as DNS replies for `ares_parse_a_reply`;
- **ignore** it, with the reason, when its files are not inputs (expected outputs, test vectors in a text format a parser does not read).

`import` copies the mapped corpora into `workspace/fuzz_assets/corpora/<id>/`, content-addressed. Unmapped corpora are not imported, and a warning lists them. The limits are fixed: 1 MiB per input, 20,000 inputs and 256 MiB per corpus. Zip entry names are never used as paths, and symlinks and special files are skipped. Each corpus's `imported` record counts what was kept and why the rest was dropped. A target with no fuzz assets just has empty lists: shipped assets are an improvement, never a requirement.

---

## Step 2 — Build the Call-Graph DAG, Topological Waves & Risk Tiers

```text
python3 /opt/framac-pipeline/scripts/build_callgraph_dag.py --target workspace/work --out workspace/reports/callgraph_dag.json
```

It reads `workspace/reports/phase0_model.json` from Step 1c (`--model PATH` to point elsewhere). Its functions and call edges are the model's:
- One record per function a non-test link unit compiles, under its real name, keyed by plain name or `file#name` when the name collides. Files the build does not compile (alternative backends, templates, tests, examples) are not in the DAG.
- `internal_callees` holds Frama-C's direct and indirect edges (type-matched function pointers, thread starts, callbacks). Waves, the WP scheduler, the reach gate and the hypothesis audit use them.
- Each function has a `callgraph_source`: `frama_c`, or `gcc_callgraph` for a unit on the GCC fallback. A fallback function also carries `callgraph_fallback` (Frama-C's first error), and its unit is listed in `model.gcc_fallback_units`. The fallback unit's record, and those of its path modules and clusters, get `run_eva` and `run_wp_full` false and `fuzz_engine: sanitizers`, and the functions it holds get `eva_wp_blocked` (the reason). A `params set --fuzz-engine` still wins over the DAG's engine.
- A unit whose sources include `setjmp.h` or call setjmp/longjmp gets `fuzz_engine: sanitizers` too, on the same records, with Eva and WP left on. E-ACSL builds against glibc, whose `setjmp.h` Frama-C rejects (CERT MSC38-C), and E-ACSL's memory tracking cannot follow a longjmp. `fuzz_engine_reason` gives the cause (also for a fallback unit), and the DAG warns per unit.
- Each unit module has `ldflags`: the libraries it links from outside the project, as link options (`-lz -lm`), with those of the project libraries it links. A static library, which links nothing itself, takes those of the shared library built from the same sources.
- `build_only_functions` lists, per source file, the functions the build's objects define and Frama-C's parse lacks, with a warning per file. These are usually behind a macro the compiler defines and Frama-C's preprocessing does not; libpng's SSE2 code under `__SSE2__` is an example. Eva, WP and E-ACSL never see that code, while the sanitizer build compiles it. Report each such file to the user. The fuzz build's link repair uses the list to place those symbols.
- Header functions are marked `header`. Only those an entry point of the build reaches (`reached`) get active ledger units; the others are seeded `deferred` (`header_unreached`).
- `macro_aliases` maps each alias the build defines to the functions it names. The harness generator and the reach gate resolve calls through it.

**Modules are link units** (`module_kind: "link_unit"`): one module per non-test library or executable, named after its artifact (`lib/libkv.a` -> `libkv_a`), libraries first. A source file belongs to the first unit that compiles it. A unit module carries:
- `unit`, `kind` and `files`;
- `required_sources`: its own files plus those of the project libraries it links;
- `cppflags`: the build's own flags, as single tokens, relative to the run directory;
- `force_includes`: the build's `-include` headers, kept apart (the harness generator applies them);
- `ldflags`: the libraries it links from outside the project, as link options (the harness generator adds them to the sidecar);
- `candidate_entry_points`: its API (exported functions, `main` for an executable, an executable's embedded API);
- `threat_model`: the threat model's status for the unit (Step 1d; each function's `trust` holds its own mark);
- `concurrent`: the code starts threads. The report then says that the unit's Eva and WP results assume sequential execution.

Each unit's files are also partitioned by directory into smaller **directory modules**. They name the harness sub-modules of Step 4.

**Tiers** (`scripts/tiers.py`) are set per function from its trust (Step 1d) and its structure, in the table's order below. A function is on an *untrusted path* when:
- it is untrusted;
- or the threat model's `trusted_callers` overrode an untrusted mark on it;
- or an untrusted function reaches it in the call graph.

Each function records `tier`, `tier_reasons` and `untrusted_path`. A module (link unit, directory module, split sub-module) takes the most demanding tier among its functions, with that tier's `run_*` flags, `tier_counts` and `deferred_profiles`. The DAG's `tiers` block counts the functions per tier. `python3 /opt/framac-pipeline/scripts/tiers.py summary` lists each module's tier and every Tier 3 function with its reason. Check them: a Tier 3 function is not analysed under `quick`.

**Unit split** (`scripts/unit_split.py`): a link unit whose entry points reach more than 400 functions or 15,000 lines of function bodies (what one harness driving its whole API gives Eva) is split into sub-modules for Eva and harnesses:
- each API entry point starts a cluster of the functions it reaches;
- the two clusters that overlap most, above half of the smaller one, merge, until no such pair is left;
- clusters under 10 functions (getters, setters) are packed with the cluster they share most with, else one of the same file, within the function limit.

Each cluster becomes `submodules.<unit>__<file stem>` (`unit`, `anchors` = its entry points, `functions`, `lines`, its tier and run flags). The unit records `split` (reason, sub-modules, `unclustered` functions no entry point reaches), and the DAG records `unit_split` (thresholds and one row per unit). `--split-max-functions` / `--split-max-lines` change the thresholds; `unit_split.py show` prints the clusters for other thresholds without writing the DAG. No benchmark unit splits at the default limits.

Review `workspace/reports/callgraph_dag.json`:
- Each module's `required_sources`, `external_callees`, `cppflags` and `force_includes`.
- `recursion_cycles`.
- Each function's `verifiability` (`core_provable`, `needs_calls_annotation`, or `shell_unverifiable_wp`), `wp_blockers` (`fuzz_or_eva_harness_entrypoint`, `internal_variadic`, `irreducible_goto`, `dynamic_allocation`, `container_of`, `volatile_or_asm`) and `wp_notes` (indirect calls that need `//@ calls`, recursion that needs `decreases`). They are derived from the model's signature, formals, external calls and indirect sites, and from the definition's source lines in the work tree: a backward `goto`, `container_of`, `volatile` and inline assembly. The source check skips comments and strings but does not see inside the macros a function uses.
- `model.gcc_fallback_units` and the DAG's `warnings`.
- Record any tier override with a source-backed reason.

| Risk Tier (checked in this order) | Function rule (`tiers.py`) | Verification Route |
| :--- | :--- | :--- |
| **Tier 3** | No untrusted path; or an internal scalar helper on one: not on the trust boundary, no loop, no pointer parameter, pointer return or pointer cast, no indirect call, not variadic, cyclomatic complexity at most 2 | Phase 2 (`Eva`) only, no fuzzing; `rte` units `planned` and Layers 2-6 `deferred` in `standard`/`deep`. **Deferred under `quick`:** a Tier 3 module is excluded from the Make phases and every unit of a Tier 3 function is seeded `deferred` |
| **Tier 2** | On an untrusted path, and allocates on the heap or is recursive | Phase 1 (`E-ACSL + Fuzz` with dictionary) + Phase 2 (`Eva`) + WP on non-allocating validators |
| **Tier 1B** | On an untrusted path, and writes a bounded output buffer it does not read from, or formats into one (emitter) | Phase 1 (`E-ACSL + Fuzz`) -> Phase 2 (`Eva`) -> Phase 3 (`Full Wavefront WP` + Layer 5 Sanitization) |
| **Tier 1A** | Any other function on an untrusted path (parsers, validators, the trust boundary itself) | Phase 1 (`E-ACSL + Fuzz`) -> Phase 2 (`Eva`) -> Phase 3 (`Full Wavefront WP` + Layers 1-6) |

A module's route is that of its most demanding function, so a harness module holding one Tier 1A function is fuzzed even when the rest of its scope is Tier 3.

---

## Step 3 — Stub External Libraries & Generate Security Properties

For each `Tier 1A`, `Tier 1B`, and `Tier 2` module, check `required_sources` and `external_callees` in `callgraph_dag.json`:
- **In-repository callees:** Compile the sibling `.c` files listed in `required_sources` together in the slice rather than stubbing them, so call chains into sibling modules remain reachable for fuzzing, Eva, and WP.
- **True external library calls (`external_callees`):** Under Frama-C (`__FRAMAC__`), external functions **must remain bodyless prototypes** (declared in real target headers, `/opt/framac-pipeline/templates/fc_stubs/` for `bsd/string.h`, `json-c/json.h`, `netinet/ip_icmp.h`, or `/opt/framac-pipeline/templates/acsl/external_stubs.h`) with optional ACSL contracts (`requires`, `assigns`, `ensures`). **Never** give an external function a dummy C body like `{ return 0; }` under Frama-C: a C body hides the open assumption from the ledger (`Considered valid` / `STATUS_ASSUMED`) and makes callers falsely appear proven under `return 0;`.
- **Network/IPC boundary stubs for dynamic fuzzing:** If a module reads input through a blocking socket/port helper (e.g., `RECEIVE_MESSAGE`), put `extern` declarations in a `.h` file and function definitions in a single `.c` file (never define functions in a force-included header across multiple TUs), and inject `fuzz_buf` on **every** call (never gate injection on a `static int calls` counter, which would block all LibFuzzer iterations after the first).

Then, once per run (not per module), generate the Layer 3–6 properties from the threat model before seeding the ledger:

```text
python3 /opt/framac-pipeline/scripts/security_props.py run
```

It reads `workspace/reports/phase0_model.json` and the threat model the model recorded (Step 1d; a model without a trust annotation uses Step 1d's search order, with a warning), and writes `workspace/reports/security_props.json` for the whole run:
- **L3:** an `l3_frame` unit for every function that writes through a pointer;
- **L4:** auth gates become MetAcsl `\writing` and `\precond` properties (`l4_auth_state`, `l4_auth_required`);
- **L5:** output sinks become sanitization properties (`l5_sanitized`);
- **L6:** secrets become "wiped before release" and "never reaches a sink" (`l6_wiped`, `l6_no_leak`).

Each property is rendered from `templates/metacsl/` and lists the functions where its generated annotations land; those are the ledger units. Nothing is attached to the code by hand. Without a threat model only `l3_frame` units are generated. It writes nothing and stops the run when:
- the model recorded an invalid threat model: exit 2 with the errors. Fix it, then re-run the model;
- the recorded threat model changed, went missing or appeared since the model was built: exit 1. Re-run the model as Step 1d says.

Schema problems in its own output are recorded as a `schema:` warning in the file. `ledger.py seed` (Step 5) reads the file when it exists; the Makefile's `seed` target runs `security-props` first. See [security-properties.md](../../docs/security-properties.md).

---

## Step 4 — Generate Dual-Use Module Harnesses

For each `Tier 1A`, `Tier 1B`, and `Tier 2` module:

```text
python3 /opt/framac-pipeline/scripts/generate_harness.py --module <mod> [--unit <unit>] --sources <required_sources...> --header <mod.h> --entry-fn <entry_fn> --entry-style <buffer_len|c_string|global_buffer|struct_arg|void_call|auto_prototype|custom|argv|dispatch> [--auto-args] [--dispatch-case '<stmts>']... [--ldflags='<-lfoo ...>'] --max-size 1500 --out-dir workspace/harnesses
```

Harnesses are written against link units and their API entry points (`candidate_entry_points`). A harness module is either a unit itself or a **sub-module** of one:
- **Unit harness:** named as the unit (`libkv_a`), it answers for the whole unit.
- **Directory sub-module:** a library with several entry families gets one harness per family, named after the directory module it drives (QCBOR's `decode`, `encode`... inside `libqcbor_a`). Its scope is that directory module's functions, and it takes its tier and run flags from them.
- **Cluster sub-module:** a unit the DAG split (`split`, Step 2) gets one harness per cluster instead, named as the cluster (`libcryptolib_so__crypto_tc`), with one dispatch case per anchor. Its scope is the cluster's functions and its tier the cluster's.
- **Other names:** a sub-module whose name is neither a directory module nor a cluster answers for the files in its sidecar's `scope_files`, set with `--scope-file <path>` (repeatable) and kept when the harness is regenerated, `--api` and `--record-repair` included; without them, its `sources`.

The sidecar records its `unit` (`--unit <unit>`; inferred from the DAG when omitted: each function the harness names votes for its unit by DAG key, and a name defined in several units counts only through the file among `--sources` that defines it). A sub-module's reports, corpus and candidates stay under its own name and credit its unit's functions: every comparison goes through `scripts/module_map.py`.

The sidecar `harness_<mod>.json` is the single source of truth for later phases: `sources`, `scope_files`, `cppflags`, `ldflags`, `include_source`, `reachability`. It must match `schemas/harness_sidecar.schema.json`: the generator records any mismatch in its `warnings`, and `validate_artifacts.py run-dir` fails on it. `pipeline_make.py gen` builds every module's fuzz, Eva and build recipes from it, so link flags belong here rather than on later command lines. The generator adds the unit's `ldflags` from the DAG after any `--ldflags` you give, skipping a library already given. Pass `--ldflags` only for what the build's link line lacks. The generator applies the unit's `force_includes`. Quoted `-D` values (`-DLOG="x"`) and the build's `-std=` are not copied from the DAG: state them in the harness flags yourself when the harness needs them. Flags outside the build allowlist (for example `-fplugin`, `-B`, `-fuse-ld`, `-Wl,`) exclude the module from the Make phases. `gen` reports them.

Supported `--entry-style` modes and options in `generate_harness.py`:
- `buffer_len` (default): `entry_fn(input_buf, input_len)` for standard `(const uint8_t *, size_t)` parsers.
- `c_string`: NUL-terminates `fuzz_buf` in both Eva and LibFuzzer and calls `entry_fn((const char *)fuzz_buf)`.
- `global_buffer`: copies fuzz/symbolic bytes into `--global-buf <name>` (and optional `--global-len <name>`) before calling `entry_fn()`.
- `struct_arg`: populates a stack struct of `--struct-type <Type>` with fuzz/symbolic bytes before calling `entry_fn(&target_arg)`.
- `void_call`: invokes `entry_fn()` directly after initializing any globals.
- `auto_prototype` (or `--auto-args`): inspects the C declaration of `--entry-fn` in `--header` or `--sources`, automatically synthesizes Eva (`Frama_C_make_unknown`) and LibFuzzer (`fuzz_buf + fuzz_off`) argument unpacking for arbitrary multi-argument internal functions (buffer+length pairs, C strings, output buffers, pointers, and scalars), and defaults `reachability` to `internal_api` when the entry function has no trust in the DAG (Step 1d).
- `custom`: executes arbitrary C statements passed via `--call-expr '<stmts using fuzz_buf and fuzz_len>'` (or separate `--eva-expr` and `--fuzz-expr`), with optional `--null-terminate` and repeatable `--extra-include <hdr.h>`.
- `argv`: CLI-style targets whose entry is `main(int argc, char **argv)` — the default when `--entry-fn main` is given without an explicit `--entry-style`. Eva side emulates `argc`/`argv` with `Frama_C_interval(0, 5)` and five unknown 256-byte buffers (upstream `share/libc/eva_stubs.c`, vendored as `docs/upstream/sources/eva_stubs.c`); the LibFuzzer side passes the input as `argv[1]` NUL-terminated. The sidecar `cppflags` get `-Dmain=__framac_target_main`, renaming the target's `main` in every build so libFuzzer's own `main` does not clash at link time.
- `dispatch`: one harness for an API library with many entry points. Each repeatable `--dispatch-case '<stmts>'` drives one API call; the first input byte selects the case and the rest of the input is that case's `fuzz_buf`/`fuzz_len`. Eva sees an unknown selector, so one analysis covers every case. Each case must build its arguments within the callee's contract (for a builder: a real buffer, its real size as `buflen`, and the setup calls the API documents, such as writing the message header first) and must never `return`. Pass the module's main parser as `--entry-fn`. The sidecar records the cases in `dispatch_cases`. The fuzz campaign skips a case once it has crashed, by rebuilding with `-DFRAMAC_FUZZ_SKIP_CASES`, so keep unrelated API calls in separate cases: a skipped case is not fuzzed for the rest of the campaign. The seeds of Step 1e are written per case, so a dispatch harness gets the most out of them.
- `--api` (no `--sources`, `--entry-fn` or `--entry-style`): a `dispatch` harness for the module's **whole API**, generated from the Phase 0 model by `scripts/api_harness.py`. Every entry point in the module's scope gets a case whose arguments come from the model's signature and formals:
  - scalars, enums and pointer-free structs by value are read from the input; a struct by value with pointers (a `{ptr, len}` slice) is filled field by field from its layout (clang's AST of the harness): each (pointer, length) pair gets generator storage (an input pair takes the rest of the input or a 256-byte input buffer, an output pair a zeroed spare buffer) and a clamped length; with no layout it is zeroed (`notes`); a `_Bool` takes the input byte's low bit;
  - a pointer to a struct the API has an initializer for (`*_Init`, `*_init`, `*Init*`, `*_new`, `*_create`, first parameter a non-const pointer to it; the traces' first choice) is initialized by that call first (`inits` in the layout);
  - the first input `(buf, len)` pair gets the rest of the input itself; a pair needs an unsigned length or a length-named signed one, never an enum;
  - a byte pointer gets a buffer of the size the call sites agree on (`param_sizes`), read from the input when the pointee is `const`, else zeroed; without a known size it gets a zeroed spare buffer of `2 * max-size + 1024` bytes;
  - output lengths are clamped to their buffer, and function pointers are NULL.
  Recorded call sequences (Step 1e traces) add one case per chain of calls that share buffers, so a key pair reaches the call that uses it. Each case's input layout goes to the sidecar as `api_cases`, which seed writing reads. Functions it cannot call (static, variadic, an anonymous struct by value, a case the compiler refuses, with its first error) go to `api_skipped` and stay reach gaps. Pass `--scope-file` to give a freely named sub-module its scope; the API cases follow it, and a later `--api` run without the flag keeps the recorded one. Start from `--api` for any unit with more than a few entry points, then add `custom` cases or a hand-written harness where a contract needs more than the model knows (a buffer whose size depends on another argument, a required call order the traces did not show).
- Note: Passing a workspace path like `--header workspace/work/src/Mod/Mod.h` automatically adds `-Iworkspace/work/src/Mod` to `cppflags` and emits `#include "Mod.h"`.
- If `entry_fn` is `static` inside its `.c` file, pass `--include-source` so the harness includes the `.c` translation unit directly instead of compiling it twice.
- If a dynamic LibFuzzer binary cannot link an external third-party library symbol at link time, pass `--stubbed-callee <fn>` so it is recorded in `harness_<mod>.json` (`stubbed_callees`) and any linker stub is guarded by `#ifndef __FRAMAC__`.
- Harness code may call a function through a macro alias (`crypto_hash` for `crypto_hash_sha512_tweet`): the generator and the reach gate resolve it through the DAG's `macro_aliases`.

**Target fuzz harnesses.** Each `usable` fuzzer in `workspace/reports/fuzz_assets.json` (Step 1f) gets one more harness module, `tf_<id>`, besides the unit's own harness:

```text
python3 /opt/framac-pipeline/scripts/generate_harness.py --module tf_<id> --unit <unit> --target-fuzzer <work_path> --target-fuzzer-id <id> --sources <the unit's required_sources...> --header none --cppflags='<the unit's cppflags>' --out-dir workspace/harnesses
```

- **Unit:** the link unit whose API the fuzzer calls (its `direct_api_calls`). Pass the fuzzer's `work_path` from the report.
- **What it generates:** the target's `LLVMFuzzerTestOneInput` and `LLVMFuzzerInitialize` are renamed (`__framac_target_embedded_*`). The harness copies the input into `fuzz_buf`, calls the target's initializer once, then calls the target's fuzz function. The two rules below therefore still hold. Use `--target-fuzzer`, never `--self-harnessed`, for a target's fuzzer.
- **Input size:** `max_input_size` comes from the fuzzer's `.options` `max_len`, else from its largest imported input (4 KiB to 1 MiB). Pass `--max-size` only to override it.
- **Additive:** the module's scope is the fuzzer file, so it answers for no entry point. The unit still needs its own harness for the reach gate, and the gate fails a `tf_` module whose fuzzer reaches no DAG function (`target_fuzzer_reaches_nothing`). `tf_` modules are fuzzed and measured for coverage, never analysed by Eva.
- **Skip** a fuzzer that needs code outside the unit's sources (another library, C++ helpers) or that writes files or opens sockets, and say why in your summary.
- A crash inside the fuzzer's own code is harness-side: the crash location is the first target frame below it.

Module headers are often not self-sufficient (for example `Events.h` uses `Boolean_T`, `GST_CHAIN_MODE_T`, or `CMD_NAME_MAX_LEN` defined in `PtfUtil.h` without including it). Auto-prelude handles this (on by default):
- After writing the harness, `generate_harness.py` runs `clang -fsyntax-only -x c <cppflags> harness_<mod>.c` (LibFuzzer branch, no `-D__FRAMAC__`; with the run snapshot's include options, as every compile of the target, so a header the build generated such as libpng's `pnglibconf.h` is found), collects `unknown type name` / `use of undeclared identifier` diagnostics, finds the defining `*.h` in the `-I` directories of `--cppflags` (typedefs, `} X;`, `#define X`, enum constants; top-level of each directory only), and `#include`s it before the module header. It repeats this up to 3 rounds.
- The outcome is recorded in `harness_<mod>.json` and the JSON output as `prelude_headers`, `prelude_status` (`clean`, `resolved`, `unresolved`, `skipped` when clang is missing or hits a fatal error, `disabled`), and `prelude_unresolved`. If symbols are still unresolved, the command fails and lists them; the harness it wrote is kept for inspection, but the reach gate fails the module (`harness_prelude_unresolved: <symbols>`), so it is never built or fuzzed. In that case, add the missing directory with `-I`, or use the manual form below.
- Pass `--no-auto-prelude` to turn it off. The manual form still works: `--header <root>.h --extra-include <mod>.h` (the root header that defines the shared types goes first, then the module header).
- Boundary stubs and harness code must never redefine identifiers the target owns (enum constants, target typedefs, target macros). The target header is parsed after the prelude and stubs, so a redefinition causes a redeclaration error or silently uses a different type. Include the target's own header instead.
- Never pass libFuzzer's `data` pointer to target code: use `fuzz_buf`, which the harness has already copied into its own buffer (every generated `--entry-style` does this). E-ACSL builds check initialization (`-rte-initialized`), and `data` is written outside instrumented code, so every read of it would be reported as uninitialized.
- Never define `LLVMFuzzerInitialize` in a harness, including in `custom` statements. E-ACSL builds link `templates/eacsl_runtime/fuzz_init.c`, which defines it to initialize the E-ACSL runtime; a second definition is refused with `eacsl_init_hook_conflict`.

The harness must respect the entry function's declared or documented contract (buffer sizes, non-NULL arguments, length limits). A crash caused by a harness that violates that contract is `rejected` as harness-induced, so get this right before fuzzing. Verify that every generated harness parses cleanly with the Frama-C kernel (`frama-c -machdep gcc_x86_64 ... -kernel-warn-key annot-error=abort`).

### Step 4b — Harness Reachability Gate

A harness that calls one entry point leaves the rest of the module's API unexercised: Phase 1 never fuzzes it, Phase 2 marks it dead (`harness gap`), and Phase 3 breakers cannot reach it. Gate every harness before seeding the ledger:

```text
python3 /opt/framac-pipeline/scripts/harness_reach.py check
```

It reads `workspace/reports/callgraph_dag.json` and each `harness_<mod>.json` / `harness_<mod>.c`. It takes the DAG functions the harness names (directly, through a header macro such as a `for_each` iterator, through a macro alias, or through a header `static inline` wrapper) and their transitive in-repo callees, direct and indirect. Then it checks that every `candidate_entry_points` function of the module is reached:
- A sub-module is checked against the unit's entry points in its own scope.
- Entry points of a unit that no harness module's scope holds are reported as the unit's gaps.
- A Tier 1A/1B/2 module without a harness fails with `no_harness`.

The report goes to `workspace/reports/harness_reach.json`; exit code 1 means a gap.

For each module with `gaps`:

1. Regenerate its harness with `--api` (every entry point the model can call), or with `--entry-style dispatch`, one `--dispatch-case` per unreached entry point (several related calls may share a case, for example building a message then parsing it). Keep the existing parser call as a case. Do not cover a gap by violating a callee's contract: a crash from such a case is `rejected` as harness-induced.
2. Re-run `harness_reach.py check`.
3. An entry point that cannot be driven from bytes (it needs a live kernel socket, a real file descriptor, or a process-global the harness cannot set up safely) gets a recorded reason instead: `harness_reach.py exempt --module <mod> --function <fn> --reason '<why>'`. Name the function by its DAG key (`file#name` when the name collides) or by its plain name when no other DAG function has it; the static and the dynamic gate match it the same way. A Tier 1A/1B/2 module that needs no harness at all (example programs, test drivers) gets `harness_reach.py exempt --module <mod> --reason '<why>'`. Exemptions survive harness regeneration. Never exempt an entry point only because writing its case is tedious.

Move on only when `check` exits 0. Its `exempt` entries are the accepted, documented gaps.

The check records its result in `workspace/reports/phase0_gates.json`, together with a digest of each harness and of the DAG. Make enforces it: `seed` runs the check first (`reach-gate`), and the `build-`, `fuzz-`, `coverage-` and `eva-` targets of a module stop with the reason when the module failed it, or when its harness or the DAG changed after the check ran. After any harness repair or DAG rebuild, run `check` again.

Phase 1 reopens the gate: after `coverage-<mod>`, `reach-dynamic-<mod>` fails the module when its corpus never executed an entry point the gate holds it to (`/framac-fuzz` Step 3). Repair the harness or exempt the entry point the same way.

---

## Step 5 — Seed the Coverage Ledger, Build-Check and Checkpoint

```text
python3 /opt/framac-pipeline/scripts/ledger.py seed --dag workspace/reports/callgraph_dag.json [--profile <quick|standard|deep>] [--scope <repo-relative path>]... [--security-props workspace/reports/security_props.json]
python3 /opt/framac-pipeline/scripts/validate_artifacts.py run-dir .
python3 /opt/framac-pipeline/scripts/checkpoint.py init state --target /target   # keeps an existing progress file
python3 /opt/framac-pipeline/scripts/pipeline_make.py gen
python3 /opt/framac-pipeline/scripts/pipeline_make.py build-check   # Phase 0's last gate; records phase_done = 0
```

The Makefile's `seed` target (`pipeline_make.py run seed`) runs the first three lines after the reach gate and `security-props`. Seeding does not record Phase 0 as done: `build-check` is its last gate, and it records the checkpoint (`checkpoint.py save-phase state --phase 0`) itself, only when it passes and the reach gate holds for every module of the plan, with each harness and the DAG unchanged since the check. Its JSON says so under `phase0_checkpoint` (`saved`, or the gate `reasons` that kept it from saving). Never save the Phase 0 checkpoint by hand.

`validate_artifacts.py run-dir` also checks the Phase 0 artifacts present (`build_capture.json`, `phase0_model.json`, `security_props.json`, `callgraph_dag.json`, `build_check.json`, `harness_reach_dynamic.json`, `seed_harvest.json`, `fuzz_assets.json`, each harness sidecar, `seed_records/traces.jsonl`) against `schemas/`, and fails on the schema problems their producers recorded as `schema:` warnings. A link-unit DAG without `schema_version` predates the GCC-fallback blocking: rebuild it with `build_callgraph_dag.py`.

`ledger.py seed` creates one unit per function × obligation class, keyed by link unit:
- each unit takes its function's `callgraph_source`; units on the GCC fallback carry `bookkeeping.callgraph_fallback`, and those of a function whose link unit is on the fallback (`eva_wp_blocked`) are seeded `deferred` with a `callgraph_fallback:` reason, since Eva and WP cannot run on them; the report lists them under "Units not worked in this run";
- functions found only in test units get no unit;
- unreached header functions are seeded `deferred` (`header_unreached`);
- concurrent units carry `bookkeeping.concurrent`;
- the security properties of Step 3 add their classes per instance (`--security-props`, default `workspace/reports/security_props.json` when it exists). The Makefile's `seed` target runs `security-props` first, so the file is current.

`pipeline_make.py gen` writes `workspace/build/Makefile` for the deterministic per-module phases (`/framac-fuzz`, `/framac-eva`), one record per harness module. Check its JSON for modules excluded with a reason before moving on. Under `quick`, Tier 3 modules are excluded with a reason.

`pipeline_make.py build-check` builds every fuzzed module (`run build`, cached, so Phase 1 reuses it) and exits 1 unless each one was instrumented with E-ACSL. The Frama-C kernel parse in Step 4 uses Frama-C's own libc, but the E-ACSL build runs with `-no-frama-c-stdlib` against the host headers, so a harness can pass Step 4 and still fall back to ASan/UBSan, losing the E-ACSL checks. For each failing module, `workspace/reports/build_check.json` gives `status` (`eacsl_fallback`, `build_failed`, `not_built`), the `compile_log`, and its `first_error`; a `not_built` module gives its `reason`, which is the reach gate's when that gate stopped its build (repair the harness first, Step 4b). Fix the cause (usually a host header Frama-C cannot parse: put a minimal stub under `workspace/harnesses/include/` on the sidecar's `-I` path, ahead of `-idirafter /usr/include`), regenerate the harness, and rerun. Only when E-ACSL cannot work for the module, record that choice with `pipeline_make.py params set --module <mod> --fuzz-engine sanitizers`, which the check accepts. A module whose unit the DAG already put on the sanitizers (GCC fallback, setjmp/longjmp) passes as `sanitizers_chosen` with the DAG's `fuzz_engine_reason` as its `reason`, and no E-ACSL attempt is made.

`build-check` records its result in the same `phase0_gates.json`. `fuzz-<mod>` refuses a module that failed it, and `wp-queue` refuses the run until every module of the plan passes both gates, with each harness and the DAG unchanged since the reach check; `wp_scheduler.py init` refuses the same way. A plan with nothing to fuzz passes `build-check`. Run `build-check` again after a repair: that is also what records the Phase 0 checkpoint once everything passes.

`gen` warns (top-level `warnings`) when a fuzz budget does not fit the profile's per-unit cap: a `params.json` budget above the cap is kept as recorded, and a unit with so many campaigns that the 30-second minimum per campaign exceeds the cap gets more than the cap. Lower the budgets with `params set --module <mod> --fuzz-budget <cpu-seconds>` if that is not intended.
