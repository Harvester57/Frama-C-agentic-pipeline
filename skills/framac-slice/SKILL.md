---
name: framac-slice
description: >-
  Phase 0 of the Frama-C verification pipeline. Initializes the run's
  workspace/ shadow overlay from the read-only target, parses
  compile_commands.json and C sources to build the function Call-Graph DAG and
  bottom-up topological waves (Wave 0 leaf functions to Wave K callers),
  classifies modules into Risk Tiers (Tier 1A Binary Parsers, Tier 1B Emitters,
  Tier 2 Heap/Tree Parsers, Tier 3 Glue), infers Layers 2-6 security properties
  from THREAT_MODEL.md and code patterns, generates per-module dual-use
  harnesses (Eva + E-ACSL LibFuzzer), and seeds the coverage ledger.
argument-hint: "<target-dir> [--compile-commands <path>] [--run-dir <dir>]"
---

# /framac-slice

Slices a large C codebase into verifiable module harnesses and per-function topological waves inside the run directory, then seeds the coverage ledger.

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

## Step 1 — Initialize the Shadow Overlay Workspace

```text
python3 /opt/framac-pipeline/scripts/workspace_overlay.py init --target /target --overlay workspace
```

The target is never modified. If the overlay already exists and the target changed since it was captured, `init` fails: start a new run directory instead of resuming.

Pipeline output kept inside the target (a folder holding `run-metadata.json`, `coverage-ledger.json`, or `overlay_meta.json`, such as a previous run's results) is not source. `init` does not copy it and lists it in `overlay_meta.json` as `skipped_pipeline_output`, and `build_callgraph_dag.py` skips it with a warning. If either reports one, tell the user so they can move it out of the target tree.

If the target has no `compile_commands.json` (or has an out-of-tree build system where running `bear` is impractical), `build_callgraph_dag.py` in Step 2 automatically discovers all in-repository header directories and can emit a synthesized `compile_commands.json` via `--emit-compile-commands workspace/reports/compile_commands.json` while stripping any host `/usr/include` paths. If you do want to capture build flags from the target's native build, do so in a disposable full copy run through `sandbox_exec.py` (rlimits, env allowlist, timeout):

```text
mkdir -p workspace/build-scratch && cp -a /target/. workspace/build-scratch/
python3 /opt/framac-pipeline/scripts/sandbox_exec.py run --writable workspace/build-scratch --cwd workspace/build-scratch -- bear -- make -j"$FRAMAC_JOB_CPUS"
```

The broker sizes a sandboxed `bear`, `make`, `cmake`, `ninja`, `meson` or `configure` command like a whole phase (`phase-dynamic`), and `FRAMAC_JOB_CPUS` is the CPU count it leased. `$FRAMAC_JOB_CPUS` must reach the container unexpanded: in the PowerShell wrapper's double-quoted command write `` `$FRAMAC_JOB_CPUS ``.

For CMake: `cmake -B build "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON"` inside the same scratch copy. Pass the result to Step 2 with `--compile-commands`. Additional Debian `-dev` packages belong in the build recipe (Step 1b): the capture installs them in the build image and copies the headers and libraries the build used to the run's snapshot, where every later step reads them.

### Step 1b — Build Recipe and Build Capture

Phase 0 needs the target's own build: what it compiles, links and exports. A target that does not build stops Phase 0 until the user gives a working recipe. There is no fallback inventory.

1. **Recipe.** Read `build` in `run-metadata.json` (`run_metadata.py show`). If it is missing, propose one (`python3 /opt/framac-pipeline/scripts/build_capture.py propose` reads the build files) and ask the user to confirm or correct it: the build command, the Debian packages it needs, extra environment or flags, the working directory, and the command that runs the tests. Never record a recipe the user has not given or confirmed. Then record it:

   ```text
   python3 /opt/framac-pipeline/scripts/run_metadata.py set-build --command "<cmd>" [--workdir <dir>] [--package <pkg>]... [--env KEY=VALUE]... [--test-command "<cmd>"] [--origin user|agent_confirmed]
   ```

2. **Capture.** Run it in the build image, on the run's scratch volume, sized as `phase-dynamic`. Pass the recipe's packages as target packages, so the wrapper builds the derived build image `framac-build:<repo>`:

   ```powershell
   & ".\wrappers\framac-docker.ps1" -TargetDir "<target-dir>" -RunDir "<run-dir>" -BuildImage -Scratch -Class phase-dynamic `
     [-TargetPackages "<pkg1> <pkg2>"] "python3 /opt/framac-pipeline/scripts/build_capture.py run"
   ```

   ```bash
   ./wrappers/framac-docker.sh --target "<target-dir>" --run-dir "<run-dir>" --build-image --scratch --class phase-dynamic \
     [--target-packages "<pkg1> <pkg2>"] -- "python3 /opt/framac-pipeline/scripts/build_capture.py run"
   ```

   The build runs under `bear` through `sandbox_exec.py`, in a copy of the target on the volume. A build that fails with parallel jobs is retried once with one job. The result is `workspace/reports/build_capture.json`:
   - **units:** link units, with their files, links, per-file flags and entry points; test executables are marked `test`;
   - **snapshot:** the headers and libraries outside the project and libc, copied to the run's `workspace/snapshot/` with a digest. The analysis image, where every later step runs, has none of the target's packages: Frama-C, E-ACSL, the sanitizer and coverage builds read the target's headers from there (`-idirafter`, searched last) and link its libraries from there (with an RPATH, so the fuzz binaries run without the packages). Do not pass `-TargetPackages` to any step other than the capture: the wrapper ignores it there. Run the capture before Step 2, and again after a recipe change.

3. **Stop and ask.** Exit code 3 and `"status": "needs_build_recipe"` mean the build failed, built no C file, or has no recipe. The checkpoint records the same status. Show the user `diagnostics`: `first_error`, `missing_headers`, `candidate_packages` (a heuristic) and `packages_not_installed`. Ask for a corrected command, packages or flags, record them with `set-build`, and run the capture again. A successful capture clears the status, and Phase 0 continues.

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

Units with the same sources and flags share one parse. Each parse takes a `parse` lease from the broker (`--no-broker` skips it, `--jobs N` caps the parallel parses). Target headers come from the capture's snapshot. The result is `workspace/reports/phase0_model.json`, validated against `schemas/phase0_model.schema.json`:
- **functions:** keyed `file#name`, so same-named statics stay apart, with lines, loops, cyclomatic complexity, storage, the units that contain them, and the Frama-C kernel name per unit; `static inline` functions in headers belong to every unit that compiles them;
- **edges:** direct calls, indirect calls matched by signature against address-taken functions of the same program, thread spawns (`pthread_create`, `thrd_create`) and callbacks passed to external functions; each edge carries its sources;
- **macro_aliases:** `#define a b` chains in project headers that end at a defined function;
- **thread_entries**, units marked `concurrent`, and `externals`.

Read `units.<name>.parse.status`. `gcc_fallback` means Frama-C could not parse the unit: its functions and edges come from GCC's `-fcallgraph-info`, without loops, complexity or signatures, and `parse.error` holds Frama-C's first error. Report every fallback unit to the user with that error; Eva and WP will fail on it the same way. A non-zero exit means the capture is missing, the scratch volume is not mounted, or the dump module did not compile (`kernel_ast.py`): fix that before Step 2.

Step 2 reads the model. Without it (no capture, or a model whose `status` is not `ok`), Step 2 falls back to the lexer and says so in the DAG's `warnings`.

### Step 1d — Trust Boundary

The model already holds each function's `trust` (`scripts/trust.py`, run by `phase0_model.py`): `untrusted` or `trusted`, the deciding rule (`source`), and `boundary` when attacker data reaches the parameters directly. The rules:
- **Library API:** every API function of a library unit is untrusted (`default`, boundary).
- **Input path:** a function calling an input reader (`read`, `recv`, `recvfrom`, `fread`, `fgets`, `getline`, `getenv` and close relatives), `main` with argv, and the threat model's `input_sources` are input roots. Every function they reach in the call graph is untrusted (`call_graph`).
- **Threat model:** `trusted_callers` marks functions (or a unit's API) called only by trusted code. It wins over the other rules and keeps what it overrode under `overridden`.
- **Everything else** is trusted (`default`).

The threat model is the fenced `framac-threat-model` JSON block of THREAT_MODEL.md, validated against `schemas/threat_model.schema.json` (`input_sources`, `trusted_callers`, `secrets`, `auth_gates`, `output_sinks`). It is read from `workspace/THREAT_MODEL.md`, else the target's own. Check it before the model runs:

```text
python3 /opt/framac-pipeline/scripts/trust.py check-threat-model [PATH]
```

Exit 0 means valid, 1 means no file or no block (every unit records `no_threat_model`), and 2 means invalid (fix the listed errors). Report `no_threat_model` to the user: the default rules then decide alone. Run `trust.py run` again after changing the threat model, then rebuild the DAG (Step 2).

**CodeQL (optional).** CodeQL may add untrusted marks (`codeql`); it never removes one. It runs only when the user declares the target open source, because CodeQL's licence covers open-source code only. Ask the user; never assume it. Then:

```powershell
& ".\wrappers\framac-docker.ps1" -TargetDir "<target-dir>" -RunDir "<run-dir>" -Class phase-static `
  "python3 /opt/framac-pipeline/scripts/run_metadata.py set-codeql --enable --open-source --declared-by user"
& ".\wrappers\framac-docker.ps1" -TargetDir "<target-dir>" -RunDir "<run-dir>" -Scratch -CodeQL -TargetPackages "<pkgs>" -Class phase-dynamic `
  "python3 /opt/framac-pipeline/scripts/codeql_trust.py run && python3 /opt/framac-pipeline/scripts/trust.py run"
```

(sh: `--codeql`.) `-CodeQL` runs in `framac-codeql:<repo>`: the target's derived build image plus the CodeQL CLI copied from `framac-codeql:latest`. It is built locally and never pushed. `codeql_trust.py` replays the build recipe under CodeQL's tracer and writes `workspace/reports/codeql_trust.json`. Then `trust.py run` merges its facts.

Consumers: the harness sidecar's `reachability` defaults from trust (`untrusted_surface` at a boundary, else `internal_api`; `reachability_source` records `trust:<rule>`). The contract trust-boundary check applies to every boundary function. The report lists the trust source of each entry point.

---

## Step 2 — Build the Call-Graph DAG, Topological Waves & Risk Tiers

```text
python3 /opt/framac-pipeline/scripts/build_callgraph_dag.py --target workspace/work --out workspace/reports/callgraph_dag.json --emit-compile-commands workspace/reports/compile_commands.json
```

It reads `workspace/reports/phase0_model.json` from Step 1c (`--model PATH` to point elsewhere, `--no-model` to use the lexer alone). The DAG's functions and call edges are then the model's:
- one record per function a non-test link unit compiles, under its real name. Files the build does not compile (alternative backends, templates, tests) are left out and listed in `model.lexer_only_functions`; check that list against what the user expects analysed.
- `internal_callees` holds Frama-C's direct and indirect edges (type-matched function pointers, thread starts, callbacks), and `indirect_callees` holds the indirect ones alone. Waves, the WP scheduler and the hypothesis audit use both.
- Each function has a `callgraph_source`: `frama_c`, or `gcc_callgraph` for a unit on the GCC fallback, which also carries `callgraph_fallback` (Frama-C's first error) and gets listed in `model.gcc_fallback_units`.
- Header functions are marked `header`. Only those an entry point of the build reaches (`reached`) get ledger units.
- `macro_aliases` maps each alias the build defines to the functions it names. The harness generator and the reach gate resolve calls through it.

With the model, the DAG's `modules` are the build's non-test **link units** (`module_kind: "link_unit"`): one module per library or executable, named after its artifact (`lib/libkv.a` -> `libkv_a`), libraries first. A unit module carries its `kind`, `files`, `required_sources` (its own files plus those of the project libraries it links), `cppflags`, `concurrent` (the build links a thread library or the code starts threads) and `candidate_entry_points` (its API: exported functions, `main` for an executable, an executable's embedded API). A source file belongs to the first unit that compiles it. Code no non-test unit compiles keeps its lexer module.

Tiers and the per-function analysis stay the lexer's (C/ACSL token stream `tokenize_c_acsl`, Tarjan's SCC for recursion cycles, structural signature and body analysis, with no project-specific keyword hints). The lexer's modules are kept under `lexer_modules`, `unit_of_lexer_module` maps each to its unit, and every function keeps its `lexer_module` and that module's `tier`. A unit's `tier` and `run_*` flags are the most demanding of its lexer modules'; the ledger seeds each function with its own tier. Review `workspace/reports/callgraph_dag.json`:
- Check each module's `required_sources` (the transitive in-repository `.c` file closure needed to compile and analyze the module together with its in-repo sibling callees), `cross_module_callees`, `external_callees`, and auto-discovered `cppflags`.
- Check `name_collisions` (same-named static functions in different files), `recursion_cycles`, and `indirect_calls` (function-pointer call sites requiring `//@ calls f1, f2;` or `//@ assert fp \in {...};`).
- Check each function's `verifiability` (`core_provable`, `needs_calls_annotation`, or `shell_unverifiable_wp`), `wp_blockers` (`fuzz_or_eva_harness_entrypoint`, `internal_variadic`, `irreducible_goto`, `dynamic_allocation`, `container_of`, `volatile_or_asm`), and `wp_notes` (e.g., `while (n--)` unsigned wraparound idiom or pointer casts requiring `-wp-model Typed+cast`).
- Record any tier override with a source-backed reason.

| Risk Tier | Code Archetype (Structural Signature & Body Profile) | Verification Route |
| :--- | :--- | :--- |
| **Tier 1A** | Untrusted Binary / Buffer Parser (`const uint8_t*/char*` + `size_t` reader with loops and no heap allocation) | Phase 1 (`E-ACSL + Fuzz`) -> Phase 2 (`Eva`) -> Phase 3 (`Full Wavefront WP` + Layers 1-6) |
| **Tier 1B** | Structured Packet / Buffer Emitter (mutable output buffer + capacity writer or formatting calls) | Phase 1 (`E-ACSL + Fuzz`) -> Phase 2 (`Eva`) -> Phase 3 (`Full Wavefront WP` + Layer 5 Sanitization) |
| **Tier 2** | Recursive or Heap-Allocating Module (`recursion_cycles` or `malloc`/`calloc`/`realloc`/`free` in call tree) | Phase 1 (`E-ACSL + Fuzz` with dictionary) + Phase 2 (`Eva`) + WP on non-allocating validators |
| **Tier 3** | Internal Glue & State Machines | Seeded `deferred` in `quick`/`standard` profiles; `rte` units seeded `planned` for WP in `deep` profile |

---

## Step 3 — Stub External Libraries & Inject Security Templates

For each `Tier 1A`, `Tier 1B`, and `Tier 2` module:
1. Check `required_sources` and `external_callees` in `callgraph_dag.json`.
   - **In-repository callees (`cross_module_callees`):** Compile the sibling `.c` files listed in `required_sources` together in the slice rather than stubbing them, so call chains into sibling modules remain reachable for fuzzing, Eva, and WP.
   - **True external library calls (`external_callees`):** Under Frama-C (`__FRAMAC__`), external functions **must remain bodyless prototypes** (declared in real target headers, `/opt/framac-pipeline/templates/fc_stubs/` for `bsd/string.h`, `json-c/json.h`, `netinet/ip_icmp.h`, or `/opt/framac-pipeline/templates/acsl/external_stubs.h`) with optional ACSL contracts (`requires`, `assigns`, `ensures`). **Never** give an external function a dummy C body like `{ return 0; }` under Frama-C: a C body hides the open assumption from the ledger (`Considered valid` / `STATUS_ASSUMED`) and makes callers falsely appear proven under `return 0;`.
   - **Network/IPC boundary stubs for dynamic fuzzing:** If a module reads input through a blocking socket/port helper (e.g., `RECEIVE_MESSAGE`), put `extern` declarations in a `.h` file and function definitions in a single `.c` file (never define functions in a force-included header across multiple TUs), and inject `fuzz_buf` on **every** call (never gate injection on a `static int calls` counter, which would block all LibFuzzer iterations after the first).
2. Generate the Layer 3–6 properties from the threat model before seeding the ledger: `python3 /opt/framac-pipeline/scripts/security_props.py run` (reads `workspace/reports/phase0_model.json` and the target's `THREAT_MODEL.md`, writes `workspace/reports/security_props.json`), then `ledger.py seed ... --security-props workspace/reports/security_props.json`. Auth gates, output sinks and secrets become MetAcsl meta-properties (`templates/metacsl/`) whose generated annotations are ledger units; nothing is attached to the code by hand. Without a threat model only `l3_frame` units are generated. See [security-properties.md](../../docs/security-properties.md).

---

## Step 4 — Generate Dual-Use Module Harnesses

For each `Tier 1A`, `Tier 1B`, and `Tier 2` module:

```text
python3 /opt/framac-pipeline/scripts/generate_harness.py --module <mod> --sources <required_sources...> --header <mod.h> --entry-fn <entry_fn> --entry-style <buffer_len|c_string|global_buffer|struct_arg|void_call|auto_prototype|custom|argv|dispatch> [--auto-args] [--dispatch-case '<stmts>']... [--ldflags='<-lfoo ...>'] --max-size 1500 --out-dir workspace/harnesses
```

With link units, a harness module is either a unit itself or a **sub-module** of one: a library with several entry families gets one harness per family, named after the lexer module it drives (QCBOR's `decode`, `encode`... inside `libqcbor_a`). The sidecar records its `unit` (`--unit <unit>`; inferred from the DAG when omitted). A sub-module keeps its lexer module's tier, flags and sources; its reports, corpus and candidates stay under its own name and credit its unit's functions. A sub-module whose name is not a lexer module answers for the files in its sidecar's `scope_files` (else `sources`).

The sidecar `harness_<mod>.json` is the single source of truth for later phases: `sources`, `cppflags`, `ldflags`, `include_source`. `pipeline_make.py gen` builds every module's fuzz, Eva and build recipes from it, so put the module's real link flags in `--ldflags` here rather than on later command lines. Flags outside the build allowlist (for example `-fplugin`, `-B`, `-fuse-ld`, `-Wl,`) exclude the module from the Make phases. `gen` reports them.

Supported `--entry-style` modes and options in `generate_harness.py`:
- `buffer_len` (default): `entry_fn(input_buf, input_len)` for standard `(const uint8_t *, size_t)` parsers.
- `c_string`: NUL-terminates `fuzz_buf` in both Eva and LibFuzzer and calls `entry_fn((const char *)fuzz_buf)`.
- `global_buffer`: copies fuzz/symbolic bytes into `--global-buf <name>` (and optional `--global-len <name>`) before calling `entry_fn()`.
- `struct_arg`: populates a stack struct of `--struct-type <Type>` with fuzz/symbolic bytes before calling `entry_fn(&target_arg)`.
- `void_call`: invokes `entry_fn()` directly after initializing any globals.
- `auto_prototype` (or `--auto-args`): inspects the C declaration of `--entry-fn` in `--header` or `--sources`, automatically synthesizes Eva (`Frama_C_make_unknown`) and LibFuzzer (`fuzz_buf + fuzz_off`) argument unpacking for arbitrary multi-argument internal functions (buffer+length pairs, C strings, output buffers, pointers, and scalars), and defaults `reachability` to `internal_api` when the entry function has no trust in the DAG (Step 1d).
- `custom`: executes arbitrary C statements passed via `--call-expr '<stmts using fuzz_buf and fuzz_len>'` (or separate `--eva-expr` and `--fuzz-expr`), with optional `--null-terminate` and repeatable `--extra-include <hdr.h>`.
- `argv`: CLI-style targets whose entry is `main(int argc, char **argv)` — the default when `--entry-fn main` is given without an explicit `--entry-style`. Eva side emulates `argc`/`argv` with `Frama_C_interval(0, 5)` and five unknown 256-byte buffers (upstream `share/libc/eva_stubs.c`, vendored as `docs/upstream/sources/eva_stubs.c`); the LibFuzzer side passes the input as `argv[1]` NUL-terminated. The sidecar `cppflags` get `-Dmain=__framac_target_main`, renaming the target's `main` in every build so libFuzzer's own `main` does not clash at link time.
- `dispatch`: one harness for an API library with many entry points. Each repeatable `--dispatch-case '<stmts>'` drives one API call; the first input byte selects the case and the rest of the input is that case's `fuzz_buf`/`fuzz_len`. Eva sees an unknown selector, so one analysis covers every case. Each case must build its arguments within the callee's contract (for a builder: a real buffer, its real size as `buflen`, and the setup calls the API documents, such as writing the message header first) and must never `return`. Pass the module's main parser as `--entry-fn`. The sidecar records the cases in `dispatch_cases`. The fuzz campaign skips a case once it has crashed, by rebuilding with `-DFRAMAC_FUZZ_SKIP_CASES`, so keep unrelated API calls in separate cases: a skipped case is not fuzzed for the rest of the campaign.
- Note: Passing a workspace path like `--header workspace/work/src/Mod/Mod.h` automatically adds `-Iworkspace/work/src/Mod` to `cppflags` and emits `#include "Mod.h"`.
- If `entry_fn` is `static` inside its `.c` file, pass `--include-source` so the harness includes the `.c` translation unit directly instead of compiling it twice.
- If a dynamic LibFuzzer binary cannot link an external third-party library symbol at link time, pass `--stubbed-callee <fn>` so it is recorded in `harness_<mod>.json` (`stubbed_callees`) and any linker stub is guarded by `#ifndef __FRAMAC__`.

Module headers are often not self-sufficient (for example `Events.h` uses `Boolean_T`, `GST_CHAIN_MODE_T`, or `CMD_NAME_MAX_LEN` defined in `PtfUtil.h` without including it). Auto-prelude handles this (on by default):
- After writing the harness, `generate_harness.py` runs `clang -fsyntax-only -x c <cppflags> harness_<mod>.c` (LibFuzzer branch, no `-D__FRAMAC__`), collects `unknown type name` / `use of undeclared identifier` diagnostics, finds the defining `*.h` in the `-I` directories of `--cppflags` (typedefs, `} X;`, `#define X`, enum constants; top-level of each directory only), and `#include`s it before the module header. It repeats this up to 3 rounds.
- The outcome is recorded in `harness_<mod>.json` and the JSON output as `prelude_headers`, `prelude_status` (`clean`, `resolved`, `unresolved`, `skipped` when clang is missing or hits a fatal error, `disabled`), and `prelude_unresolved`. If symbols are still unresolved, the command fails and lists them. In that case, add the missing directory with `-I`, or use the manual form below.
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

It reads `workspace/reports/callgraph_dag.json` and each `harness_<mod>.json` / `harness_<mod>.c`, takes the DAG functions the harness names (directly, through a header macro such as a `for_each` iterator, or through a header `static inline` wrapper) and their transitive in-repo callees, and checks that every `candidate_entry_points` function of the module is reached. A sub-module is checked against the unit's entry points in its own scope; entry points of a unit that no harness module's scope holds are reported as the unit's gaps. A Tier 1A/1B/2 module without a harness fails with `no_harness`. The report goes to `workspace/reports/harness_reach.json`; exit code 1 means a gap.

For each module with `gaps`:

1. Regenerate its harness with `--entry-style dispatch`, one `--dispatch-case` per unreached entry point (several related calls may share a case, for example building a message then parsing it). Keep the existing parser call as a case. Do not cover a gap by violating a callee's contract: a crash from such a case is `rejected` as harness-induced.
2. Re-run `harness_reach.py check`.
3. An entry point that cannot be driven from bytes (it needs a live kernel socket, a real file descriptor, or a process-global the harness cannot set up safely) gets a recorded reason instead: `harness_reach.py exempt --module <mod> --function <fn> --reason '<why>'`. A Tier 1A/1B/2 module that needs no harness at all (example programs, test drivers) gets `harness_reach.py exempt --module <mod> --reason '<why>'`. Exemptions survive harness regeneration. Never exempt an entry point only because writing its case is tedious.

Move on only when `check` exits 0. Its `exempt` entries are the accepted, documented gaps.

The check records its result in `workspace/reports/phase0_gates.json`, together with a digest of each harness. Make enforces it: `seed` runs the check first (`reach-gate`), and the `build-`, `fuzz-`, `coverage-` and `eva-` targets of a module stop with the reason when the module failed it or when its harness changed after the check ran. After any harness repair, run `check` again.

---

## Step 5 — Seed the Coverage Ledger and Checkpoint

```text
python3 /opt/framac-pipeline/scripts/ledger.py seed --dag workspace/reports/callgraph_dag.json [--profile <quick|standard|deep>] [--scope <repo-relative path>]...
python3 /opt/framac-pipeline/scripts/validate_artifacts.py run-dir .
python3 /opt/framac-pipeline/scripts/checkpoint.py init state --target /target   # keeps an existing progress file
python3 /opt/framac-pipeline/scripts/checkpoint.py save-phase state --phase 0 --from-file workspace/reports/callgraph_dag.json
python3 /opt/framac-pipeline/scripts/pipeline_make.py gen
python3 /opt/framac-pipeline/scripts/pipeline_make.py build-check
```

`pipeline_make.py gen` writes `workspace/build/Makefile` for the deterministic per-module phases (`/framac-fuzz`, `/framac-eva`). Check its JSON for modules excluded with a reason before moving on.

`pipeline_make.py build-check` builds every fuzzed module (`run build`, cached, so Phase 1 reuses it) and exits 1 unless each one was instrumented with E-ACSL. The Frama-C kernel parse in Step 4 uses Frama-C's own libc, but the E-ACSL build runs with `-no-frama-c-stdlib` against the host headers, so a harness can pass Step 4 and still fall back to ASan/UBSan, losing the E-ACSL checks. For each failing module, `workspace/reports/build_check.json` gives `status` (`eacsl_fallback`, `build_failed`, `not_built`), the `compile_log`, and its `first_error`. Fix the cause (usually a host header Frama-C cannot parse: put a minimal stub under `workspace/harnesses/include/` on the sidecar's `-I` path, ahead of `-idirafter /usr/include`), regenerate the harness, and rerun. Only when E-ACSL cannot work for the module, record that choice with `pipeline_make.py params set --module <mod> --fuzz-engine sanitizers`, which the check accepts.

`build-check` records its result in the same `phase0_gates.json`. `fuzz-<mod>` refuses a module that failed it, and `wp-queue` refuses the run until every module passes both gates. Run `build-check` again after a repair.
