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

If the target has no `compile_commands.json` (or has an out-of-tree build system where running `bear` is impractical), `build_callgraph_dag.py` in Step 2 automatically discovers all in-repository header directories and can emit a synthesized `compile_commands.json` via `--emit-compile-commands workspace/reports/compile_commands.json` while stripping any host `/usr/include` paths. If you do want to capture build flags from the target's native build, do so in a disposable full copy run through `sandbox_exec.py` (rlimits, env allowlist, timeout):

```text
mkdir -p workspace/build-scratch && cp -a /target/. workspace/build-scratch/
python3 /opt/framac-pipeline/scripts/sandbox_exec.py run --writable workspace/build-scratch --cwd workspace/build-scratch -- bear -- make -j"$FRAMAC_JOB_CPUS"
```

The broker sizes a sandboxed `bear`, `make`, `cmake`, `ninja`, `meson` or `configure` command like a whole phase (`phase-dynamic`), and `FRAMAC_JOB_CPUS` is the CPU count it leased. `$FRAMAC_JOB_CPUS` must reach the container unexpanded: in the PowerShell wrapper's double-quoted command write `` `$FRAMAC_JOB_CPUS ``.

For CMake: `cmake -B build "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON"` inside the same scratch copy. Pass the result to Step 2 with `--compile-commands`. If the target depends on additional Debian/Ubuntu `-dev` packages not in the base image, pass `--target-packages "<pkg1> <pkg2>"` (or `-TargetPackages` in PowerShell) to the Docker wrapper so the real headers and libraries are installed into a cached derived image before container privileges are dropped.

---

## Step 2 — Build the Call-Graph DAG, Topological Waves & Risk Tiers

```text
python3 /opt/framac-pipeline/scripts/build_callgraph_dag.py --target workspace/work --out workspace/reports/callgraph_dag.json --emit-compile-commands workspace/reports/compile_commands.json
```

Read `workspace/reports/callgraph_dag.json` and review the structural classifications. `build_callgraph_dag.py` uses a C/ACSL lexical token stream (`tokenize_c_acsl`), Tarjan's SCC algorithm for recursion cycles, and purely structural signature/body analysis (no project-specific keyword hints):
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
2. Inspect each function's `security_properties` array and attach the corresponding template headers from `/opt/framac-pipeline/templates/acsl/`:
   - `layer4_auth_state_machine.acsl` for authentication / access-control gates (`g_sec_auth_verified`, `g_sec_acl_authorized`).
   - `layer5_output_sanitization.acsl` for structured output formatters (`no_crlf_or_nul`, `is_printable_ascii`).
   - `layer6_zeroization_and_taint.acsl` for key/secret zeroization (`buffer_is_zeroed`) and Eva taint annotations.

   Name every layer clause `L4_*`, `L5_*`, or `L6_*` (for example `ensures L5_no_crlf: no_crlf_or_nul(out, \result);`). Unnamed clauses cannot be credited to a layer unit.

---

## Step 4 — Generate Dual-Use Module Harnesses

For each `Tier 1A`, `Tier 1B`, and `Tier 2` module:

```text
python3 /opt/framac-pipeline/scripts/generate_harness.py --module <mod> --sources <required_sources...> --header <mod.h> --entry-fn <entry_fn> --entry-style <buffer_len|c_string|global_buffer|struct_arg|void_call|auto_prototype|custom|argv|dispatch> [--auto-args] [--dispatch-case '<stmts>']... [--ldflags='<-lfoo ...>'] --max-size 1500 --out-dir workspace/harnesses
```

The sidecar `harness_<mod>.json` is the single source of truth for later phases: `sources`, `cppflags`, `ldflags`, `include_source`. `pipeline_make.py gen` builds every module's fuzz, Eva and build recipes from it, so put the module's real link flags in `--ldflags` here rather than on later command lines. Flags outside the build allowlist (for example `-fplugin`, `-B`, `-fuse-ld`, `-Wl,`) exclude the module from the Make phases. `gen` reports them.

Supported `--entry-style` modes and options in `generate_harness.py`:
- `buffer_len` (default): `entry_fn(input_buf, input_len)` for standard `(const uint8_t *, size_t)` parsers.
- `c_string`: NUL-terminates `fuzz_buf` in both Eva and LibFuzzer and calls `entry_fn((const char *)fuzz_buf)`.
- `global_buffer`: copies fuzz/symbolic bytes into `--global-buf <name>` (and optional `--global-len <name>`) before calling `entry_fn()`.
- `struct_arg`: populates a stack struct of `--struct-type <Type>` with fuzz/symbolic bytes before calling `entry_fn(&target_arg)`.
- `void_call`: invokes `entry_fn()` directly after initializing any globals.
- `auto_prototype` (or `--auto-args`): inspects the C declaration of `--entry-fn` in `--header` or `--sources`, automatically synthesizes Eva (`Frama_C_make_unknown`) and LibFuzzer (`fuzz_buf + fuzz_off`) argument unpacking for arbitrary multi-argument internal functions (buffer+length pairs, C strings, output buffers, pointers, and scalars), and defaults `reachability` to `internal_api`.
- `custom`: executes arbitrary C statements passed via `--call-expr '<stmts using fuzz_buf and fuzz_len>'` (or separate `--eva-expr` and `--fuzz-expr`), with optional `--null-terminate` and repeatable `--extra-include <hdr.h>`.
- `argv`: CLI-style targets whose entry is `main(int argc, char **argv)` — the default when `--entry-fn main` is given without an explicit `--entry-style`. Eva side emulates `argc`/`argv` with `Frama_C_interval(0, 5)` and five unknown 256-byte buffers (upstream `share/libc/eva_stubs.c`, vendored as `docs/upstream/sources/eva_stubs.c`); the LibFuzzer side passes the input as `argv[1]` NUL-terminated. The sidecar `cppflags` get `-Dmain=__framac_target_main`, renaming the target's `main` in every build so libFuzzer's own `main` does not clash at link time.
- `dispatch`: one harness for an API library with many entry points. Each repeatable `--dispatch-case '<stmts>'` drives one API call; the first input byte selects the case and the rest of the input is that case's `fuzz_buf`/`fuzz_len`. Eva sees an unknown selector, so one analysis covers every case. Each case must build its arguments within the callee's contract (for a builder: a real buffer, its real size as `buflen`, and the setup calls the API documents, such as writing the message header first) and must never `return`. Pass the module's main parser as `--entry-fn`. The sidecar records the cases in `dispatch_cases`.
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

It reads `workspace/reports/callgraph_dag.json` and each `harness_<mod>.json` / `harness_<mod>.c`, takes the DAG functions the harness names (directly, through a header macro such as a `for_each` iterator, or through a header `static inline` wrapper) and their transitive in-repo callees, and checks that every `candidate_entry_points` function of the module is reached. A Tier 1A/1B/2 module without a harness fails with `no_harness`. The report goes to `workspace/reports/harness_reach.json`; exit code 1 means a gap.

For each module with `gaps`:

1. Regenerate its harness with `--entry-style dispatch`, one `--dispatch-case` per unreached entry point (several related calls may share a case, for example building a message then parsing it). Keep the existing parser call as a case. Do not cover a gap by violating a callee's contract: a crash from such a case is `rejected` as harness-induced.
2. Re-run `harness_reach.py check`.
3. An entry point that cannot be driven from bytes (it needs a live kernel socket, a real file descriptor, or a process-global the harness cannot set up safely) gets a recorded reason instead: `harness_reach.py exempt --module <mod> --function <fn> --reason '<why>'`. A Tier 1A/1B/2 module that needs no harness at all (example programs, test drivers) gets `harness_reach.py exempt --module <mod> --reason '<why>'`. Exemptions survive harness regeneration. Never exempt an entry point only because writing its case is tedious.

Move on only when `check` exits 0. Its `exempt` entries are the accepted, documented gaps.

---

## Step 5 — Seed the Coverage Ledger and Checkpoint

```text
python3 /opt/framac-pipeline/scripts/ledger.py seed --dag workspace/reports/callgraph_dag.json [--profile <quick|standard|deep>] [--scope <repo-relative path>]...
python3 /opt/framac-pipeline/scripts/validate_artifacts.py run-dir .
python3 /opt/framac-pipeline/scripts/checkpoint.py init state --target /target   # keeps an existing progress file
python3 /opt/framac-pipeline/scripts/checkpoint.py save-phase state --phase 0 --from-file workspace/reports/callgraph_dag.json
python3 /opt/framac-pipeline/scripts/pipeline_make.py gen
```

`pipeline_make.py gen` writes `workspace/build/Makefile` for the deterministic per-module phases (`/framac-fuzz`, `/framac-eva`). Check its JSON for modules excluded with a reason before moving on.
