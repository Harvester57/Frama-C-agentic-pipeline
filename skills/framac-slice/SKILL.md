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
$env:PYTHONIOENCODING="utf-8"
& "C:\Users\Florian\OneDrive\Documents\Dev\frama-c\wrappers\framac-docker.ps1" `
  -TargetDir "<target-dir>" -RunDir "<run-dir>" -BuildIfMissing `
  "<command>"
```

`S=/opt/framac-pipeline/scripts`.

## Step 1 — Initialize the Shadow Overlay Workspace

```text
python3 $S/workspace_overlay.py init --target /target --overlay workspace
```

The target is never modified. If the overlay already exists and the target changed since it was captured, `init` fails: start a new run directory instead of resuming.

If the target has no `compile_commands.json` (or has an out-of-tree build system where running `bear` is impractical), `build_callgraph_dag.py` in Step 2 automatically discovers all in-repository header directories and can emit a synthesized `compile_commands.json` via `--emit-compile-commands workspace/reports/compile_commands.json` while stripping any host `/usr/include` paths. If you do want to capture build flags from the target's native build, do so in a disposable full copy inside the inner sandbox:

```text
mkdir -p workspace/build-scratch && cp -a /target/. workspace/build-scratch/
python3 $S/sandbox_exec.py run --writable workspace/build-scratch --cwd workspace/build-scratch -- bear -- make -j4
```

For CMake: `cmake -B build "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON"` inside the same scratch copy. Pass the result to Step 2 with `--compile-commands`. If the target depends on additional Debian/Ubuntu `-dev` packages not in the base image, pass `--target-packages "<pkg1> <pkg2>"` (or `-TargetPackages` in PowerShell) to the Docker wrapper so the real headers and libraries are installed into a cached derived image before container privileges are dropped.

---

## Step 2 — Build the Call-Graph DAG, Topological Waves & Risk Tiers

```text
python3 $S/build_callgraph_dag.py --target workspace/work --out workspace/reports/callgraph_dag.json --emit-compile-commands workspace/reports/compile_commands.json
```

Read `workspace/reports/callgraph_dag.json` and review the structural classifications. `build_callgraph_dag.py` uses a C/ACSL lexical token stream (`tokenize_c_acsl`), Tarjan's SCC algorithm for recursion cycles, and purely structural signature/body analysis (no project-specific keyword hints):
- Check each module's `required_sources` (the transitive in-repository `.c` file closure needed to compile and analyze the module together with its in-repo sibling callees), `cross_module_callees`, `external_callees`, and auto-discovered `cppflags`.
- Check `name_collisions` (same-named static functions in different files), `recursion_cycles`, and `indirect_calls` (function-pointer call sites requiring `//@ calls f1, f2;` or `//@ assert fp \in {...};`).
- Check each function's `verifiability` (`verifiable`, `needs_annotation_or_stub`, or `refactor_required`), `wp_blockers` (`irreducible_goto`, `dynamic_allocation`, `container_of`, `volatile_or_asm`), and `wp_notes` (e.g., `while (n--)` unsigned wraparound idiom or pointer casts requiring `-wp-model Typed+cast`).
- Record any tier override with a source-backed reason.

| Risk Tier | Code Archetype (Structural Signature & Body Profile) | Verification Route |
| :--- | :--- | :--- |
| **Tier 1A** | Untrusted Binary / Buffer Parser (`const uint8_t*/char*` + `size_t` reader with loops and no heap allocation) | Phase 1 (`E-ACSL + Fuzz`) -> Phase 2 (`Eva`) -> Phase 3 (`Full Wavefront WP` + Layers 1-6) |
| **Tier 1B** | Structured Packet / Buffer Emitter (mutable output buffer + capacity writer or formatting calls) | Phase 1 (`E-ACSL + Fuzz`) -> Phase 2 (`Eva`) -> Phase 3 (`Full Wavefront WP` + Layer 5 Sanitization) |
| **Tier 2** | Recursive or Heap-Allocating Module (`recursion_cycles` or `malloc`/`calloc`/`realloc`/`free` in call tree) | Phase 1 (`E-ACSL + Fuzz` with dictionary) + Phase 2 (`Eva`) + WP on non-allocating validators |
| **Tier 3** | Internal Glue & State Machines | Seeded `deferred` in the ledger; spot `Eva` / on-demand `WP` only when explicitly scheduled |

---

## Step 3 — Stub External Libraries & Inject Security Templates

For each `Tier 1A`, `Tier 1B`, and `Tier 2` module:
1. Check `required_sources` and `external_callees` in `callgraph_dag.json`.
   - **In-repository callees (`cross_module_callees`):** Compile the sibling `.c` files listed in `required_sources` together in the slice rather than stubbing them, so call chains into sibling modules remain reachable for fuzzing, Eva, and WP.
   - **True external library calls (`external_callees`):** Under Frama-C (`__FRAMAC__`), external functions **must remain bodyless prototypes** (declared in real target headers or `/opt/framac-pipeline/templates/acsl/external_stubs.h`) with optional ACSL contracts (`requires`, `assigns`, `ensures`). **Never** give an external function a dummy C body like `{ return 0; }` under Frama-C: a C body hides the open assumption from the ledger (`Considered valid` / `STATUS_ASSUMED`) and makes callers falsely appear proven under `return 0;`.
2. Inspect each function's `security_properties` array and attach the corresponding template headers from `/opt/framac-pipeline/templates/acsl/`:
   - `layer4_auth_state_machine.acsl` for authentication / access-control gates (`g_sec_auth_verified`, `g_sec_acl_authorized`).
   - `layer5_output_sanitization.acsl` for structured output formatters (`no_crlf_or_nul`, `is_printable_ascii`).
   - `layer6_zeroization_and_taint.acsl` for key/secret zeroization (`buffer_is_zeroed`) and Eva taint annotations.

   Name every layer clause `L4_*`, `L5_*`, or `L6_*` (for example `ensures L5_no_crlf: no_crlf_or_nul(out, \result);`). Unnamed clauses cannot be credited to a layer unit.

---

## Step 4 — Generate Dual-Use Module Harnesses

For each `Tier 1A`, `Tier 1B`, and `Tier 2` module:

```text
python3 $S/generate_harness.py --module <mod> --sources <required_sources...> --header <mod.h> --entry-fn <entry_fn> --entry-style <buffer_len|global_buffer|struct_arg|void_call> --max-size 1500 --out-dir workspace/harnesses
```

Supported `--entry-style` modes in `generate_harness.py`:
- `buffer_len` (default): `entry_fn(input_buf, input_len)` for standard `(const uint8_t *, size_t)` parsers.
- `global_buffer`: copies fuzz/symbolic bytes into `--global-buf <name>` (and optional `--global-len <name>`) before calling `entry_fn()`.
- `struct_arg`: populates a stack struct of `--struct-type <Type>` with fuzz/symbolic bytes before calling `entry_fn(&arg)`.
- `void_call`: invokes `entry_fn()` directly after initializing any globals.
- If `entry_fn` is `static` inside its `.c` file, pass `--include-source <rel.c>` so the harness includes the `.c` translation unit directly instead of compiling it twice.
- If a dynamic LibFuzzer binary cannot link an external third-party library symbol at link time, pass `--stubbed-callee <fn>` so it is recorded in `harness_<mod>.json` (`stubbed_callees`) and any linker stub is guarded by `#ifndef __FRAMAC__`.

The harness must respect the entry function's declared or documented contract (buffer sizes, non-NULL arguments, length limits). A crash caused by a harness that violates that contract is `rejected` as harness-induced, so get this right before fuzzing. Verify that every generated harness parses cleanly with the Frama-C kernel (`frama-c -machdep gcc_x86_64 ... -kernel-warn-key annot-error=abort`).

---

## Step 5 — Seed the Coverage Ledger and Checkpoint

```text
python3 $S/ledger.py seed --dag workspace/reports/callgraph_dag.json [--scope <repo-relative path>]...
python3 $S/validate_artifacts.py run-dir .
python3 $S/checkpoint.py init state --target /target
python3 $S/checkpoint.py save-phase state --phase 0 --from-file workspace/reports/callgraph_dag.json
```
