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

If the target has no `compile_commands.json`, generate one in a disposable full copy, never in the target, and run the target's build only inside the inner sandbox:

```text
mkdir -p workspace/build-scratch && cp -a /target/. workspace/build-scratch/
python3 $S/sandbox_exec.py run --writable workspace/build-scratch --cwd workspace/build-scratch -- bear -- make -j4
```

For CMake: `cmake -B build "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON"` inside the same scratch copy. Pass the result to Step 2 with `--compile-commands`.

---

## Step 2 — Build the Call-Graph DAG, Topological Waves & Risk Tiers

```text
python3 $S/build_callgraph_dag.py --target workspace/work --out workspace/reports/callgraph_dag.json
```

Read `workspace/reports/callgraph_dag.json` and review the structural classifications. `build_callgraph_dag.py` uses a C/ACSL lexical token stream (`tokenize_c_acsl`), Tarjan's SCC algorithm for recursion cycles, and purely structural signature/body analysis (no project-specific keyword hints):
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
1. Check `external_callees` in `callgraph_dag.json` (e.g., OpenSSL/mbedTLS crypto routines, OS socket calls).
2. Map external calls to `/opt/framac-pipeline/templates/acsl/external_stubs.h` or add 5-line ACSL contract declarations (`requires \valid_read(...); assigns ...; ensures ...;`) in `workspace/work/` header stubs so Frama-C verifies buffer validity at the boundary without parsing third-party library source code. Stub contracts are trusted assumptions; they are recorded as such in the ledger.
3. Inspect each function's `security_properties` array and attach the corresponding template headers from `/opt/framac-pipeline/templates/acsl/`:
   - `layer4_auth_state_machine.acsl` for authentication / access-control gates (`g_sec_auth_verified`, `g_sec_acl_authorized`).
   - `layer5_output_sanitization.acsl` for structured output formatters (`no_crlf_or_nul`, `is_printable_ascii`).
   - `layer6_zeroization_and_taint.acsl` for key/secret zeroization (`buffer_is_zeroed`) and Eva taint annotations.

   Name every layer clause `L4_*`, `L5_*`, or `L6_*` (for example `ensures L5_no_crlf: no_crlf_or_nul(out, \result);`). Unnamed clauses cannot be credited to a layer unit.

---

## Step 4 — Generate Dual-Use Module Harnesses

For each `Tier 1A`, `Tier 1B`, and `Tier 2` module:

```text
python3 $S/generate_harness.py --module <mod> --sources <c-files...> --header <mod.h> --entry-fn <entry_fn> --max-size 1500 --out-dir workspace/harnesses
```

The harness must respect the entry function's declared or documented contract (buffer sizes, non-NULL arguments, length limits). A crash caused by a harness that violates that contract is `rejected` as harness-induced, so get this right before fuzzing. Verify that every generated harness parses cleanly with the Frama-C kernel (`frama-c -machdep gcc_x86_64 ... -kernel-warn-key annot-error=abort`).

---

## Step 5 — Seed the Coverage Ledger and Checkpoint

```text
python3 $S/ledger.py seed --dag workspace/reports/callgraph_dag.json [--scope <repo-relative path>]...
python3 $S/validate_artifacts.py run-dir .
python3 $S/checkpoint.py init state --target /target
python3 $S/checkpoint.py save-phase state --phase 0 --from-file workspace/reports/callgraph_dag.json
```
