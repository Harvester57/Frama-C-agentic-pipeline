---
name: framac-fuzz
description: >-
  Phase 1 of the Frama-C verification pipeline. Runs zero-ACSL dynamic bug
  hunting per module slice by generating RTE assertions (-rte), compiling them
  with E-ACSL into runtime shadow-memory and arithmetic checks, and fuzzing the
  resulting binary with Clang LibFuzzer inside the hardened framac-pipeline
  container and the bubblewrap inner sandbox. Catches intra-struct sub-object
  overflows, uninitialized reads, signed/unsigned overflows, and Layer 4-6 ACSL
  security contract violations. Crashes become fingerprinted candidates, not
  findings, until independently verified.
argument-hint: "<target-dir> --run-dir <dir> [--module <name>] [--time <seconds>] [--dict <file>]"
---

# /framac-fuzz

Dynamic bug-hunting stage that pairs **Frama-C RTE + E-ACSL** with **Clang LibFuzzer** across module slices before any static proof effort is spent.

## Why This Runs Before Eva and WP

1. **Zero Human ACSL Required:** `--rte=all` automatically injects `\valid`, `\valid_read`, `\initialized`, `signed_overflow`, `division_by_zero`, and shift bounds across every C expression in the slice.
2. **Sub-Object Precision:** Unlike ASan (which only places redzones between top-level allocations), E-ACSL checks exact array/field sub-object bounds (catching `pkt.header[16]` overflowing into `pkt.is_admin` inside the same struct) and tracks byte-level initialization without full-program MSan rebuilds.
3. **Coverage-Guided ACSL Exploration:** E-ACSL compiles ACSL predicates into explicit C `if` branches before calling `__e_acsl_assert()`. Clang's `-fsanitize=fuzzer` instruments those generated branches, actively steering mutations toward RTE and security contract boundaries.

---

## Step 1 — Load Module Slices from Phase 0

Read `workspace/reports/callgraph_dag.json` and `workspace/harnesses/`. If Phase 0 has not been run yet, execute `/framac-slice <target-dir>` first.

Select all modules with `run_eacsl_fuzz: true` (or the specific `--module <name>` passed by the user).

---

## Step 2 — Parallel Fuzzing Fan-Out

Run one campaign per module slice (up to 8 concurrently). Each campaign writes only its own module's corpus, crash directory, and report:

```powershell
$env:PYTHONIOENCODING="utf-8"
& "C:\Users\Florian\OneDrive\Documents\Dev\frama-c\wrappers\framac-docker.ps1" `
  -TargetDir "<target-dir>" -RunDir "<run-dir>" `
  "python3 /opt/framac-pipeline/scripts/run_eacsl_fuzz.py campaign --module <mod> --sources workspace/work/src/<mod>/*.c workspace/harnesses/harness_<mod>.c --out-bin workspace/harnesses/fuzz_<mod> --corpus-dir workspace/corpus/<mod> --artifacts-dir workspace/crashes/<mod> --max-time <time> --engine auto --cppflags '-Iworkspace/work/include -I/opt/framac-pipeline/templates/acsl' --out-json workspace/reports/fuzz/<mod>.json"
```

`run_eacsl_fuzz.py` supports `--engine {auto,eacsl,sanitizers}` (default `auto` in `campaign` mode):
- It first invokes `e-acsl-gcc` (or legacy `e-acsl-gcc.sh`) with `-rte-select` and `-e-acsl-functions` scoped to the target slice functions so E-ACSL does not attempt to instrument Frama-C's internal `__fc_libc` helpers, and writes the full compiler transcript to `<out-bin>.compile.log`.
- If `e-acsl-gcc` still fails on a target C construct and `--engine auto` is active, `campaign` mode automatically falls back to compiling a native Clang LibFuzzer + AddressSanitizer + UndefinedBehaviorSanitizer binary (`-fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all`), parses ASan/UBSan runtime failures into the identical `failure` structure and `<file>#<function>::<kind>::<hash10>` fingerprint format, and records `"engine_used": "clang_sanitizers_fallback"` in `workspace/reports/fuzz/<mod>.json`.
- Note: Phase 3 `/framac-wp` `guardrail` mode always uses E-ACSL (`compile_eacsl_binary`), because the guardrail's purpose is to execute candidate ACSL annotations against the corpus.

The fuzzer, and every crash replay, runs inside `sandbox_exec.py` (read-only filesystem except the corpus/crash/scratch directories, no network, rlimits, timeout). If the report says `sandbox_unavailable`, stop and fix the container rather than running unsandboxed; `-AllowDegradedSandbox` is an explicit operator decision that is recorded.

*(Never pass `-fsanitize=address` alongside E-ACSL's memory tracking runtime in the same binary, as both intercept `malloc`/`free` and map conflicting shadow memory.)*

---

## Step 3 — Read Outcomes and Ingest

`workspace/reports/fuzz/<mod>.json` has one of these statuses:

| Status | Meaning |
| :--- | :--- |
| `crash_found` | At least one `crash-*` artifact. Each artifact was replayed once (`reproducible`), its E-ACSL failure parsed (`failure`: file, line, function, kind, predicate), and fingerprinted. |
| `timeout_found` / `oom_found` | Per-input timeout or RSS limit hit. A termination/DoS lead, not a memory-safety bug. |
| `clean` | No failure within the time budget. The corpus in `workspace/corpus/<mod>/` becomes the dynamic anti-hallucination corpus for `/framac-wp`. Fuzzing is not proof. |
| `fuzzer_error` / `compile_error` / `sandbox_unavailable` | The campaign did not run to completion. Never read this as clean. |

Then ingest all reports (parent only):

```text
python3 /opt/framac-pipeline/scripts/ledger.py ingest-fuzz workspace/reports/fuzz/*.json
python3 /opt/framac-pipeline/scripts/validate_artifacts.py run-dir .
```

Each fingerprint becomes one entry in `candidates.json` (several crash inputs with the same failing predicate collapse into one candidate), and the matching ledger units become `candidate` (including any `deferred` Tier 3 helper functions reached via cross-module calls), which excludes them from WP. A crash is a candidate until a verifier confirms that the fault is in target code and that the harness respected the entry function's contract.

To scaffold a schema-valid `crash_verifier` JSON record for any candidate in `candidates.json` (pre-populating `sha256`, `size_bytes`, `linked_units`, and `refingerprint_reason`), run:

```text
python3 /opt/framac-pipeline/scripts/ledger.py scaffold-verifier --fingerprint <fp> --decision confirmed --agent-id verifier-1 --out agents/verifier-1/scratch/result.json
```

At the end of a `quick` or profile-bounded run where Phase 3 WP is not scheduled for remaining `planned` units, close remaining open units cleanly before marking the run `complete`:

```text
python3 /opt/framac-pipeline/scripts/ledger.py close-remaining --reason "quick_profile_wp_not_scheduled: Phase 3 WP not run in quick profile"
```
