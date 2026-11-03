---
name: framac-fuzz
description: >-
  Phase 1 of the Frama-C verification pipeline. Runs zero-ACSL dynamic bug
  hunting per module slice by generating RTE assertions (-rte -rte-initialized),
  compiling them with E-ACSL into runtime shadow-memory and arithmetic checks,
  and fuzzing the resulting binary with Clang LibFuzzer inside the hardened
  framac-pipeline container under sandbox_exec.py (rlimits, env allowlist,
  timeout). Catches intra-struct sub-object overflows, use-after-free,
  uninitialized reads, signed overflows, and Layer 4-6 ACSL security contract
  violations. Crashes become fingerprinted candidates, not
  findings, until independently verified.
argument-hint: "<target-dir> --run-dir <dir> [--module <name>] [--time <seconds>] [--dict <file>]"
---

# /framac-fuzz

Dynamic bug-hunting stage that pairs **Frama-C RTE + E-ACSL** with **Clang LibFuzzer** across module slices before any static proof effort is spent.

## Why This Runs Before Eva and WP

1. **Zero Human ACSL Required:** `-rte -rte-initialized @all` automatically injects `\valid` / `\valid_read` (`mem_access`), `initialization`, `signed_overflow`, `division_by_zero`, and shift bounds across every C expression in the slice. `--warn-unsigned-downcast` adds unsigned downcasts. Unsigned overflow and signed downcasts are **not** checked while fuzzing: intentional wrap-around (hashes, checksums) and narrowing casts (byte encoders) would stop every campaign on its first input. Eva and WP check those kinds statically.
2. **Sub-Object Precision:** Unlike ASan (which only places redzones between top-level allocations), E-ACSL checks exact array/field sub-object bounds (catching `pkt.header[16]` overflowing into `pkt.is_admin` inside the same struct). Its per-byte initialization tracking backs the `initialization` checks without full-program MSan rebuilds.
3. **Coverage-Guided ACSL Exploration:** E-ACSL compiles ACSL predicates into explicit C `if` branches before calling `__e_acsl_assert()`. Clang's `-fsanitize=fuzzer` instruments those generated branches, actively steering mutations toward RTE and security contract boundaries.

---

## Step 1 — Load Module Slices from Phase 0

Read `workspace/reports/callgraph_dag.json` and `workspace/harnesses/`. If Phase 0 has not been run yet, execute `/framac-slice <target-dir>` first.

Select all modules with `run_eacsl_fuzz: true` (or the specific `--module <name>` passed by the user).

---

## Step 1b — Verify the E-ACSL Toolchain (once per image / Frama-C version)

The `selftest` Make target (a prerequisite of `fuzz`) runs it; for a one-off check:

```powershell
& "C:\Users\Florian\OneDrive\Documents\Dev\frama-c\wrappers\framac-docker.ps1" `
  -TargetDir "<target-dir>" -RunDir "<run-dir>" `
  "python3 /opt/framac-pipeline/scripts/run_eacsl_fuzz.py selftest"
```

`selftest` builds `templates/eacsl_canary/canary.c` through the exact production E-ACSL path and writes `workspace/reports/eacsl_selftest.json`. Its checks are `compiled`, `no_gmp_only`, `instrumented_binary`, `benign_input_clean`, `detects_overflow`, `detects_uninitialized`, and `attributes_line` (the last one is informational). `benign_input_clean` matters because a replay counts any non-zero exit as a reproduction: a binary that fails on every input (uninitialized runtime, false `\valid` alarms) would otherwise pass `detects_overflow`. If it fails, `campaign --engine auto` skips E-ACSL for every module with `engine_fallback_reason: eacsl_selftest_failed: ...` instead of failing each compile. Read `checks` and the canary `compile_log` before touching harnesses: a failing canary is a toolchain problem, not a target problem.

---

## Step 2 — Fuzz Every Module with Make (no subagents)

Campaigns need no judgment, so they run from the generated Makefile, not from one LLM subagent per module. Make admits each campaign by CPU and memory and gives it as many LibFuzzer workers as the measured budget allows (`docs/resources-and-caching.md`). The wrapper commands below are the same on POSIX (`framac-docker.sh`). `S=/opt/framac-pipeline/scripts`.

1. Generate the Makefile once, in the foreground: `python3 /opt/framac-pipeline/scripts/pipeline_make.py gen`. Its JSON lists the runnable modules and any module excluded with a reason (no harness sidecar, or a flag outside the allowlist).
2. Compile every module: `python3 /opt/framac-pipeline/scripts/pipeline_make.py run build`. Builds are cached by content, so repeating this after a harness repair rebuilds only what changed. Write this command exactly as shown, with the full path: only this exact command line may also fill the shared cross-run cache (`docs/resources-and-caching.md`, Section 5).
3. Fuzz every module: `python3 /opt/framac-pipeline/scripts/pipeline_make.py run fuzz` (run in the foreground and wait for completion, or concurrently in the background alongside `/framac-eva` if your host harness supports background wrapper calls).
4. Tune per module only where needed, then re-run the target. Options: dictionaries, budgets, `--fuzz-max-time`. When no `--dict` / `--fuzz-dict` is configured (unless `--no-auto-dict` is passed), `run_eacsl_fuzz.py campaign` automatically invokes `scripts/fuzz_dictionary.py` to extract string literals, hex constants, and comparison magic numbers from the module's sources into `workspace/dicts/<mod>.dict`. You can also generate or inspect a dictionary standalone with `python3 /opt/framac-pipeline/scripts/fuzz_dictionary.py --sources <files...> --out workspace/dicts/<mod>.dict`.
   ```text
   python3 /opt/framac-pipeline/scripts/pipeline_make.py params set --module <mod> --fuzz-dict <file> --fuzz-budget <cpu-seconds>
   ```

Each campaign writes only its own module's corpus, crash directory, and report (`workspace/reports/fuzz/<mod>.json`). The fuzz budget is CPU-seconds per module from the profile (quick 60, standard 120, deep 900). Wall time = budget / workers, at least 30 s, so a larger node finishes sooner at equal or greater effort. `-rss_limit_mb` stays fixed at 2048 on every machine, so `oom_found` means the same thing everywhere.

For a single module in guidance mode, the underlying command is:

```text
python3 /opt/framac-pipeline/scripts/run_eacsl_fuzz.py campaign --module <mod> --sources <sidecar sources> workspace/harnesses/harness_<mod>.c --out-bin workspace/harnesses/fuzz_<mod> --corpus-dir workspace/corpus/<mod> --artifacts-dir workspace/crashes/<mod> --workers auto --fuzz-budget <cpu-seconds> --engine auto --cppflags='<sidecar cppflags> -I/opt/framac-pipeline/templates/acsl' --out-json workspace/reports/fuzz/<mod>.json
```

`run_eacsl_fuzz.py` supports `--engine {auto,eacsl,sanitizers}` (default `auto` in `campaign` mode):
- **Two-stage E-ACSL build.** Stage 1 instruments only (`e-acsl-gcc -n -F <frama-c flags> -E <frontend>`). It receives all preprocessor flags (`-I`, `-D`, `-include`), the `fc_stubs` directory first, `fc_compat_types.h` and `-D__FRAMAC_EACSL__`. Without `-n`, `e-acsl-gcc` also links the original main-less harness and fails. Stage 2 compiles the self-contained `<out-bin>.instrumented.c` with `e-acsl-gcc -C -e <codegen flags only>`.
- **Runtime initialization.** Harnesses have no `main()`, so the build uses `-e-acsl-full-mtracking` and links `templates/eacsl_runtime/fuzz_init.c`. Its `LLVMFuzzerInitialize` initializes the E-ACSL runtime the way an instrumented `main()` would. Without full tracking, valid writes to a caller's stack buffer fail `\valid`; without the hook, every input crashes in `shadow_alloca`. A harness must therefore not define its own `LLVMFuzzerInitialize` (`reason: eacsl_init_hook_conflict`). Never force-include headers into stage 2 (it redefines `timeval`, `fd_set`, ...), so boundary stub headers do not need E-ACSL-specific branches. The full transcript is in `<out-bin>.compile.log`.
- **Initialization checks.** Stage 1 adds `-rte-initialized @all`, so every read of a local or pointed-to value must be initialized. libFuzzer writes the input buffer outside instrumented code, so target code must never read `data` directly: generated harnesses copy it into their own buffer (`fuzz_buf`) first. Reads of memory filled by other uninstrumented code, such as external libraries behind `fc_stubs` or `read`/`recv`, can raise false `initialization` alarms. Measured on one harness, the checks roughly halve throughput (3.3k vs 7.5k exec/s). `--no-rte-initialized` (campaign and guardrail) turns them off. That opt-out is recorded in `reduced_checks` and in the ledger's evidence note, and Eva still reports uninitialized reads statically.
- **Argv contract.** `e-acsl-gcc` splits flag values on spaces and re-parses standalone short options (a bare `-g` becomes `--gmp`). The script joins `-I dir` into `-Idir`, rewrites `-g` to `-gline-tables-only`, and refuses other standalone single-letter tokens or paths containing spaces (`reason: eacsl_argv_unsafe`).
- **Instrumented binary only.** The fuzzed binary is `<out-bin>.e-acsl`, and it must contain E-ACSL instrumentation (`reason: eacsl_binary_not_instrumented` otherwise). The guardrail refuses uninstrumented binaries instead of reporting a vacuous `passed_dynamic_oracle`.
- **Function scoping.** `-rte-select` / `-e-acsl-functions` come from the preprocessed slice sources, so functions disabled by `#if` are excluded. Functions Frama-C still reports as unknown are dropped once and listed in `rte_select_dropped`.
- **Variadic fallbacks.** Undefined `<fn>_fallback_<N>` symbols are defined in a generated, link-only `<out-bin>_fallbacks/eacsl_fallbacks.o`, which forwards to the real libc function when possible. `variadic_fallbacks` lists each one; `mode: enosys` entries always fail with `ENOSYS`, which is a coverage caveat for the code behind them. `--no-variadic-translation` asks Frama-C not to emit them at all.
- **Sanitizer fallback.** With `--engine auto`, an E-ACSL failure (or a failed selftest) falls back to Clang LibFuzzer + ASan + UBSan (`-fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all`). The report then has `engine_used: sanitizers` and `engine_fallback_reason`, and ledger evidence notes that no E-ACSL contract checks or intra-object bounds checks ran.
- **Crash attribution.** When an E-ACSL crash has no usable location (for example the RTL crashed in `unsafe_initialize`), the input is replayed on a sanitizer build of the same slice. The artifact then has `attribution` and `failure_source: sanitizer_replay`. Disable with `--no-attribution-replay`.
- Phase 3 `/framac-wp` `guardrail` mode always uses E-ACSL (`compile_eacsl_binary`), because its purpose is to execute candidate ACSL annotations against the corpus.
- `compile.undeclared_functions` lists functions called without a prototype. Add them to the matching `templates/fc_stubs/` header (see `templates/fc_stubs/README.md`).

The fuzzer, and every crash replay, runs inside the hardened container through `sandbox_exec.py` (rlimits, env allowlist, timeout with process-group kill). There is no filesystem isolation inside the container. If the report says `sandbox_unavailable`, the command was not run inside the container (non-POSIX host); stop and rerun it through the wrapper rather than running it unsandboxed.

*(Never pass `-fsanitize=address` alongside E-ACSL's memory tracking runtime in the same binary, as both intercept `malloc`/`free` and map conflicting shadow memory.)*

For E-ACSL behaviour not covered here, start with [`docs/references/e-acsl-quickref.md`](../../docs/references/e-acsl-quickref.md), which covers `e-acsl-gcc` and `-e-acsl-*` options, runtime output and limitations. Then grep the E-ACSL plug-in manual (Frama-C 33.0) in [`docs/references/`](../../docs/references/README.md). The manual's examples mix old and new option spellings, so check any flag against `e-acsl-gcc -h` in the container.

---

## Step 3 — Read Outcomes and Ingest

`workspace/reports/fuzz/<mod>.json` has one of these statuses:

| Status | Meaning |
| :--- | :--- |
| `crash_found` | At least one `crash-*` artifact. Each artifact was replayed once (`reproducible`), its E-ACSL failure parsed (`failure`: file, line, function, kind, predicate), and fingerprinted. |
| `timeout_found` / `oom_found` | Per-input timeout or RSS limit hit. A termination/DoS lead, not a memory-safety bug. |
| `clean` | No failure within the time budget. The corpus in `workspace/corpus/<mod>/` becomes the dynamic anti-hallucination corpus for `/framac-wp`. Fuzzing is not proof. |
| `fuzzer_error` / `compile_error` / `sandbox_unavailable` | The campaign did not run to completion. Never read this as clean. |
| `not_run` | No report was produced for an expected module (the job was killed or excluded). Written by `ingest` so the gap is recorded, never silent. |

Then ingest (parent only), after both fuzz and Eva have finished:

```text
python3 /opt/framac-pipeline/scripts/pipeline_make.py run ingest
```

`ingest` ingests only reports it has not seen before, matched by content digest. Fuzz reports go before Eva reports. Every expected module gets a report, or a `not_run` record. Then it runs `validate_artifacts.py run-dir .`.

Each fingerprint becomes one entry in `candidates.json` (several crash inputs with the same failing predicate collapse into one candidate), and the matching ledger units become `candidate` (including any `deferred` Tier 3 helper functions reached via cross-module calls), which excludes them from WP. A crash is a candidate until a verifier confirms that the fault is in target code and that the harness respected the entry function's contract.

To scaffold a schema-valid `crash_verifier` JSON record for any candidate in `candidates.json` (pre-populating `sha256`, `size_bytes`, `linked_units`, and `refingerprint_reason`), run:

```text
python3 /opt/framac-pipeline/scripts/ledger.py scaffold-verifier --fingerprint <fp> --decision confirmed --agent-id verifier-1 --out agents/verifier-1/scratch/result.json
```

At the end of a `quick` or profile-bounded run where Phase 3 WP is not scheduled for remaining `planned` units, close remaining open units cleanly before marking the run `complete`:

```text
python3 /opt/framac-pipeline/scripts/ledger.py close-remaining --reason "quick_profile_wp_not_scheduled: Phase 3 WP not run in quick profile"
```
