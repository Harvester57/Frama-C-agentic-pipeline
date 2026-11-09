---
name: framac-fuzz
description: >-
  Phase 1 of the Frama-C verification pipeline. Runs zero-ACSL dynamic bug
  hunting per module slice by generating RTE assertions (-rte -rte-initialized),
  compiling them with E-ACSL into runtime shadow-memory and arithmetic checks,
  and fuzzing the resulting binary with Clang LibFuzzer inside the hardened
  analysis container under sandbox_exec.py (rlimits, env allowlist,
  timeout), starting from seeds recorded from the target's own tests and from
  the fuzz corpora the target ships. Catches
  intra-struct sub-object overflows, use-after-free, uninitialized reads,
  signed overflows, and ACSL contract violations. Measures per-function
  coverage and reopens the reach gate for API entry points no input executed.
  Crashes become fingerprinted candidates, not findings, until independently
  verified.
argument-hint: "<target-dir> --run-dir <dir> [--module <name>] [--time <seconds> (params set --fuzz-max-time)] [--dict <file> (params set --fuzz-dict)]"
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

Campaigns run per **harness module**: a link unit, or a sub-module of one (`unit` in `harness_<mod>.json`). Each one's reports, corpus and crashes stay under its own name and credit its unit's functions. Select all harness modules whose tier has `run_eacsl_fuzz: true` (or the specific `--module <name>` passed by the user). `pipeline_make.py gen` lists them; under `quick`, Tier 3 modules are excluded with a reason.

Everything below runs in the analysis image (the wrapper's default). The target's headers and libraries come from the run's snapshot (`workspace/snapshot/`, written by the build capture): builds add `-idirafter` for its headers and link its libraries with an RPATH, so fuzz, replay and coverage binaries run without the target's packages and without `LD_LIBRARY_PATH`. Never pass `-TargetPackages` here.

---

## Step 1b — Verify the E-ACSL Toolchain (once per image / Frama-C version)

The `selftest` Make target (a prerequisite of `fuzz`) runs it; for a one-off check:

```powershell
# Windows (PowerShell)
& ".\wrappers\framac-docker.ps1" `
  -TargetDir "<target-dir>" -RunDir "<run-dir>" `
  "python3 /opt/framac-pipeline/scripts/run_eacsl_fuzz.py selftest"
```

```bash
# Linux / macOS (POSIX)
./wrappers/framac-docker.sh \
  --target "<target-dir>" --run-dir "<run-dir>" \
  -- "python3 /opt/framac-pipeline/scripts/run_eacsl_fuzz.py selftest"
```

`selftest` builds `templates/eacsl_canary/canary.c` through the exact production E-ACSL path and writes `workspace/reports/eacsl_selftest.json`. Its checks are `compiled`, `no_gmp_only`, `instrumented_binary`, `benign_input_clean`, `detects_overflow`, `detects_uninitialized`, and `attributes_line` (the last one is informational). `benign_input_clean` matters because a replay counts any non-zero exit as a reproduction: a binary that fails on every input (uninitialized runtime, false `\valid` alarms) would otherwise pass `detects_overflow`. If it fails, `campaign --engine auto` skips E-ACSL for every module with `engine_fallback_reason: eacsl_selftest_failed: ...` instead of failing each compile. Read `checks` and the canary `compile_log` before touching harnesses: a failing canary is a toolchain problem, not a target problem.

---

## Step 2 — Fuzz Every Module with Make (no subagents)

Campaigns need no judgment, so they run from the generated Makefile, not from one LLM subagent per module. Make admits each campaign by CPU and memory and gives it as many LibFuzzer workers as the measured budget allows (`docs/resources-and-caching.md`). The wrapper commands below are the same on POSIX (`framac-docker.sh`). `S=/opt/framac-pipeline/scripts`.

1. Generate the Makefile once, in the foreground: `python3 /opt/framac-pipeline/scripts/pipeline_make.py gen`. Its JSON lists the runnable modules and any module excluded with a reason (no harness sidecar, or a flag outside the allowlist).
2. Compile every module: `python3 /opt/framac-pipeline/scripts/pipeline_make.py run build`. Builds are cached by content, so repeating this after a harness repair rebuilds only what changed. Write this command exactly as shown, with the full path: only this exact command line may also fill the shared cross-run cache (`docs/resources-and-caching.md`, Section 5).
3. Fuzz every module: `python3 /opt/framac-pipeline/scripts/pipeline_make.py run fuzz` (run in the foreground and wait for completion, or concurrently in the background alongside `/framac-eva` if your host harness supports background wrapper calls).
4. Measure what each corpus reached: `python3 /opt/framac-pipeline/scripts/pipeline_make.py run coverage`, then check it against the harness API: `python3 /opt/framac-pipeline/scripts/pipeline_make.py run reach-dynamic` (see Step 3).
5. Tune per module only where needed, then re-run the target. Options: dictionaries, budgets, `--fuzz-max-time`. When no `--dict` / `--fuzz-dict` is configured (and `--no-auto-dict` is not passed), `run_eacsl_fuzz.py campaign` runs `scripts/fuzz_dictionary.py` in-process on the module's target sources (the harness excluded): it writes their string literals plus fixed 8/16/32/64-bit boundary tokens (decimal, hex and byte forms) to `workspace/dicts/<mod>.dict` and passes it to LibFuzzer as `-dict=`. The report's `dictionary` field records `{path, auto, entries}`; when extraction finds no readable source or fails, the campaign runs without a dictionary and `dictionary.reason` says why. You can also generate or inspect a dictionary standalone with `python3 /opt/framac-pipeline/scripts/fuzz_dictionary.py --sources <files...> --out-dict workspace/dicts/<mod>.dict`.
   ```text
   python3 /opt/framac-pipeline/scripts/pipeline_make.py params set --module <mod> --fuzz-dict <file> --fuzz-budget <cpu-seconds>
   ```
   With the module's flags (`--cppflags`, as `make` passes them), the auto dictionary also holds the values of the object-like macros the project defines, read from `cc -E -dD` on the preprocessed sources: integers as decimal text and little- and big-endian bytes, strings as their content. Macros of system headers, the compiler and Frama-C are left out.

Each campaign writes only its own module's corpus, crash directory, and report (`workspace/reports/fuzz/<mod>.json`). The fuzz budget is CPU-seconds per harness case from the profile (quick 60, standard 120, deep 900): a dispatch harness with N cases gets N shares, any other harness one. The campaigns of one link unit together get at most 480 / 1200 / 7200 CPU-seconds (quick / standard / deep); above that each is scaled down in proportion, never below 30. `gen` records `fuzz_cases` and `fuzz_budget_source` (`cases`, `unit_cap`, or `params` when `params set --fuzz-budget` fixed it).

Wall time = budget / workers, at least 30 s, so a larger node finishes sooner at equal or greater effort. `-rss_limit_mb` stays fixed at 2048 on every machine, so `oom_found` means the same thing everywhere.

**Seeds from the tests.** Phase 0 records the API calls the target's tests make (`/framac-slice` Step 1e: `seed_harvest.py record`, build image, scratch volume; without a test command, the project's non-test executables run once with no arguments instead):
- each test executable is relinked with `-Wl,--wrap` recorders for the model's API functions and run in the sandbox (no network, capped time) under `strace`;
- the arguments of each outermost API call (buffers with their length, strings, scalars, pointees, `{ptr, len}` struct members) go to `workspace/seed_records/calls.jsonl`, with up to 64 small data files the tests opened.

Before each campaign, `seed_harvest.py write --module <mod>` turns them into `workspace/seeds/<mod>/seed-*` in the harness's own case format, read from `harness_<mod>.c`: the dispatch selector byte, the fixed-size slots in order, then the data. Data files become whole-input seeds for the cases that take the whole buffer. `workspace/reports/seeds/<mod>.json` says what each case got. The `seeds` Make target writes them for every module.

The campaign and `coverage` read the seeds as a read-only extra corpus (`--extra-corpus`). No test command and no executable that calls the API, a failing test suite, or no recorded call just means fewer or no seeds, never an error. Calls made through header `static inline` functions are not recorded, so their harness cases start from an empty corpus.

**The target's own corpus.** Phase 0 imports the fuzz corpora the target ships (`/framac-slice` Step 1f). Before each campaign, `fuzz_assets.py write --module <mod>` writes them to `workspace/imported_corpus/<mod>/imp-*`:
- a target fuzz module (`tf_<id>`, sidecar `target_fuzzer`) gets the corpora mapped to its fuzzer as they are: they are that fuzzer's own input format;
- any other module gets each mapped corpus in the cases that take the whole buffer and call one of the corpus's functions (its mapped `--function`s, or its fuzzer's `direct_api_calls`), with the dispatch selector byte in front;
- inputs longer than the module's `max_input_size` are dropped and counted, and a module gets at most 20,000 inputs.

`workspace/reports/imported_corpus/<mod>.json` says what each case got. The campaign and `coverage` read the folder as a second read-only extra corpus. When the fuzzer ships a dictionary, its valid entries go to `workspace/dicts/<mod>.extra.dict` and are appended to the auto dictionary (the report's `dictionary.extra_entries`); an explicit `--dict` is used alone. Imported inputs are named `imp-`, not `seed-`, so guardrails do not replay them all.

A campaign keeps going after a crash, so one shallow bug does not hide the others in its module:
- **Dispatch harnesses** run in rounds. Each case an input crashed (or timed out) in (the input's first byte modulo the case count) is skipped from the next round on. The skip uses a rebuild with the same engine and the mask in 64-bit words: `-DFRAMAC_FUZZ_SKIP_CASES=<mask>` for cases 0..63 and `-DFRAMAC_FUZZ_SKIP_CASES_<k>=<mask>` for cases 64k..64k+63, so every case of a dispatch harness (up to 255) can be skipped. Rounds share the campaign's wall time and end when a round finds no new crashing case, every case is skipped, less than 5 s are left (`MIN_ROUND_WALL_S`; the first round gets at least 30 s), or a rebuild fails. A skipped case is not fuzzed for the rest of the campaign, so a second bug in the same case can still be hidden; the report's `keep_going.rounds` lists what each round skipped and found.
- **Cases that cannot be skipped.** A dispatch harness generated before every case became skippable (its guard lacks the `every dispatch case skippable` marker) can skip cases 0..63 only. When a round's only new crashing cases cannot be skipped, the round records `stopped: "unskippable_case"` with `unskippable_cases`; after that, or after `rebuild_failed`, the time left runs in fork mode with `-ignore_crashes=1` on the last binary (`keep_going.fork_fallback`). Regenerate such a harness to get rounds for every case.
- **Other harnesses** (and dispatch harnesses generated before the skip macro existed) run in libFuzzer fork mode with `-ignore_crashes=1` (`keep_going.mode: fork`). The same bug is then saved many times: at most 64 crash inputs are replayed, and at most 3 artifacts are listed per fingerprint (`artifacts_omitted` counts the rest).
- `--stop-on-first-crash` restores the old behavior: one campaign that ends at the first crash.

For a single module in guidance mode, check the module's Phase 0 gate first, then run the underlying command:

```text
python3 /opt/framac-pipeline/scripts/phase0_gates.py check --module <mod> --need reach,build_check
python3 /opt/framac-pipeline/scripts/seed_harvest.py write --module <mod>
python3 /opt/framac-pipeline/scripts/fuzz_assets.py write --module <mod>
python3 /opt/framac-pipeline/scripts/run_eacsl_fuzz.py campaign --module <mod> --sources <sidecar sources> workspace/harnesses/harness_<mod>.c --out-bin workspace/harnesses/fuzz_<mod> --corpus-dir workspace/corpus/<mod> --artifacts-dir workspace/crashes/<mod> --extra-corpus workspace/seeds/<mod> workspace/imported_corpus/<mod> --workers auto --fuzz-budget <cpu-seconds> --engine auto --cppflags='<sidecar cppflags> -I/opt/framac-pipeline/templates/acsl' --out-json workspace/reports/fuzz/<mod>.json
```

The gate check exits 1 with the reasons when the module failed the reach gate or build-check, or its harness or the DAG changed since the reach check: repair the harness and re-run the gate (`/framac-slice` Steps 4b and 5); never fuzz around it. `campaign --module <mod>` enforces the same check itself whenever the run directory has a gate stamp (`workspace/reports/phase0_gates.json`): it refuses the module with the reasons and writes no report. A campaign outside a run directory is not gated.

`run_eacsl_fuzz.py` supports `--engine {auto,eacsl,sanitizers}` (default `auto` in `campaign` mode):
- **Two-stage E-ACSL build.** Stage 1 instruments only (`e-acsl-gcc -n -F <frama-c flags> -E <frontend>`). It receives all preprocessor flags (`-I`, `-D`, `-include`), the `fc_stubs` directory first, `fc_compat_types.h`, `-D__FRAMAC_EACSL__`, and for glibc's floating-point classification macros (`isnan`, `isinf`, `fpclassify`, `signbit`, ...) `-D__SUPPORT_SNAN__` with the `fc_stubs/eacsl` `math.h` shim, since Frama-C knows neither the `__builtin_*` forms nor glibc's `_Generic` dispatch. Without `-n`, `e-acsl-gcc` also links the original main-less harness and fails. Stage 2 compiles the self-contained `<out-bin>.instrumented.c` with `e-acsl-gcc -C -e <codegen flags only>`.
- **Runtime initialization.** Harnesses have no `main()`, so the build uses `-e-acsl-full-mtracking` and links `templates/eacsl_runtime/fuzz_init.c`. Its `LLVMFuzzerInitialize` initializes the E-ACSL runtime the way an instrumented `main()` would. Without full tracking, valid writes to a caller's stack buffer fail `\valid`; without the hook, every input crashes in `shadow_alloca`. A harness must therefore not define its own `LLVMFuzzerInitialize` (`reason: eacsl_init_hook_conflict`). Never force-include headers into stage 2 (it redefines `timeval`, `fd_set`, ...), so boundary stub headers do not need E-ACSL-specific branches. The full transcript is in `<out-bin>.compile.log`.
- **Initialization checks.** Stage 1 adds `-rte-initialized @all`, so every read of a local or pointed-to value must be initialized. libFuzzer writes the input buffer outside instrumented code, so target code must never read `data` directly: generated harnesses copy it into their own buffer (`fuzz_buf`) first. Reads of memory filled by other uninstrumented code, such as external libraries behind `fc_stubs` or `read`/`recv`, can raise false `initialization` alarms. Measured on one harness, the checks roughly halve throughput (3.3k vs 7.5k exec/s). `--no-rte-initialized` (campaign and guardrail) turns them off; in a run, set it per module with `pipeline_make.py params set --module <mod> --no-fuzz-rte-initialized`. That opt-out is recorded in `reduced_checks` and in the ledger's evidence note, and Eva still reports uninitialized reads statically. E-ACSL registers formal parameters without marking them initialized, so the build marks each one initialized at function entry (`compile.formal_inits`); otherwise the first read of a by-value struct field would fail `\initialized` on every call. The cost: E-ACSL does not report uninitialized struct members passed by value. An `initialization` alarm on a formal (`\initialized(&s.len)` at a function's first statement) means the build skipped that step: rebuild, do not opt out.
- **Argv contract.** `e-acsl-gcc` splits flag values on spaces and re-parses standalone short options (a bare `-g` becomes `--gmp`). The script joins `-I dir` into `-Idir`, rewrites `-g` to `-gline-tables-only`, and refuses other standalone single-letter tokens or paths containing spaces (`reason: eacsl_argv_unsafe`).
- **Instrumented binary only.** The fuzzed binary is `<out-bin>.e-acsl`, and it must contain E-ACSL instrumentation (`reason: eacsl_binary_not_instrumented` otherwise). The guardrail refuses uninstrumented binaries instead of reporting a vacuous `passed_dynamic_oracle`.
- **Function scoping.** `-rte-select` / `-e-acsl-functions` come from the preprocessed slice sources, so functions disabled by `#if` are excluded. Functions Frama-C still reports as unknown are dropped once and listed in `rte_select_dropped`.
- **Variadic fallbacks.** Undefined `<fn>_fallback_<N>` symbols are defined in a generated, link-only `<out-bin>_fallbacks/eacsl_fallbacks.o`, which forwards to the real libc function when possible. `variadic_fallbacks` lists each one; `mode: enosys` entries always fail with `ENOSYS`, which is a coverage caveat for the code behind them. `--no-variadic-translation` asks Frama-C not to emit them at all.
- **Sanitizer fallback.** With `--engine auto`, an E-ACSL failure (or a failed selftest) falls back to Clang LibFuzzer + ASan + UBSan (`-fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all`). The report then has `engine_used: sanitizers` and `engine_fallback_reason`, and ledger evidence notes that no E-ACSL contract checks or intra-object bounds checks ran.
- **Both engines.** With `--engine auto` and a working E-ACSL build, the campaign fuzzes twice, half the wall time each: ASan+UBSan first, then E-ACSL on the grown shared corpus. The engines catch different bugs: ASan intercepts libc calls (an overlapping `memcpy`, for example), which E-ACSL does not check, while E-ACSL checks initialization, intra-object bounds and contracts. On libmnl, ASan alone found 4 of 5 known bugs and E-ACSL alone 2. The report has `engine_used: eacsl+sanitizers`, each engine's own outcome under `engines`, and an `engine` on every artifact; candidate replay uses that engine. `--engine eacsl` or `--engine sanitizers` (`params set --fuzz-engine`) fuzzes with one engine only. A module whose unit E-ACSL cannot build fuzzes with the sanitizers only, by the DAG's choice (`fuzz_engine_reason`): a unit on the GCC fallback, or one that includes `setjmp.h` or calls setjmp/longjmp. If the sanitizer build fails, the campaign fuzzes with E-ACSL only and records `dual_engine_skipped`.
- **Link repair.** When the link stops on `undefined reference to 'X'`, the build adds the source defining `X` and links again. That source comes from the DAG's functions, else from its `build_only_functions`: code the compiler builds and Frama-C's parse lacks, such as libpng's `png_target_init` under `__SSE2__`. The report records the repair under `link_repair`.
- **Crash attribution.** When an E-ACSL crash has no usable location (for example the RTL crashed in `unsafe_initialize`), the input is replayed on a sanitizer build of the same slice. The artifact then has `attribution` and `failure_source: sanitizer_replay`. Disable with `--no-attribution-replay`.
- Phase 3 `/framac-wp` `guardrail` mode always uses E-ACSL (`compile_eacsl_binary`), because its purpose is to execute candidate ACSL annotations against the corpus.
- `compile.undeclared_functions` lists functions called without a prototype. Add them to the matching `templates/fc_stubs/` header (see `templates/fc_stubs/README.md`).

The fuzzer, and every crash replay, runs inside the hardened container through `sandbox_exec.py` (rlimits, env allowlist, timeout with process-group kill). There is no filesystem isolation inside the container. If the report says `sandbox_unavailable`, the command was not run inside the container (non-POSIX host); stop and rerun it through the wrapper rather than running it unsandboxed.

*(Never pass `-fsanitize=address` alongside E-ACSL's memory tracking runtime in the same binary, as both intercept `malloc`/`free` and map conflicting shadow memory.)*

For E-ACSL behaviour not covered here, start with `docs/references/e-acsl-quickref.md`, which covers `e-acsl-gcc` and `-e-acsl-*` options, runtime output and limitations. Then grep the E-ACSL plug-in manual (Frama-C 33.0) in `docs/references/` (see `docs/references/README.md`). The manual's examples mix old and new option spellings, so check any flag against `e-acsl-gcc -h` in the container.

---

## Step 3 — Read Outcomes and Ingest

`workspace/reports/fuzz/<mod>.json` has one of these statuses:

| Status | Meaning |
| :--- | :--- |
| `crash_found` | At least one `crash-*` artifact in any round. Each listed artifact was replayed once (`reproducible`), its E-ACSL failure parsed (`failure`: file, line, function, kind, predicate), and fingerprinted. |
| `timeout_found` / `oom_found` | Per-input timeout or RSS limit hit. A termination/DoS lead, not a memory-safety bug. |
| `clean` | No failure within the time budget. The corpus in `workspace/corpus/<mod>/` becomes the dynamic anti-hallucination corpus for `/framac-wp`. Fuzzing is not proof. |
| `fuzzer_error` / `compile_error` / `sandbox_unavailable` | The campaign did not run to completion. Never read this as clean. |
| `insufficient_memory` | The job's memory lease is below what LibFuzzer needs at the fixed `-rss_limit_mb` (the report's `error_summary` gives both numbers). Nothing ran; never read this as clean. Give the container engine more memory, or lower the pool's concurrency. |
| `not_run` | No report was produced for an expected module (the job was killed or excluded). Written by `ingest` so the gap is recorded, never silent. |

`workspace/reports/coverage/<mod>.json` says which of the target's functions and code regions the corpus executes, measured by replaying `workspace/corpus/<mod>/` on a plain Clang source-coverage build (`run_eacsl_fuzz.py coverage`, no E-ACSL and no sanitizers). `functions[]` has `executions`, `regions` and, for a function that ran, `uncovered_lines`. `make` replays the corpus as it stands, so run `coverage` again after a corpus changes.

| Status | Meaning |
| :--- | :--- |
| `ok` | Every input replayed. |
| `partial` | Some inputs failed or were not replayed (`failed_inputs`, `inputs`), so the counts are lower bounds. A failing input is a lead to replay on the fuzz binary, not a candidate. Failures no longer stop the replay: only the time budget does (`inputs.not_replayed`). `failed_inputs` details the first 16 failures, `failed_inputs_unlisted` counts the rest, and inputs matching a crash artifact of the module replay last (`inputs.known_crash`). |
| `no_inputs` / `compile_error` / `coverage_error` / `sandbox_unavailable` | Nothing was measured. Never read this as no reach. |

When llvm-cov rejects the build with "truncated coverage data" (LLVM 19 writes an unreadable mapping when a header is included inside a function body), `coverage` rebuilds once with those headers included first and lists them in `pre_included`.

`reach-dynamic-<mod>` (after `coverage-<mod>`) is the dynamic half of the reach gate: an entry point the gate holds the module to, and that its corpus never executed, fails the module in `phase0_gates.json` (`dynamic: entry points never executed by the corpus`; rows in `workspace/reports/harness_reach_dynamic.json`). Fuzz and Eva of that module then stop at the gate, and `reach-gate` keeps the gap while the harness is the one coverage measured. Repair the harness (its digest changes), or exempt the entry point with `harness_reach.py exempt --module <mod> --function <fn> --reason <why>`, naming it by its DAG key (`file#name` when the name collides) or by its plain name when no other DAG function has it; the static and the dynamic gate match it the same way. Either way, re-run the reach gate (`pipeline_make.py run reach-gate`) before the module's targets: they refuse a harness whose digest changed since the gate ran. A whole-run `reach-gate` exits 1 while another module still has a gap, but it records this module's row.

Gaps are only trusted on a complete replay. A `partial` report with `inputs.not_replayed > 0` is treated as unmeasured (`partial coverage: N of M inputs not replayed`): the printed row keeps `executions` and lists its gaps as `gaps_lower_bound`, but the gate is not reopened. When every input was replayed and only some failed, the measurement counts and the row records `failed_inputs`. A module that moves from a failed dynamic check to passing or unmeasured has the stale `dynamic:` failure lifted from its gate row.

A module whose coverage measured nothing (the statuses above, or no report) gets no row: it is listed with its reason under `unmeasured` in `harness_reach_dynamic.json`, and `reach-dynamic-<mod>` exits 2 without reopening the gate, so its fuzz and Eva go on. Read the reason. When every input crashes, the corpus can never grow (oscs-qlz: a misaligned store at `quicklz.c:161` on every input, the empty one included): the crash is the finding and goes to the Crash Verification Gate. There is nothing to repair in the harness, and the module's reach stays unmeasured; do not exempt its entry points for it.

Exemptions are for entry points that cannot be driven from bytes, not for a corpus that did not get deep enough:
- **Valid reasons:** the function needs a live kernel socket or a real file descriptor; it reads a process-global the harness cannot set up safely; it is a callback only the platform calls.
- **Not reasons:** "30 s of fuzzing did not reach it"; "behind a parser check"; "reached only through `parse_x509_cert`". Those are reach gaps to work on, in this order: recorded seeds (`/framac-slice` Step 1e), the target's own corpus mapped to the function (`/framac-slice` Step 1f), a dictionary (`params set --fuzz-dict`), a larger budget (`--fuzz-budget`), then a dispatch case that calls the function directly with fixed-size slots. Exempt only what still cannot be driven, and say what you tried in the reason.
- **Not a repair:** a case that calls the function with constant arguments only to tick the gate. The gate then passes, but fuzzing exercises nothing.

Read `executions: 0` before tuning. The harness may simply not call that function, which a better dictionary or budget cannot fix: repair the harness instead. If the harness does call it, the corpus is stuck behind an input check, and `uncovered_lines` on the callers shows where. This report is reach only: it is not proof, the ledger does not read it, and a reached function is not a safe one.

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
