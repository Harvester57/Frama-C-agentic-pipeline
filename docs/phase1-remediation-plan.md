# Phase 1 remediation plan

This plan turns the open items of [`phase1-review.md`](phase1-review.md) into steps:
- the 17 defects F1–F17 (F4 is already fixed in `684052f`);
- the decided design questions D1 and D3, and D2, decided here;
- the question D4, which stays open until the work it depends on has landed.

The work lives on branch `phase1-remediation`, cut from `main` at `edcbf50`.

Locations were re-checked on `main` at `edcbf50`. Since the review's base `60107a9`, the Phase 0 remediation (R1–R10) and the fixes found by validation V (`bd3f909`) changed some of the code the review cites. Every defect below still holds on `edcbf50`, with these changes:
- **F6:** a round after a crash now runs down to `MIN_ROUND_WALL_S` (5 s) instead of 30 s. The rounds still depend on wall time.
- **F11:** `campaign --module` and `run_eva_slice.py` now refuse a gated module when the run directory has a gate stamp (R1, R6). That makes F11's consequence worse: a module that fails the dynamic gate cannot be re-fuzzed, which is the very thing that could close its gap. S5 fixes this.
- **F2:** `harness_reach.py dynamic` now records a module it could not measure under `unmeasured` (oscs-qlz: every input crashes, so the corpus is empty), instead of dropping it.
- **F15:** `build-%` has a gate check, and a comment that makes not depending on `selftest` deliberate. The build still reads the selftest result.

Line numbers drift: search for the named function.

## Decisions (2026-11-08)

| # | Question | Options | Decision |
| :--- | :--- | :--- | :--- |
| D1 | What identity a sanitizer crash gets. | See the review: A, B, C, D. | **A first, then D** (user). Per-engine fingerprints that are stable, then candidates grouped by statement site. |
| D1a | Where the site comes from. | (a) Normalized text of the faulting source line; (b) line to statement through a kernel AST dump. | **(a)** (planning). Neither `kernel_ast_dump.ml` nor `phase0_dump.ml` records statement locations, and every producer (E-ACSL, ASan, UBSan, Eva) reports `file:line`. An occurrence index separates identical lines in one function. Revisit only if V shows lines with two statements merging distinct bugs. |
| D1b | One bug seen at two statements (LIBMNL-04: E-ACSL at `nlmsg.c:311`, ASan at `:339`). | (a) Link the candidates through a cross-engine replay; (b) leave them as two. | **(a)** (user). |
| D1c | Phase 3's merge of hypotheses (`_find_matching_sink_candidate`, function + kind). | (a) The site key when the hypothesis has a line, function + kind otherwise; (b) keep function + kind. | **(a)** (planning). One merge rule for every producer; function + kind stays only where there is no line to key on. |
| D2 | What a module that fails the dynamic reach gate gets. | (a) Its units leave the WP queue with a recorded reason, and the run goes on; (b) a re-fuzz before re-checking; (c) the whole-run stop of today. | **(a)** (user). A re-fuzz stays a manual follow-up. A dynamic gap no longer stops fuzz, coverage or Eva of the module, since those are what can close it. |
| D3 | `run_eacsl_fuzz.py` does too much. | See the review: A, B, C, D. | **B first, then C** (user). |
| D4 | E-ACSL's share of each campaign. | Keep 50/50; shift toward the sanitizers; E-ACSL for replay only. | **Open.** Decided in S10, after F17 is fixed and the seeded benchmark holds bugs only E-ACSL can catch. |
| D5 | Memory leaks (F8). | (a) Out of scope with `-detect_leaks=0`; (b) parse LeakSanitizer reports into candidates. | **(b)** (user). A leak gets the new kind `leak` (CWE-401). It links no proof unit: no obligation class covers leaks, and `l6_no_leak` is about secrets, not memory. It therefore gates no WP task. |
| D6 | How to fix F17 (E-ACSL false alarms on libc out-parameters). | (a) Initialization wrappers; (b) a known-false-alarm list; (c) remembered verifier rejections; combinations. | **(a)** (user). E-ACSL-only wrappers mark the out-parameter initialized after the call. They cover a list derived from the `assigns` clauses of Frama-C's libc. |
| D7 | F3: dispatch harnesses above 64 cases (skip mask) and above 256 (selector). | (a) Change the generated code of every dispatch harness; (b) change it only for harnesses that need it. | **(b)** (planning). The wider skip mask applies above 64 cases and the two-byte selector above 256. Smaller harnesses keep their code, their seeds and their `harness_digest`. |
| D8 | F15: `build-%` reads the selftest result without depending on `selftest`. | (a) Depend on `selftest`; (b) stop reading the selftest result in `build`. | **(b)** (planning), following the deliberate Make comment. `build` compiles what `--engine` asks for (both engines for `auto`), and the campaign applies the selftest. The campaign then reuses the cached builds instead of rebuilding. |
| D9 | F12: `run_sandboxed(writable=...)` is not enforced. | (a) Rename the parameter now, and leave the mount namespace to the backlog; (b) both now. | **(a)** (planning). The namespace needs a check of the hardened container profile first (see Backlog). |
| D10 | When `phase1-remediation` merges to `main`. | (a) Step by step; (b) after the steps and one validation run. | **(b)** (planning, as Phase 0's D1′). One validation (V) covers all the steps, and `main` stays as it is until V passes. |

## Rules for every step

The same rules as the Phase 0 plans:
- **Ownership:** each step owns the files it lists, and parallel steps own disjoint files.
- **Checks:** `ruff`, `ruff format --check`, `mypy scripts tests` and the full pytest suite pass after each step.
- **Docs and skills** change in the same step as the behavior. `skills/` is mirrored into `.claude/skills/`, and this Windows checkout holds those mirrors as plain directories: never commit their "deletion".
- **Pipeline runs:** no step needs one to land, except S0, S10 and V, which the user starts. Unit tests on recorded fixtures cover each item.
- **Fingerprint changes:** a step that changes how a fingerprint is computed recomputes the known-bug fingerprints in `benchmark/manifest.json` and `docs/bugs-found/`, as `684052f` did, and says so in its commit message. Recall matches by file, function, kind and line, so it is unaffected. A compare against an older baseline shows the changed candidates once, as gone and as new.
- **Moves before changes:** a step that moves code (D3) lands the move as its own commit with no behavior change, then the fixes.

## Steps

### S0. Confirming run on libmnl (user-triggered)

- **Goal:** reproduce the defects found by reading the code, before fixing them.
- **Run:** libmnl with the blind protocol of the earlier runs, on `edcbf50`, twice: with `--workers 1` and with the machine's default worker count.
- **Check:**
  - **F2:** a dispatch case that crashes on every input. Does its entry point show as a dynamic gap or as `unmeasured`?
  - **F6:** `keep_going.rounds` and the distinct crashes found, in the two runs.
  - **F10:** do UBSan's `alignment` or `pointer-overflow` checks fire, and on which inputs?
  - **F1:** two distinct ASan overflows merged into one candidate.
- **Record:** `docs/progress/phase1-s0-<date>.md`.
- **Blocks:** S8 only. Every other step lands on unit tests.

### S1. Failure identity module, moved out (D3 step 1) (S)

- **Goal:** failure parsing and fingerprinting have one owner, outside the 4,300-line script.
- **Work** (a pure move first, as its own commit):
  - **New module `scripts/failure_identity.py`.** It gets:
    - the E-ACSL, ASan and UBSan regexes;
    - `parse_eacsl_failure`, `parse_sanitizer_failure`, `parse_runtime_failure` and `needs_attribution`;
    - `_map_sanitizer_alarm_kind`, `stable_ubsan_message`, `_resolve_function_at_line` and their helpers;
    - `_failure_fingerprint`, made public as `failure_fingerprint`.

    `run_eacsl_fuzz.py` re-imports every moved name, so tests and callers keep working.
  - **Dictionary cleanup** (`sanitize_dictionary_*`, `auto_dictionary_path`, `build_auto_dictionary` and related) moves into `fuzz_dictionary.py`, which already builds the dictionaries.
  - **Docstring:** `run_eacsl_fuzz.py`'s module docstring lists all 10 subcommands (minimize, minimize-candidates and minimize-interest are missing).
- **Owns:** `scripts/failure_identity.py` (new), `scripts/fuzz_dictionary.py`, the parsing and dictionary sections and the docstring of `scripts/run_eacsl_fuzz.py`.
- **Tests:** the existing suite unchanged (`test_tool_parsing.py`, `test_fuzz_dictionary.py`, `test_fuzz_subcommands.py`), plus an import test: `run_eacsl_fuzz` still exposes every moved name.
- **Acceptance:** `git diff --stat` shows moves only; the suite passes.

### S2. Stable ASan and LeakSanitizer identity (F1, F8, D5) (M, after S1)

- **Goal:** one ASan or LSan fingerprint per defect: not one per input, and not one per function.
- **Work** (in `failure_identity.py`):
  - **F8, the headline:** capture the whole ASan headline up to ` on ` or the address (`_ASAN_ERR_RE` captures one word). Map `attempting double-free` and `attempting free on address which was not malloc()-ed` to `freeable`; today they become `asan_attempting` / `mem_access`.
  - **F1, the discriminator:** the ASan predicate gains something that survives line shifts, never a line number:
    - the normalized text of the faulting source line (the best frame), read with `_resolve_source_candidates`;
    - when the top frame is an interceptor (`memcpy`, `strlen`, ...), `<interceptor> from <caller>`, plus the caller's line text.
  - **D5, leaks:**
    - parse LeakSanitizer reports (`Direct leak` / `Indirect leak of N byte(s)`) from the first allocation stack frame in target code;
    - kind `leak`, alarm kind `memory_leak`; direct and indirect leaks are separate kinds, since an indirect leak follows from a direct one;
    - a leak whose allocation lies in a test or harness frame is attributed to the first target frame, as other failures are;
    - `ledger.py ingest-fuzz` links no unit for `memory_leak` and notes why;
    - the report gives it CWE-401;
    - leak artifacts no longer become `unknown_function::unparsed_leak` candidates.
  - **Fixture corpus** `tests/fixtures/failures/`: recorded output for:
    - E-ACSL: an assertion, a segment failure, a `-rte-initialized` failure;
    - ASan: heap-, stack- and global-buffer-overflow, two overflows of the same size at two lines of one function, use-after-free, double-free, bad-free, `memcpy-param-overlap` (LIBMNL-01);
    - UBSan: signed overflow, a shift, `abs(INT_MIN)`;
    - LSan: a direct and an indirect leak.

    Take the outputs from the libmnl, minmea and tweetnacl run directories where they exist. Record the rest from small C programs in the analysis image, with a Docker-backed test that re-records them.
  - **Fingerprints:** recompute every ASan-derived fingerprint in the manifest and `docs/bugs-found/` per the rules.
- **Owns:** `scripts/failure_identity.py`, `tests/fixtures/failures/`, the leak branch of `scripts/ledger.py` `cmd_ingest_fuzz`, the CWE map in `scripts/generate_report.py`, `benchmark/manifest.json` and `docs/bugs-found/` (fingerprints only), `skills/framac-wp/crash_verifier_brief.md` (how to verify a leak), `skills/framac-fuzz/SKILL.md` (failure kinds).
- **Tests:**
  - two overflows of the same size in one function give two fingerprints;
  - the same overflow after inserting lines above it keeps its fingerprint;
  - double-free gives `freeable`;
  - each fixture parses to the expected file, function, kind and predicate;
  - a leak gives a `leak` candidate with no linked unit.
- **Acceptance:** replaying any fixture twice gives the same fingerprint; `minimize_interest` accepts a reduction that keeps the same defect.

### S3. Sandbox seam and build module (D3 step 2, items 1–2; F15/D8) (M, after S1)

- **Goal:** code can leave `run_eacsl_fuzz.py` without silently disarming the tests' patches.
- **Work:**
  - **Seam:**
    - every module calls the sandbox as `sandbox_exec.run_sandboxed` (module attribute, looked up at call time), never a name imported with `from sandbox_exec import run_sandboxed`;
    - the tests patch `sandbox_exec.run_sandboxed`;
    - check all 88 `monkeypatch.setattr` calls on the module (34 of them on `run_sandboxed`) against their new targets;
    - add a guard test that fails when a script imports `run_sandboxed` by name.
  - **Build module `scripts/fuzz_build.py`** (move, then fixes):
    - `compile_eacsl_binary`, `_compile_eacsl_binary_uncached`, `_eacsl_cache_material`, `_compile_clang_binary`, `compile_sanitizer_binary` and `compile_coverage_binary`;
    - the link repair (`parse_undefined_references`, `repair_sources_for_link`), `build_module_binary` and `_discover_slice_functions`.

    `run_eacsl_fuzz.py` re-imports them.
  - **F15 (D8):**
    - `build` stops reading the selftest result and compiles what `--engine` asks for (both engines for `auto`);
    - `_run_campaign_mode` applies the selftest and takes the binaries from the build cache instead of rebuilding;
    - `workspace/build/<mod>.build.json` records both builds.
- **Owns:** `scripts/fuzz_build.py` (new), `scripts/sandbox_exec.py` (docstring only), the build section and `_run_build_mode` / `_run_campaign_mode` of `scripts/run_eacsl_fuzz.py`, every test file that patches the moved names, `templates/pipeline.mk` (the `build-%` comment).
- **Tests:**
  - the suite passes with the patches retargeted;
  - the guard test;
  - a campaign after `build` makes no compile call (recorded runner);
  - `build` with a failed selftest still builds what `--engine` names.
- **Acceptance:** every patch in the suite applies to the code that runs (the guard test, and each retargeted test fails when its patch is removed).

### S4. Candidates grouped by site, cross-engine link, crash-replay module (D1 step 2, F5, D1a–D1c; D3 step 2, item 3) (L, after S2 and S3)

- **Goal:** one candidate per site, holding every engine's detection, and one finding for one bug seen at two statements.
- **Work:**
  - **Site key** (`failure_identity.site_key`):
    - `file#function@<hash10 of the normalized line text>`;
    - `#<n>` is appended when the same normalized text occurs more than once in the function, found through the DAG's line ranges (`_dag_line_index`).
  - **Candidates schema** (`schemas/candidates.schema.json`):
    - `site`;
    - `observations`, each with `fingerprint`, `origin`, `engine`, `kind`, `message`, `tool_output` and `reproducer`;
    - `related`, each with `fingerprint` and `reason`.

    The candidate's key and `fingerprint` stay those of its first observation, so existing candidate IDs and the benchmark's lists keep working.
  - **Grouping in `upsert_candidate`** (`ledger.py`), the single entry point of every producer:
    - a new detection whose site matches an unverified candidate becomes an observation of it;
    - the candidate's class comes from E-ACSL or Eva when either has observed it, otherwise from the sanitizer mapping;
    - this applies to fuzz ingest (both engines), Eva ingest, breaker reproductions and prover reports.
  - **Phase 3 merge (D1c):** `_find_matching_sink_candidate` keys on the site when the hypothesis has a line, and keeps function + kind otherwise.
  - **Crash-replay module `scripts/crash_replay.py`** (move first):
    - `replay_artifact`, `replay_inputs`, `prepare_replay_binary`, `replay_report`, `replay_build_spec`, `replay_candidates`;
    - `minimize_*` and `find_creduce`.

    `run_eacsl_fuzz.py` keeps its subcommands as thin dispatchers.
  - **Cross-engine link (D1b):**
    - `replay-candidates --cross-engine` replays each fuzz candidate's reproducers on the other engine's binary of the module, using the cached builds from S3;
    - a failure in the same function at another site is written to the replay index;
    - `ledger.py link-related` reads the index and records `related` on both candidates.
  - **Verifier:**
    - the brief shows a candidate's observations and related candidates;
    - the verifier may record `same_root_cause_as: <fingerprint>`;
    - `ingest-verifier` then gives the related candidate the same verdict, with a note, so the report lists one finding.
  - **Make:** the `replay` recipe runs the cross-engine replay, then `link-related`.
- **Owns:** `scripts/failure_identity.py` (site key), `scripts/crash_replay.py` (new), the replay and minimize sections of `scripts/run_eacsl_fuzz.py`, `scripts/ledger.py` (`upsert_candidate`, `_find_matching_sink_candidate`, `link-related`, `ingest-verifier`), `schemas/candidates.schema.json`, the findings schema if the verdict carries the link, `scripts/generate_report.py`, `templates/pipeline.mk` (`replay`), `skills/framac-wp/crash_verifier_brief.md`, `skills/framac-fuzz/SKILL.md`.
- **Tests:**
  - a planted overflow found by ASan and by E-ACSL, plus an Eva Invalid at the same statement, gives one candidate with three observations;
  - two overflows on two lines of one function give two candidates;
  - lines inserted above keep the site;
  - two identical lines in one function give two sites;
  - a LIBMNL-04-shaped fixture (an uninitialized read at one line, the over-read at a later one, the same reproducer) gives two linked candidates and one finding after the verdict;
  - a hypothesis without a line still merges at function + kind;
  - old `candidates.json` files without `site` load.
- **Acceptance:** on the recorded libmnl run-6 candidates, LIBMNL-04 becomes one finding.

### S5. Dynamic reach gate per module (D2, F2, F11; D3 step 2, item 4) (M, after S3 and S4)

- **Goal:** a gap that depends on budget or luck holds back only its own module, and only from WP.
- **Work:**
  - **F2(a), crashes count as reach.** An entry point counts as executed when a crash artifact of its module selects its dispatch case (`artifact_dispatch_case`, and the sidecar's `api_cases` for the case → entry point map), or when the artifact's replayed failure stack names it.

    The coverage build does not replay crash inputs: a crashing process writes no profile. `check_dynamic` reads the campaign report's artifacts instead.

    A module whose every input crashes (`unmeasured` today) is measured that way too.
  - **D2:**
    - `phase0_gates.py` reach rows record `origin: static | dynamic`;
    - the whole-run check (`--modules`, used by `wp-queue`, `wp_scheduler.py init` and `ledger.py seed`) fails only on static failures;
    - the module check used by `fuzz-%`, `coverage-%`, `eva-%`, `campaign --module` and `run_eva_slice.py` fails only on static failures;
    - a dynamic failure gives every unit in the module's scope `reach_gated` evidence, with the entry points never executed;
    - `wp_scheduler.py` keeps those units out of the queue as `deferred` (`unresolved: dynamic_reach_gap: ...`);
    - the report lists gated modules with their gaps.
  - **F11:** the skill and the Make comments say what the gate does: a dynamic gap keeps the module's units out of WP, and repairing the harness or exempting the entry point clears it. `ingest` records the module's fuzz and Eva reports as usual.
  - **Coverage module `scripts/fuzz_coverage.py`** (move first): `replay_for_coverage`, `_export_coverage`, `summarize_coverage_export`, `coverage_report` and their helpers.
- **Owns:** `scripts/harness_reach.py`, `scripts/phase0_gates.py`, `scripts/wp_scheduler.py` (queue filter), `scripts/ledger.py` (`reach_gated` evidence), `scripts/fuzz_coverage.py` (new), the coverage section of `scripts/run_eacsl_fuzz.py`, `templates/pipeline.mk`, `schemas/harness_reach_dynamic.schema.json`, `skills/framac-fuzz`, `skills/framac-verify`, `skills/framac-slice` (gate text), `scripts/generate_report.py` (gated modules).
- **Tests:**
  - a dispatch harness with one case that crashes on every input passes the dynamic gate through its artifacts;
  - a real dynamic gap leaves the run going, keeps that module's units out of WP and queues the other modules;
  - a static gap still fails the run;
  - a dynamically gated module can still be fuzzed, measured and analysed with Eva;
  - repairing the harness clears the gap.
- **Acceptance:** no dynamic gap stops another module; no path reaches WP for a dynamically gated module.

### S6. Keep-going (F3, D7, F6) (M, after S3)

- **Goal:** keep-going covers every case of a dispatch harness, and the number of rounds does not depend on the machine.
- **Work:**
  - **F3, Phase 1:**
    - for a harness with more than 64 cases, the skip mask becomes a generated table of 64-bit words (`FRAMAC_FUZZ_SKIP_CASES_<k>`), so every case can be skipped. Harnesses of 64 cases or fewer keep their code and their digest;
    - `run_campaign_rounds` drops its `c < 64` filter;
    - a case beyond what the harness's mask covers (an old harness) falls back to fork mode for the rest of the campaign, with `stopped: case_beyond_mask`.
  - **F3, Phase 0 (D7):**
    - `generate_harness.py` uses a two-byte selector when the harness has more than 256 cases;
    - `seed_harvest.py write` and `artifact_dispatch_case` read the selector width from the sidecar;
    - harnesses with 256 cases or fewer are unchanged.
  - **F6:** rounds are bounded by CPU-seconds, not wall seconds:
    - each round gets the remaining CPU budget divided by the workers;
    - a new round needs at least a fixed CPU-second floor;
    - `keep_going` records `cpu_seconds_spent` and a `stopped` reason for every way the loop ends (`no_new_case`, `all_skipped`, `budget`, `rebuild_failed`, `case_beyond_mask`).
- **Owns:** the campaign section of `scripts/run_eacsl_fuzz.py` (`run_campaign_rounds`, `campaign_wall_time`, `_run_campaign_mode`'s round loop), `scripts/generate_harness.py` and `scripts/api_harness.py` (selector), `scripts/seed_harvest.py` (selector width), `schemas/harness_sidecar.schema.json`, `skills/framac-fuzz/SKILL.md`.
- **Tests:**
  - a 70-case harness that crashes in case 65 goes on to a second round with 65 skipped;
  - a 300-case harness reaches case 280, and its seeds carry two selector bytes;
  - with a recorded runner, the same campaign with 1 and with 8 workers runs the same rounds;
  - every exit path records `stopped`.

### S7. Ledger evidence (F7, F9) (S, after S4 and S5)

- **Goal:** the ledger says what ran, per function and per engine.
- **Work:**
  - **F7:**
    - `cmd_ingest_fuzz` reads `workspace/reports/coverage/<mod>.json`;
    - a function with `executions: 0` gets `fuzz_not_executed` evidence instead of `fuzz_clean`;
    - without a usable coverage report (`no_inputs`, `compile_error`, `coverage_error`), the clean evidence says it is unmeasured.
  - **F9:**
    - `merge_engine_campaigns` adds `engine_errors` (engine → status and reason);
    - ingest adds `fuzz_fuzzer_error` evidence for each failed engine, even when the other one crashed.
- **Owns:** `scripts/ledger.py` (`cmd_ingest_fuzz`), `merge_engine_campaigns` in `scripts/run_eacsl_fuzz.py`, `scripts/generate_report.py` (the evidence wording).
- **Tests:**
  - a module with an internal function no input reaches;
  - an ASan crash together with an E-ACSL `fuzzer_error` keeps both.

### S8. UBSan check set (F10) (S, after S0)

- **Goal:** UBSan checks what the pipeline means to check while fuzzing, no more.
- **Work:**
  - **If S0 shows `alignment` firing:** add `-fno-sanitize=alignment` to `compile_sanitizer_binary` (now in `fuzz_build.py`), since misaligned access is normal in packet parsers.
  - **`pointer-overflow`:** keep it unless S0 shows it stopping campaigns, since it is UB that RTE also reports.
  - **Skill:** document the sanitizer check set next to the RTE one in `skills/framac-fuzz/SKILL.md`.
- **Owns:** `scripts/fuzz_build.py` (sanitizer flags), `skills/framac-fuzz/SKILL.md`.
- **Tests:** the compile command carries the flag set; a fixture with a misaligned read is not a candidate.

### S9. E-ACSL libc out-parameter wrappers (F17, D6) (M, after S3)

- **Goal:** E-ACSL no longer reports values libc writes through out-parameters as uninitialized.
- **Work:**
  - **The list:**
    - derive the functions and parameters from the `assigns` clauses of Frama-C's libc (`share/libc`) that write through a pointer parameter (`getsockname`, `getpeername`, `accept`, `recvfrom`, `getsockopt`, the `strto*` `endptr`, `*_r` functions, ...);
    - record it as `templates/fc_stubs/eacsl_libc_outparams.json`, with the length expression of each written range (`*addrlen`, `sizeof(char *)`, ...).
  - **The wrappers:**
    - generated into a link-only object for the E-ACSL binary, as `eacsl_fallbacks.o` is;
    - each calls the real function (`-Wl,--wrap=<fn>`), then marks the written range initialized with the E-ACSL runtime's `__e_acsl_initialize`, which the build already uses for contract wrappers;
    - only functions the target calls are wrapped.
  - **Measure:** the E-ACSL alarms on the recorded libmnl socket and minmea `strtol` inputs.
- **Owns:** `templates/fc_stubs/` (list and README), the wrapper generation and link in `scripts/fuzz_build.py`, `scripts/eacsl_toolchain.py` if the link flags live there, `skills/framac-fuzz/SKILL.md`.
- **Tests:**
  - Docker-backed: `getsockname` on a socketpair, then a read of the address, raises no E-ACSL alarm;
  - a `strtol` call, then a read through `endptr`, raises none;
  - a real uninitialized read still fails;
  - the list parser on a libc snippet.
- **Acceptance:** the libmnl socket false alarm and minmea's `strtol` stop are gone on their recorded inputs.

### S10. Engine split decision (D4) (user-triggered, after S9)

- **Goal:** decide E-ACSL's share of each campaign on evidence.
- **Work:**
  - **The seeded set:** check whether it holds bugs only E-ACSL can catch: an overflow into another field of the same struct, and an uninitialized read that never faults. Add such bugs to the seeded corpus if it does not.
  - **The run:** the seeded benchmark with `--engine sanitizers`, `--engine eacsl` and `auto`, at equal budget.
  - **The decision:** keep 50/50, shift the fixed share, or make E-ACSL replay-only. Record it in the decision table above and in the review.
- **Then:** F13 (S12) and any change to `_run_campaign_mode`'s split.

### S11. Guardrail script (D3 step 2, item 5) (M, after S3)

- **Goal:** Phase 3's dynamic oracle leaves the Phase 1 script.
- **Work:**
  - **Move:** `run_guardrail_check`, `classify_guardrail`, `parse_guardrail_reach`, `derive_eacsl_diagnostic_hints`, the corpus selection helpers and `guardrail_crash_input` go to `scripts/run_guardrail.py`.
  - **Callers:** `prover_candidates.py`, `workspace_overlay.py`, the WP skill and its briefs call the new script.
  - **Meanwhile:** `run_eacsl_fuzz.py guardrail` keeps dispatching until every caller has moved.
- **Owns:** `scripts/run_guardrail.py` (new), the guardrail section of `scripts/run_eacsl_fuzz.py`, `scripts/prover_candidates.py`, `scripts/workspace_overlay.py` (the guardrail call), `skills/framac-wp/`.
- **Tests:** the guardrail tests (`test_guardrail_p1.py`, `test_diagnostic_hints.py`, `test_verdict_limits.py`) against the new module; the old subcommand still works.
- **When:** any time after S3, ideally when Phase 3 next changes the guardrail.

### S12. Docs (F13, F14, F16) (S)

- **F14** (any time): `skills/framac-verify/SKILL.md:110` says the build check makes sure the E-ACSL half of each campaign can run.
- **F16** (any time): redraw the Phase 1 diagram in `docs/architecture.md` from the Make targets: `selftest`, `build`, `seeds`, `fuzz`, `coverage`, `reach-dynamic`, `ingest`, `replay`, `minimize`. Candidates, not "True Bug".
- **F13** (after S10): rewrite "Why This Runs Before Eva and WP" for both engines, what each catches and how the time is split; update the skill's `description`.
- **Owns:** `skills/framac-verify/SKILL.md`, `docs/architecture.md`, `skills/framac-fuzz/SKILL.md` (rationale and description).

### S13. Sandbox parameter name (F12, D9) (S)

- **Work:**
  - rename `run_sandboxed(writable=...)` to `work_dirs` in `sandbox_exec.py` and every caller;
  - the docstring says it sets cwd and HOME only.
- **Owns:** `scripts/sandbox_exec.py` and the call sites. After S3, so the seam is in place; S11 takes the new name if it lands later.

### V. Validation run (user-triggered, last)

- **Runs:**
  - libmnl, minmea and oscs-tweetnacl, with the blind protocol;
  - the seeded benchmark;
  - `FRAMAC_DOCKER_TESTS=1 python -m pytest`.
- **Check:**
  - LIBMNL-01, -03, -04 and -05 found, with LIBMNL-04 as one finding;
  - no getsockname false alarm;
  - no ASan candidate merging two bugs;
  - UBSan values do not split tweetnacl's `car25519` shift;
  - no dynamic gap stopping another module;
  - `keep_going.stopped` recorded everywhere;
  - leaks parsed.
- **Then:** record the baseline `phase1-r1` with every candidate-count change explained, and merge `phase1-remediation` to `main` (D10).

## Order and parallelism

```text
S0 (user) ─────────────────────────────────────▶ S8
S1 ─┬─▶ S2 ─────────┐
    └─▶ S3 ─┬───────┴─▶ S4 ─▶ S5 ─▶ S7
            ├─▶ S6
            ├─▶ S9 ─▶ S10 (user) ─▶ S12 (F13)
            ├─▶ S11
            └─▶ S13
S12 (F14, F16): any time
                                         all ─▶ V (user)
```

- **S1 comes first:** it creates the module that S2 and S4 extend.
- **S2 and S3 can run in parallel.** S2 owns `failure_identity.py`, the fixtures and the leak branch of ingest. S3 owns the build code and the test patches.
- **S4 needs both:** the stable fingerprints from S2, and the cached builds and seam from S3.
- **S5 after S4.** Both change `scripts/ledger.py`, and one writer at a time keeps their ownership disjoint. S5 needs S3's seam for its coverage move.
- **S6, S9, S11 and S13 own disjoint files after S3** and can run in parallel with S4 and S5. S6 and S4 both touch `run_eacsl_fuzz.py`, but different sections (rounds vs replay).
- **S7 comes last among the ledger steps**, since it touches `cmd_ingest_fuzz` after S4 and S5.

## Backlog (not planned)

- **Mount namespace for sandboxed children (F12, longer term):** run fuzz and replay children with the run directory read-only and only their own directories writable. This first needs a check that the hardened container profile allows `unshare` / a user namespace. Worth promoting if a target ever writes outside its work directories during a campaign.
- **A cross-statement site for macros and multi-line statements:** D1a hashes one source line. A statement split over lines, or a macro expanding to several statements, keys on the line the producer reports. Promote if V shows a bug split or merged by it.
- **LIBMNL-02 (Phase 0):** it needs an unaligned `nlmsg_len`, which the API-only harness cannot produce. That is a limit of `generate_harness.py`, not of Phase 1.

## Status

| Step | Size | Status |
| :--- | :--- | :--- |
| S0 | — | waits for the user |
| S1 | S | open |
| S2 | M | open |
| S3 | M | open |
| S4 | L | open |
| S5 | M | open |
| S6 | M | open |
| S7 | S | open |
| S8 | S | open, after S0 |
| S9 | M | open |
| S10 | — | waits for S9, then the user |
| S11 | M | open |
| S12 | S | open (F13 after S10) |
| S13 | S | open |
| V | — | waits for the user |
