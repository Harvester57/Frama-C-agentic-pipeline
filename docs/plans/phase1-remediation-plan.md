# Phase 1 remediation plan

This plan turns the open items of [`./phase1-review.md`](./phase1-review.md) into steps:
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

### Re-check on `phase1-remediation` at `9d439e4` (2026-11-17)

The steps before the merge (S1–S7, S12's F14 and F16, V) were checked again against the branch, 298 commits after `edcbf50`. `scripts/run_eacsl_fuzz.py` now has 5,995 lines. What changed:
- **F8 is fixed.** `_ASAN_ERR_RE` captures the multi-word headlines, and `_map_sanitizer_alarm_kind` gives `freeable` for double-free and bad-free. Tests: `test_d1_asan_attempting_double_free` and `test_d1_asan_attempting_free_not_malloced` in `tests/test_run_eacsl_fuzz.py`, `TestD1MultiWordAsanKinds` in `tests/test_challenger_m4_empirical.py`. Leaks (D5) are still not parsed.
- **F1 still holds, and is coarser.** The ASan predicate no longer carries the access size (`test_d2_asan_access_size_dropped_from_fingerprint`): it is `rte: <alarm>: AddressSanitizer: <kind> (READ)`. Two overflows in one function share a fingerprint whatever their size.
- **F2(a) is mostly fixed** (`d5ae38a`, `a923d42`, `ffca52b`). `harness_reach._crashed_entry_points` credits an entry point from reproducible crash artifacts of the current harness. Tests: `tests/test_harness_reach_crash_credit.py`. Still open: a module with no usable coverage report stays `unmeasured` even when its crashes prove every entry point.
- **D2 is not done.** `phase0_gates.check` has `allow_dynamic_gap`, used by `coverage-%` only (`d5ae38a`). A dynamic gap still stops `build-%`, `fuzz-%`, the Eva targets, `wp-replay`, `wp-queue`, `wp_scheduler.py init` and `ledger.py seed`.
- **F3, Phase 1, is fixed** (`18bc5e9`, `aeac81d`, `73a2ec2`). The `c < 64` filter is gone (`c < skippable`). A harness with the runtime skip marker skips cases through the `FRAMAC_FUZZ_SKIP_CASES` environment variable, without a rebuild. Cases that cannot be skipped end the rounds with `stopped: unskippable_case` and the rest of the time runs in fork mode (`keep_going.fork_fallback`). That is the plan's `case_beyond_mask`, under the code's name.
- **F3, Phase 0, no longer holds as written** (`45c7a5f`). The selector is `identity`: the first byte is the case, and a byte at or above the case count is rejected. `generate_harness.py` refuses more than `DISPATCH_MAX_CASES` (256) cases with a `ValueError`, and `api_harness.py` drops `--api` cases above `MAX_CASES` (255) into `api_skipped`. No case is silently unreachable any more. D7's two-byte selector is now an extension, not a fix: see S6b.
- **F6 still holds.** `run_campaign_rounds` stops on `max_time - spent < MIN_ROUND_WALL_S`, in wall seconds. Most exits record `stopped`; the exit on "no new crashing case" and on `insufficient_memory` does not.
- **F7 and F9 still hold.** `769619e` added `fuzz_keep_going_error` evidence, which is neither.
- **F15 still holds** for `build`. The campaign's builds already go through the build cache.
- **No CWE map exists.** `scripts/generate_report.py` and `schemas/findings.schema.json` hold no CWE field. S2 no longer owns one.
- **No recorded run directory is in the repository.** Fixtures are written in the step (D15).
- **Test patches:** 160 `monkeypatch.setattr` calls target the `run_eacsl_fuzz` module, in 21 test files, 50 of them on `run_sandboxed`. The plan said 88 and 34. The table is in S3.

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
| D10 | When `phase1-remediation` merges to `main`. | (a) Step by step; (b) after the steps and one validation run. | **(b)** (planning, as Phase 0's D1′). One validation (V) covers the steps before the merge, and `main` stays as it is until V passes. Which steps come before the merge: see D11. |
| D11 | Which steps must land before the merge (re-scope, 2026-11-17). | (a) All steps, as first planned; (b) only the steps that change results, with the rest on `main` after the merge. | **(b)** (user). Before the merge: S1–S7, S12's F14 and F16, then V. S0 is dropped: V checks what it was to confirm. After the merge, on `main`: S8 (decided from V), S10 and S12's F13, and S11 and S13, which change no result. |

### Decisions added by the re-check (2026-11-17)

These settle choices the steps left open. Each step below applies them without re-deciding.

| # | Question | Decision |
| :--- | :--- | :--- |
| D12 | How a test patch stays live when its function moves to another module (D3). | **A patched name has one home.** A function that moved is called from every other module as `<home>.<name>(...)` (module attribute, looked up at call time), in scripts and in tests. Tests patch `<home>.<name>`. `run_eacsl_fuzz.py` re-imports every moved name with `from <home> import <name>  # noqa: F401`, only so that `R.<name>` still reads for outside importers; no code calls the re-imported name. Homes: `sandbox_exec`, `fuzz_build`, `crash_replay`, `fuzz_coverage`. A guard test (S3) enforces it. `failure_identity` and `fuzz_dictionary` hold no patched function that another module calls, so their names may be imported and called directly. |
| D13 | Where helpers shared by the new modules live. | **`scripts/fuzz_common.py`** (new, S3): constants and small pure helpers that more than one of the new modules needs. Import layering, each module importing only from those before it: `failure_identity`, `fuzz_dictionary`, `fuzz_common` → `fuzz_build` → `crash_replay` → `fuzz_coverage` → `run_eacsl_fuzz`. No new module imports `run_eacsl_fuzz`. |
| D14 | The form of F1's discriminator and of the leak kinds. | **A hash of the line text.** The ASan predicate gains the suffix ` [line <h>]`, `<h>` being the first 10 hex digits of the sha256 of the faulting source line with its whitespace runs collapsed and its ends stripped. When the source line cannot be read, there is no suffix (today's predicate). A leak has `kind: lsan_direct_leak` or `lsan_indirect_leak`, `alarm_kind: memory_leak`, and the candidate's `property.kind` is `memory_leak`. These are D5's kind `leak`, under the names the step already gave (alarm kind `memory_leak`, direct and indirect apart); no kind is named plain `leak`. D5's CWE-401 goes into the verifier brief, since no script holds a CWE map. |
| D15 | What a step needs to be accepted. | **Unit and fixture tests only** (user). No step needs a target run, a pipeline run or a container. Fixtures are written in the step under `tests/fixtures/` and marked `synthetic`. A Docker-backed test (`FRAMAC_DOCKER_TESTS=1`) may be written in a step, but it is skipped by default and runs once, in V. Checks that need a real target (re-recording fixtures, recomputing known-bug fingerprints, LIBMNL-04 as one finding) are in V. |
| D16 | The shape of `workspace/build/<mod>.build.json` with both builds (D8). | **Today's keys stay.** `compile` and `engine_used` describe the E-ACSL build when it compiled, as `phase0_gates.current_build_status` and `pipeline_make.build_check` read them. The sanitizer build of an `auto` module is added as `sanitizer_compile`, the key the campaign report already uses. |
| D17 | How one bug seen at two sites becomes one finding (D1b). | **Through the existing `duplicate` rejection class.** S4 records the link (`related`) and the brief shows it. The verifier of the second candidate rejects it as `duplicate`, naming the first, as `crash_verifier_brief.md` already describes. No `same_root_cause_as` field and no change to `ingest-verifier`. The cost is one verifier run for the second candidate. |
| D18 | How D2 keeps a gated module's units out of WP. | **`ledger.py gate-reach`.** Reach rows record `origin`. `phase0_gates.check` passes a row whose only failure is dynamic. `gate-reach` gives the planned units of each dynamically gated module `reach_gated` evidence and the status `blocked` with the reason `dynamic_reach_gap: <entry points>`, and returns them to `planned` when the gap is gone. `blocked`, not `deferred`: the ledger refuses `deferred` on a unit that carries evidence. `wp_scheduler.py init` and the `wp-replay` recipe call it. |
| D19 | F6's CPU-second floor and the `stopped` names. | **`MIN_ROUND_CPU_S = 10`**, fixed. A new round needs at least that many CPU-seconds left, CPU-seconds being wall seconds times workers. `stopped` keeps the names in the code (`time_budget_spent`, `every_case_skipped`, `unskippable_case`, `rebuild_failed`, `crash_in_skipped_case`) and gains `no_new_case` and `insufficient_memory`. |
| D20 | How S6 is cut. | **S6a** (F6 and `stopped`) and **S6b** (D7's two-byte selector). S6b comes last, after S5, because it changes `harness_reach.py`. Its selector is `identity16`: the first two input bytes, little-endian, are the case. **S6b moved after the merge** (user, 2026-11-17): F3 no longer loses cases silently, since more than 256 cases is refused, so the selector is an extension, and no validation target needs it. |
| D21 | When a coverage report is usable for F7. | **Status `ok`, or `partial` with `inputs.not_replayed` 0 or absent**, as `harness_reach.partial_coverage_reason` reads it. A function the report does not list counts as not executed, as in the dynamic reach gate. |

## Rules for every step

The same rules as the Phase 0 plans:
- **Ownership:** each step owns the files it lists, and parallel steps own disjoint files.
- **Checks:** `ruff`, `ruff format --check`, `mypy scripts tests` and the full pytest suite pass after each step.
- **Docs and skills** change in the same step as the behavior. `skills/` is mirrored into `.claude/skills/`, and this Windows checkout holds those mirrors as plain directories: never commit their "deletion".
- **Pipeline runs:** no step needs one to land, except S10 and V, which the user starts (S0 was dropped, D11). Unit tests on recorded fixtures cover each item.
- **Fingerprint changes:** a step that changes how a fingerprint is computed recomputes the known-bug fingerprints in `benchmark/manifest.json` and `docs/bugs-found/`, as `684052f` did, and says so in its commit message. Recall matches by file, function, kind and line, so it is unaffected. A compare against an older baseline shows the changed candidates once, as gone and as new.
- **Moves before changes:** a step that moves code (D3) lands the move as its own commit with no behavior change, then the fixes.

Added by the re-check, for the steps before the merge:
- **One worktree per step**, cut from the tip of `phase1-remediation` after the step before it is merged. Check with `git merge-base`.
- **Commits** follow the numbered sub-steps of the step, in that order, one commit each.
- **A move commit** changes no function body. It may change only: imports, the `<home>.` prefix on a call (D12), and the test patch targets its step lists. The reviewer reads it with `git show --color-moved=dimmed-zebra --color-moved-ws=allow-indentation-change`.
- **Skills:** after any edit under `skills/`, run `python tools/sync_skill_mirrors.py` and commit the mirrors with it. Edit only under `skills/`.
- **New test modules** define no module-level constant that another test module defines (`TREE`, `R`, ...). Import `run_eacsl_fuzz as R` as the other test files do.
- **Fingerprints (D15):** a step computes new known-bug fingerprints only when it can do so from files in the repository. S2 cannot (the predicate now depends on the target's source line), so V does it.
- **Standard checks**, run from the repository root. Each step's acceptance is these plus what it lists:

  ```text
  python -m ruff check scripts tests
  python -m ruff format --check scripts tests
  python -m mypy scripts tests
  python -m pytest -n auto -q
  python tools/check_generated_text.py
  python tools/sync_skill_mirrors.py --check          (when the step edited skills/)
  python -m pytest tests/test_docs_structure.py -n auto -q   (when the step edited docs/)
  ```

  The concurrency and run-lock tests are known to be flaky: rerun once before investigating.

## Steps

### S0. Confirming run on libmnl (user-triggered)

- **Dropped (D11, 2026-11-17).** Its checks moved into V, which runs after the fixes and shows the same things. Kept below for the record.
- **Goal:** reproduce the defects found by reading the code, before fixing them.
- **Run:** libmnl with the blind protocol of the earlier runs, on `edcbf50`, twice: with `--workers 1` and with the machine's default worker count.
- **Check:**
  - **F2:** a dispatch case that crashes on every input. Does its entry point show as a dynamic gap or as `unmeasured`?
  - **F6:** `keep_going.rounds` and the distinct crashes found, in the two runs.
  - **F10:** do UBSan's `alignment` or `pointer-overflow` checks fire, and on which inputs?
  - **F1:** two distinct ASan overflows merged into one candidate.
- **Record:** `docs/runs/phase1-s0-<date>.md`.
- **Blocks:** S8 only. Every other step lands on unit tests.

### S1. Failure identity module, moved out (D3 step 1) (S)

- **Goal:** failure parsing and fingerprinting have one owner, outside the 5,995-line script.
- **Changes no behavior.** Two commits.
- **Owns:** `scripts/failure_identity.py` (new), `scripts/fuzz_dictionary.py`, `scripts/run_eacsl_fuzz.py` (the names below and the module docstring), `tests/test_failure_identity.py` (new), the three patches in `tests/test_target_fuzzer_harness.py`.
- **Work:**
  1. **Commit 1, the moves.**
     - **To `scripts/failure_identity.py`** (new; module docstring: "Parsing of E-ACSL, ASan, UBSan runtime failures and their fingerprints."), these 36 module-level names of `run_eacsl_fuzz.py`, in their present order, with the comments above them:
       - constants: `_FN_RE`, `_ERR_RE`, `_OLD_RE`, `_PRED_HEAD_RE`, `_SEGMENT_RE`, `_RUNTIME_FN_PREFIXES`, `_RUNTIME_FILE_MARKERS`, `_UBSAN_RE`, `_UBSAN_VALUE_RE`, `_ASAN_ERR_RE`, `_ASAN_OP_RE`, `_STACK_FRAME_RE`, `_LIBC_FN`, `_LIBC_TEMPLATES`, `_LIBC_QUOTED_RE`, `_EACSL_GEN_PREFIX`, `_SIGNEDNESS_PAIRS`, `STACK_FRAMES_MAX`, `_PROCESS_FRAME_FNS`;
       - functions: `is_runtime_function`, `stable_ubsan_message`, `_map_sanitizer_alarm_kind`, `_resolve_source_candidates`, `_is_acsl_annotation_line`, `_resolve_function_at_line`, `is_harness_fuzz_function`, `_parse_segment_failure`, `_caller_of_eacsl_runtime`, `_parse_libc_failure`, `_failing_predicate`, `parse_eacsl_failure`, `parse_sanitizer_failure`, `parse_runtime_failure`, `needs_attribution`, `stack_frames`;
       - `_failure_fingerprint`, renamed `failure_fingerprint`. `run_eacsl_fuzz.py` keeps `_failure_fingerprint = failure_fingerprint`.
     - `failure_identity.py` imports what these use (`acsl_ast`, `c_definitions`, `fingerprint`, and `DISPATCH_SKIP_FN`, `TARGET_EMBEDDED_PREFIX` from `generate_harness`). It does not import `run_eacsl_fuzz`.
     - **To `scripts/fuzz_dictionary.py`**, these 14 names: `_DICT_LINE_RE`, `sanitize_dictionary_token`, `sanitize_dictionary_line`, `sanitize_dictionary_content`, `sanitize_fuzzer_dictionary`, `AUTO_DICT_DIR`, `_dict_stem`, `auto_dictionary_path`, `dictionary_target_sources`, `build_auto_dictionary`, `resolve_campaign_dictionary`, `extra_dictionary_path`, `_dictionary_entry_lines`, `merge_extra_dictionary`. Inside `build_auto_dictionary`, `fuzz_dictionary.build_dictionary` and `fuzz_dictionary.render_dictionary` become `build_dictionary` and `render_dictionary`.
     - **`run_eacsl_fuzz.py`** re-imports all 50 names by name (`from failure_identity import (...)  # noqa: F401`, the same for `fuzz_dictionary`). Its other code is unchanged: it keeps calling them by their bare names (D12 allows it for these two modules).
     - **`tests/test_target_fuzzer_harness.py`:** the three `monkeypatch.setattr(R, "build_auto_dictionary", ...)` become `monkeypatch.setattr(fuzz_dictionary, "build_auto_dictionary", ...)`, with `import fuzz_dictionary`. The function under test, `resolve_campaign_dictionary`, now reads the name in `fuzz_dictionary`.
  2. **Commit 2, the docstring.** The module docstring of `run_eacsl_fuzz.py` lists 7 modes. Add the three missing subcommands as items 8 to 10: `minimize`, `minimize-candidates`, `minimize-interest`, one sentence each, taken from their `add_parser(..., help=...)` text.
- **Tests:** `tests/test_failure_identity.py`:
  - `test_run_eacsl_fuzz_reexports_every_moved_name`: for each of the 50 names, `getattr(run_eacsl_fuzz, name) is getattr(home, name)`; and `run_eacsl_fuzz._failure_fingerprint is failure_identity.failure_fingerprint`;
  - `test_failure_identity_does_not_import_run_eacsl_fuzz`: the text of `scripts/failure_identity.py` and of `scripts/fuzz_dictionary.py` holds no `import run_eacsl_fuzz` and no `from run_eacsl_fuzz`.
- **Acceptance:**
  - the standard checks;
  - `git show --stat HEAD~1` (commit 1) lists only `scripts/failure_identity.py`, `scripts/fuzz_dictionary.py`, `scripts/run_eacsl_fuzz.py`, `tests/test_target_fuzzer_harness.py` and `tests/test_failure_identity.py`;
  - `git grep -n "^def parse_eacsl_failure\|^def build_auto_dictionary" -- scripts` shows one definition of each, outside `run_eacsl_fuzz.py`.

### S2. Stable ASan and LeakSanitizer identity (F1, F8, D5) (M, after S1)

- **Goal:** one ASan or LSan fingerprint per defect: not one per input, and not one per function.
- **Already on the branch (checked 2026-11-17):** F8's headline capture and the `freeable` mapping, with their tests (see the re-check). Do not redo them. Still to do: F1's discriminator and D5's leaks.
- **Owns:** `scripts/failure_identity.py`, `tests/fixtures/failures/` (new), `tests/test_failure_fixtures.py` (new), `tests/test_failure_fixtures_docker.py` (new), the leak branch of `cmd_ingest_fuzz` in `scripts/ledger.py`, `skills/framac-wp/crash_verifier_brief.md` (how to verify a leak), the failure-kind text of `skills/framac-fuzz/SKILL.md`. It edits no existing test file: S3 owns those in parallel.
- **Work:**
  1. **Commit 1, the line text (F1, D14).** In `failure_identity.py`:
     - add `normalized_source_line(file_path: str, line: int) -> str | None`: the text of line `line` of the first file `_resolve_source_candidates(file_path)` returns, stripped, with each run of whitespace replaced by one space; `None` when `line <= 0`, no file resolves, or the file is shorter;
     - add `line_text_hash(file_path: str, line: int) -> str | None`: the first 10 hex digits of the sha256 of that text in UTF-8, or `None`;
     - in the ASan branch of `parse_sanitizer_failure`, after `file_` and `line_` are known: `pred` gains ` in <name> from <fn>` when the top stack frame is an interceptor (its function starts with `__interceptor_` or `__asan_`; `<name>` is the function without that prefix, `<fn>` the best frame's function), then ` [line <h>]` when `line_text_hash(file_, line_)` is not `None`.
     - The line number is never in the predicate. With no readable source and no interceptor frame, the predicate is today's.
     - No existing test asserts the text of an ASan predicate or a literal ASan fingerprint (checked on `9d439e4`); the tests that compare two fingerprints change on both sides. If an existing test fails on this commit, do not edit it (S3 owns those files): stop and report it.
  2. **Commit 2, leaks (D5, D14).** In `failure_identity.py`:
     - add `_LSAN_ERR_RE` (matches `ERROR: LeakSanitizer: detected memory leaks`) and `_LSAN_BLOCK_RE` (matches `Direct leak of N byte(s) in M object(s) allocated from:` and the same with `Indirect`);
     - add `_parse_leak_failure(text) -> dict | None`, called by `parse_sanitizer_failure` after the UBSan and ASan branches. It takes the first `Direct leak` block, else the first `Indirect leak` block. In that block's stack, it takes the first frame that is not a runtime function (`is_runtime_function`), not a harness frame (`harness_*` file, `is_harness_fuzz_function`), and not an allocator (`malloc`, `calloc`, `realloc`, `reallocarray`, `strdup`, `strndup`, `aligned_alloc`, `posix_memalign`, `memalign`, `valloc`, with or without `__interceptor_`);
     - the result: `file`, `line`, `function` from that frame (`unknown`, 0, `unknown_function` when there is none); `kind: lsan_direct_leak` or `lsan_indirect_leak`; `alarm_kind: memory_leak`; `is_rte: False`; `predicate: "memory_leak: LeakSanitizer: direct leak allocated in <function>"` (or `indirect leak`), plus ` [line <h>]` as in commit 1. Byte and object counts are not in the predicate.
  3. **Commit 3, ingest.** In `cmd_ingest_fuzz` (`scripts/ledger.py`), in the branch for an artifact with a failure and a fingerprint: when `failure.get("alarm_kind") == "memory_leak"`, `linked` is `[]`, and the note is `a memory leak has no obligation class: no unit is linked (D5)` instead of the `no ledger unit for ...` note. Nothing else in that branch changes. A leak artifact whose report cannot be parsed still takes the `unparsed_leak` branch.
  4. **Commit 4, fixtures.** `tests/fixtures/failures/<name>.txt` holds one sanitizer or E-ACSL output each, and `tests/fixtures/failures/expected.json` maps each name to `{file, function, kind, alarm_kind, predicate, synthetic: true}`. Write the texts by hand in the formats of the logs in `tests/test_tool_parsing.py` and `tests/test_run_eacsl_fuzz.py`, with stack frames whose file is `src/demo.c`. The fixtures:
     - E-ACSL: `eacsl_assertion`, `eacsl_segment`, `eacsl_initialized`;
     - ASan: `asan_heap_overflow`, `asan_stack_overflow`, `asan_global_overflow`, `asan_overflow_line_a` and `asan_overflow_line_b` (the same kind in one function at two lines), `asan_use_after_free`, `asan_double_free`, `asan_bad_free`, `asan_memcpy_overlap` (top frame `__asan_memcpy`, LIBMNL-01's shape);
     - UBSan: `ubsan_signed_overflow`, `ubsan_shift`, `ubsan_abs_int_min`;
     - LSan: `lsan_direct`, `lsan_indirect`.

     `tests/fixtures/failures/src/demo.c` is the source the frames point to, so the line text can be read. `tests/fixtures/failures/programs/` holds one small C program per ASan, UBSan and LSan fixture, for the Docker-backed test.
  5. **Commit 5, skills.** `crash_verifier_brief.md`: a leak candidate (`property.kind: memory_leak`) is verified by replaying its reproducer and reading the allocation stack; a confirmed leak is CWE-401; a leak of the harness's own allocation is `harness_induced`. `skills/framac-fuzz/SKILL.md`: the failure kinds name `memory_leak` and say that leaks link no ledger unit. Then `python tools/sync_skill_mirrors.py`.
- **Tests:**
  - `tests/test_failure_fixtures.py` (it runs each parse with `monkeypatch.chdir(tests/fixtures/failures)`, so `src/demo.c` resolves):
    - `test_each_fixture_parses_to_its_expected_record` (parametrized over `expected.json`);
    - `test_two_overflows_in_one_function_have_two_fingerprints` (`asan_overflow_line_a` and `_b`);
    - `test_inserting_lines_above_keeps_the_fingerprint`: copy `demo.c` to `tmp_path/src/demo.c` with three lines inserted at the top, shift the fixture's line numbers by three, compare `failure_fingerprint`;
    - `test_an_unreadable_source_gives_the_predicate_without_a_line_hash`;
    - `test_an_interceptor_frame_names_the_interceptor_and_its_caller` (`asan_memcpy_overlap`);
    - `test_a_fixture_parsed_twice_gives_one_fingerprint`, and the same fingerprint for the same report with other addresses and sizes (what `minimize_interest` compares);
    - `test_direct_and_indirect_leaks_are_two_kinds_with_alarm_kind_memory_leak`;
    - `test_a_leak_is_attributed_to_the_first_target_frame`;
    - `test_ingest_fuzz_links_no_unit_for_a_leak`: a fuzz report with one leak artifact, ingested as the tests in `tests/test_r2_ledger_seed_fuzz.py` ingest one, gives a candidate with `property.kind == "memory_leak"`, `linked_units == []` and the D5 note.
  - `tests/test_failure_fixtures_docker.py`: one test, behind the `FRAMAC_DOCKER_TESTS=1` skip of `tests/conftest.py`. It compiles each program of `programs/` with `clang -g -fsanitize=address,undefined` in the analysis image, runs it, and checks that the output parses to the `kind` and `alarm_kind` of `expected.json`. It is skipped in this step and runs in V (D15).
- **Acceptance:** the standard checks; `python -m pytest tests/test_failure_fixtures.py tests/test_tool_parsing.py tests/test_run_eacsl_fuzz.py tests/test_challenger_m4_empirical.py -q` passes with no change to the last three files.
- **Not in this step (D15):** recomputing the fingerprints of `benchmark/manifest.json` and `docs/bugs-found/`. The new ASan predicate needs the target's source line, which is not in the repository. V does it.

### S3. Sandbox seam and build module (D3 step 2, items 1–2; F15/D8) (M, after S1)

- **Goal:** code can leave `run_eacsl_fuzz.py` without silently disarming the tests' patches.
- **Owns:** `scripts/fuzz_common.py` (new), `scripts/fuzz_build.py` (new), `scripts/sandbox_exec.py` (docstring only), `scripts/run_eacsl_fuzz.py` (the names below, the `run_sandboxed` call sites, `_run_build_mode`, `_run_campaign_mode`), `scripts/loop_seeds.py` (its `run_eacsl_fuzz.compile_eacsl_binary` call), the patch lines of the 21 test files in the table, `tests/test_seam_guard.py` (new), `tests/test_fuzz_build.py` (new), `templates/pipeline.mk` (the `build-%` recipe and its comment). It does not edit `scripts/failure_identity.py` (S2 runs in parallel).
- **The patches on `run_eacsl_fuzz` today** (160; `R` is the tests' alias):

  | Patched name | Count | Target after this step |
  | :--- | ---: | :--- |
  | `run_sandboxed` | 50 | `sandbox_exec` |
  | `compile_eacsl_binary` | 19 | `fuzz_build` |
  | `compile_sanitizer_binary` | 9 | `fuzz_build` |
  | `_resolve_eacsl_gcc` | 8 | `fuzz_build` |
  | `compile_coverage_binary` | 7 | `fuzz_build` |
  | `build_module_binary` | 7 | `fuzz_build` |
  | `framac_version` | 5 | `fuzz_build` |
  | `eacsl_share_dir`, `EACSL_GCC_CHECK_OPTIONS` | 2, 1 | `fuzz_build` (only the build code reads them) |
  | `is_eacsl_instrumented` | 3 | `R` and `fuzz_build`: keep the line and add the same patch on `fuzz_build` |
  | `find_creduce`, `prepare_replay_binary`, `replay_artifact` | 3, 2, 1 | unchanged here; `crash_replay` in S4 |
  | `_export_coverage`, `in_function_includes` | 4, 1 | unchanged here; `fuzz_coverage` in S5 |
  | `build_auto_dictionary` | 3 | `fuzz_dictionary` (done in S1) |
  | `enforced_memory_mb`, `run_fuzz_campaign`, `run_guardrail_check`, `_run_campaign_mode`, `GUARDRAIL_MAX_EXCLUDED_INPUTS`, `_summary` | 11, 8, 4, 4, 2, 1 | unchanged: their code stays in `run_eacsl_fuzz.py` |
  | `R.time.monotonic`, `R.subprocess.run`, `R.shutil.which`, `R.prover_candidates.add_candidate_block` | 2, 1, 1, 1 | unchanged: they patch the shared module object |

  The files: `test_fuzz_coverage.py` (26), `test_fuzz_subcommands.py` (26), `test_eacsl_toolchain.py` (21), `test_fuzz_keep_going.py` (14), `test_guardrail_p1.py` (11), `test_tool_sizing.py` (10), `test_remediation_p2_fuzz.py` (9), `test_fuzz_harness_identity.py` (8), `test_target_fuzzer_harness.py` (5), `test_cache.py` (4), `test_fuzz_artifact_prefix.py` (4), `test_guardrail_format_runtime.py` (4), `test_prover_candidates.py` (3), `test_r6_fuzz_side.py` (3), `test_eacsl_format_signedness.py` (2), `test_link_repair_globals.py` (2), `test_pipeline_make.py` (2), `test_promote_and_verifier.py` (2), `test_seed_write_status.py` (2), `test_fuzz_link_repair.py` (1), `test_sandbox_and_overlay.py` (1). `test_promote_and_verifier.py` uses the alias `fuzz_mod`, `test_pipeline_make.py` the alias `fuzz`.
- **Work:**
  1. **Commit 1, the sandbox seam.**
     - `run_eacsl_fuzz.py`: `from sandbox_exec import Limits, SandboxUnavailable, run_sandboxed` becomes `import sandbox_exec` and `from sandbox_exec import Limits, SandboxUnavailable`. Its 7 calls of `run_sandboxed(` (in `replay_artifact`, `run_fuzz_campaign`, `run_guardrail_check`, `minimize_input`, `replay_for_coverage`, twice in `_export_coverage`) become `sandbox_exec.run_sandboxed(`.
     - Tests: the 50 patches become `monkeypatch.setattr(sandbox_exec, "run_sandboxed", ...)`, with `import sandbox_exec` in each file.
     - `sandbox_exec.py`: the docstring of `run_sandboxed` gains one sentence: callers reach it as `sandbox_exec.run_sandboxed`, so that a test patch on the module applies to every caller.
     - `build_capture.py`, `codeql_trust.py`, `seed_harvest.py` and `stub_check.py` import `run_sandboxed` inside a function. That import runs at call time and sees a patch: leave them.
     - Add `tests/test_seam_guard.py` (see Tests), with `SEAM_MODULES = ("sandbox_exec",)`.
  2. **Commit 2, the moves** (no behavior change).
     - **To `scripts/fuzz_common.py`** (new), 12 names: `BUILD_TIMEOUT_S`, `DEFAULT_PER_INPUT_TIMEOUT_S`, `DUAL_ENGINE`, `SANITIZER_RUNTIME_ENV`, `ARTIFACT_KINDS`, `_artifact_kind`, `sha256_file`, `derive_seed`, `_in_agent_scratch`, `replay_artifact_dir`, `_collect_inputs`, `DEFAULT_SELFTEST_JSON`. `run_eacsl_fuzz.py` re-imports them by name and keeps calling them by their bare names (`fuzz_common` is not a seam module).
     - **To `scripts/fuzz_build.py`** (new), 40 names:
       - compile: `_decode`, `_discover_slice_functions`, `_resolve_eacsl_gcc`, `_run_tool`, `_note_cache_restore`, `_eacsl_cache_material`, `_check_options`, `_runtime_patches`, `_PATCHED_STDIO_ERROR_RE`, `_format_runtime_share`, `_GETENV_CALL_RE`, `_ENVIRON_KEEP_SOURCE`, `_build_environ_keep_object`, `compile_eacsl_binary`, `_compile_eacsl_binary_uncached`, `_compile_clang_binary`, `compile_sanitizer_binary`, `compile_coverage_binary`;
       - selftest result: `framac_version`, `selftest_blocks_eacsl` (`run_selftest` and `resolve_canary_source` stay);
       - link repair: `_UNDEFINED_REF_RE`, `parse_undefined_references`, `_dag_symbol_files`, `_normalize_dag_source`, `LINK_GLOBALS_FILE`, `LINK_GLOBALS_ASSUMPTION`, `_GLOBAL_TYPE_CHARS_RE`, `_GLOBAL_TAG_RE`, `_GLOBAL_POINTER_SLOT_RE`, `_GLOBAL_ARRAY_RE`, `_model_global_variables`, `global_definition_text`, `_declaring_header`, `link_globals_source`, `_dag_tree_path`, `_link_unit_context`, `_place_global`, `repair_sources_for_link`;
       - `build_module_binary`, `_sanitizer_attribution_builder`.
     - `fuzz_build.py` imports from `fuzz_common`, `failure_identity` (`is_harness_fuzz_function`), `eacsl_toolchain`, `cache` and the other modules these functions use. It does not import `run_eacsl_fuzz`. Inside `fuzz_build.py`, the moved functions call each other by their bare names.
     - **`run_eacsl_fuzz.py`:** `import fuzz_build`, and the re-import of all 40 names (`# noqa: F401`). Every call of a moved function in the code that stays becomes `fuzz_build.<name>(...)`: in `run_selftest` (`_resolve_eacsl_gcc`, `framac_version`, `compile_eacsl_binary`), `main` (`compile_eacsl_binary`), `prepare_replay_binary` (`build_module_binary`, `_sanitizer_attribution_builder`), `coverage_report` (`compile_coverage_binary`), `run_guardrail_check` (`_in_agent_scratch` is in `fuzz_common`: bare), `_run_build_mode` and `_run_campaign_mode` (`build_module_binary`, `_sanitizer_attribution_builder`).
     - **`scripts/loop_seeds.py`:** `run_eacsl_fuzz.compile_eacsl_binary(` becomes `fuzz_build.compile_eacsl_binary(`, with `import fuzz_build` next to its `import run_eacsl_fuzz`.
     - **Tests:** retarget the patches as the table says. Direct calls such as `R.compile_eacsl_binary(...)` and `R._discover_slice_functions(...)` stay as they are.
     - `tests/test_seam_guard.py`: `SEAM_MODULES = ("sandbox_exec", "fuzz_build")`.
  3. **Commit 3, F15 (D8, D16).**
     - `build_module_binary` gains the keyword `apply_selftest: bool = True`. With `False`, `_attempt` does not call `selftest_blocks_eacsl`.
     - `_run_build_mode` passes `apply_selftest=False`. When `args.engine == "auto"` and the result's `engine_used` is `eacsl`, it also calls `build_module_binary` with `engine="sanitizers"` (the call `_run_campaign_mode` makes for its second engine) and records that build's `compile` as `res["sanitizer_compile"]`. `compile`, `engine_used` and `status` are computed as today.
     - `_run_campaign_mode` is unchanged: it applies the selftest, and its builds restore from the cache what `build` compiled.
     - `templates/pipeline.mk`: the `build-%` recipe drops `--selftest-json $(SELFTEST_JSON)`. Its comment becomes: "Compile only: what `--engine` asks for, both engines for `auto`. It never reads the selftest result; the campaign applies it and restores these builds from the cache."
- **Tests:**
  - `tests/test_seam_guard.py`:
    - a helper `bare_seam_calls(source: str) -> list[str]`: parse the text with `ast`; collect the names bound by a module-level `from <m> import ...` with `<m>` in `SEAM_MODULES`; return each `ast.Call` whose function is one of those names and which `inspect.isfunction` says is a function of `<m>`. Classes (`Limits`) and constants pass;
    - `test_no_script_calls_a_seam_function_by_its_bare_name`: the helper returns `[]` for each `scripts/*.py`, the seam modules themselves excepted;
    - `test_the_guard_sees_a_bare_call`: the helper on the text `"from sandbox_exec import run_sandboxed\nrun_sandboxed([], [], 1)\n"` returns one call, and on `"import sandbox_exec\nsandbox_exec.run_sandboxed([], [], 1)\n"` none;
    - `test_no_test_patches_a_seam_function_on_run_eacsl_fuzz`: for each `tests/*.py`, fail on a `monkeypatch.setattr(<alias of run_eacsl_fuzz>, "<name>"` where `<name>` is a function defined in a seam module.
  - `tests/test_fuzz_build.py`:
    - `test_run_eacsl_fuzz_reexports_every_moved_name` (the 52 names of commit 2, by identity);
    - `test_fuzz_build_and_fuzz_common_do_not_import_run_eacsl_fuzz`;
    - `test_build_ignores_a_failed_selftest`: with `selftest_blocks_eacsl` patched to return a reason and the two compile functions patched to succeed, `_run_build_mode` reports `engine_used == "eacsl"`;
    - `test_build_auto_records_both_builds`: `sanitizer_compile` is present for `--engine auto`, absent for `--engine eacsl` and `--engine sanitizers`;
    - `test_campaign_still_applies_the_selftest`: `build_module_binary(..., engine="auto")` with the default `apply_selftest` and a failed selftest gives `engine_used == "sanitizers"` and the fallback reason;
    - `test_a_campaign_after_build_compiles_nothing`: in a run directory with the cache on, as `test_eacsl_hit_restores_every_output` and `test_sanitizer_build_is_cached` in `tests/test_cache.py` set it up, `_run_build_mode` then the two `build_module_binary` calls of the campaign: the recorded compile runner is called for the first only, and the second pair of results carries a cache hit.
- **Acceptance:**
  - the standard checks;
  - `git grep -n "run_sandboxed" -- scripts/run_eacsl_fuzz.py` shows only `sandbox_exec.run_sandboxed` and docstring text;
  - `git grep -n "^def compile_eacsl_binary\|^def build_module_binary" -- scripts` shows one definition of each, in `fuzz_build.py`;
  - `python -m pytest tests/test_seam_guard.py tests/test_fuzz_build.py -q` passes.
- **Changed by this step, to check in V:** `build-check` no longer sees a failed selftest. A module whose E-ACSL build compiles passes `build-check` even when the selftest then fails, and the campaign falls back to the sanitizers with `engine_fallback_reason` in its report. That follows from D8.

### S4. Candidates grouped by site, cross-engine link, crash-replay module (D1 step 2, F5, D1a–D1c; D3 step 2, item 3) (L, after S2 and S3)

- **Goal:** one candidate per site, holding every engine's detection, and one finding for one bug seen at two statements.
- **Already on the branch (checked 2026-11-17):**
  - `generate_report.dedupe_findings_for_report` merges verdict records of one file, function, line and kind;
  - the verifier's `duplicate` rejection class covers "the same root cause at a different sink" (`crash_verifier_brief.md`), and `87bb1b6` flags opposite verdicts on one sink.

  Neither groups candidates before the verifier runs. D17 uses the second for the verdict.
- **Owns:** `scripts/crash_replay.py` (new), the replay and minimize code of `scripts/run_eacsl_fuzz.py`, `scripts/failure_identity.py` (`site_key`), `scripts/ledger.py` (`upsert_candidate` and its 8 call sites, `_find_matching_sink_candidate` and its 3 callers, `link-related`), `scripts/benchmark.py` and `scripts/decision_point_check.py` (their `run_eacsl_fuzz.` replay calls), `schemas/candidates.schema.json`, `scripts/generate_report.py` (related candidates), `templates/pipeline.mk` (`replay`), `skills/framac-wp/crash_verifier_brief.md`, `skills/framac-fuzz/SKILL.md` (candidates text), the patch lines of `tests/test_fuzz_subcommands.py`, `tests/test_pipeline_make.py` and `tests/test_promote_and_verifier.py`, `tests/test_crash_replay.py` and `tests/test_candidate_sites.py` (new).
- **Work:**
  1. **Commit 1, the move** (no behavior change). To `scripts/crash_replay.py` (new), 17 names: `replay_artifact`, `replay_inputs`, `_slim_compile`, `prepare_replay_binary`, `replay_report`, `acsl_include_dir`, `_unit_harness_module`, `_sidecar_build_spec`, `replay_build_spec`, `_candidate_slug`, `_candidate_engine`, `_reproducer_paths`, `replay_candidates`, `find_creduce`, `minimize_interest`, `minimize_input`, `minimize_candidates`, and the comment block above `find_creduce`.
     - `crash_replay.py` imports `sandbox_exec`, `fuzz_build`, `fuzz_common`, `failure_identity`. It calls `sandbox_exec.run_sandboxed(` and `fuzz_build.<name>(`.
     - `run_eacsl_fuzz.py`: `import crash_replay`, the re-import of the names, and `crash_replay.<name>(` at every call that stays: `run_fuzz_campaign` and `run_selftest` (`replay_artifact`), `main` (`prepare_replay_binary`, `replay_report`, `replay_candidates`, `minimize_interest`, `minimize_input`, `minimize_candidates`). The subcommands stay in `main`.
     - `scripts/benchmark.py` (`replay_build_spec`, `prepare_replay_binary`, `replay_report`) and `scripts/decision_point_check.py` (the same three and `_candidate_engine`): `import crash_replay` and call it instead of `run_eacsl_fuzz`.
     - Tests: `find_creduce` (3, `test_fuzz_subcommands.py`), `prepare_replay_binary` (2, `test_pipeline_make.py`), `replay_artifact` (1, `test_promote_and_verifier.py`) are patched on `crash_replay`. `is_eacsl_instrumented`: add the same patch on `crash_replay` (`replay_report` reads it).
     - `tests/test_seam_guard.py`: add `"crash_replay"` to `SEAM_MODULES`.
  2. **Commit 2, the site key (D1a).** In `failure_identity.py`:
     - `site_key(file: str, function: str, line: int, fn_range: tuple[int, int] | None = None) -> str | None`: `None` when `normalized_source_line(file, line)` is `None`. Else `<normalize_file(file)>#<function>@<h>`, `<h>` being `line_text_hash(file, line)`. When `fn_range` (first and last line of the function) is given and the same normalized text occurs more than once in that range, append `#<n>`, `<n>` counting from 1 the occurrences from the range's first line down to `line`.
     - The caller gives `fn_range`. In `ledger.py` it comes from `_dag_line_index`: the `(first, last, name)` entry of the file that contains the line.
  3. **Commit 3, the schema and the grouping (F5).**
     - `schemas/candidates.schema.json`, three optional properties of a candidate: `site` (string); `observations` (array of objects with `fingerprint`, `origin`, `engine` (string or null), `kind`, `message`, `tool_output`, `reproducer` (string or null); all required); `related` (array of objects with `fingerprint` and `reason`).
     - `upsert_candidate` gains the keywords `site: str | None = None` and `engine: str | None = None`:
       - when `fp` is not a key of `candidates`, `site` is not `None`, and an `unverified` candidate has that `site`: that candidate takes the detection. Its key and `fingerprint` do not change. Reproducers, tool outputs, linked units and notes are added as today;
       - otherwise as today, and a new candidate records `site` when it is given;
       - in both cases an observation is appended, unless one with the same `fingerprint`, `origin` and `engine` exists;
       - when the detection's `origin` is `eva`, or its `engine` is `eacsl`, and the candidate was first seen by the sanitizers, the candidate's `property` becomes the detection's;
       - it returns the candidate, as today.
     - The 8 call sites (two in the fuzz ingest, three in the Eva ingest, three in the hypothesis and breaker ingest; find them with `git grep -n "upsert_candidate(" -- scripts/ledger.py`) pass `site` (from the failure's or alarm's file, function and line; `None` for the unparsed-artifact call) and `engine` (the artifact's `engine` for fuzz, `None` otherwise). After the call each uses `cand["fingerprint"]` of the returned candidate, never its own `fp`, for `mark_candidate`, for `candidates[...]` lookups and for the reopening calls.
     - A `candidates.json` written before this step (no `site`, no `observations`) loads and validates.
  4. **Commit 4, Phase 3's merge (D1c).** `_find_matching_sink_candidate` gains `site: str | None = None`. With a site, it returns the candidate with that `site` if there is one. Otherwise, and when no candidate has it, it applies today's function + kind rule. Its 3 callers compute the site when the hypothesis or the breaker's failure has a line greater than 0.
  5. **Commit 5, the cross-engine link (D1b).**
     - `crash_replay.replay_candidates` gains `cross_engine: bool = False` and the subcommand `replay-candidates` the flag `--cross-engine`. With it, after a candidate's own replay, and when its engine is `eacsl` or `sanitizers`, its reproducers are replayed on the other engine's binary of the same module (`prepare_replay_binary` with `engine=` the other one; a failed build is recorded and skipped). The candidate's `index.json` entry gains `cross_engine: {engine, status, failures}`, `failures` listing each distinct replayed failure as `{fingerprint, file, line, function, kind}`.
     - `ledger.py link-related --index <path>` (new subcommand, `cmd_link_related`, under the ledger lock): for each index entry and each of its `cross_engine.failures` whose `fingerprint` is another candidate's key or one of its observations' fingerprints, in the same file and function as the entry's candidate, add to both candidates a `related` entry `{fingerprint: <the other key>, reason: "cross-engine replay: <engine> fails at <file>:<line> on the same reproducer"}`, once.
     - `templates/pipeline.mk`, `replay`: the recipe passes `--cross-engine`, then runs `$(RUN) --class light --key candidates -- $(PY) $(S)/ledger.py link-related --index workspace/reports/replay/index.json`.
  6. **Commit 6, the verifier and the report (D17).**
     - `crash_verifier_brief.md`: read the candidate's `observations` (every engine that saw this site) and `related` (candidates another engine reports on the same reproducer). When a related candidate has the same root cause and is already verified, reject this one as `duplicate` and name the other fingerprint in `record.reason`.
     - `generate_report.py`: a finding whose candidate has `related` entries lists them on one line ("Related candidates: ...").
     - `skills/framac-fuzz/SKILL.md`: one candidate per site; what `observations` and `related` mean. Then `python tools/sync_skill_mirrors.py`.
- **Tests:**
  - `tests/test_crash_replay.py`: `test_run_eacsl_fuzz_reexports_every_moved_name`; `test_crash_replay_does_not_import_run_eacsl_fuzz`; `test_cross_engine_replay_records_the_other_engines_failures`, with `prepare_replay_binary` and `replay_report` patched on `crash_replay` as `tests/test_pipeline_make.py` patches them.
  - `tests/test_candidate_sites.py` (sources written under `tmp_path/workspace/work`, with `monkeypatch.chdir(tmp_path)`):
    - `test_asan_eacsl_and_eva_at_one_statement_give_one_candidate_with_three_observations`;
    - `test_two_overflows_on_two_lines_give_two_candidates`;
    - `test_lines_inserted_above_keep_the_site`;
    - `test_two_identical_lines_in_one_function_give_two_sites`;
    - `test_a_detection_at_the_site_of_a_verified_candidate_opens_a_new_candidate`;
    - `test_the_eacsl_observation_sets_the_property_of_a_sanitizer_candidate`;
    - `test_a_hypothesis_with_a_line_merges_by_site`, `test_a_hypothesis_without_a_line_merges_by_function_and_kind`;
    - `test_candidates_without_site_load_and_validate`;
    - `test_link_related_links_two_candidates_of_one_reproducer`: a LIBMNL-04-shaped fixture, an `initialization` candidate at one line and a `mem_access` candidate at a later line of one function, with a replay index whose `cross_engine.failures` names the other; both get `related`;
    - `test_a_duplicate_verdict_on_a_related_candidate_leaves_one_finding`: the first confirmed and the second rejected as `duplicate` through `cmd_ingest_verifier`, as `tests/test_promote_and_verifier.py` drives it; the report lists one finding.
- **Acceptance:** the standard checks; `python -m pytest tests/test_candidate_sites.py tests/test_crash_replay.py tests/test_ledger.py tests/test_ledger_p1.py tests/test_ledger_sink_conflicts.py tests/test_seam_guard.py -q`; `python scripts/validate_artifacts.py --help` still runs.
- **Not in this step (D15):** LIBMNL-04 as one finding on a real libmnl run. It is a check of V.

### S5. Dynamic reach gate per module (D2, F2, F11; D3 step 2, item 4) (M, after S3 and S4)

- **Goal:** a gap that depends on budget or luck holds back only its own module, and only from WP.
- **Already on the branch (checked 2026-11-17):** F2(a)'s crash credit (`_crashed_entry_points`, `tests/test_harness_reach_crash_credit.py`), and `--allow-dynamic-gap` on `coverage-%`. Do not redo the crash credit; this step replaces the flag.
- **Owns:** `scripts/fuzz_coverage.py` (new), the coverage code of `scripts/run_eacsl_fuzz.py`, `scripts/harness_reach.py` (`run_dynamic`), `scripts/phase0_gates.py`, `scripts/ledger.py` (`gate-reach`), `scripts/wp_scheduler.py` (the `init` branch of `main`), `scripts/generate_report.py` (gated modules), `templates/pipeline.mk` (`coverage-%`, `reach-dynamic`, `wp-replay`, their comments), `schemas/harness_reach_dynamic.schema.json` (only if a row gains a field), `skills/framac-fuzz/SKILL.md`, `skills/framac-verify/SKILL.md`, `skills/framac-slice/SKILL.md` (gate text), `docs/guides/architecture.md` (the "Gates" bullet), the patch lines of `tests/test_fuzz_coverage.py`, the gate tests named below, `tests/test_reach_gate_dynamic.py` (new).
- **Work:**
  1. **Commit 1, the move** (no behavior change). To `scripts/fuzz_coverage.py` (new), 22 names: the constants `COVERAGE_BATCH_SIZE`, `COVERAGE_LISTED_FAILED_INPUTS`, `COVERAGE_MAX_TIME_S`, `COVERAGE_TOOL_TIMEOUT_S`, `COVERAGE_MAX_UNCOVERED_RANGES`, `COVERAGE_SNAPSHOT_ROOT`, `COVERAGE_EXTERNAL_PREFIXES`, `LLVM_COV_CODE_REGION`, `COVERAGE_TRUNCATED_MAPPING`, `_RUNNING_RE`, `_INCLUDE_RE`, and the functions `_written_profiles`, `replay_for_coverage`, `_input_running_at_exit`, `_includes_inside_braces`, `in_function_includes`, `_export_coverage`, `_coverage_file_role`, `_merge_line_ranges`, `summarize_coverage_export`, `coverage_report`, `_known_crash_digests`.
     - `fuzz_coverage.py` imports `sandbox_exec`, `fuzz_build`, `fuzz_common`. It calls `sandbox_exec.run_sandboxed(` and `fuzz_build.compile_coverage_binary(`.
     - `run_eacsl_fuzz.py`: `import fuzz_coverage`, the re-import, and `fuzz_coverage.coverage_report(` in `main`.
     - Tests: `_export_coverage` (4) and `in_function_includes` (1) in `tests/test_fuzz_coverage.py` are patched on `fuzz_coverage`. Add `"fuzz_coverage"` to `SEAM_MODULES`.
  2. **Commit 2, F2(a): a module measured by its crashes.** In `harness_reach.run_dynamic`, for a module whose coverage report is missing or not in `_COVERAGE_OK`: call `check_dynamic` with the coverage `{"status": <status>, "functions": []}`. If the row passes (every entry point is exempt or in `crashed_entry_points`), keep it, with `"measured_by": "crashes"`. If not, write the `passed: None` row of today. Add `measured_by` to the row's properties in `schemas/harness_reach_dynamic.schema.json`.
  3. **Commit 3, the gate (D2, D18).** In `phase0_gates.py`:
     - `record_reach` stores `"origin": "dynamic"` in a row whose `error` is `DYNAMIC_GAP_ERROR`, `"static"` in every other row;
     - `_row_reach_ok(row)` returns `True` for a row that passed, or whose origin is dynamic (a row without `origin` is dynamic when its `error` is `DYNAMIC_GAP_ERROR`). The harness-digest and DAG-digest checks still apply to such a row;
     - the parameter `allow_dynamic_gap` and the flag `--allow-dynamic-gap` are removed, and the `coverage-%` recipe drops the flag;
     - new `dynamic_gaps(run_dir) -> dict[str, list[str]]`: module to gaps, for the rows that did not pass and whose origin is dynamic.

     Every caller of `check` then lets a dynamically gated module through without a change of its own: `build-%`, `fuzz-%`, `coverage-%`, the Eva recipes, `campaign_gate_reasons`, `run_eva_slice.phase0_gate_reasons`, `pipeline_make.build_check`, and the whole-run checks of `wp-replay`, `wp-queue`, `wp_scheduler.py init` and `ledger.seed_input_problems`. A static failure fails them as today.
  4. **Commit 4, the units (D18).** In `ledger.py`, `cmd_gate_reach()` (under the ledger lock, modelled on `cmd_close_remaining`) and the subcommand `gate-reach`:
     - for each module of `phase0_gates.dynamic_gaps(Path("."))`: each `planned` unit in the module's scope (`_module_units(units, *_report_scope(mm, module))`) gets `reach_gated` evidence (phase `fuzz`, producer `harness_reach.py`, not discharging, tool output `workspace/reports/harness_reach_dynamic.json`, description naming the entry points never executed), the status `blocked`, and the reason `dynamic_reach_gap: <entry points, comma-separated>` in `unresolved`;
     - for each `blocked` unit that has a `dynamic_reach_gap:` reason and whose module is no longer in `dynamic_gaps`: remove that reason; if `unresolved` is then empty, the unit returns to `planned`;
     - it returns `{"gated_modules": {...}, "blocked": n, "reopened": m}`.

     `wp_scheduler.py`, `main`, `init`: after the gate check passes and before `cmd_init`, call `ledger.cmd_gate_reach()` and put its result in the output as `reach_gate`. `templates/pipeline.mk`, `wp-replay`: after `$(GATE)`, run `$(RUN) --class light --key wp-replay -- $(PY) $(S)/ledger.py gate-reach`.
  5. **Commit 5, report, skills, comments (F11).**
     - `generate_report.py`: a section "Modules held back from WP by the dynamic reach gate", one line per module of `dynamic_gaps` with its gaps; nothing when there is none.
     - `templates/pipeline.mk`, the comment of `reach-dynamic`: a dynamic gap keeps the module's planned units out of WP (`ledger.py gate-reach`); it stops no fuzz, coverage or Eva target; repairing the harness or exempting the entry point clears it.
     - The same text in `skills/framac-fuzz/SKILL.md` (the `reach-dynamic` section), `skills/framac-verify/SKILL.md`, `skills/framac-slice/SKILL.md` and the "Gates" bullet of `docs/guides/architecture.md`, wherever they say that a dynamic gap stops fuzz or Eva. `ingest` records the module's fuzz and Eva reports as usual. Then `python tools/sync_skill_mirrors.py`.
- **Tests:**
  - Existing tests that pin today's blocking, to rewrite for the new rule (a dynamic gap passes `check`, a static gap, a missing stamp and a stale digest fail it):
    - `tests/test_harness_reach.py`: `test_phase0_gates_allow_dynamic_gap_unblocks_coverage_only_when_digests_match` becomes `test_phase0_gates_pass_a_dynamic_gap_only_when_digests_match`, with every `allow_dynamic_gap=True` and `--allow-dynamic-gap` removed and the "default check blocks" assertion inverted; `test_pipeline_mk_coverage_uses_allow_dynamic_gap_while_fuzz_and_eva_block` becomes `test_pipeline_mk_gates_carry_no_dynamic_gap_flag`, asserting that every `$(GATE) --module $* --need reach` line of the template is the same; the section comment above them loses the flag's name;
    - `tests/test_harness_reach_crash_credit.py` (line 201 on `9d439e4`): the `--allow-dynamic-gap` argument is removed;
    - `tests/test_phase0_gates.py` (lines 63, 64 and 206 on `9d439e4`): the keyword and the comment go, and the `coverage-%` row of the recipe table reads `reach`.
    - Any other test that fails on this step for the same reason is rewritten the same way.
  - `tests/test_reach_gate_dynamic.py`:
    - `test_a_module_whose_every_input_crashes_is_measured_by_its_crashes` (no coverage report, crash artifacts for every entry point: the row passes with `measured_by: crashes`);
    - `test_a_module_without_coverage_and_without_crash_proof_stays_unmeasured`;
    - `test_record_reach_stores_the_origin`;
    - `test_a_dynamic_gap_passes_the_module_check_and_the_whole_run_check`;
    - `test_a_static_gap_still_fails_both`;
    - `test_a_dynamic_gap_with_a_changed_harness_is_stale`;
    - `test_gate_reach_blocks_the_planned_units_of_the_gated_module_only` (two modules, one gated: the other's units stay `planned`);
    - `test_gate_reach_reopens_the_units_when_the_gap_is_gone`;
    - `test_gate_reach_leaves_candidate_and_covered_units_alone`;
    - `test_wp_scheduler_init_queues_no_task_for_a_gated_module`;
    - `test_campaign_and_eva_gates_let_a_dynamically_gated_module_run` (`campaign_gate_reasons` and `run_eva_slice.phase0_gate_reasons` return `[]`);
    - `test_the_report_lists_gated_modules`.
- **Acceptance:** the standard checks; `git grep -n -i "allow.dynamic.gap" -- scripts templates tests skills` returns nothing (the two tests are renamed for that); `python -m pytest tests/test_reach_gate_dynamic.py tests/test_harness_reach.py tests/test_harness_reach_crash_credit.py tests/test_phase0_gates.py tests/test_r1_gates_resume.py tests/test_fuzz_coverage.py tests/test_seam_guard.py -q`.

### S6. Keep-going (F3, D7, F6) (M, after S3)

- **Goal:** keep-going covers every case of a dispatch harness, and the number of rounds does not depend on the machine.
- **Already on the branch (checked 2026-11-17):** F3's Phase 1 half (`18bc5e9`, `aeac81d`, `73a2ec2`): every case is skippable, at run time or by rebuild; the `c < 64` filter is gone; cases that cannot be skipped stop the rounds with `unskippable_case` and the time left runs in fork mode. F3's Phase 0 defect is gone too (`45c7a5f`): more than 256 cases is refused, not silently lost. Still to do: F6 (S6a), and D7's two-byte selector (S6b).
- **Two parts (D20).** S6a can run once S3 has landed. S6b comes after S5.

#### S6a. Rounds by CPU-seconds, and `stopped` everywhere (F6, D19)

- **Owns:** `run_campaign_rounds` and the `run_campaign_rounds(...)` call of `_run_campaign_mode` in `scripts/run_eacsl_fuzz.py`; the keep-going text of `skills/framac-fuzz/SKILL.md`; `tests/test_fuzz_rounds_cpu.py` (new); the assertions on `keep_going` of `tests/test_fuzz_keep_going.py` that the change breaks.
- **Work**, one commit:
  1. Add `MIN_ROUND_CPU_S = 10` next to `MIN_ROUND_WALL_S`, with the comment: fixed, never derived from the machine.
  2. `run_campaign_rounds` gains the keyword `workers: int = 1`. `_engine_campaign` in `_run_campaign_mode` passes `workers=workers`.
  3. The test for another round, `max_time - spent < MIN_ROUND_WALL_S`, becomes `(max_time - spent) * max(1, workers) < MIN_ROUND_CPU_S`. The fork fallback's test, `left >= MIN_ROUND_WALL_S`, becomes `(max_time - spent) * max(1, workers) >= MIN_ROUND_CPU_S`. A round's wall time stays `max(MIN_FUZZ_WALL_S if not rounds else MIN_ROUND_WALL_S, int(max_time - spent))`, and the fallback's is `max(MIN_ROUND_WALL_S, int(max_time - spent))`.
     - **Changed in review (`cb56350`):** that wall floor let the last round overrun the budget by up to 5 s times the workers. A round's and the fallback's wall time is now the wall time left, `int(max_time - spent)` (at least 1 s for the first round); a later round also needs a whole second left. `MIN_ROUND_WALL_S` is gone.
  4. `stopped` on every exit of the loop: the `break` on `not fresh` sets `rnd["stopped"] = "no_new_case"`, and the one on `insufficient_memory` sets `"insufficient_memory"`. The other names stay.
  5. `keep_going` (mode `dispatch_rounds`) gains `stopped` (the last round's), `workers` and `cpu_seconds_spent` (`round(spent * max(1, workers), 1)`). `fuzz_seconds` stays. Mode `fork` has no loop and gets no `stopped`.
  6. `skills/framac-fuzz/SKILL.md`: rounds are bounded by CPU-seconds; the list of `stopped` values. Then `python tools/sync_skill_mirrors.py`.
- **Tests:** `tests/test_fuzz_rounds_cpu.py`, with the fake `campaign` and patched `R.time.monotonic` of `test_rounds_share_one_time_budget` in `tests/test_fuzz_keep_going.py`:
  - `test_one_and_eight_workers_run_the_same_rounds`: a fake campaign that spends a fixed number of CPU-seconds per round (the clock advances by that number divided by the workers) and crashes in a new case each round; `max_time` 240 with 1 worker and 30 with 8; the two `keep_going.rounds` have the same length and the same `skipped_cases`, and the same `stopped`;
  - `test_a_round_needs_ten_cpu_seconds_left`: 9 CPU-seconds left ends with `time_budget_spent`, 11 runs another round;
  - `test_every_exit_records_stopped`, parametrized over `no_new_case`, `every_case_skipped`, `time_budget_spent`, `unskippable_case`, `rebuild_failed`, `crash_in_skipped_case`, `insufficient_memory`: the last round and `keep_going` both carry it;
  - `test_keep_going_records_cpu_seconds_spent`.
- **Acceptance:** the standard checks; `python -m pytest tests/test_fuzz_rounds_cpu.py tests/test_fuzz_keep_going.py tests/test_dispatch_selector.py -q`.

#### S6b. Two-byte selector above 256 cases (D7)

- **When (D20):** after the merge, on `main`.

- **Before starting:** this is the widest change of the plan and no longer fixes a silent defect (see the re-check). The reviewer may decide to move it after the merge; if so, mark it in the Status table and skip it.
- **Owns:** `scripts/generate_harness.py` (dispatch code), `scripts/api_harness.py` (`MAX_CASES`), `scripts/seed_harvest.py` and `scripts/fuzz_assets.py` (the selector bytes they write), `scripts/harness_reach.py` (`_artifact_first_byte` and its callers), `artifact_dispatch_case` in `scripts/run_eacsl_fuzz.py`, `templates/harness_dual.c.template` if the skip function's argument type must widen, `schemas/harness_sidecar.schema.json` (`dispatch_selector`), `skills/framac-fuzz/SKILL.md`, `skills/framac-slice/SKILL.md`, `tests/test_dispatch_selector.py`, `tests/test_dispatch_selector_wide.py` (new).
- **Work**, one commit:
  1. `generate_harness.py`: add `DISPATCH_SELECTOR_IDENTITY16 = "identity16"` and `DISPATCH_MAX_CASES_WIDE = 4096` (the runtime skip limit, `DISPATCH_RUNTIME_SKIP_MAX_CASES`). `_build_dispatch_invocation` with more than 256 cases emits `uint16_t harness_selector = (uint16_t)(fuzz_buf[0] | (fuzz_buf[1] << 8));`, needs two input bytes, gives the case the input after them, and writes the marker `dispatch selector: identity16, <n> cases`. More than `DISPATCH_MAX_CASES_WIDE` cases is the `ValueError` of today. A harness with 256 cases or fewer is generated byte for byte as today.
  2. `DISPATCH_SWITCH_RE` gains the `identity16` form. `dispatch_selector_of_text` and `dispatch_selector_of` return it. The sidecar records `dispatch_selector: identity16`, and the schema's enum allows it.
  3. Add `dispatch_selector_width(selector) -> int` (2 for `identity16`, else 1) and `dispatch_case_of_bytes(prefix: bytes, n_cases, selector) -> int | None`. `dispatch_case_of` stays for one byte.
  4. Readers use them: `run_eacsl_fuzz.artifact_dispatch_case` (reads `dispatch_selector_width` bytes), `harness_reach._artifact_first_byte` (renamed `_artifact_selector_bytes`, returning bytes) and its two callers.
  5. Writers use them: `seed_harvest.py` and `fuzz_assets.py` write `dispatch_selector_width` selector bytes, little-endian, in front of a case's input.
  6. `api_harness.py`: `MAX_CASES` becomes `DISPATCH_MAX_CASES_WIDE - 1`, so `--api` cases above 255 are no longer dropped into `api_skipped`.
  7. Skills: the selector width and the limits. Then `python tools/sync_skill_mirrors.py`.
- **Tests:** `tests/test_dispatch_selector_wide.py`:
  - `test_a_300_case_harness_selects_case_280_with_two_bytes` (generated text and `dispatch_case_of_bytes(bytes([280 & 255, 280 >> 8]), 300, "identity16") == 280`);
  - `test_a_256_case_harness_is_generated_as_before` (identity selector, one byte, the same text as a harness generated by the code before this commit: compare with the marker and switch lines the existing tests assert);
  - `test_more_than_4096_cases_is_refused`; rewrite `test_more_than_256_cases_is_refused_and_leaves_no_harness` in `tests/test_dispatch_selector.py` to that limit;
  - `test_seeds_of_a_300_case_harness_carry_two_selector_bytes`;
  - `test_reach_credits_a_crash_in_case_280`;
  - `test_keep_going_skips_case_280`;
  - when host clang is present, as `test_generated_dispatch_harness_runs_case_k_for_byte_k` does: `test_generated_wide_harness_runs_case_280`.
- **Acceptance:** the standard checks; `python -m pytest tests/test_dispatch_selector.py tests/test_dispatch_selector_wide.py tests/test_fuzz_keep_going.py tests/test_harness_reach.py tests/test_harness_reach_crash_credit.py -q`.
- **Review (2026-11-17), on the branch rebased onto `b540121` (S1 to S7 and S12 merged):**
  - Re-run: `ruff check`, `mypy scripts tests`, `tools/check_generated_text.py`, `tools/sync_skill_mirrors.py --check`, `tests/test_docs_structure.py`, and the whole suite (5941 passed, 219 skipped). `ruff format --check` reports 44 files, all in lines the branch did not write (the four it touches were unformatted before the step too).
  - `test_generated_wide_harness_runs_case_280` passes in the analysis image (`FRAMAC_DOCKER_TESTS=1`): a compiled 300-case harness runs case k for selector k, and nothing for a selector at or above 300 or a one-byte input.
  - After the rebase no script outside the ones this step owns reads or writes the selector byte (searched at `b540121`: `read(1)`, `bytes([sel])`, `first_byte`, `<= 255`).
  - Measured with libFuzzer on trivial harnesses from an empty corpus (`-seed=1`, cases reached after 2,000 / 10,000 / 30,000 executions): 250 cases, one byte: 188 / 250 / 250. 300 cases, two bytes: 98 / 225 / 292. 1,000 cases: 175 / 545 / 872. At 300,000 executions every case of 300 and of 1,000 is reached, and 3,950 of 4,000. So the two-byte selector does not hide cases, but a case without a seed costs about three times the executions to find. With one two-byte seed per case in the corpus every case runs when the corpus is loaded. The pipeline writes no such seed today (open, not part of this step).
  - The selector enum is in `schemas/harness_sidecar.schema.json` only, so a crash artifact stamped `identity16` validates. The skip function takes `unsigned int`, so `templates/harness_dual.c.template` did not need to change.
  - The seed cost above is one run per size on a trivial harness; it is recorded as an open gap in `docs/troubleshooting/harnesses-and-seeds.md`.
  - Not checked: the skip of a case at or above 256 in a compiled harness, Eva on a wide harness (one analysis over 300 or more cases, and a shard's `-DFRAMAC_EVA_SHARD_CASE_<k>` list for that many cases), and a real target.
- **Rebased again (2026-11-17) onto `434d4a9`** (R1, the mpack run-3 supervisor fixes and the redone S5 merged):
  - One conflict, in the `argv` and `dispatch` lines of `skills/framac-slice/SKILL.md`: the tip's `argv` text and this step's `dispatch` text are kept, and the mirrors are regenerated.
  - Re-run on it: the same checks, and the whole suite (6065 passed, 224 skipped). `test_generated_wide_harness_runs_case_280` passes in the rebuilt analysis image.
  - The scripts and templates the tip changed since `b540121` add no reader or writer of the selector byte (their diff was searched for the selector, the first byte and the case index).
  - Still not checked: the three items above.

### S7. Ledger evidence (F7, F9) (S, after S4, S5 and S6a)

- **Goal:** the ledger says what ran, per function and per engine.
- **Owns:** `cmd_ingest_fuzz` in `scripts/ledger.py` (its `clean` branch and the engine errors), `merge_engine_campaigns` in `scripts/run_eacsl_fuzz.py`, the evidence text of `skills/framac-fuzz/SKILL.md`, `tests/test_ledger_fuzz_evidence.py` (new). `scripts/generate_report.py` is not touched: it prints each evidence entry's own description and holds no wording per result.
- **Work:**
  1. **Commit 1, F7 (D21).** In `ledger.py`:
     - add `_fuzz_coverage_executions(module) -> tuple[dict[tuple[str, str], int] | None, str]`: reads `workspace/reports/coverage/<module>.json`. When the report is usable (D21) it returns `{(normalize_file(file), function): executions}` summed over its `functions` rows, and `""`. Otherwise `None` and the reason (`no coverage report`, the report's status, or `partial coverage: N inputs not replayed`);
     - in the `status == "clean"` branch of `cmd_ingest_fuzz`, per unit: with executions known and the unit's function at 0 or not listed (match on the function name and on the file as a path suffix, as `harness_reach._entry_executions` does), the evidence result is `fuzz_not_executed` and the description `"<engine note> campaign: no replayed input executed this function (not evidence of anything)."`; with executions greater than 0, `fuzz_clean` as today; with executions unknown, `fuzz_clean` with the description ending `" Which functions ran was not measured (<reason>)."`.
  2. **Commit 2, F9.**
     - `merge_engine_campaigns` adds `engine_errors`: for each engine whose status is `fuzzer_error`, `{"status": "fuzzer_error", "reason": <its error_summary joined by "; ", or "returncode <n>">}`. The key is absent when no engine failed.
     - `cmd_ingest_fuzz`, after the `fuzz_keep_going_errors` loop: for each engine of `report.get("engine_errors")`, each unit of the module gets `fuzz_fuzzer_error` evidence, `"<engine> campaign did not run to completion (<reason>); the other engine's results are ingested."`. This is the branch for a report whose merged status is a finding, so the evidence is added even when the other engine crashed.
  3. `skills/framac-fuzz/SKILL.md`: the three evidence results. Then `python tools/sync_skill_mirrors.py`.
- **Tests:** `tests/test_ledger_fuzz_evidence.py`, ingesting as `tests/test_r2_ledger_seed_fuzz.py` does:
  - `test_a_function_no_input_reached_gets_fuzz_not_executed` (a clean report, a coverage report with one function at `executions: 0` and one at 5);
  - `test_a_function_the_coverage_report_does_not_list_gets_fuzz_not_executed`;
  - `test_without_a_usable_coverage_report_the_clean_evidence_says_unmeasured`, parametrized over a missing report, `no_inputs`, `compile_error`, `coverage_error`, and `partial` with `not_replayed: 3`;
  - `test_merge_records_the_engine_that_failed` (`sanitizers` `crash_found`, `eacsl` `fuzzer_error`: status `crash_found`, `engine_errors == {"eacsl": {...}}`);
  - `test_merge_without_a_failed_engine_has_no_engine_errors`;
  - `test_an_asan_crash_and_an_eacsl_fuzzer_error_are_both_ingested` (the candidate exists and the module's units carry `fuzz_fuzzer_error`).
- **Acceptance:** the standard checks; `python -m pytest tests/test_ledger_fuzz_evidence.py tests/test_r2_ledger_seed_fuzz.py tests/test_link_unit_ingest.py tests/test_fuzz_keep_going.py -q`.

### S8. UBSan check set (F10) (S, after V, on `main`)

- **When (D11):** after the merge. V records whether UBSan's `alignment` and `pointer-overflow` checks fire and on which inputs; this step acts on that.
- **Goal:** UBSan checks what the pipeline means to check while fuzzing, no more.
- **Work:**
  - **If V shows `alignment` firing:** add `-fno-sanitize=alignment` to `compile_sanitizer_binary` (now in `fuzz_build.py`), since misaligned access is normal in packet parsers.
  - **`pointer-overflow`:** keep it unless V shows it stopping campaigns, since it is UB that RTE also reports.
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
- **Done (2026-11-14, commit `7be8bd1`):**
  - **The list:** it lives in `EACSL_LIBC_EFFECTS` in `scripts/eacsl_toolchain.py`, not in a JSON file under `templates/fc_stubs/`. Each entry holds the written range as a C statement (`pre`/`post`), which states in/out lengths (`FC_MIN(fc_in, *addrlen)`), the result count of `read`, `recvmsg`'s iovec and failure cases more simply than a length expression. It was written by hand from the libc contracts, not parsed from `share/libc`. `test_effects_table_signatures_match_the_errno_table` checks it against `ERRNO_SHIM_FUNCTIONS`.
  - **The wrappers:**
    - They are the errno shim's wrappers (`eacsl_errno_shim.o`), because a function can be wrapped only once. A slice that does not read errno gets the effects alone.
    - They call `__e_acsl_initialize` only in memory the runtime tracks (`__e_acsl_valid`), and only after `fuzz_init.c` sets `__fc_eacsl_runtime_ready`.
    - Backlog item 38 is folded in: libc's static results (`strerror`, `gmtime`, ...) come back as a tracked copy.
    - If the effects fail to compile, the errno wrappers are linked alone (`effects_error`).
  - **Also fixed:** the `\initialized` check on a `va_list` (`skip_va_list_initialized_checks`). With the `endptr` alarm gone, it was minmea's next false stop.
  - **Measured:**
    - libmnl: `mnl_socket_fdopen` stopped at `socket.c:183` before and runs clean after.
    - minmea: MINMEA-01 now reaches its real bug at `minmea.c:656` on E-ACSL.
    - The probe, the commands and the remaining gaps are in [`../troubleshooting/eacsl-and-fuzzing.md`](../troubleshooting/eacsl-and-fuzzing.md).
  - **Not done:**
    - minmea's `fuzz_rte_initialized: false` was dropped from `benchmark/manifest.json` (2026-11-14). The next benchmark run differs from the stored baselines on minmea's E-ACSL campaign; explain that difference when re-baselining. QCBOR's and CryptoLib's opt-outs stay until they are checked the same way.
    - `test_every_shim_wrapper_compiles_against_the_host_libc` runs only where clang and glibc headers exist. The image has no pytest, so the full-table compile was checked by hand in the container.
  - **Tests:**
    - The Docker-backed `test_libc_shim_clears_libc_false_alarms_and_keeps_real_ones_in_the_analysis_image` (`FRAMAC_DOCKER_TESTS=1`) covers `getsockname`, `strtol`'s `endptr`, `recvmsg`, `strerror`, `gmtime` and `va_arg`, plus two real uninitialized reads next to wrapped calls.
    - The unit tests check the generated wrappers.
    - There is no list parser to test, since nothing parses `share/libc`.

### S10. Engine split decision (D4) (user-triggered, after S9 and the merge)

- **When (D11):** after the merge, on `main`.

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
- **When:** after the merge (D11), on `main`, ideally when Phase 3 next changes the guardrail. It moves code and changes no result.

### S12. Docs (F13, F14, F16) (S)

- **Before the merge (D11):** F14 and F16, one commit each, after S5: S5 edits the same two files, and the diagram shows S5's gate. F13 comes after the merge, with S10.
- **F14.** In `skills/framac-verify/SKILL.md`, the last bullet of "Phase 0 — Slicing, DAG, ledger seeding" (line 116 on `9d439e4`) ends "so Phase 1 never falls back to ASan/UBSan silently". Replace that clause with: "so the E-ACSL half of each campaign can run (under `auto`, every module is also fuzzed with ASan+UBSan)". Leave the rest of the bullet. Then `python tools/sync_skill_mirrors.py`.
- **F16.** In `docs/guides/architecture.md`, section 2, the `P1` subgraph of the mermaid diagram still shows harness generation and the static reach gate (both Phase 0 now), "True Bug", and "Keep in CI Fuzzing". Redraw it from the Make targets:
  - Phase 0's subgraph gains two nodes after the stubs node: "Dual harness per module (generate_harness.py)" and "Reach gate (harness_reach.py check) and E-ACSL build check (pipeline_make.py build-check)". The Tier edges leave from there.
  - `P1` holds, in this order: `selftest`, `build` (E-ACSL and ASan+UBSan), `seeds`, `fuzz` (ASan+UBSan, then E-ACSL, keep-going rounds), `coverage`, `reach-dynamic`, `ingest`, `replay`, `minimize`.
  - The crash edge reads "Failure: candidate" and leads to a node "Candidate in candidates.json; a Crash Verifier decides (Phase 3 gate)". No "True Bug".
  - Remove the node `T2_DONE` and its two edges. A clean module of any fuzzed tier goes on to Phase 2.
  - The `reach-dynamic` node has two edges: "no gap" to `ingest`, and "gap: the module's units stay out of WP" to `ingest` as well (D2: the run goes on).
- **Acceptance (F14, F16):** the standard checks for docs and skills; the mermaid block still opens with `flowchart TD` and every node id used on an edge is defined.
- **F13** (after S10): rewrite "Why This Runs Before Eva and WP" for both engines, what each catches and how the time is split; update the skill's `description`.
- **Owns:** `skills/framac-verify/SKILL.md`, `docs/guides/architecture.md` (the diagram; S5 owns the "Gates" bullet), `skills/framac-fuzz/SKILL.md` (rationale and description, F13).

### S13. Sandbox parameter name (F12, D9) (S)

- **Work:**
  - rename `run_sandboxed(writable=...)` to `work_dirs` in `sandbox_exec.py` and every caller;
  - the docstring says it sets cwd and HOME only.
- **Owns:** `scripts/sandbox_exec.py` and the call sites. After S3, so the seam is in place; S11 takes the new name if it lands later.
- **When (D11):** after the merge, on `main`. A rename changes no result.

### S14. The target's own fuzz targets and corpora (M, before S3, S6 and S11)

- **Goal:** a fuzz corpus or fuzz target the target ships is used. Until now nothing looked for them: no `*_seed_corpus.zip`, no `corpus/` folder, no `.dict` or `.options`, and a target's own `LLVMFuzzerTestOneInput` was not in the DAG and had no harness.
- **Work:**
  - `scripts/fuzz_assets.py` (new): `discover`, `map` (the Phase 0 agent pairs what OSS-Fuzz naming does not), `import` (fixed limits, zip-safe), `write --module` (per harness module, `workspace/imported_corpus/<mod>/imp-*`);
  - `generate_harness.py --target-fuzzer`: an extra module `tf_<id>` that renames the target's fuzz entry and initializer, copies the input into `fuzz_buf` and calls them;
  - the reach gate reads the fuzzer source for a `tf_` module, which answers for no entry point; `pipeline_make` gives `tf_` modules no Eva; `fuzz-%` and `coverage-%` take the imported corpus as a second `--extra-corpus`;
  - the seeded fixture `s09_shipped_corpus` and the seeded benchmark's Phase 0 sequence.
- **Owns:** `scripts/fuzz_assets.py`, `schemas/fuzz_assets.schema.json`, the target-fuzzer parts of `scripts/generate_harness.py`, `schemas/harness_sidecar.schema.json`, `scripts/harness_reach.py`, `scripts/phase0_gates.py`, `scripts/pipeline_make.py`, `templates/pipeline.mk`, three small spots in `scripts/run_eacsl_fuzz.py` (RTE selection, crash frames, dictionary merge), `scripts/benchmark_seeded.py`, the s09 fixture, and the Phase 0/1 skills.
- **Order:** it lands before S3, S6 and S11, which then move or change `run_eacsl_fuzz.py`, `generate_harness.py` and the sidecar schema from it.

### V. Validation run (user-triggered, last)

- **Before the runs**, on the tip of `phase1-remediation` with every step merged:
  - the standard checks;
  - `FRAMAC_DOCKER_TESTS=1 python -m pytest`, with both images built. It runs the Docker-backed tests the steps wrote and skipped, `tests/test_failure_fixtures_docker.py` among them (D15). Where a real sanitizer output differs from a synthetic fixture in a parsed field, replace the fixture with the recorded output and drop its `synthetic` mark.
- **Runs:**
  - libmnl, minmea and oscs-tweetnacl, with the blind protocol;
  - libmnl a second time with `--workers 1` (S0's check of F6, D11);
  - the seeded benchmark.
- **Check:**
  - **From S0 (D11):**
    - F2: a dispatch case that crashes on every input counts as executed, and its module is not `unmeasured`;
    - F6: `keep_going` runs the same rounds with `--workers 1` and with the default count;
    - F10: whether UBSan's `alignment` or `pointer-overflow` checks fire, and on which inputs. Record it for S8.
  - **From the steps (D15):**
    - S2: recompute the ASan-derived fingerprints of `benchmark/manifest.json` and `docs/bugs-found/` from these runs, per the fingerprint rule, and say so in the commit;
    - S3: `workspace/build/<mod>.build.json` of an `auto` module holds `sanitizer_compile`, and the campaign's two builds are cache hits; no module passed `build-check` and then fuzzed with the sanitizers alone without an `engine_fallback_reason`;
    - S4: on libmnl, LIBMNL-04's two candidates are `related`, and the report lists one finding;
    - S5: `ledger.py gate-reach` ran before `wp-queue`; if a run shows a dynamic gap, its module's units are `blocked` with `dynamic_reach_gap` and the other modules are queued. If no run shows one, say so in the run record: D2 then rests on its unit tests;
    - S7: a function with `fuzz_not_executed` evidence has `executions` 0 or no row in its module's coverage report, and one with `fuzz_clean` has more than 0; a campaign report with an engine in `fuzzer_error` has `engine_errors`, and its module's units carry `fuzz_fuzzer_error`. Count the units that moved from `fuzz_clean` to `fuzz_not_executed` for the baseline's explanation.
  - LIBMNL-01, -03, -04 and -05 found, with LIBMNL-04 as one finding;
  - the seeded benchmark finds what `seeded-s14` found (9 of 9 bugs, 0 of 4 decoys);
  - no getsockname false alarm;
  - no ASan candidate merging two bugs, and no bug split into two candidates by its line text (D1a's revisit condition);
  - UBSan values do not split tweetnacl's `car25519` shift;
  - no dynamic gap stopping another module;
  - `keep_going.stopped` recorded on every campaign that ran in dispatch rounds;
  - leaks parsed: no `unparsed_leak` candidate whose replay log holds a LeakSanitizer report;
  - `validate_artifacts.py run-dir .` passes in each run directory.
- **Record:** `docs/runs/<date>-phase1-validation.md`, and every pipeline bug met in [`../troubleshooting/README.md`](../troubleshooting/README.md)'s documents.
- **Then:** record the baseline `phase1-r1` with every candidate-count change explained, and merge `phase1-remediation` to `main` (D10).

## Order and parallelism

Before the merge (D11):

```text
S1 ─┬─▶ S2 ─────┐
    └─▶ S3 ─┬───┴─▶ S4 ─▶ S5 ─┬─▶ S7 ───────────┬─▶ V (user) ─▶ merge to main
            └─▶ S6a ──────────┤                 │
                              └─▶ S12 (F14, F16)┘
(S9 and S14 are done.)
```

After the merge, on `main`:

```text
V ─▶ S8
S6b: any time
S10 (user) ─▶ S12 (F13)
S11, S13: any time, S13 before S11 if both land
```

- **One step at a time is the default:** S1, S2, S3, S4, S5, S12 (F14, F16), S6a, S7. Each step's worktree is cut after the step before it is merged. Nothing below is needed for that order.
- **S1 comes first:** it creates the module that S2 and S4 extend.
- **S2 and S3 can run in parallel.** S2 owns `failure_identity.py`, the fixtures, new test files and the leak branch of ingest. S3 owns the build code, `fuzz_common.py` and the patch lines of the existing test files. They share no file. Both touch `run_eacsl_fuzz.py` only through S3.
- **S4 needs both:** the line-text helpers from S2, and the seam, `fuzz_build` and `fuzz_common` from S3.
- **S5 after S4.** Both change `scripts/ledger.py`, `scripts/generate_report.py` and `templates/pipeline.mk`, and S5's coverage move imports what S4's move left in place.
- **S6a after S3; in parallel with S4 and S5 only with care.** It owns `run_campaign_rounds`, which neither moves. But all three edit the import block of `run_eacsl_fuzz.py` and `skills/framac-fuzz/SKILL.md`, so a parallel S6a ends in a textual merge. Run it after S5 unless time matters.
- **S7 comes last among the ledger steps**, since it touches `cmd_ingest_fuzz` after S2, S4 and S5. It also edits `merge_engine_campaigns`, next to S6a's function: after S6a.
- **S6b after the merge (D20), and after S5 and S6a:** it changes `harness_reach.py` (S5's file) and `artifact_dispatch_case`.
- **S12 (F14, F16) after S5:** both edit `skills/framac-verify/SKILL.md` and `docs/guides/architecture.md`.
- **Shared files, one writer at a time:** `skills/framac-verify/SKILL.md` and `docs/guides/architecture.md` (S5, S12), `skills/framac-slice/SKILL.md` (S5, S6b), `skills/framac-fuzz/SKILL.md` (S2, S4, S5, S6a, S6b, S7), `scripts/ledger.py` (S2, S4, S5, S7), `templates/pipeline.mk` (S3, S4, S5), `tests/test_seam_guard.py` (S3, S4, S5).

## Backlog (not planned)

- **Mount namespace for sandboxed children (F12, longer term):** run fuzz and replay children with the run directory read-only and only their own directories writable. This first needs a check that the hardened container profile allows `unshare` / a user namespace. Worth promoting if a target ever writes outside its work directories during a campaign.
- **A cross-statement site for macros and multi-line statements:** D1a hashes one source line. A statement split over lines, or a macro expanding to several statements, keys on the line the producer reports. Promote if V shows a bug split or merged by it.
- **LIBMNL-02 (Phase 0):** it needs an unaligned `nlmsg_len`, which the API-only harness cannot produce. That is a limit of `generate_harness.py`, not of Phase 1.
- **One verdict for related candidates without a second verifier run:** D17 uses the `duplicate` class, so the second candidate still gets a verifier. Promote if V shows many related pairs.

## Status

Re-scoped on 2026-11-17 (D11). "Before merge" steps gate the merge to `main`; the others land on `main` after it. The steps before the merge were re-checked on `9d439e4` the same day (D12–D21).

| Step | Size | When | Status |
| :--- | :--- | :--- | :--- |
| S0 | — | — | dropped; its checks are in V |
| S1 | S | before merge | done (2026-11-17), merge `d5d2aa7` |
| S2 | M | before merge | done (2026-11-17), merge `aa3aa9c`; known-bug fingerprints are recomputed in V |
| S3 | M | before merge | done (2026-11-17), merge `018c159` |
| S4 | L | before merge | done (2026-11-17), merge `4de97ca`; replay and minimize accept a candidate's observations (`586d28d`); hypotheses without a line stay at function + kind (open entry in `ledger-and-verifier.md`) |
| S5 | M | before merge | done (2026-11-17), merge `72db709` (in `cd4f827`) |
| S6a | S | before merge | done (2026-11-17), merge `7e431a6`; round wall time is the time left (`cb56350`) |
| S6b | M | after merge (D20) | written on `p1/s6b-wide-selector` (code and tests, then skills and docs), started early (user, 2026-11-17) and rebased onto `phase1-remediation` with S1 to S7 and S12 merged; the compiled wide harness test passes in the analysis image (`FRAMAC_DOCKER_TESTS=1`); lands after the merge |
| S7 | S | before merge | done (2026-11-17), merge `9890f29` |
| S8 | S | after merge | open, after V |
| S9 | M | before merge | done, commit `7be8bd1` (2026-11-14); minmea's `-rte-initialized` opt-out dropped from the benchmark manifest |
| S10 | — | after merge | waits for the user |
| S11 | M | after merge | open |
| S12 | S | F14, F16 before merge; F13 after | F14 and F16 done (2026-11-17, merge `cd4f827`); F13 open |
| S13 | S | after merge | open |
| S14 | M | before merge | done; seeded benchmark 9/9 bugs, 0/4 decoys (run seeded-s14, s09 found by both `tf_fuzz_parse` and the imported corpus in `librcf_a`); a c-ares coverage comparison is still to do |
| V | — | last before merge | ready: S1–S7, F14 and F16 are on the branch (implemented by Claude Haiku 5.5, reviewed per step); waits for the user |
