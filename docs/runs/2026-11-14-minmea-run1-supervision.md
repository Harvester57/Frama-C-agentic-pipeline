# minmea `run-1`: External Supervision Report (2026-11-14)

- **Run directory:** `C:\Users\Florian\framac-pipeline\minmea\run-1` (target `targets/minmea`, commit `c43c9e7c5ed788122a9d8a5445679e1594f8a030`, profile `standard`, scope `minmea.c`, `minmea.h`).
- **Driven by:** an opencode session (model `deepseek-v4.1-flash`), 1 main session and 38 subagent sessions; 38 agent directories in the run.
- **Supervisor:** a separate session that only read the run directory and a copy of the opencode database. It wrote nothing under the run directory.
- **Pipeline code:** `phase1-remediation` at `7369244` plus the uncommitted working tree, which the run bind-mounts. The run's agent changed that working tree while the run was going (see [Changes made by the run's agent](#changes-made-by-the-runs-agent)).

## Why the supervision stopped

The run never reached `complete`: its agent closed it as `incomplete` at 13:55 local time, which is a terminal status. No failure recurred three times. One blocker is external, an E-ACSL internal error, and has an upstream draft (see [External blocker](#external-blocker-e-acsl-and-strlen-loop-variants)).

Three failures went through the fix loop. These did not, on purpose:

- **NaN returns** (`-warn-special-float`), **variadic `minmea_scan`** and **the union under WP's `Typed` model**: fixing them changes what the pipeline proves, which is a design decision.
- **Header `static inline` functions unreachable by the harness** (`minmea_rescale` ended `needs_validation`): needs a harness or driver design, not a bug fix.
- **Sanitizer-only defects replayed on the E-ACSL binary**, **the WP time limits**, **subagents using Docker directly**: recorded as open entries; none stopped the run.
- **Failures the run's agent patched itself** in the working tree (brief harness names, trust-boundary NUL termination, parent guardrail sources): checked by the supervisor, not redone.

## Final status

`run_status: incomplete`. Reason recorded in `run-metadata.json`:

> 19 of 37 ledger units blocked and 1 deferred by callee-side/oracle gaps: variadic minmea_scan has no framing contract, WP Typed model flags union minmea_type, and E-ACSL cannot type a strlen loop variant; all 6 candidates verified (3 confirmed findings, 1 needs_validation, 2 engine-duplicate fingerprints merged into confirmed findings).

| Ledger state | Units |
| :--- | ---: |
| `covered` | 7 |
| `blocked` | 19 |
| `candidate` | 7 |
| `deferred` | 1 |
| `out_of_scope` | 3 |
| Total | 37 |

Every Make run record has `ok: true`; no phase failed at the Make level. The failures below are scheduler-level refusals in Phase 3.

### Findings

| Verdict | Fingerprint | Defect |
| :--- | :--- | :--- |
| confirmed | `minmea.c#minmea_scan::signed_overflow::d8e58750af` | Overflow of the fractional scale in the `f` field parser (`minmea.c:186`, `scale * 10`). |
| confirmed | `minmea.c#minmea_getdatetime::signed_overflow::b7030b5601` | Overflow when the unvalidated `date->month` is `INT_MIN` (`minmea.c:656`). |
| confirmed | `minmea.c#minmea_parse_zda::signed_overflow::ea5e61f9eb` | `abs(INT_MIN)` bypasses the UTC hour-offset range check. |
| needs_validation | `minmea.h#minmea_rescale::signed_overflow::e02d0e78e8` | Overflow in `minmea_rescale` for fields near `INT_LEAST32_MAX`. Reproduced only with a hand-written driver under UBSan; the module harness never calls this header inline. |

Two more candidates (`minmea_scan::525b51da66`, `minmea_getdatetime::5ab43d1511`) are the same two overflows seen through the other engine. They are `verified` in `candidates.json` and have no record of their own in `findings.json`, which holds four records and no field linking a record to a second fingerprint. "Merged into confirmed findings" is the wording of the run's agent in the status reason; how the two were folded was not traced.

The 7 units still in state `candidate` are the `rte`, `l3_frame` and `l2_termination` units of the four functions with a finding (`minmea_scan`, `minmea_getdatetime`, `minmea_parse_zda`, `minmea_rescale`). Whether a unit is meant to stay `candidate` after its candidate is verified was not checked.

## Wall-clock time per phase

Local time (UTC+1). The run was created at 11:42:08 and reached its terminal status at about 13:56: 2 h 14 min.

| Phase | Start | End | Wall clock | Notes |
| :--- | :--- | :--- | ---: | :--- |
| Phase 0 (overlay, build capture, model, harness, reach gate, seed, build) | 11:42:08 | 11:45:23 | 3 min 15 s | `run stubs` and `run seed` failed once before `gen` (Makefile missing). `stubs` never ran. |
| Phase 1 (E-ACSL + LibFuzzer) | 11:45:31 | 11:48:34 | 3 min 03 s | `fuzz` 182.8 s, two sinks found. Coverage and `reach-dynamic` ran later (18.1 s, 12:20:48). |
| Phase 2, Eva base run | 11:48:43 | 11:49:14 | 31 s | |
| Phase 2, `eva-tune` | 11:49:20 | 12:20:39 | 31 min 19 s | 146 to 106 Unknowns, 15 to 12 functions; the `precision` rung and one loop trial hit the 600 s limit. |
| Ingest, replay, WP queue | 12:21:11 | 12:21:36 | 25 s | |
| Phase 3 (crash verifiers, provers, breakers, architect, negotiators) | 12:21:39 | 13:54:42 | 93 min | 38 agents. |
| `wp-sweep` and report | 13:54:42 | 13:56:23 | 1 min 41 s | `report` ran twice (3.4 s, 3.5 s). |

`eva-tune` took 23% of the run for a module whose base run takes half a minute, and Phase 3 took 69%.

## Fix loop

Three Phase 3 failures went through the loop: capture, a subagent in a worktree cut from `phase1-remediation` at `7369244`, reproduction in Docker on a copy of the run, a regression test that fails on current code, a fix, then `pytest -n auto`, ruff and mypy.

**Merged after the run, nothing pushed.** The user first chose to leave the fixes on their branches, then asked for the merge. `phase1-remediation` was fast-forwarded from `7369244` to `1b90874`: three `--no-ff` merge commits, `e2ba684` (F1), `831caf1` (F2) and `1b90874` (F3). The working tree's uncommitted changes were reapplied on top and are still uncommitted.

| # | Failure in the run | Branch | Commits | Worktree |
| :--- | :--- | :--- | :--- | :--- |
| F1 | `step --complete verify-minmea_getdatetime_5ab43d1511`: `confirmed finding ... requires a parent-verified reproducible crash report matching sha256 19de7e90...`, `requeued_ingest_error` | `fix/verifier-scratch-reproducers` | `8f25258` | `.claude/worktrees/fix-verifier-scratch-reproducers` |
| F2 | Guardrail `code_fault` at `minmea.c:186` (`minmea_scan`) held against the candidates of `prove-minmea_tocoord` and `prove-minmea_tofloat` | `fix/guardrail-fault-outside-functions` | `aa63112`, `b967da7` | `.claude/worktrees/fix-guardrail-fault-outside` |
| F3 | `step --complete prove-minmea_parse_rmc`: `$.strengthening_requests[0].caller_function: unexpected property`, `requeued_invalid_result` | `fix/prover-result-schema-hint` | `11e8bfa`, `288c9b6` | `.claude/worktrees/fix-prover-result-schema-hint` |

After the run ended, the supervisor ran the full checks in each worktree at the branch tip:

| Branch | `pytest -n auto` | `ruff check` | `mypy scripts tests tools` | `check_generated_text.py` |
| :--- | :--- | :--- | :--- | :--- |
| `fix/verifier-scratch-reproducers` (`8f25258`) | 4845 passed, 178 skipped | clean | clean (205 files) | exit 0 |
| `fix/guardrail-fault-outside-functions` (`b967da7`) | 4857 passed, 178 skipped | clean | clean (205 files) | exit 0 |
| `fix/prover-result-schema-hint` (`288c9b6`) | 4855 passed, 178 skipped | clean | clean (206 files) | exit 0 |

What was tested about merging:

- **Branch against branch:** pairwise `git merge-tree` of the three branches reports no textual conflict.
- **Combined committed tree (`1b90874`, scratch worktree):** 4879 passed, 178 skipped; ruff clean; `mypy scripts tests` clean (204 files).
- **Main checkout after the merge, with the uncommitted changes reapplied:** 4920 passed, 180 skipped; ruff and mypy clean. One conflict, in the replay loop of `run_guardrail_check`: the branch's loop was kept and the run agent's call to `crash_matches_known_candidate` was dropped (the helper, `known_candidate_fingerprints` and their tests were left uncalled, then deleted). The `framac-wp` skill mirrors under `.agents/skills` and `.claude/skills` were refreshed from `skills/framac-wp` (five files), as the mirror-sync tests require.
- **Branch against the working tree as it stood after the run:** `git apply --check` of each branch's diff. F1 and F3 apply. F2 does not: `scripts/run_eacsl_fuzz.py:2615`, the replay-loop body of `run_guardrail_check`, where the run's agent added its own patch. The branch's loop should be kept.

**The Docker results of F1 and F2 depend on an uncommitted change.** With the committed scripts of `7369244` alone, the minmea E-ACSL build stops on `\initialized(&endptr)` after `strtol` (`minmea.c:224`). The working tree carries the fix for that (the libc effects shim, S9 of the remediation plan, [`../troubleshooting/eacsl-and-fuzzing.md`](../troubleshooting/eacsl-and-fuzzing.md)). The branches are cut from the commit, so they behave as described on minmea only once that change is committed too.

### F1: the parent replays a verifier's scratch reproducers

- **Cause:** `_parent_replay` in `scripts/wp_scheduler.py` replayed only the candidate's own reproducers, while the crash verifier brief says the parent replays the verifier's. A `confirmed` verdict that lists an input the verifier wrote itself was always refused.
- **Fix:** `_complete_verifier` replays the scratch reproducers of `confirmed` records on the candidate's module binary (new `run_eacsl_fuzz.py replay-candidates --fingerprint ... --inputs ... --out-json ...`) and passes that report to `ingest-verifier`. `ledger.py` is unchanged.
- **Docker reproduction (subagent's report):** unfixed scripts give the run's refusal; fixed scripts with the working tree's changes give `ingested`, `confirmed`, `fingerprint_matches: true`.
- **Tests added:**
  - `tests/test_wp_scheduler.py::test_parent_replays_the_scratch_reproducers_a_verifier_confirms_on`
  - `tests/test_wp_scheduler.py::test_a_scratch_reproducer_the_parent_cannot_reproduce_is_still_refused`
  - `tests/test_wp_scheduler.py::test_a_verdict_without_scratch_reproducers_needs_no_extra_replay`
  - `tests/test_fuzz_subcommands.py::test_replay_candidates_fingerprint_replays_given_inputs_on_the_candidates_binary`
- **Left open:** the ledger accepts a reproducer whenever the parent's replay fails, whatever the failure. With the committed scripts alone the verifier's seed failed on `\initialized(&endptr)` and the finding was still confirmed (`fingerprint_matches: false`).

### F2: an E-ACSL failure outside the checked functions is not a `code_fault` of the contract

- **Cause:** `minmea_tocoord` and `minmea_tofloat` are `static inline` in `minmea.h`. Frama-C rejects `-rte-select` for them, the build falls back to instrumenting the whole module, and every replay stops on the known overflow of `minmea_scan`. `crash_outside_checked_functions` excused only crashes with no E-ACSL report.
- **Fix:** new `failure_outside_checked_functions` in `scripts/run_eacsl_fuzz.py`. A corpus input that fails in a function that is not checked is dropped and listed in `excluded_inputs`; a failing mutation makes the guardrail replay the corpus without mutations; past the limit of 8 the status is `guardrail_error`, never `code_fault` or `rejected_overconstrained`.
- **Docker reproduction (subagent's report):** with the working tree's changes plus the branch the `minmea_tocoord` guardrail returns `passed_dynamic_oracle`. With the committed scripts plus the branch it returns `guardrail_error`, because that build also fails on `\initialized(&endptr)` at `minmea.c:224` (the uncommitted shim fix named above).
- **Tests added (all in `tests/test_guardrail_p1.py`):**
  - `test_eacsl_failure_outside_the_checked_functions_is_named`
  - `test_eacsl_failure_in_or_below_a_checked_function_or_unknown_scope_is_not_excused`
  - `test_eacsl_failure_without_a_stack_or_a_named_function_is_not_excused`
  - `test_guardrail_drops_an_input_whose_eacsl_failure_is_in_another_function`
  - `test_guardrail_keeps_the_code_fault_in_or_below_a_checked_function`
  - `test_guardrail_keeps_a_contract_violation_of_the_checked_function`
  - `test_module_wide_guardrail_never_excuses_a_failed_annotation`
  - `test_guardrail_never_blames_the_contract_past_the_exclusion_limit`
  - `test_guardrail_skips_the_mutation_burst_when_a_mutation_fails_in_another_function`
  - `test_guardrail_keeps_the_code_fault_of_a_mutation_in_a_checked_function`
  - `test_guardrail_never_blames_the_contract_for_an_input_it_cannot_drop`
- **Left open:** the dropped `-rte-select` itself. A header inline under proof still gets a whole-module build and its reach is `null`, so a pass does not show the contract was exercised. An excluded fault is recorded only in the guardrail report, not ingested as a candidate.

### F3: an agent result is not lost to one unknown key

- **Cause:** the result schema forbids unknown keys in a strengthening request. The prover brief named the allowed keys only in prose far above the result skeleton, never said the list is closed, and no brief made the agent validate its result. The scheduler gave the re-run none of the validation errors.
- **Fix:** the prover brief shows one request entry next to the skeleton; the four agent briefs end with a validation step (`validate_artifacts.py agent-result`); on `requeued_invalid_result` the scheduler passes the errors to the re-run's brief. The schema stays closed.
- **Tests added:**
  - `tests/test_brief_result_contract.py` (new file): `test_prover_brief_shows_exactly_the_schema_keys_of_a_strengthening_request`, `test_brief_makes_the_agent_validate_its_result_before_returning`, `test_brief_of_a_rerun_names_why_the_previous_result_was_rejected`, `test_rejected_result_errors_cannot_leave_their_code_block`, `test_prover_brief_step_c_names_the_same_request_keys`, `test_brief_result_skeleton_has_only_schema_keys`
  - `tests/test_wp_scheduler.py::test_rerun_after_an_invalid_result_is_told_the_validation_errors`
- **Left open:** `workspace_overlay.py prepare-agent` cannot render the rejected-result section by hand; the validator CLI does not run the scheduler's own identity checks; whether a live prover runs the validation step was not tried.

## External blocker: E-ACSL and `strlen` loop variants

WP proves a `strlen` loop variant for the string walks of `minmea_checksum` and `minmea_check`, but the E-ACSL guardrail fails to compile it: `[e-acsl] Failure: typing was not performed on construct strlen(sentence)`. Their termination units stayed blocked.

A diagnosis subagent classified it as an **upstream E-ACSL bug**, an internal error present in 34.0~beta and 35.0~~dev. The supervisor reran the minimal reproducer in the analysis image and got the same abort (exit 4, "Please report as 'crash'").

- **Trigger:** a `loop variant` whose term is exactly one application of a logic function that reads memory. A 17-line file with its own logic function and no header reproduces it. The same application in an `assert`, `requires`, `ensures` or `loop invariant`, or as a strict subterm of the variant, translates.
- **The run agent's hypothesis is refuted:** the host C `strlen` plays no part.
- **Upstream draft (not filed):** [`../upstream/frama-c/frama-c-eacsl-loop-variant-logic-function-application.md`](../upstream/frama-c/frama-c-eacsl-loop-variant-logic-function-application.md), Issue 16 of [`../upstream/frama-c/frama-c-e-acsl-issues.md`](../upstream/frama-c/frama-c-e-acsl-issues.md).
- **Workaround (subagent's result, not rerun by the supervisor):** `loop variant strlen(sentence) + 0;`. On `minmea_checksum` in a copy of the run, WP returns `all_proven` (11/11) and the guardrail `passed_dynamic_oracle`.
- **Pipeline side, open:** with today's prelude E-ACSL ignores the rewritten variant, so termination rests on WP alone and the guardrail report does not say so. Giving the prelude's `strlen` a C result type makes the variant checked at run time; tried on a scratch copy of the templates only, not applied. The prover brief does not warn against a bare `strlen(s)` variant.
- **Found on the way, open:** `run_wp_function.py` can return `unproven_goals_remain` with 11/11 goals counted as proved and an empty unproven list when only loop-variant goals time out ([`../troubleshooting/wp-and-guardrail.md`](../troubleshooting/wp-and-guardrail.md)).

## Changes made by the run's agent

The run's agent edited the pipeline in the working tree during the run (uncommitted, not reviewed line by line by the supervisor):

| Change | Files | Supervisor check |
| :--- | :--- | :--- |
| Briefs name the sub-module harness (`{harness_module_name}`) | `scripts/workspace_overlay.py`, `scripts/wp_scheduler.py`, three briefs, `tests/test_workspace_overlay.py` | Tests, ruff, mypy pass. |
| Guardrail drops inputs that hit a known candidate (`crash_matches_known_candidate`) | `scripts/run_eacsl_fuzz.py`, `tests/test_run_eacsl_fuzz.py` | Tests pass, but the new call is unreachable for a `code_fault` (the loop exits first), and it ignores which functions are under proof. Superseded by F2: the call was removed when F2 was merged, and the helper and its tests were deleted afterwards. |
| A synthetic trust-boundary entry inherits NUL termination | `scripts/workspace_overlay.py`, `tests/test_r3_trust.py` | Tests, ruff, mypy pass. |
| The parent guardrail takes its sources from the harness module that answers for the function | `scripts/workspace_overlay.py`, `tests/test_workspace_overlay.py` | Covered by the full-suite run below. |

After the run ended, the supervisor ran the checks on the working tree as it stands, with all of these changes: `pytest -n auto` 4880 passed, 180 skipped; `ruff check` clean; `mypy scripts tests tools` clean (205 files).

## Where the agent struggled because of the pipeline

Each item has an entry in [`../troubleshooting/`](../troubleshooting/README.md); the supervisor's entries are marked there.

- **The run was not blind.** Asked for a standard analysis, the agent took the harness expression, threat model, build recipe and known-bug list from `benchmark/manifest.json`, and recorded the recipe as `agent_confirmed` without asking the user ([`../troubleshooting/resources-and-infra.md`](../troubleshooting/resources-and-infra.md)).
- **Phase 0 order.** The skill orders `run stubs` and `run seed` before `gen`, which cannot work; `stubs` never ran.
- **One overflow, two candidates.** The E-ACSL and UBSan messages of the same overflow hash to different fingerprints, so 2 defects became 4 candidates and 4 verifiers ([`../troubleshooting/eacsl-and-fuzzing.md`](../troubleshooting/eacsl-and-fuzzing.md)).
- **`eva-tune` cost.** 31 minutes for 40 fewer Unknowns, with two 600 s timeouts and a timed-out rung whose `error_summary` is preprocessor noise ([`../troubleshooting/eva.md`](../troubleshooting/eva.md)).
- **`"dirty": true` on a clean target.** CRLF checkout seen from the Linux container; not reproduced in a container ([`../troubleshooting/phase0-build-and-model.md`](../troubleshooting/phase0-build-and-model.md)).
- **Header `static inline` functions.** `minmea_rescale`, `minmea_tocoord` and `minmea_tofloat` have no caller in the compiled unit: `-rte-select` is dropped (F2), a breaker campaign cannot reach them, and a real overflow in `minmea_rescale` could only be recorded as `needs_validation`.
- **NaN returns.** `-warn-special-float non-finite` makes `return NAN;` an unprovable goal. Left open on purpose: changing it changes what is proved.
- **Variadic `minmea_scan` and the union.** Every `minmea_parse_*` prover stalls on `assigns \everything` and on `[wp:unsupported:union]` with the `Typed` model. Left open: a design decision.
- **Sanitizer-only defects.** A verifier replaying on the E-ACSL binary gets `not_reproduced` for an `abs(INT_MIN)` overflow that only UBSan reports ([`../troubleshooting/ledger-and-verifier.md`](../troubleshooting/ledger-and-verifier.md)).

- **WP limits.** One WP call may run 3,600 s while the scheduler asks a prover to finalize after 900 s; a `minmea_check` WP call ran about 19 minutes, and the prover started a second run on the same output directory meanwhile ([`../troubleshooting/wp-and-guardrail.md`](../troubleshooting/wp-and-guardrail.md)).

- **Subagents used Docker directly.** Breakers started their own containers (`docker run`, one named `breaker-minmea-check` with limits the agent typed) and ran campaigns with `docker exec` inside containers the wrapper had started for other agents. Those containers take no broker lease and carry no run label, while `REPORT.md` states the run was sandboxed ([`../troubleshooting/resources-and-infra.md`](../troubleshooting/resources-and-infra.md)).
- **Recorded resources.** `run-metadata.json` records 1 CPU and 1,024 MB, the grant of the container that wrote it, although the broker pool was 30 CPUs and containers ran on up to 8 cores (same document).

Observations with no troubleshooting entry (agent behaviour or target-side, not pipeline defects as far as checked):

- **Tasks marked running without an agent.** The rescale verifier and breaker were marked running at `--prepare` and sat about 18 minutes before the agent spawned them; the scheduler's `FINALIZE NOW` warning exposed it. Read as an orchestration miss, not a scheduler bug.
- **Images rebuilt mid-run.** The user told the agent to use the latest Docker image versions and the images were rebuilt during the run.
- **Subagents read each other's scratch.** They run on the host, so a breaker read another agent's `result.json` and driver; isolation between agents is by brief only.
- **Windows shell slips.** Subagents repeatedly tried `grep`, `sed`, `basename`, `/dev/null` and heredocs in PowerShell, and hit `cp1252` decoding errors reading JSON; each cost a tool call, none a result.
- **`dag_cppflags_missing: ["-std=c99"]`** was reported for the module; its effect on the analyses was not examined.

## Leftovers

- The three fix worktrees and branches listed under [Fix loop](#fix-loop) were removed after the merge, at the user's request; the commits are reachable from `phase1-remediation`.
- The reproduction copies under `C:\Users\Florian\framac-pipeline\minmea-repro\` were deleted at the same time. The E-ACSL reproducer is inline in the upstream draft. No reproduction container is left running.
- The working tree described above as uncommitted was committed on `phase1-remediation` later the same day, in topic groups: `438267e` (Frama-C 34 Eva options), `7be8bd1` (libc effects shim and libc checks, S9), `181f814` (the run agent's changes), then the documentation. Statements in this report about "the working tree" or "uncommitted" changes describe the state during and right after the run.
