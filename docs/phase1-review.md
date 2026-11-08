# Phase 1 Review: Coherency and Defects (2026-11-08)

**Status:** review findings; remediation on branch `phase1-remediation`. 15 of the 17 rows are still Open (F4 fixed, F6 partly fixed).

This review comes from a read-only pass over Phase 1 (`/framac-fuzz`). It covered:
- the skill;
- `run_eacsl_fuzz.py`;
- the Make recipes in `templates/pipeline.mk`;
- `harness_reach.py dynamic`, `fingerprint.py`, `ledger.py ingest-fuzz`;
- the corpus cache in `cache.py`, and `sandbox_exec.py`.

It was read at commit `60107a9` on `phase0-redesign`; line numbers refer to that commit. Nothing was run. F1–F16 were found in the code, and none of them has been reproduced on a target yet. F17, D4 and the cross-engine point under D1 were added afterwards from earlier target runs: libmnl runs 5 and 6 (2026-11-07; run directories outside this repository), minmea and x509-parser (`docs/benchmark.md`). Each remediation names a test that would confirm the defect before fixing it.

The fixes are planned in [`phase1-remediation-plan.md`](phase1-remediation-plan.md) (steps S0–S13 and V), on branch `phase1-remediation`. That plan re-checks every defect on `main` at `edcbf50` and records the decisions taken since this review.

Priorities and classes follow `docs/remediation-plan.md`:
- **P0 Critical**: a unit credited without the evidence the claim implies.
- **P1 High**: the workflow cannot finish correctly, loses findings, or weakens isolation.
- **P2 Medium**: silent degradation, or an instruction that does not match the code.
- **P3 Low**: documentation drift.

Classes: `soundness`, `workflow`, `recall`, `isolation`, `degradation`, `doc`. No P0 defect was found.

## Summary

Phase 1 is coherent as a pipeline: gates, caching, sizing, sandboxing and the "candidates are not findings" rule are applied consistently. The defects cluster in two places:

- **The dual-engine change** (`ea15b2a`: ASan+UBSan, then E-ACSL, in one campaign) was layered on a design built around E-ACSL. Fingerprints, alarm-kind mapping, the docs and the skill's rationale still assume E-ACSL output (F1, F4, F5, F8, F10, F13, F14).
- **Interactions between components** give wrong results: the dynamic reach gate against keep-going rounds (F2), the dynamic reach gate against ingest (F11), and ledger evidence against coverage (F7).
- **E-ACSL has not yet paid for its half of each campaign** on any target. Every libmnl and minmea bug it found, ASan found too, and some of its share is spent on libc false alarms (F17, D4).

---

## P1 High

| ID | Class | Defect | Remediation | Status |
|---|---|---|---|---|
| F1 | recall | **ASan fingerprints are too coarse.** `parse_sanitizer_failure` builds the predicate as `AddressSanitizer: <kind> (READ of size N)` (`run_eacsl_fuzz.py:532`), and fingerprints carry no line number (`fingerprint.py`, `make_fingerprint`). Two distinct overflows in one function with the same access size merge into one candidate: the verifier sees one, and the other is lost. ASan runs first in every `auto` campaign, so this is the common path. | Add a discriminator that survives line shifts to the ASan predicate: the source text of the faulting line, or the callee of the top frame (for interceptors, `memcpy` called from `f`). Never the line number. **Test:** two planted overflows of the same size in one function, one campaign; expect two candidates. | Open |
| F2 | workflow | **A crashing entry point can fail the dynamic reach gate, and that blocks Phase 3 for the whole run.** The chain: crash inputs go to `workspace/crashes/<mod>/`, never to the corpus; keep-going rounds mask the crashed dispatch case; `coverage-<mod>` replays only the corpus and the seeds (`templates/pipeline.mk:134`); `check_dynamic` (`harness_reach.py:468`) then reports the entry point as never executed, unless the tests recorded seeds for that case. `wp-queue` checks reach for every module (`templates/pipeline.mk:261`, `phase0_gates.py:146`), so one gap that depends on budget or luck stops Phase 3 for every module. The skill's advice ("repair the harness or exempt the entry point") is wrong for a harness that worked. | (a) Count an entry point as executed when a crash artifact of its module selects its case, or when the artifact's replay failure names it. Alternatively, replay `crashes/<mod>/` on the coverage build as an extra corpus. (b) Make a dynamic gap exclude that module's units from the WP queue, with a recorded reason, instead of failing `wp-queue` for the run. **Test:** a dispatch harness in which one case crashes on every input. | Open |
| F3 | recall | **Keep-going rounds stop silently on large dispatch harnesses.** A crash in case 64 or above gives `new == []` (`run_eacsl_fuzz.py:1328`): the loop ends with no `stopped` reason and the rest of the budget is unused. The selector is one `uint8_t` (`generate_harness.py:766`), so cases from 256 up can never run. When N does not divide 256, the low cases also get more inputs. | Phase 0: use a two-byte selector when N > 256. Phase 1: widen the skip mask (several 64-bit words, or a generated table); or, past case 63, fall back to fork mode with `-ignore_crashes=1` and record `stopped: case_beyond_mask`. **Test:** a 70-case harness that crashes in case 65. | Open |

## P2 Medium

| ID | Class | Defect | Remediation | Status |
|---|---|---|---|---|
| F4 | degradation | **UBSan fingerprints change with the input.** The predicate is the raw runtime message (`run_eacsl_fuzz.py:500`, `:518`), and `normalize_predicate` (`fingerprint.py`) strips neither values nor addresses (`2147483647 + 1`, `index 1025`, `misaligned address 0x7ffd...`). One bug becomes many candidates, each costing a verifier subagent. The misaligned-address message carries an address that changes with ASLR, so `fingerprint_matches` in `replay-candidates` can fail on the very input that produced it. | Before hashing, reduce UBSan messages to their template: numbers, addresses and quoted values become placeholders. Keep the raw message as evidence. **Test:** one signed overflow hit with two different operand values; expect one candidate. | Fixed in `684052f`: `stable_ubsan_message` replaces integers, hex addresses and floats by `N` in the predicate, and the printed message moves to a `message` field. Tests are in `tests/test_tool_parsing.py`. |
| F5 | degradation | **No identity across engines.** The same bug found by ASan and by E-ACSL gets two fingerprints, and neither matches Eva's alarm at the same site. The `fingerprint.py` docstring ("the same root cause keeps the same identity across tools") holds only for E-ACSL, Eva and WP. | D1 step 2 (option D): group candidates by a `site` key (file + function + normalized statement), keeping each engine's fingerprint as an observation of that candidate. Eva's alarms and Phase 3 hypotheses join by the same key. **Test:** a planted overflow both engines find, plus an Eva alarm at the same statement; expect one candidate with three observations. | Open |
| F6 | degradation | **Keep-going depends on the machine and the profile.** Wall time is budget ÷ workers (`campaign_wall_time`, `run_eacsl_fuzz.py:2666`), and a new round needs at least 30 s of wall time left (`MIN_FUZZ_WALL_S`, `:1331`). With the dual-engine split, a machine with as many workers as cases gives each engine about 30 s under `quick`, so its first crash ends that engine's campaign. A bigger node gets fewer rounds from the same CPU budget. That makes the number of distinct bugs found depend on the hardware, against the rule that result-deciding limits stay fixed. | Bound rounds by CPU-seconds spent, a share of the budget, not by wall seconds. Record the rounds run, and why they stopped, in the report. **Test:** the same module with 1 worker and with 8 workers; compare `keep_going.rounds`. | Partly fixed in `bd3f909`: a round after the first now needs 5 s of wall time left (`MIN_ROUND_WALL_S`); the first still needs 30 s. Still open: rounds are bounded by wall seconds, not CPU-seconds, so the number of rounds still depends on the worker count. |
| F7 | soundness | **`fuzz_clean` evidence for functions the fuzzer never ran.** `cmd_ingest_fuzz` adds `fuzz_clean` to every unit of the module (`ledger.py:577`), whatever `workspace/reports/coverage/<mod>.json` says. The ledger then claims a clean campaign for functions with `executions: 0`. It is not `covered`, but it overstates what ran. | Read the module's coverage report in ingest. Functions with `executions: 0` get `fuzz_not_executed` evidence instead of `fuzz_clean`, and units of a module without a usable coverage report get a note saying so. **Test:** a module with an internal function no input reaches. | Open |
| F8 | recall | **ASan double-free and bad-free are misparsed; leaks are not parsed.** `_ASAN_ERR_RE` captures one word (`run_eacsl_fuzz.py:237`), so "attempting double-free" becomes kind `asan_attempting` with class `mem_access`, and the `"attempting free"` branch of `_map_sanitizer_alarm_kind` (`:268`) can never match. LeakSanitizer reports do not match the ASan header, so leak artifacts become `unknown_function` candidates. | Capture the whole ASan headline up to ` on ` or the address. Map double-free and bad-free to `freeable`. Either parse LeakSanitizer's first allocation stack, or rule leaks out of scope and run with `-detect_leaks=0`. Decided: parse them (plan D5). **Test:** parser unit tests on recorded ASan and LSan output. | Open |
| F9 | degradation | **One engine's failure is hidden by the other's crash.** `merge_engine_campaigns` (`run_eacsl_fuzz.py:1388`) reports `crash_found` when ASan crashed, even if the E-ACSL pass hit `fuzzer_error`. Only `engines` keeps the failure, and ingest does not read it. | Ingest each engine's status: add `fuzz_fuzzer_error` evidence for the engine that failed, and give the report an `engine_errors` field. **Test:** a unit test of the merge. | Open |
| F10 | degradation | **UBSan checks what RTE deliberately leaves out.** *(Not yet confirmed on a target.)* `compile_sanitizer_binary` uses the whole `-fsanitize=undefined` (`run_eacsl_fuzz.py:1133`), including `alignment` and `pointer-overflow`. Misaligned access is normal in packet parsers. It would stop campaigns on early inputs, the same reason RTE leaves unsigned overflow out while fuzzing, and those alarms are filed as `mem_access`. | Confirm on libmnl first. If it fires, add `-fno-sanitize=alignment` (and decide on `pointer-overflow`). Document the sanitizer check set next to the RTE one in the skill. | Open |
| F11 | workflow | **The dynamic reach gate does not stop what the skill says.** `skills/framac-fuzz/SKILL.md:142` says a failure stops fuzz and Eva of the module. `reach-dynamic` runs after both have finished, and `ingest` is not gated, so the module's reports are ingested anyway. In practice the gate blocks only `wp-queue` and the next run. | Either gate `ingest` per module on reach (a gated module's reports are recorded as `gated` evidence), or fix the text. Decide together with F2(b). | Open |
| F12 | isolation | **`run_sandboxed(writable=...)` is not enforced.** It sets cwd and HOME only (`sandbox_exec.py:182`). The module docstring says fuzzed code can write the whole run directory, `candidates.json` and the ledger included, which undercuts "the parent is the only writer". This is documented, but the parameter name promises more. | Rename the parameter (`work_dirs`). Longer term: run fuzz and replay children with the run directory read-only and only their own directories writable (a mount namespace inside the container, if the hardened profile allows one). | Open |
| F17 | recall | **E-ACSL raises false alarms on values libc writes through out-parameters.** *(Seen on targets.)* E-ACSL runs on host headers without Frama-C's libc specifications (`templates/fc_stubs/README.md`), so it does not see a libc call write an out-parameter. With `-rte-initialized`, the next read of that value fails as `initialization`. Two cases so far: `getsockname` in libmnl's socket module (libmnl runs 5 and 6, rejected by the Crash Verification Gate) and `strtol`'s `endptr` in minmea (`docs/benchmark.md:63`). Each one costs a verifier run in every run. Worse, keep-going masks the dispatch case that raised it, so the E-ACSL half never explores past it, which is exactly where its uninitialized-read checks would matter. Nothing in the scripts filters a known false alarm before the verifier. | Options: (a) E-ACSL-only wrappers that mark the out-parameter initialized after the libc call, in `templates/fc_stubs` (as `errno.h` already does for `errno`); (b) a list of known libc false alarms keyed by fingerprint (fragile, and depends on D1); (c) remembering the verifier's rejections across runs (saves verifier runs, but the case stays masked). Only (a) removes the masking. Decided: (a) (plan D6). Fix before deciding D4. **Test:** a harness that calls `getsockname`, then reads the returned address; expect no E-ACSL alarm. | Open |

## P3 Low

| ID | Class | Defect | Remediation | Status |
|---|---|---|---|---|
| F13 | doc | The skill's rationale (`skills/framac-fuzz/SKILL.md:20`–`26`) argues for E-ACSL only: sub-object bounds, and coverage guided by ACSL branches. Under `auto`, half of each campaign runs on ASan, which has neither. The skill's `description` does not mention the second engine. | Rewrite "Why This Runs Before Eva and WP" to cover both engines, what each catches, and how the time is split. Update the description. | Open |
| F14 | doc | `skills/framac-verify/SKILL.md:108` says the build check makes sure "Phase 1 never falls back to ASan/UBSan silently". Under `auto` every module is fuzzed with ASan anyway, so the sentence no longer says anything useful. | Reword: the build check makes sure the E-ACSL half of each campaign can run. | Open |
| F15 | workflow | `build-<mod>` reads the selftest result without depending on `selftest` (`templates/pipeline.mk:92`), and the campaign rebuilds anyway (`run_eacsl_fuzz.py:4192`). On a first run, `workspace/build/<mod>.build.json` can name a different engine than the campaign used. | Make `build-%` depend on `selftest` (it runs once and is cheap), or stop reading the selftest result in `build`. | Open |
| F16 | doc | The Phase 1 diagram in `docs/architecture.md` is stale. It shows harness generation and the static reach gate in Phase 1 (both are Phase 0 now). It labels a crash "True Bug", against "candidates are not findings". It still routes clean Tier 2 modules to "Keep in CI Fuzzing", a route that no longer exists. | Redraw Phase 1 from the Make targets: `selftest`, `build`, `seeds`, `fuzz`, `coverage`, `reach-dynamic`, `ingest`, `replay`, `minimize`. | Open |

---

## Design questions

These are not defects. Each needs a decision before the related fixes.

- **D1. What identity a sanitizer crash gets. Decided 2026-11-08: option A first, then option D as the final design.**

  Treating sanitizers as a mere supporting signal is not an option. On libmnl, ASan alone found 4 of the 5 known bugs and E-ACSL alone found 2, and some bugs only ASan sees (libc misuse such as an overlapping `memcpy`). Those need an identity of their own. The real question is which identity a crash gets and what it is matched with. An identity has to:
  - merge the many crash inputs of one bug into one candidate;
  - merge the same bug found by ASan and by E-ACSL;
  - match Eva's alarm at the same place;
  - link to ledger units by function and obligation class;
  - survive the line shifts that Phase 3's ACSL insertions cause (hence no line numbers);
  - stay equal on replay: `fingerprint_matches` in `replay-candidates` and the cvise interest test (`minimize_interest`, `run_eacsl_fuzz.py:3098`) both require the same fingerprint. Runtime values in UBSan IDs make cvise reject nearly every reduction. Coarse ASan IDs let minimization drift to a different bug in the same function.

  Options considered:

  | | Merges engines | Matches Eva | Keeps today's fingerprints | Main risk | Cost |
  |---|---|---|---|---|---|
  | A. Normalize each engine, keep today's format | no | no | yes | duplicate verifier runs | low |
  | B. Translate sanitizer crashes to the E-ACSL identity | partly | partly | yes | wrong bug's identity | medium |
  | C. Statement-based fingerprint for every tool | yes | yes | no | format change everywhere | medium–high |
  | D. Two levels: per-engine fingerprints, grouped by statement | yes | yes | yes | site extraction quality | medium |

  - **B rejected.** E-ACSL also checks initialization and ASan does not, so the E-ACSL replay often stops at an earlier, different alarm. The candidate then takes another bug's identity. B still needs A for bugs only ASan sees, so it adds code rather than saving it.
  - **C not chosen.** It changes the fingerprint format for Eva, the WP breakers, the verifiers' refingerprinting and the seeded-bug IDs in `benchmark.py`, which breaks comparison with earlier runs.

  **Decision.**
  - **Step 1, option A (F1, F4, F8).** Per-engine fingerprints that are stable, in today's format. UBSan messages are reduced to templates, keeping the raw message as evidence; this part (F4) is done in `684052f`. The whole ASan headline is parsed. The ASan predicate gets a discriminator that survives line shifts: the normalized source text of the faulting line, or the intercepted function plus its caller. Never a line number. This step lands on its own and makes replay and minimize reliable.
  - **Step 2, option D (F5).** Fingerprints stay the IDs of individual detections (observations), and replay and minimize keep using them. A `site` key is added: file + function + a hash of the normalized faulting statement, with an occurrence index for statements that repeat in a function. Ingest groups candidates by site across fuzz ingest (both engines), Eva ingest and Phase 3 hypotheses. A candidate gains `site` and `observations` (fingerprint, engine, artifact, raw message). Its key stays the fingerprint of its first observation, so existing candidate IDs and benchmark seeded-bug lists keep working. The site key leaves out the alarm class, because ASan says `mem_access` where E-ACSL says `index_bound` for the same access. The class comes from E-ACSL or Eva when either is present, and from the sanitizer mapping otherwise. When one site holds two root causes, the verifier splits the candidate (`skills/framac-wp/crash_verifier_brief.md:81`).

  Settled on 2026-11-08 (plan D1a–D1c and D5):
  - the site is the normalized text of the faulting line;
  - Phase 3 keys on the site when a hypothesis has a line;
  - leaks are in scope (LeakSanitizer parsed, kind `leak`);
  - one bug seen at two statements is linked by a cross-engine replay.

  The questions, as they were posed:
  - **Where the site comes from.** The cheap way hashes the normalized text of the faulting source line. The precise way maps line to statement through the kernel AST dump; whether `scripts/kernel_ast_dump.ml` records statement spans has not been checked.
  - **Phase 3's merge.** Phase 3 merges hypotheses at function + kind level (`_find_matching_sink_candidate`, `ledger.py:1529`). It should probably move to the site key, since two merge rules at different granularities repeat the same incoherence.
  - **Leaks (F8).** Either parse LeakSanitizer output or rule leaks out of scope with `-detect_leaks=0`.
  - **One bug at two statements.** Libmnl run 6 confirmed LIBMNL-04 twice: E-ACSL at `nlmsg.c:311` (an uninitialized read, rated medium) and ASan at `:339` (the read past the buffer, rated low). They are different statements, so the site key keeps them apart too. The strong signal is the input: one reproducer makes both engines fail in the same function. Proposal, not yet decided: at ingest, replay each engine's reproducers on the other engine's binary. When the replay fails in the same function at another site, link the two candidates, so that one verifier sees both and can record them as one finding. This is option B's mechanism, used to link candidates rather than to assign identity.
- **D2. How fine the gates are. Decided 2026-11-08: the module's units leave the WP queue (plan D2, step S5).** The static reach gate failing the whole run is reasonable: it depends only on the harness. The dynamic gate depends on budget, seeds and luck, so it should act per module (F2(b), F11). What remains to decide is what a module that fails the dynamic gate gets:
  - **Its units leave the WP queue** with a recorded reason (`gated` evidence), and the rest of the run goes on. The cheapest choice, and the gap stays visible in the report.
  - **It is fuzzed again**, with the crash artifacts as extra corpus, before the gate is checked again. It costs time, and the outcome still depends on luck.
  - **Someone exempts the entry point**, as for a harness that cannot reach it. It needs a human, and it is the wrong answer for a harness that worked (F2).

  **Decision:** the first option. A re-fuzz stays a manual follow-up, and a dynamic gap no longer stops fuzz, coverage or Eva of the module, since those are what can close it.
- **D3. `run_eacsl_fuzz.py` does too much. Decided 2026-11-08: option B first, then option C.**

  Status: 4,298 lines and 10 subcommands (campaign, guardrail, selftest, build, replay, replay-candidates, coverage, minimize, minimize-candidates, minimize-interest). The module docstring lists only the first 7. Approximate split by concern:

  | Concern | Lines | Used by |
  |---|---|---|
  | Failure parsing and identity (regexes, E-ACSL/ASan/UBSan parsers, kind mapping, `_failure_fingerprint`) | ~400 | campaign, replay, minimize, guardrail |
  | Builds (two-stage E-ACSL, Clang, sanitizer, coverage, link repair, cache) | ~780 | every subcommand |
  | Campaign (rounds, engine merge, artifact dedup, dictionary cleanup) | ~700 | Phase 1 |
  | Guardrail and diagnostic hints | ~480 | Phase 3 (`prover_candidates.py`, the WP skill) |
  | Replay and replay-candidates | ~400 | crash verification gate |
  | Minimize | ~260 | crash verification gate |
  | Coverage | ~290 | dynamic reach gate |
  | Selftest | ~150 | Phase 0 build check |
  | CLI (argparse, `main`, mode runners) | ~670 | Make |

  - **A split stays internal.** The command line is the real interface: Make calls six subcommands, and Phase 3 calls `guardrail`. Only `workspace_overlay.py` and `benchmark.py` import from the module in Python, one constant each.
  - **Test patches are the main cost.** 19 test files import the module, with 88 `monkeypatch.setattr` calls on it, 34 of them on `run_sandboxed`. Those patches replace names in this module's globals. Moving a function that calls `run_sandboxed` elsewhere silently disarms them: the test then either runs the real sandbox or fails in a confusing way.
  - **Two earlier extractions stopped halfway.** `eacsl_toolchain.py` took the e-acsl-gcc invocation contract. `fuzz_dictionary.py` took dictionary building, but the ~200 lines of dictionary cleanup (`sanitize_dictionary_*`) stayed behind.

  Options considered:
  - **A. Fix in place.** No move. Failure identity keeps having no owner just as D1 makes it Phase 1's most important code.
  - **B. Extract failure identity only.** About 400 lines of pure functions that never call `run_sandboxed`, so no test patch breaks.
  - **C. Split by consumer.** Separate the guardrail, replay/minimize, coverage and build code.
  - **D. A full `scripts/fuzz/` package.** Not chosen: the largest diff, every patch retargeted, and nothing in this review needs it.

  **Decision.**
  - **Step 1, option B, together with D1 step 1.** A new module owns the E-ACSL, ASan, UBSan and LSan parsers, the sanitizer kind mapping, `_failure_fingerprint` and attribution. Later it also owns D1's normalization and the site key, so the ledger and the verifiers can import them without loading the whole fuzz script. `run_eacsl_fuzz.py` re-imports the names. Do it in two commits: a pure move, then the fixes (F1, F4, F8), tested against a fixture corpus of real tool output. The dictionary cleanup moves into `fuzz_dictionary.py` in the same pass. The docstring gets all 10 subcommands.
  - **Step 2, option C.** In this order:
    1. **Sandbox seam first.** Every module calls the sandbox through one shared attribute (`sandbox_exec.run_sandboxed`), and the tests patch only that. Before anything else moves, check all 88 patches against the new targets.
    2. **Builds** get their own module, because replay, coverage and the guardrail all need them.
    3. **Replay and minimize** move to a crash-replay module for the verification gate, together with D1 step 2 (which changes `replay-candidates` to handle observations anyway).
    4. **Coverage** moves to a reach module.
    5. **The guardrail** becomes its own script, since Phase 3 is its only user.

    `run_eacsl_fuzz.py` keeps its 10 subcommands as thin dispatchers until Make, the skills and `prover_candidates.py` are moved to the new entry points. Then it keeps build, campaign and selftest.
- **D4. Is E-ACSL worth half of every campaign? Open; decide after F17.** Under `--engine auto`, each campaign gives ASan+UBSan the first half of the wall time and E-ACSL the second (`share = max(30, max_time // 2)` in `_run_campaign_mode`). The evidence so far:
  - **libmnl run 6** (both engines, half the time each): ASan found LIBMNL-01, -03, -04 and -05. E-ACSL found -04 and -05, both also found by ASan, and raised the only false alarm (F17). In run 5 (E-ACSL only) it found -05 and probably -04, and missed -01 (E-ACSL has no overlap check) and -03.
  - **minmea:** E-ACSL misses MINMEA-01 to 03 (`abs(INT_MIN)` is a UBSan check), and it stops earlier at the `strtol` false alarm (`docs/benchmark.md:63`).
  - **x509-parser:** E-ACSL cannot build the target, so only the sanitizers run (`docs/benchmark.md:135`).

  E-ACSL's stated advantages have not yet shown up on a target: sub-object overflows, uninitialized reads, and coverage guided by ACSL branches (`skills/framac-fuzz/SKILL.md:20`–`26`). Options:
  - keep 50/50;
  - shift the fixed share toward the sanitizers;
  - stop fuzzing with E-ACSL and use it only to replay sanitizer crashes. That still gives the exact ACSL class D1 step 2 prefers, and the cross-engine replay proposed under D1.

  Whatever the choice, the split stays a fixed ratio, never sized from machine speed, so results do not depend on the hardware (see F6). Decide only once two things hold: F17 is fixed, since some of E-ACSL's weak showing may be its false alarms; and the seeded benchmark contains bugs only E-ACSL can catch (not checked yet). F13's rewrite of the skill's rationale follows this decision.

## Noted outside Phase 1

- **LIBMNL-02 is still out of reach.** It needs an unaligned `nlmsg_len`, which the API-only harness cannot produce. That is a limit of Phase 0's harness generator (`generate_harness.py`), not of Phase 1.

## Suggested order

Superseded by the steps of [`phase1-remediation-plan.md`](phase1-remediation-plan.md); kept as it was agreed.

0. **Confirm on libmnl:** one run with the current code, to reproduce F2, F6 and F10 before fixing them.
1. **Failure identity (D1 step 1, D3 step 1):** move failure parsing into its own module (a pure move), then F1 and F8 against one fixture corpus (F4 is already fixed in `684052f`).
2. **Split groundwork (D3 step 2, items 1–2):** the sandbox seam and its test patches, then the build module.
3. **Grouping by site (D1 step 2, D3 step 2 item 3):** F5, the site key and grouping at ingest, together with the crash-replay module. Settle first where the site comes from, and whether to link one bug seen at two statements.
4. **Reach gate (D3 step 2 item 4):** F2 and F11 after deciding D2, together with the coverage module, since F2(a) changes what coverage replays.
5. **Keep-going:** F3 (with its Phase 0 half) and F6.
6. **Ledger evidence:** F7 and F9.
7. **UBSan check set:** F10, if step 0 confirmed it.
8. **E-ACSL false alarms, then the engine split:** F17, then decide D4 on the seeded benchmark.
9. **Guardrail script (D3 step 2 item 5):** at any point after step 2, ideally the next time Phase 3 changes the guardrail.
10. **Docs:** F14–F16 alongside whichever of the above lands first; F13 after D4.
11. **Isolation:** F12, last; the rename is cheap, the mount namespace is not.
