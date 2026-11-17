# Open topics remediation plan (2026-11-10)

This plan orders the open items of [`../troubleshooting/README.md`](../troubleshooting/README.md) and the work left on branch `phase1-remediation` before it can merge. Most of the items come from the runs and A/B experiments of 2026-11-09:
- nettle run-3 and the libpng and libseccomp runs;
- the formal-discovery A/B on a copy of libmnl run 1.

It does not repeat work that another plan already owns:
- **Phase 1 steps S0–S13 and the validation run V:** [`./phase1-remediation-plan.md`](./phase1-remediation-plan.md). This plan only says where its items touch the same files.
- **Formal-discovery measurements** (benchmark acceptance of Tiers 1, 2, 5 and 6, the Tier 7 decision, the Tier 6 follow-ups): [`./backlog.md`](./backlog.md) Sections 1c and 4.
- **Hosts this machine cannot test** (Podman, Slurm, SELinux, NUMA): [`./backlog.md`](./backlog.md) Section 2.

## Priorities

- **P0:** can drop or corrupt results, or blocks the merge decision. All are small: do them first.
- **P1:** blocks analysis of modules on targets already run, or wastes agent budget, with no automatic workaround.
- **P2:** has a manual workaround, or only degrades coverage or diagnosis; upstream reports.
- **P3:** hygiene.

## Summary

| ID | Prio | Size | Topic | Depends on |
| :--- | :--- | :--- | :--- | :--- |
| M1 | P0 | — | Decide when `phase1-remediation` merges (user) | — |
| O1 | P0 | S | Regression tests for the three ledger fixes of `8936217` | — |
| O2 | P0 | S | `guardrail_error` on `mnl_attr_get_len` (Frama-C 35): keep the evidence, diagnose, report the binary's output | — |
| M2 | P0 | S | Redo S1 on top of the current branch | M1 |
| O3 | P1 | M | Link repair for data symbols (nettle constant tables) | before Phase 1 S3 |
| O4 | P1 | M | `--api` takes the unit's headers from the build capture | — |
| O5 | P1 | S–M | Negotiation rounds above the per-callee cap | — |
| O6 | P1 | — | Confirming runs on nettle, libpng and libseccomp (user) | O3, O4 |
| O7 | P2 | M | System headers from the build image, exact flag match | after O3 (`build_capture.py`) |
| O8 | P2 | M | Upstream drafts for the five Frama-C and E-ACSL bugs of 2026-11-09 | — |
| O9 | P2 | S–M | E-ACSL-only rewrite of `static const` unions (needs a decision) | — |
| O10 | P2 | M | A stdin entry style for harnesses | after O4 (`generate_harness.py`) |
| O11 | P2 | S | Keep prover candidate histories | before Phase 1 S11 |
| O12 | P3 | S | Cygwin fork failures in a concurrency test | — |
| O13 | P3 | S | Duplicate entry in `backlog.md` | — |
| M3 | P3 | S | Worktrees, branches and the skill mirrors | M1 |

## Rules for every step

The rules of [`./phase1-remediation-plan.md`](./phase1-remediation-plan.md#rules-for-every-step) apply:
- **Checks:** `ruff`, `ruff format --check`, `mypy scripts tests` and the full suite (`python -m pytest tests -n auto`) pass after each step.
- **Docs and skills** change in the same step as the behavior; never commit the "deletion" of the skill mirrors.
- **Code steps** run in a worktree of their own, not in the main checkout, because runs mount its live `scripts/`. Since 2026-11-17 each step has its own worktree and branch (see "Review and dispatch"); `../frama-c-phase1` is no longer used.

Two more rules for this plan:
- **Troubleshooting:** each step updates its own entry in [`../troubleshooting/`](../troubleshooting/README.md) in the same commit: open or fixed, with the commit.
- **No guessing:** a step marked "diagnose" opens the logs first and writes the cause into the entry before any fix lands.

## Merge track

### M1. When does `phase1-remediation` merge? (P0, user decision)

- **Today:** the branch is 52 commits ahead of `main`. Under decision D10 of the Phase 1 plan, it merges only after validation V, and S0, S2–S13 and V are still open.
- **But:** most of its commits are not Phase 1 work. They are:
  - the Phase 0 fixes (harness sources, `model_only`, link libraries);
  - the nettle, libpng and libseccomp fixes;
  - the E-ACSL repairs for Frama-C 35 (`register`, `_Alignas`, formals, `<==>`);
  - the formal-discovery tiers.

  Every run made from `main` lacks them.
- **Options:**
  - **(a) Keep D10:** everything waits for V.
  - **(b) Merge now:** merge this branch once O1 and O2 have landed and the Docker-backed suite passes (`FRAMAC_DOCKER_TESTS=1 python -m pytest tests -n 4`). Then continue Phase 1 (S2 onwards) on a new `phase1-remediation` cut from `main`. V then validates only the Phase 1 work, and the `phase1-r1` baseline is recorded after it, as planned.
- **Recommendation:** (b). The work on the branch is already validated on the targets it was found on, and keeping it off `main` makes every run on `main` re-find bugs that are already fixed. The cost: there is no single validation run covering the whole branch.
- **Decided (user, 2026-11-10): (b).** Merge once O1 and O2 have landed and the Docker-backed suite passes. This replaces D10 of the Phase 1 plan for the work already on the branch; V still validates the Phase 1 steps that follow.

### M2. Redo S1 on top of the current branch (P0, S, after M1)

- **Today:** S1 (the move of failure parsing into `scripts/failure_identity.py` and of the dictionary cleanup into `fuzz_dictionary.py`) is done on `phase1-s1` (`a29486d`), cut from `31923ad`. A trial merge (`git merge-tree`) conflicts in `scripts/run_eacsl_fuzz.py` and `pyproject.toml`: this branch has changed `run_eacsl_fuzz.py` since, for formal inits, `_Alignas`, `-no-variadic-translation` and the target's own fuzz targets.
- **Work:** S1 is a pure move, so redo the move on the current tip instead of resolving the conflicts by hand: move the same names, re-import them in `run_eacsl_fuzz.py`, and take over `tests/test_failure_identity_move.py`. Then retire `phase1-s1` and reset `../frama-c-phase1` to the new tip.
- **Acceptance:** S1's own acceptance (`git diff --stat` shows moves only; the suite passes), and the Phase 1 plan's status table on this branch says S1 is done.

### M3. Worktrees, branches and the skill mirrors (P3, S, after M1)

- **Merged worktrees:** remove the eight worktrees of merged branches and their branches: `fd-tier1` to `fd-tier6`, `fd-merge` (`formal-discovery-tiers`), `brave-cannon-9329e4` and `eloquent-wiles-549c91`. They are all reachable from `phase1-remediation`.
- **Skill mirrors:** `.agents/skills` and `.claude/skills` are tracked as symlinks, and this checkout has plain copies. Keep them out of every commit, as today.
- **Push:** `main` is 138 commits ahead of `origin/main`. Push when the user says so.

## Steps

### O1. Regression tests for the ledger fixes of `8936217` (P0, S)

**Done 2026-11-10.** The check below found a real regression: `needs_validation` results for unlinked candidates were discarded, including ones the verifier resolved to a target function. Fixed, with the safety net now recording the rejection as the unit's reason; see the ledger entries in [`../troubleshooting/ledger-and-verifier.md`](../troubleshooting/ledger-and-verifier.md).

- **Goal:** the three fixes that keep verifier and WP results from being discarded cannot regress silently. They landed without tests.
- **Entries:** the `linked_units: fewer than 1 items`, `deferred unit must not hide evidence` and `unresolved[N]: duplicate item` entries of [`../troubleshooting/ledger-and-verifier.md`](../troubleshooting/ledger-and-verifier.md).
- **Work:**
  - a `rejected` verifier record whose candidate lies in a libc stub (`FRAMAC_SHARE/libc/stdlib.h#free`) has empty `linked_units`, validates against `findings.schema.json`, and `ingest-verifier` accepts it;
  - a `rejected` scaffold for a function with `deferred` units links only the candidate's own units; when such a unit still receives rejection evidence, it becomes `blocked` with the rejection as `unresolved`, and `validate_artifacts.py` accepts the ledger;
  - two unproven goals with the same kind, line and annotation give one `unresolved` item, on both the unproven-goal and the error path of `cmd_ingest_wp`.
- **Check while writing them:** a `needs_validation` record still requires non-empty `linked_units`, and its scaffold now takes the candidate's own units, which are empty for a candidate in a libc stub or in harness code. If such a record can be scaffolded, the scheduler would discard it as the `rejected` ones used to be. Decide what it links: the harness module's units, or none with the schema relaxed for it. Record the decision in the entry.
- **Owns:** `tests/test_ledger*.py` (new cases), `scripts/ledger.py` and `schemas/findings.schema.json` only if the check above needs a fix.
- **Acceptance:** each test fails when its fix in `8936217` is reverted.

### O2. `guardrail_error` on `mnl_attr_get_len` (P0, S to diagnose)

**Done 2026-11-10.** Not Frama-C 35: the always-replayed seed `seed-ext-parse-offset-2pow31` reproduces a known bug in `mnl_attr_parse`, the replay stopped on its SEGV in `mnl_attr_ok`, and `UNCOVERED_PC` lines hid the report. The guardrail now drops inputs that crash outside the checked functions (`excluded_inputs`) and keeps the report; see the guardrail entry in [`../troubleshooting/wp-and-guardrail.md`](../troubleshooting/wp-and-guardrail.md). Item 3 below was wrong: the output was kept (`runtime_trace`) but crowded out. The original text follows.

- **Goal:** know why a parent guardrail fails on Frama-C 35 for a contract that cannot be wrong, and make the next such failure diagnosable from the report alone.
- **Entry:** "The `mnl_attr_get_len` Guardrail Returns `guardrail_error`", Section 5.
- **Evidence:**
  - **Contract:** the replayed contract is `requires \valid_read(attr); assigns \nothing; ensures \result == attr->nla_len;`. That points away from the contract and towards the module's guardrail binary or how its output is read. This is a lead, not a diagnosis.
  - **Where it is:** the Tier 6 A/B copy in a session scratchpad (`C:/Users/Florian/AppData/Local/Temp/claude/8d06ee997c1477c0/89e78a11-aba9-429e-bd7b-0fcac751b285/scratchpad/ab/run3-rep`):
    - `state/proof-carry/src_attr.c__mnl_attr_get_len/contract.json` and `wp_report.json`;
    - `workspace/reports/proof-carry/summary.json`.
  - **At risk:** temporary directories get cleaned. Copy these first, next to `targets/libmnl/framac-run-1-results/`.
- **Work:**
  1. Rebuild the parent guardrail of module `attr` from libmnl run 1's tree, with that contract spliced in, on `framac-analysis:latest`. Run it over the same 64 corpus inputs and read the binary's exit code and stderr.
  2. Write the cause into the entry, then fix it in the guardrail section of `scripts/run_eacsl_fuzz.py`, or upstream if it is Frama-C.
  3. Whatever the cause: `classify_guardrail` keeps no output for a `guardrail_error` without a recognizable E-ACSL report. Add the exit code and the last lines of the output (`output_tail`, bounded) to that result, so the reason reaches `summary.json` and the agent's result.
- **Owns:** `classify_guardrail` and its callers in `scripts/run_eacsl_fuzz.py`. Land it before Phase 1 S11, which moves the guardrail into `scripts/run_guardrail.py`, or hand it to S11.
- **Tests:** a `guardrail_error` result carries `returncode` and a bounded `output_tail`; plus a test for the cause once known (a fixture of the binary's output).
- **Acceptance:** the replay of `mnl_attr_get_len` passes on 35, or its rejection names a real cause.

### O3. Link repair for data symbols (P1, M)

**Done 2026-11-11, by another route than the one below.** The link repair looks up a symbol the DAG's function map lacks among the model's defined globals (`_model_global_variables` and `_place_global`, now in `scripts/fuzz_build.py` since Phase 1 S3 moved the link repair). The build capture records no `defined_data` and the DAG has no `data_symbol_files`. Unit-tested only: the acceptance on nettle `xts` waits for O6. See the data-table bullet of the nettle run-3 entry in [`../troubleshooting/harnesses-and-seeds.md`](../troubleshooting/harnesses-and-seeds.md). The original text follows.

- **Goal:** a harness whose functions read a constant table defined in another file links. Today nettle `xts`, `arctwo`, `chacha_poly1305` and `camellia256_set_decrypt_key` stop with `undefined reference to '_nettle_aes_encrypt_table'` or `'_nettle_camellia_table'`. Crypto libraries commonly keep their tables in files of their own.
- **Entry:** the open data-table bullet of the nettle run-3 entry, Section 1.
- **Cause:** `run_eacsl_fuzz.repair_sources_for_link` maps undefined symbols to files through `_dag_symbol_files`, which reads only `functions` and `build_only_functions` from the DAG.
- **Work:**
  - `build_capture.py` already runs `nm --defined-only` per object. Record the global data symbols it defines (`D`, `R`, `B`, `G`, `S` and their variants), next to `defined_functions`, as `compiles[].defined_data`. This takes them from the real build, as `d71b255` did for harness sources.
  - `build_callgraph_dag.py` exports them as a `data_symbol_files` map (symbol to compiled source).
  - `_dag_symbol_files` reads that map as well.
  - A capture that predates `defined_data` falls back to the model's non-static `global_variables`.
  - Update the capture and DAG schemas.
- **Owns:** the `nm` probe and compile records of `scripts/build_capture.py`, the DAG export in `scripts/build_callgraph_dag.py`, `_dag_symbol_files` in `scripts/run_eacsl_fuzz.py`, the two schemas. Land it before Phase 1 S3, which moves the link repair into `scripts/fuzz_build.py`.
- **Tests:**
  - a DAG with a data symbol makes `repair_sources_for_link` add its file;
  - a static table is not mapped;
  - an old capture uses the model fallback.
- **Acceptance:** nettle `xts` builds from run-3's sources with no hand-added `--sources`.

### O4. `--api` takes the unit's headers from the build capture (P1, M)

- **Goal:** an unattended Phase 0 run gives `--api` harnesses the headers that declare the API, instead of `--header none`. On nettle, `--header none` made 22 of 35 libnettle clusters fail and libhogweed skip 109 cases. libpng needed `--header` by hand.
- **Entries:**
  - the `jmp_buf, FILE` entry (its open bug);
  - "`--api` Skips Cases With `invalid application of 'sizeof'`".
- **Work:** when `--header` is not given, `api_harness.generate` takes the capture's `public_headers.files` that the unit's compiles include (`compiles[].headers`). The internal headers that declare an entry point the cases call are added the same way `--extra-include` adds them today. Record what was chosen, and why, in the sidecar. `--header none` still means none.
- **Owns:** header resolution in `scripts/api_harness.py` and the `--header` default in `scripts/generate_harness.py`. Phase 1 S6 owns the case selector in the same two files: coordinate, or land O4 first.
- **Tests:**
  - a fixture capture with a public header and an internal one gives both;
  - `--header none` gives none;
  - a unit without capture data keeps today's behavior.
- **Acceptance:** regenerating nettle's libnettle clusters without `--header` or `--extra-include` reaches the 70-gap result the manual headers gave.

### O5. Negotiation rounds above the per-callee cap (P1, S–M, diagnose first)

- **Goal:** a callee gets at most `MAX_NEGOTIATION_ROUNDS_PER_CALLEE` (3) negotiate dispatches, and a request that was dispatched is never closed as `not dispatched:`. Tier 1 reads that prefix as a structural rejection and leaves the request out of "Known Dead Ends".
- **Entry:** "A Negotiate Request Is Dispatched to an Agent, Then Closed as `not dispatched`", Section 5.
- **Evidence** (durable, in libmnl run 1 itself):
  - `targets/libmnl/framac-run-1-results/state/wp_schedule.json`, task `negotiate:src/attr.c#mnl_attr_get_payload` with its `dispatches`;
  - `workspace/reports/strengthen_requests.json`, `req_0015`;
  - agents `negotiate-mnl_attr_get_payload` to `-5`.
- **Work:**
  1. Run 1 used the scheduler of its time. First rebuild that state in a unit test against today's `wp_scheduler.py`, and only then name a cause.
  2. A lead to check: `_emit_negotiations` applies the per-callee cap only when the negotiate task is already terminal (`wp_scheduler.py`, the `settled` check). A request that joins a running task is not checked there.
  3. Fix the cap where tasks are dispatched, and give a request closed after it was assigned its own note, not `not dispatched:`.
- **Owns:** `scripts/wp_scheduler.py` (negotiation emission and dispatch).
- **Tests:**
  - the run-1 sequence dispatches the callee at most 3 times;
  - an assigned request is never closed with the `not dispatched:` prefix.

### O6. Confirming runs (P1, user-triggered, after O3 and O4)

- **Goal:** confirm on the real targets the fixes of 2026-11-09, which were verified only on reproductions or on rebuilt run-3 sources, and close or re-open their entries.
- **Runs** (fresh runs, LF checkouts, the recipes of the earlier runs):
  - **nettle** (`--disable-fat --disable-assembler`): `build-check` counts against run-3 (39 `build_failed`, 2 `eacsl_fallback`, 5 `eacsl`). Also check:
    - the getopt fix (`d71b255`) and the `register` and `_Alignas` fixes (`9b3d2f3`) with regenerated harnesses;
    - O3 and O4;
    - whether `make check` test programs now get seed recorders.
  - **libpng:** defect A (opaque handles through pointer typedefs), which `18bc5e9` may cover, and the fixes for defects B to E.
  - **libseccomp:** the gperf module starts under Eva with `-warn-invalid-pointer` on. Also check the `offsetof`, ioctl, `syscall` and system-header fixes (`7e15154`) in a full run.
- **Record:** `docs/runs/<date>-<target>-run-<n>.md` per target, then update each entry's status.

### O7. System headers from the build image, exact flag match (P2, M, after O3)

- **Goal:** Eva and WP read the same `linux/*` and `elf.h` the target was built against, and a unit flag cannot suppress a system directory by accident.
- **Entry:** "`fatal error: elf.h`", Section 1 (its open pipeline bug).
- **Work:**
  - **Snapshot:** export the headers Frama-C's libc lacks (`linux-libc-dev`, `elf.h`) from the build image into the snapshot, as the capture already does for the target's other system headers. Point `-idirafter` at the snapshot copies, and keep the image's directories only as the fallback for an older capture.
  - **Move:** move the logic from `framac_common.augment_framac_cppflags` into `target_env.with_include_flags`, which owns the include order.
  - **Exact match:** match flags as whole tokens (`-idirafter` followed by that exact directory), not as substrings.
- **Owns:** `scripts/target_env.py`, `augment_framac_cppflags` in `scripts/framac_common.py`, the snapshot export of `scripts/build_capture.py`.
- **Tests:**
  - `-idirafter /usr/include/foo` in a unit's flags no longer drops `/usr/include`;
  - a snapshot with exported UAPI headers puts them before the image's.

### O8. Upstream drafts (P2, M)

- **Done 2026-11-15.** All five are drafted with validated patches on upstream `master` `3dff90fc70`. They became Issues 20 to 27, not 15 to 17 (those numbers were taken), and the `static const` union turned out to be the same bug as Issue 27. Index: [`../upstream/frama-c/README.md`](../upstream/frama-c/README.md). Filing stays the user's decision.

- **Goal:** each Frama-C or E-ACSL bug the pipeline works around or degrades for has a draft with a minimal reproduction, so it can be filed and the workaround removed later.
- **Drafts** (the reproductions of 2026-11-09 were not kept; re-create each in `framac-analysis:latest`):
  - **E-ACSL:** `-e-acsl-full-mtracking` aborts on a `register` local (`Cil.mkAddrOf`). Workaround: `-Dregister=` in the E-ACSL frontend.
  - **Kernel printer:** `_Alignas` of a struct or union member printed after the declarator. Workaround: `rewrite_trailing_alignas`.
  - **E-ACSL:** `Unregistered("__gmpz_clear")` when the target includes `<gmp.h>` and E-ACSL needs GMP itself. No workaround: modules fall back to sanitizers.
  - **E-ACSL:** `static const` union, `implicit cast ... to void *`. Since O9 (2026-11-17) the E-ACSL frontend drops the `const` in its own text; a form the rewrite misses is a `build-check` row with `rewrite_missed`.
  - **Kernel:** `offsetof(T, m[i])` with a non-constant index (`Index is not constant`). Workaround: `fc_cpp_wrapper.py`.
- **Work:** one draft per bug in `docs/upstream/frama-c/`, in the format of `frama-c-eacsl-formal-params-initialized.md`. Add the three E-ACSL ones to [`../upstream/frama-c/frama-c-e-acsl-issues.md`](../upstream/frama-c/frama-c-e-acsl-issues.md) as Issues 15–17. Filing them, and Issues 13 and 14 (drafted, not filed), stays the user's decision.

### O9. E-ACSL-only rewrite of `static const` unions (P2, S–M, needs a decision)

- **Goal:** the 10 nettle modules that use a `static const` union lose E-ACSL today. They are:
  - `sm4`;
  - through `block-internal.h`: `ccm`, `gcm`, `gcm_2`, `gcm_camellia128`, `drbg_ctr_aes256`, `twofish`;
  - through `ocb.c`: `aes128_set_decrypt_key`, `nist_keywrap`;
  - through `cmac.c`: `cmac_2`.

  This goal is to give those modules E-ACSL back.
- **Entry:** the `static const union` bullet of the nettle run-3 entry, Section 1.
- **Proposal:** `fc_cpp_wrapper_eacsl.py` drops `const` from `static const union` declarations in the E-ACSL frontend's preprocessed text only. The entry records that a shadow-tree patch doing this instruments.
- **Trade-off:**
  - E-ACSL no longer treats those objects as read-only. The compiler still enforces `const` on the real build, and Eva and WP read the original.
  - Corrected 2026-11-17: the E-ACSL binary is compiled from the rewritten text, so it holds those objects as writable data, and a write to one through a cast pointer is not caught in that binary. The sanitizer and coverage builds compile the original source.
  - The objects are zero and never written, so no reachable behavior changes.
- **Decision for the user:** accept that trade-off, or keep `--fuzz-engine sanitizers` for those modules.
- **Decided 2026-11-17: accept.** Taken by Claude when the user asked for the open topics to be worked on, under `CLAUDE.md` ("how it's built is your call"); the user can reverse it, and the step is on a branch of its own for that reason. Why: without the rewrite these modules get no E-ACSL check at all, and with it they lose one property (a write to an object that is zero and that the compiler already refuses to write). Conditions: the rewrite touches the E-ACSL frontend's text only, every rewritten declaration is counted in the build report, and the run report says which modules were built with it. The upstream bug is filed (pub/frama-c#2795, Issues 23 and 27 of [`../upstream/frama-c/README.md`](../upstream/frama-c/README.md)); the rewrite goes when an image carries the fix.
- **Work, if accepted:**
  - the rewrite, counted in the build report;
  - the `build-check` next step updated;
  - the entry updated.
- **Tests:**
  - a `static const union` file builds and runs under E-ACSL;
  - a `static const struct` and a non-`const` union are untouched.

### O10. A stdin entry style (P2, M, after O4)

- **Goal:** command-line programs that read their input from stdin can be harnessed. Today `_check_argv_entry` tells the user to exempt them (libpng `pngfix-itxt`).
- **Entry:** "A Harness Line Like `break int main(void);`", Section 1 (its open bug).
- **Work:**
  - a new `--entry-style stdin`;
  - **fuzz side:** each input is fed to fd 0 through a pipe or a memory file, reset per input, so that both `read(0, ...)` and stdio work;
  - **Eva side:** calls `main` with Frama-C's libc model of stdin;
  - the reach gate treats it like `argv`.
- **Owns:** the entry styles of `scripts/generate_harness.py` and the harness template.
- **Tests:**
  - a program reading stdin with `fgets` and one with `read(0, ...)` both reach their parser under the fuzz build;
  - the Eva harness parses.

### O11. Keep prover candidate histories (P2, S)

- **Goal:** the Tier 3 and Tier 5 effects can be measured on the iterations they act on, not only on final patches. None of the 168 agents of libmnl run 1 kept a candidate source.
- **Entry:** "Prover Candidate Histories Cannot Be Replayed", Section 5.
- **Work:** `prover_candidates.note_oracle` writes each candidate's diff against `scratch/base` as `candidates/c<n>/candidate.patch`, bounded in size.
- **Owns:** `scripts/prover_candidates.py`. Phase 1 S11 also owns it: land O11 first or inside S11.
- **Test:** two oracle runs leave two patches, and applying the second to `scratch/base` gives the second candidate.

### O12. Cygwin fork failures in a concurrency test (P3, S)

- **Entry:** `test_sh_new_run_allocation_is_atomic_under_concurrency`, Resources section.
- **Work:** skip the test with a clear reason when Git Bash cannot fork (Win32 error 299 or return code `0xC0000142` in a child), instead of reporting an allocation race. The atomicity check stays as it is.

### O13. Duplicate entry in `backlog.md` (P3, S)

- **Work:** Section 3 of [`./backlog.md`](./backlog.md) holds the "Projected frame skeletons" item twice. One copy has the Tier 4 correction and the other the Tier 5 rank. Merge them into one item that keeps both.

## Order and parallelism

```text
M1 (user) ─▶ M2 ─▶ Phase 1 S2/S3 ...
O1 ─┐
O2 ─┴─▶ (merge per M1 option b)
O3 ─▶ O7            O3 before Phase 1 S3 (link repair moves)
O4 ─▶ O10           coordinate with Phase 1 S6 (same two files)
O3, O4 ─▶ O6 (user)
O5, O8, O9, O12, O13: any time
O11 before Phase 1 S11 (same file)
```

- **O1 and O2 run in parallel:** their files are disjoint (`ledger.py` and tests; the guardrail section of `run_eacsl_fuzz.py`).
- **O3, O4 and O5 run in parallel:** O3 owns `build_capture.py`, the DAG and the link repair; O4 owns `api_harness.py`; O5 owns `wp_scheduler.py`.
- **O7 waits for O3, and O10 for O4,** because each pair shares a file.

## Not planned

- **A file compiled by several units with different flags is analysed in one configuration only** (Section 1). It is a design limit; write a harness that states the other configuration.
- **`syscall`'s variadic contract assumes no memory is written** (Section 4). By design; results that depend on a buffer filled through `syscall` are optimistic.
- **GMP inside E-ACSL:** no pipeline-side fix exists. O8 reports it, and the affected modules use the sanitizers.

## Review and dispatch (2026-11-17)

The Status table had not been updated since 2026-11-10. Each open item was checked against the code of `phase1-remediation` at `b74a9f2`:

| ID | State found | Evidence |
| :--- | :--- | :--- |
| M2 | Done in effect | S1 to S7 are merged; `scripts/failure_identity.py` and `scripts/fuzz_dictionary.py` exist. Branch `phase1-s1` and worktree `../frama-c-phase1` are still there (M3). |
| M3 | Partly done | The `fd-*` worktrees and branches are gone. The skill mirrors are tracked plain copies, kept in step by `tools/sync_skill_mirrors.py`. Left: `phase1-s1`, and the worktrees of branches merged since. The push stays the user's. |
| O3 | Done 2026-11-11, another route | `_model_global_variables`, `_place_global` in `scripts/fuzz_build.py`. No `defined_data`, no `data_symbol_files`. |
| O4 | Open | `api_harness.no_header_warning` names the capture's public headers in a warning; nothing takes them. |
| O5 | Open, not diagnosed | The cap is checked in one place (`wp_scheduler.py`, the `settled` check). |
| O7 | Open | `framac_common.augment_framac_cppflags` still adds the image's `/usr/include` directories. |
| O8 | Done 2026-11-15 | See the step. |
| O9 | Decided 2026-11-17: accept | See the step. |
| O10 | Open | `VALID_ENTRY_STYLES` has no `stdin`. |
| O11 | Open | `prover_candidates.note_oracle` writes no patch. Phase 1 S11 has not started, so O11 lands first. |
| O12 | Open | No skip in `tests/test_run_identity_wrappers.py`. |
| O13 | Done 2026-11-17 | The two items are one in [`./backlog.md`](./backlog.md). |

**Dispatched 2026-11-17**, one agent (Claude Opus 5.5) per row, each in its own worktree under `.claude/worktrees/`, cut from the commit of this review:

| Steps | Branch | Owns | Must not touch |
| :--- | :--- | :--- | :--- |
| O4 | `ot/o4-api-headers` | Header resolution in `scripts/api_harness.py` (`generate`, `no_header_warning`), what the sidecar records about the choice, new tests | `scripts/generate_harness.py` (O10). If the `--header` default there has to change, the step says so in its result. |
| O10 | `ot/o10-stdin-entry` | The entry styles of `scripts/generate_harness.py` (`VALID_ENTRY_STYLES`, `_check_argv_entry`), `templates/harness_dual.c.template`, the places in `scripts/harness_reach.py` and the sidecar schema that name `argv`, new tests | `scripts/api_harness.py` (O4) |
| O5 | `ot/o5-negotiation-cap` | Negotiation emission and dispatch in `scripts/wp_scheduler.py`, new tests | — |
| O7 | `ot/o7-system-headers` | `scripts/target_env.py`, `augment_framac_cppflags` in `scripts/framac_common.py`, the snapshot export of `scripts/build_capture.py` and its schema, new tests | `scripts/fuzz_build.py` |
| O9 | `ot/o9-const-union` | `scripts/fc_cpp_wrapper_eacsl.py`, the E-ACSL frontend call and its build report, the `eacsl_static_const_union` row of `build-check` in `scripts/pipeline_make.py`, the line of the run report, new tests | The link repair in `scripts/fuzz_build.py`; `scripts/framac_common.py` (O7) |
| O11, O12 | `ot/o11-o12-small` | `scripts/prover_candidates.py`, `tests/test_run_identity_wrappers.py`, new tests | — |

Rules for these steps, on top of "Rules for every step":
- **No main checkout.** A run is live there (mpack run-4, started 2026-11-17 09:54), and every cache key hashes `scripts/` and `templates/`.
- **Commits.** Code and tests first. Then one commit for the step's own troubleshooting entry, the guide and the skill it changes (`skills/` only, then `python tools/sync_skill_mirrors.py`). A step does not edit this plan, `backlog.md` or `README.md` of this folder: it returns what its Status row should say.
- **Load.** The focused tests while working; the whole suite once at the end, with `-n 8`, because a run shares the machine.
- **Docker.** Only for a test the step needs, from PowerShell, with a timeout, and only containers the step started.
- **No target run.** Recorded run directories are read, never written. O6 stays the user's.
- **No merge, no push.** The reviewer reads each diff, runs the checks on all the branches merged together, and lands them when no run reads the main checkout's scripts.

After they land, `p1/s6b-wide-selector` and `feat/header-entry-points` are rebased again: O4 and O10 change `api_harness.py`, `generate_harness.py` and `harness_reach.py`, which both branches also change.

### Result (2026-11-17)

All six branches came back the same day. Each diff was read, and the six were merged together on `ot/combined` (cut from the commit of this review), where the checks ran on the combination.

| Steps | Branch | What it does | Verified | Not verified |
| :--- | :--- | :--- | :--- | :--- |
| O4 | `ot/o4-api-headers` | Without `--header`, an `--api` harness includes the capture's public headers that the unit's compiles include, and the internal ones declaring an entry point no public header declares (`api_harness.capture_headers`). The choice is in the sidecar (`api_headers`). | Unit tests with a fake harness writer and probe. | The real writer and compiler with capture headers; nettle (O6). Phase 3 reads the sidecar's `header` (`wp_scheduler.py`, `workspace_overlay.py`): a module that had none now has the chosen one, as with a given `--header`; not exercised. A driver that passes `--header none` turns the choice off. |
| O5 | `ot/o5-negotiation-cap` | The cap is checked where requests join the task, where a round would reopen, and before every dispatch. A request an agent was handed is closed as `closed after dispatch`. | A replay of run 1's sequence and four more unit tests; four of the five fail on the code before. | A real Phase 3 run. |
| O7 | `ot/o7-system-headers` | The build image's `linux-libc-dev` headers and `elf.h` are exported to `<snapshot>/libc/` and searched before the analysis image's. The order is in `target_env.with_include_flags(nostdinc=True)`; `-idirafter` is matched as a whole token. | Unit tests; one Docker test: a capture in `framac-build`, a Frama-C parse in `framac-analysis`, every such header read from the snapshot. | A target run. The Docker test was not run against the code before. |
| O9 | `ot/o9-const-union` | `fc_cpp_wrapper_eacsl.py` blanks `const` in `static const union` objects. The build report counts it (`compile.const_union_rewrites`), `REPORT.md` names the modules. Switch: `REWRITE_STATIC_CONST_UNIONS`. | Unit tests; one Docker test: the reproduction builds and runs with the rewrite, fails with `implicit cast` without. | The ten nettle modules (O6). |
| O10 | `ot/o10-stdin-entry` | `--entry-style stdin`: the fuzz side feeds each input through a fresh pipe on fd 0 after purging stdio; Eva reads Frama-C's model of stdin; the reach gate treats it as `argv`. | Unit tests; three Docker tests (plain clang, E-ACSL libFuzzer build, Eva). | A target (libpng `pngfix`); inputs above 64 KiB are rejected, untested; a program that closes stdin. |
| O11, O12 | `ot/o11-o12-small` | Each prover candidate keeps `candidates/c<n>/candidate.patch`, at most 256 KiB. The allocation race test fails on a duplicate, passes a correct allocation, skips on a Git Bash fork failure. | Unit tests; 100 stress rounds of the race on this host. | A real prover run. One failure of the first version of the O12 check was not captured and did not come back. |

Whose results these are: the "fails on the code before" checks of O4 and O5, O12's stress rounds and the Docker runs on the single branches were run by the step's agent and are taken from its report. The reviewer ran the suite and the five Docker tests of O7, O9 and O10 on the combination, and the fail-before check of the stub re-plan test.

Decisions taken in review:
- **O4:** the first version failed a module whose chosen header did not compile in the harness, where the module had a harness with fewer cases before. Sent back: the choice now degrades in steps (all chosen headers, the public ones alone, none) and records each abandoned step (`api_headers.fallbacks`). A given `--header` still fails.
- **O5:** the cap is a hard cap. The earlier exemption for a callee whose last round was applied is gone, as this plan's goal states. Consequences: a callee whose negotiations were applied three times refuses a fourth request, and a third round that ends in an invalid result gets no retry.
- **O7:** the analysis image's `/usr/include` directories stay last for every capture, not only an older one. The export holds what the build's dependency lists name; a Frama-C parse can reach other libc headers.
- **O9:** the first version gave a module with a form the rewrite misses (no `static`, a typedef name, `const` after the type) no way to continue. Sent back: the row keeps the sanitizers command and carries `rewrite_missed`. The step's texts said the compiled program keeps `const`; that is true of the sanitizer and coverage builds only, and the texts now say what the E-ACSL binary loses (see the trade-off of O9).

Found outside the steps:
- **Fixed on `ot/combined`:** `stub_gen.system_path` did not map `snapshot/libc/` back to a system path; the `--api` re-plan with NULL callbacks lost the variadic call sites; the `--header` help text and the skill's `--entry-style` list were out of date.
- **Recorded as open** in [`../troubleshooting/README.md`](../troubleshooting/README.md)'s documents: E-ACSL's format validation aborts on a `*` width or precision (upstream, no draft yet); two negotiate close paths in `wp_scheduler.py`; package headers behind symlinks in the snapshot's `root/`.

Checks on `ot/combined`: see the Status table. Landing waits until no run reads the main checkout's scripts.

## Status

| ID | Status |
| :--- | :--- |
| M1 | decided 2026-11-10: option (b), merge after O1 and O2 |
| M2 | done in effect: S1 was redone and merged with S2 to S7; `phase1-s1` and `../frama-c-phase1` are left to M3 |
| M3 | partly done (see "Review and dispatch"); the rest waits for the user |
| O1 | done 2026-11-10: tests, plus a fix for the `needs_validation` regression and the safety-net reason they found |
| O2 | done 2026-11-10: a seed reproducing a known bug elsewhere in the module stopped the replay; such inputs are now excluded (evidence kept in `targets/libmnl/ab-2026-11-09-tier6/`) |
| O3 | done 2026-11-11 by another route (the model's defined globals); unit-tested only, acceptance with O6 |
| O4 | done 2026-11-17 on `ot/o4-api-headers`: capture headers for `--api` without `--header`, degrading in steps; unit-tested only, nettle acceptance with O6 |
| O5 | done 2026-11-17 on `ot/o5-negotiation-cap`: run 1 had no per-callee cap yet and its `not dispatched:` note was typed by hand; today's scheduler let follow-up, requeue and retry rounds past the cap. Hard cap before every dispatch; unit-tested only |
| O6 | waits for the O4, O7, O9 and O10 changes to land, then the user |
| O7 | done 2026-11-17 on `ot/o7-system-headers`: libc gaps exported to the snapshot's `libc/`, order in `target_env.with_include_flags(nostdinc=True)`, exact `-idirafter` match; Docker-verified on a fixture, no target run |
| O8 | done 2026-11-15 |
| O9 | done 2026-11-17 on `ot/o9-const-union`: E-ACSL-only rewrite, counted and reported, switch `REWRITE_STATIC_CONST_UNIONS`; Docker-verified on a reproduction, nettle modules with O6 |
| O10 | done 2026-11-17 on `ot/o10-stdin-entry`: `--entry-style stdin`; Docker-verified on two small programs (clang, E-ACSL, Eva), no target run |
| O11 | done 2026-11-17 on `ot/o11-o12-small`: `candidates/c<n>/candidate.patch`, at most 256 KiB; unit-tested only |
| O12 | done 2026-11-17 on `ot/o11-o12-small`: duplicate fails, correct allocation passes, Git Bash fork failure skips |
| O13 | done 2026-11-17 |

**Where the 2026-11-17 steps are:** merged together on the local branch `ot/combined`, with the review fixes. Not on `phase1-remediation`, not pushed. Checks on `ot/combined` (2026-11-17): `ruff check` and `mypy scripts tests` pass, `tools/check_generated_text.py` and the mirror check pass, `pytest -n 8`: 6113 passed, 228 skipped. With `FRAMAC_DOCKER_TESTS=1`, the tests marked `integration` or `slow` (the Docker-backed ones, the five of O7, O9 and O10 among them): 169 passed, 5 skipped (no GNU make or POSIX host), 3 failed. The three are `tests/test_failure_fixtures_docker.py` on `asan_global_overflow`, `asan_stack_overflow` and `lsan_direct`; they fail the same way on `phase1-remediation` at `9ac8d88`, and are recorded as open in [`../troubleshooting/eacsl-and-fuzzing.md`](../troubleshooting/eacsl-and-fuzzing.md). The Docker-gated files that carry neither mark (`test_api_harness_callbacks.py`, `test_dispatch_selector.py`, `test_eva_assigns_retry.py`, `test_fuzz_keep_going.py`, `test_r8_capture.py`) pass with the gate on. No target was run.
