# Open topics remediation plan (2026-11-10)

This plan orders the open items of [`troubleshooting.md`](troubleshooting.md) and the work left on branch `phase1-remediation` before it can merge. Most of the items come from the runs and A/B experiments of 2026-11-09:
- nettle run-3 and the libpng and libseccomp runs;
- the formal-discovery A/B on a copy of libmnl run 1.

It does not repeat work that another plan already owns:
- **Phase 1 steps S0–S13 and the validation run V:** [`phase1-remediation-plan.md`](phase1-remediation-plan.md). This plan only says where its items touch the same files.
- **Formal-discovery measurements** (benchmark acceptance of Tiers 1, 2, 5 and 6, the Tier 7 decision, the Tier 6 follow-ups): [`backlog.md`](backlog.md) Sections 1c and 4.
- **Hosts this machine cannot test** (Podman, Slurm, SELinux, NUMA): [`backlog.md`](backlog.md) Section 2.

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

The rules of [`phase1-remediation-plan.md`](phase1-remediation-plan.md#rules-for-every-step) apply:
- **Checks:** `ruff`, `ruff format --check`, `mypy scripts tests` and the full suite (`python -m pytest tests -n auto`) pass after each step.
- **Docs and skills** change in the same step as the behavior; never commit the "deletion" of the skill mirrors.
- **Code steps** run in the worktree `../frama-c-phase1`, not in the main checkout, because benchmark runs mount its live `scripts/`.

Two more rules for this plan:
- **Troubleshooting:** each step updates its own entry in [`troubleshooting.md`](troubleshooting.md) in the same commit: open or fixed, with the commit.
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

- **Goal:** the three fixes that keep verifier and WP results from being discarded cannot regress silently. They landed without tests.
- **Entries:** the `linked_units: fewer than 1 items`, `deferred unit must not hide evidence` and `unresolved[N]: duplicate item` entries of [`troubleshooting.md`](troubleshooting.md) Section 5.
- **Work:**
  - a `rejected` verifier record whose candidate lies in a libc stub (`FRAMAC_SHARE/libc/stdlib.h#free`) has empty `linked_units`, validates against `findings.schema.json`, and `ingest-verifier` accepts it;
  - a `rejected` scaffold for a function with `deferred` units links only the candidate's own units; when such a unit still receives rejection evidence, it becomes `blocked` with the rejection as `unresolved`, and `validate_artifacts.py` accepts the ledger;
  - two unproven goals with the same kind, line and annotation give one `unresolved` item, on both the unproven-goal and the error path of `cmd_ingest_wp`.
- **Check while writing them:** a `needs_validation` record still requires non-empty `linked_units`, and its scaffold now takes the candidate's own units, which are empty for a candidate in a libc stub or in harness code. If such a record can be scaffolded, the scheduler would discard it as the `rejected` ones used to be. Decide what it links: the harness module's units, or none with the schema relaxed for it. Record the decision in the entry.
- **Owns:** `tests/test_ledger*.py` (new cases), `scripts/ledger.py` and `schemas/findings.schema.json` only if the check above needs a fix.
- **Acceptance:** each test fails when its fix in `8936217` is reverted.

### O2. `guardrail_error` on `mnl_attr_get_len` (P0, S to diagnose)

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
- **Record:** `docs/progress/<date>-<target>-run-<n>.md` per target, then update each entry's status.

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

- **Goal:** each Frama-C or E-ACSL bug the pipeline works around or degrades for has a draft with a minimal reproduction, so it can be filed and the workaround removed later.
- **Drafts** (the reproductions of 2026-11-09 were not kept; re-create each in `framac-analysis:latest`):
  - **E-ACSL:** `-e-acsl-full-mtracking` aborts on a `register` local (`Cil.mkAddrOf`). Workaround: `-Dregister=` in the E-ACSL frontend.
  - **Kernel printer:** `_Alignas` of a struct or union member printed after the declarator. Workaround: `rewrite_trailing_alignas`.
  - **E-ACSL:** `Unregistered("__gmpz_clear")` when the target includes `<gmp.h>` and E-ACSL needs GMP itself. No workaround: modules fall back to sanitizers.
  - **E-ACSL:** `static const` union, `implicit cast ... to void *`. No workaround yet: see O9.
  - **Kernel:** `offsetof(T, m[i])` with a non-constant index (`Index is not constant`). Workaround: `fc_cpp_wrapper.py`.
- **Work:** one draft per bug in `docs/upstream/`, in the format of `frama-c-eacsl-formal-params-initialized.md`. Add the three E-ACSL ones to [`upstream/frama-c-e-acsl-issues.md`](upstream/frama-c-e-acsl-issues.md) as Issues 15–17. Filing them, and Issues 13 and 14 (drafted, not filed), stays the user's decision.

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
  - The objects are zero and never written, so no reachable behavior changes.
- **Decision for the user:** accept that trade-off, or keep `--fuzz-engine sanitizers` for those modules.
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

- **Work:** Section 3 of [`backlog.md`](backlog.md) holds the "Projected frame skeletons" item twice. One copy has the Tier 4 correction and the other the Tier 5 rank. Merge them into one item that keeps both.

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

## Status

| ID | Status |
| :--- | :--- |
| M1 | decided 2026-11-10: option (b), merge after O1 and O2 |
| M2 | open, after M1 |
| M3 | open, after M1 |
| O1 | open |
| O2 | open; the evidence is in a temporary scratchpad (copy it first) |
| O3 | open |
| O4 | open |
| O5 | open |
| O6 | waits for O3, O4, then the user |
| O7 | open |
| O8 | open |
| O9 | waits for the user's decision |
| O10 | open |
| O11 | open |
| O12 | open |
| O13 | open |
