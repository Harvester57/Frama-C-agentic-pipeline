# nginx 1.31.9 run-3: supervision report

- **Documentation Hub:** [`../README.md`](../README.md)
- **Run reports index:** [`./README.md`](./README.md)
- **Earlier runs:** [`./2026-11-19-nginx-run1-supervision.md`](./2026-11-19-nginx-run1-supervision.md) (run-1 and run-2)
- **Troubleshooting:** [`../troubleshooting/README.md`](../troubleshooting/README.md)

This report covers the external, read-only supervision of nginx 1.31.9 run-3. run-2 had halted on the opencode provider's usage limit, so the user resumed the work with Antigravity (Gemini) from a fresh run-3 prompt. The supervisor never wrote in the run directory, never messaged the session and never touched its containers.

## Parameters

| Parameter | Value |
| :--- | :--- |
| Run dir | `C:\Users\Florian\framac-pipeline\nginx-1.31.9\run-3` (`nginx-1.31.9-3e44199e7906 / run-3-94c5746e2bf8`) |
| Target | `C:\Users\Florian\OneDrive\Documents\Dev\targets\nginx-1.31.9` (no VCS), with run-1's build recipe from the user |
| Session | Antigravity conversation `e791011a-e085-487a-b2c3-079799cff13f`, read through its `transcript.jsonl` |
| Pipeline code | worktree `.agents/worktrees/nginx-run3-p1r`, detached at `f37cc6a` (phase1-remediation with the run-1/run-2 fixes merged), clean at the start |
| Fix mode | `hold`: fixes stay on `sup/nginx-*` branches and are not applied to the run |
| Poll / stall / recur limit | 2 min / 10 min / 3 |

## Status

**run-3 ended `incomplete` at 15:16 (2 h 24 min after the kickoff at 12:52:56), at the end of Phase 0.** `pipeline_make.py build-check` failed for both modules and `validate_artifacts.py` rejected the API harness sidecar. The model recorded the reason `phase0_gate_failed: build-check failed because link_repair added generated objs/ngx_modules.c which is not in workspace/work/ (missing from snapshot), and validate_artifacts.py failed on harness_nginx__ngx_event_openssl.json (selector > 254 in harness_sidecar.schema.json)`. `progress.json` keeps `phase_done: -1`. No Phase 1, 2 or 3 work ran.

Both reasons are pipeline bugs (S7, S6). A third one happened on the way and is hidden by the build report (S8): the broker admitted both E-ACSL builds at 2 GiB each, and both were OOM-killed.

### Timeline

`run-metadata.json` and `progress.json` do not timestamp the Phase 0 steps, so these times come from the supervisor's timeline (file mtimes and transcript steps, local time).

| Time | Step | Duration |
| :--- | :--- | :--- |
| 12:52:56 | Kickoff received; `run_metadata.py init` at 12:53:20 | |
| 12:54:20-12:55:34 | Build capture: one unit `objs/nginx`; the `objs/autotest` probe is dropped (S2 fix holds) | 1 min 14 s |
| 12:55:48-13:16:11 | Phase 0 model: `objs/nginx` parsed in 1207.9 s, 2240 functions, 12167 edges | 20 min 23 s |
| 13:16:23-13:18:20 | CodeQL and trust: 59 facts, 0 unmatched; 2183 untrusted, 57 trusted, 786 boundary | 2 min |
| 13:18:2x-13:18:46 | Seed harvest, fuzz assets (none shipped) | < 1 min |
| 13:18:46-13:21:56 | DAG: one cluster of 2208 functions and one of 20 (O1 reproduced) | 3 min 10 s |
| 13:23:32-13:58 | Stubs (25 headers, 295 functions, 25 author subagents) and security properties (23) | 35 min |
| 13:58-14:28 | API harnesses, reach gate, bulk exemptions | 30 min |
| 14:28-14:29 | First Step 5: `build-check` stops on the `pcre2.h` stub-check failure (S3) | |
| 14:29:41-14:34 | Second Step 5 after the overlay `#define` workaround: stub-check, seed, validate, checkpoint, gen | 5 min |
| 14:34-15:15:31 | `build-check`: two whole-tree E-ACSL builds, two OOM kills (the first at 15:01:48), both fail | 41 min |
| 15:16-15:17 | Model records the open bugs, sets `incomplete`, runs the report | |

## Findings and fixes

The numbering continues from the run-1 and run-2 report.

### S3. stub-check probes include a header without the macros the target defines first (`pcre2.h`)

- **Fingerprint:** `stub_check.py run` / `#error PCRE2_CODE_UNIT_WIDTH must be defined before including pcre2.h.` All three checks failed, and `stub_check.json` blocked every module.
- **Cause:** the ABI, Eva and dynamic probes include the overlay header bare. nginx defines `PCRE2_CODE_UNIT_WIDTH 8` in `src/core/ngx_regex.h` before it includes `<pcre2.h>`.
- **Fix (held):** branch `sup/nginx-stub-check-include-context` (`129e3c2`, `b68ff10`, `b838ce6`, `f029b86` on `f37cc6a`). `stub_check.py` derives each header's include context from `gcc -E -dD` of up to four caller compiles, writes the macros defined before the header's first inclusion ahead of `#include <H>` in every probe, and records `include_context` per header in `stub_check.json`. Tests in `tests/test_stub_check.py`, including two Docker regression cases. Supervisor check: read-only derivation against run-3's data gave `PCRE2_CODE_UNIT_WIDTH 8` for `pcre2.h`, `OPENSSL_SUPPRESS_DEPRECATED` for `ssl.h`, `_FILE_OFFSET_BITS 64` for `zlib.h`, and nothing for the other 22 headers.
- **In the run:** see "Model behaviour" for the workaround the model used.

### S4. The harness includes system headers before the target's feature-test macros (`in6_pktinfo`)

- **Fingerprint:** `generate_harness.py --api` / `ngx_event_udp.h:46:27: error: field has incomplete type 'struct in6_pktinfo'`. Without `--header`, the automatic prelude dropped every nginx header for the same reason (`the build capture's headers do not compile in the harness`).
- **Cause:** the generated harness includes `<stdint.h>` and other system headers before `ngx_config.h`, so nginx's `_GNU_SOURCE` arrives after glibc's `features.h` has been read.
- **Fix (held):** branch `sup/nginx-harness-feature-macros` (`50310f6`, `274f86a`, stacked on S3). The new `scripts/include_context.py` shares the S3 scan. `generate_harness.py` passes the derived feature-test macros as `-D` flags and records a `feature_macros` sidecar field. Tests: `tests/test_harness_feature_macros.py`, plus additions to `tests/test_stub_check.py`. Supervisor check: 50 passed with `FRAMAC_DOCKER_TESTS=1`, and ruff is clean.
- **In the run:** the model used the documented `--cppflags "-D_GNU_SOURCE"` workaround and wrote an accurate open-bug entry.

### S5. `--api` cannot spell a pointer to an anonymous-struct typedef (`ngx_str_t *`)

- **Fingerprint:** `api_harness` / `api_skipped` reason `pointer to an anonymous struct`. 284 of 370 skips on `nginx__ngx_event_openssl`; the reach gate then reported 369 gaps.
- **Cause:** nginx's core types are `typedef struct { ... } ngx_str_t;`. The model shows them as `struct __anonstruct_ngx_str_t_N *`, and `_spell_params` refuses every pointer to an anonymous tag, although the typedef name can be declared.
- **Fix (held):** branch `sup/nginx-api-anon-struct-typedef` (`4fd870e` test, `ea22f05` fix, `1a07593` docs), stacked on S4, following the anonymous-enum precedent (`1a7799f`).
  - The layout probe links each typedef to its nameless record by clang AST id and lays the record out under the typedef name. Such a typedef is no longer taken for an opaque handle (clang 19 writes it as `struct ngx_str_t`, glibc's `pthread_cond_t` as `union ...`).
  - `_bind_call` keeps the model tag as the pointee, so layouts, initializers, constructors and destructors reuse the named-struct path, and the object is declared and cast through the typedef. A record with no typedef name is still skipped, with its tag in the reason.
  - `_fill_fields` now also pairs a (length, byte pointer) field pair with a buffer the harness owns, clamping the length to it. It keeps a length before a pointer to wider elements at 0 (GMP's `_mp_size`). Without this, the fixture showed harness-induced overflows. This changes harnesses of named structs of those two shapes on other targets as well, so their selectors and consumed bytes shift.
  - Tests: `tests/test_api_harness_anon_struct.py` (13 tests, including a Docker test that builds from clang's real AST and fuzzes 100k runs under ASan/UBSan). `tests/test_api_harness_anon_enum.py` was adjusted. The new tests failed at `4fd870e`.
  - Fixer's dry run on a copy of run-3's inputs: 720 cases instead of 498, and 149 skips instead of 370. 221 of the 284 functions gain a case. 54 of the rest point to typedefs declared only in headers the harness does not include, which need `--extra-include`, mostly `ngx_quic_header_t`. The harness passes `clang -fsyntax-only`. Old corpora and crash inputs must be harvested again, since only 1 of the 409 surviving cases keeps its selector.
  - Supervisor check: 83 passed and 4 Docker tests skipped over the new and neighbouring test files, and ruff is clean. The fixer reports `pytest -n auto` at 7343 passed and 306 skipped, mypy clean, and the Docker tests passed.
- **In the run:** the model bulk-exempted about 360 reach gaps (see "Model behaviour").

### S6. The sidecar schema caps the dispatch selector at 254 although the generator uses two bytes

- **Fingerprint:** `validate_artifacts.py run-dir .` / `$.api_cases[255].selector: above maximum 254` (100 errors, cases 255-497).
- **Cause:** `a60a5a2` ("two-byte dispatch selector above 256 cases") made the generator emit `identity16` dispatch (`uint16_t harness_selector`, 498 cases here), but `schemas/harness_sidecar.schema.json` still has `"maximum": 254` in all five case definitions. This is also true on phase1-remediation `973e519` and on `main`.
- **Fix (held):** `ec4a477` on `sup/nginx-api-anon-struct-typedef`. The five case kinds share one `case_selector` definition with maximum 4094 (`api_harness.MAX_CASES - 1`). `dispatch_case_count` and `dispatch_cases` are bounded by 4096 (`DISPATCH_MAX_CASES_WIDE`). The schema language cannot tie the bound to `dispatch_selector`, so `validate_artifacts.validate_sidecar` checks the 256-case limit of one-byte dispatch in code. Tests: `tests/test_sidecar_selector_bound.py` (5 tests, all failing on the old schema). `tests/test_challenger_m4_adversarial.py` now rejects 4097 cases instead of accepting 1000000.
- **Remaining effect on run-3's files:** the existing sidecar still fails with one error, because the generator recorded its own schema warning in `warnings`. Regenerating the harness clears it.

### S7. Generated C sources are not kept after Phase 0 (`objs/ngx_modules.c`)

- **Fingerprint:** `pipeline_make.py build-check` / `run_eacsl_fuzz.py build` / `[kernel] User Error: source file 'workspace/work/objs/ngx_modules.c' does not exist`; sanitizer fallback: `clang: error: no such file or directory: 'workspace/work/objs/ngx_modules.c'`.
- **Cause:** nginx's `./configure` generates `objs/ngx_modules.c` in the scratch build tree. The capture and the DAG list it as a unit source, and the model parsed it from the scratch tree. `build_capture.py` snapshots only generated headers (`objs/ngx_auto_config.h`, `objs/ngx_auto_headers.h`), and `workspace/work/` has no `objs/`. When the harness link failed on `ngx_core_module` and `ngx_modules`, link repair added `src/core/nginx.c` and `objs/ngx_modules.c`, and every retry failed on the missing file.
- **Fix (held):** branch `sup/nginx-generated-sources`, cut from phase1-remediation `973e519` (`c97e28c` fix, `e0f94a7` docs, `79f49ec` kill detection, `c6ee2fa` docs).
  - The capture keeps every compiled in-tree `.c` file the target lacks in the snapshot, under `generated/<path>`, with a manifest entry and the digest. `target_env.install_generated_sources` copies it into `workspace/baseline/` and `workspace/work/` at its tree path. The capture, `workspace_overlay.py init` and the new `workspace_overlay.py install-generated` call it.
  - The copy keeps the one existing `workspace/work/<path>` rule that about 157 call sites rely on. The baseline copy, plus an explicit skip, keeps `apply_in_place` from writing the file into the target.
  - Targets without generated sources keep a byte-identical digest and manifest.
  - Link repair never adds a path that does not exist. It records `link_repair.missing_sources` with a named reason (snapshot copy not installed, deleted by the build, not kept by the capture, plain missing source), and build-check's `reason` names the file.
  - The build report now has `build_attempts`: engine, return code, reason and end of stderr per attempt, with earlier logs kept as `<stem>.attempt<N>.log`. e-acsl-gcc exits 1 whatever kills Frama-C, so `killed_suspected` marks an attempt that stopped with `aborted by Frama-C` and no Frama-C error line, and the hint says to confirm with `docker events`.
  - Tests: `tests/test_generated_sources.py` (16 tests) and `tests/test_generated_sources_docker.py` (E-ACSL and sanitizer builds after the scratch volume is removed). Before the fix, the Docker test reproduced run-3's errors on the fixture.
  - Fixer's read-only replay on run-3's data: link repair now adds `src/core/nginx.c` for `ngx_core_module` and reports `objs/ngx_modules.c` as `generated_source_missing` ("run the build capture again"). run-3 was captured before the fix.
  - Supervisor check: 182 passed and 19 Docker tests skipped over the new, overlay and capture test files, and ruff is clean. The fixer reports `pytest -n auto` at 7370 passed and 305 skipped, mypy clean, and 142 Docker tests passed.
- **Likely next failure (open, not verified):** link repair adds `src/core/nginx.c`, which defines nginx's `main`, to the libFuzzer link for the global `ngx_core_module`, instead of stubbing that global as `link_globals_source` does for others. The next nginx build-check will probably stop on a duplicate `main`.

### S8. Two whole-tree E-ACSL builds admitted at 2 GiB each: OOM kill, hidden by the report

- **Fingerprint:** docker event `oom` on the build-check container at 15:01:48, when the container was at 16.78 of 17 GiB (swap equal to the limit) with two Frama-C processes at about 8.4 and 8.8 GB, after 23 minutes of preprocessing. The container's own history record says `oom_kills: 2`, peak 17408 MiB.
  - **Attribution, from the per-key peaks:** `nginx__ngx_files` peaked at 8809 MiB, while the surviving process was at 9172 MiB and growing at 15:02:15. So the first kill hit the ngx_files Frama-C. The openssl Frama-C then grew alone to the container limit (`peak_mb` 17173) and was killed by the second kill.
  - This corrects the supervisor's live note, which had attributed the first kill to openssl by process-id order.
  - The openssl whole-program E-ACSL instrumentation alone needs more than the 17 GiB the build-check container had. Serializing the builds is necessary but not enough. The host has about 39 GiB, so a larger build container, or smaller slices (O1), is needed.
- **Cause:** `CLASSES["build"]` in `scripts/resources.py` reserves 2048 MiB with no per-CPU memory, and there was no build history for these keys. Phase 0 had already measured a 10471 MB peak for the whole-unit nginx parse (`state/resource-history/phase-static`). Under engine `auto`, a killed E-ACSL compile falls back to the sanitizer build (`fuzz_build._attempt`), so `run_eacsl_fuzz` does not exit with -9/137 and the broker's one OOM retry never fires. The build report and compile log keep only the last attempt, so `build.json` says `eacsl_instrumentation_failed` from the post-repair attempt and the OOM appears nowhere. The history recorded `peak_mb` 17173 for the openssl key (rusage over all attempts) with `oom_killed: false`.
- **Fix (held):** branch `sup/nginx-build-memory`, cut from phase1-remediation `973e519` (`c35dfb0`, `7dbaf92`, `090c0f3`, `3ccf6a1`). All code changes are in `scripts/resources.py`.
  - `first_build_estimate` sizes a module's first `build` lease as 1.25 × the Phase 0 parse peak of each parse job, scaled by the share of that job's sources the build compiles. The parse peak comes from the job's own parse history, or else from the model container's record (within 120 s of the model's end).
  - For run-3 this asks 12931 MiB for openssl and 12772 MiB for files. That exceeds the 17408 MiB pool together, so they run one at a time.
  - The lease takes the larger of the estimate and the key's history, so a build that aborts in seconds cannot size the next one back down to 2 GiB.
  - Small units are unchanged: the 2048 MiB class default applies while 1.25 × the scaled peak is at most 2048. The 1.25 margin is `history_estimate`'s existing one, not a measured E-ACSL overhead.
  - Parse leases now record history: they used to write it into the scratch tree.
  - `oom_evidence` charges a cgroup `oom_kill` during a job to that job when it was SIGKILLed, ran alone, or went over its gated lease. A job that stayed within its lease beside others is not charged; the raw count stays in `oom_kills_during`. A kill that hit a grandchild therefore sets `oom_killed: true` even with exit code 1.
  - The one retry asks for max(2 × lease, 1.25 × peak), capped at the pool, and only for a failed job.
  - Tests: `tests/test_resources_build_memory.py` (run-3's records copied verbatim, real `resources.py run` processes on a fake 17 GiB cgroup). 17 of the first 19 tests failed on `973e519`, for example with `assert (2048, 2048) == (12931, 12772)`. Guide: `docs/guides/resources-and-caching.md`.
  - Supervisor check: 101 passed and 3 skipped over the new tests and `tests/test_resources.py`, and ruff is clean. The fixer reports `pytest -n auto` at 7371 passed and 303 skipped, and mypy clean.
  - Not verified: a real two-module build-check in Docker. This Windows host has no `os.wait4`, so the tests inject peaks through a fake cgroup. `eva` still has a fixed 2048 MiB. The reporting half (keep each attempt's failure reason) is in the S7 fixer's brief.

### S9. stub-check's smoke driver zeroes a `const` scalar with `memset` (open, found by the run's model)

- **Fingerprint:** `stub_check.py` / status `valid_call_alarm` on `workspace/stubs/openssl/tls1.h` (`SSL_get_servername`). `fc_stub_smoke_report.csv`: `precondition of memset Invalid or unreachable valid_s: valid_or_empty(s, n)`.
- **Cause:** for a `const`-qualified scalar parameter, the smoke driver declares `int const v_1;` and then emits `memset(&v_1, 0, sizeof v_1);` (`scripts/stub_check.py` line 291 on the merged tree). Frama-C's libc rejects writing to a `const` object, so the call after it is dead.
- **Effect in run-3:** none on the gate; stub-check reported no failures. The smoke check of that function proves nothing, though.
- **Fix:** none. Open pipeline bug: strip the top-level `const` from the smoke variable, or initialize it with `= 0`. Entry: `kernel-and-stubs.md`, "`stub_check.py` Reports `valid_call_alarm` When a Stubbed Function Has a `const`-Qualified Scalar Parameter".

### O1. The unit split cannot divide nginx (still open, no fixer)

Reproduced on `f37cc6a`: one cluster of 2208 functions (133900 lines, 779 anchors) and one of 20, with 17 unclustered. New evidence from run-3: the E-ACSL builds take the whole tree in both clusters (163 and 161 `.c` files, even for the 20-function cluster), so each needs a whole-program instrumentation of about 9 GB. O1 multiplies S8.

## Troubleshooting entries and upstream drafts

- The model wrote accurate entries in the run worktree (uncommitted): S3 with its overlay workaround, S4, S5, S6, S7 and S9. They are harvested in the supervisor's docs commit, not copied, because each fixer branch has its own entry for S3 to S7:
  - the overlay workaround and the recovery step go into the S3 entry;
  - S9 becomes a new open entry in `kernel-and-stubs.md`;
  - the bulk exemptions become a new open-gap entry in `harnesses-and-seeds.md` ("The Reach Gate Passes After Hundreds of Exemptions Whose Reason Names a Pipeline Bug");
  - the S8 entry in `resources-and-infra.md` gets the two-kill attribution and the 17 GiB finding.
- Fixer branches: S3 and S4 entries in `kernel-and-stubs.md` and `harnesses-and-seeds.md`. S5 in `harnesses-and-seeds.md` (`--api` Skips nginx's `ngx_str_t *` Parameters), with an update to the GMP `mpz_t` entry. S6 in `ledger-and-verifier.md`. S7 in `phase0-build-and-model.md`, and the last-attempt-only report in `eacsl-and-fuzzing.md`. S8 in `resources-and-infra.md` ("`build-check` E-ACSL Build OOM-Killed: Two Whole-Program Builds Admitted at 2 GiB Each"). It is amended in the supervisor's docs commit.
- No upstream draft: none of these is a Frama-C or E-ACSL bug.

## Model behaviour (not pipeline bugs)

- **`pcre2.h` overlay workaround (14:29:24, step 263).** After build-check stopped on S3, the model added `#ifndef PCRE2_CODE_UNIT_WIDTH` / `#define PCRE2_CODE_UNIT_WIDTH 8` before `#include_next <pcre2.h>` in `run-3/workspace/stubs/pcre2.h`. This breaks the kickoff rule (stop and report when a Phase 0 gate fails) and the stub author brief (contracts only). It was transparent: the model updated its troubleshooting entry to say so. The value matches nginx's own and is guarded, so nginx's units are unaffected, but the overlay digest changes. The supervisor notified the user, who chose to let the run continue.
- **Bulk reach exemptions (14:17-14:28).** The model exempted about 360 reach gaps through `harness_reach.py exempt`, grouped under blanket reasons such as `api_harness_anonymous_struct_typedef ... (open pipeline bug)` and `api_harness_omitted: ... requires nginx runtime state`, without checking each function. `framac-slice` reserves exemption for entry points that cannot be driven from bytes. The root cause is S5; the gate accepts any reason. Suggested change (not applied): `harness_reach.py exempt` could refuse a reason that names a pipeline bug and point to the troubleshooting entry instead.
- **`harness_reach.py check || true`** in the model's own regeneration script (`cmd_fix_files_harness.sh`) swallowed the gate's exit code. build-check still ran the gate, so nothing was skipped.
- **Stub-check after the authors.** The 25 stub authors each ran `stubs stub-check` (the brief tells them to), up to nine at once. The orchestrator did not rerun it before moving on to the harnesses, so the S3 blocker surfaced only at build-check, about 30 minutes later.
- **Good:** accurate diagnoses and open-bug entries for S4, S6 and S7, no pipeline file edited, and a clean stop with a recorded reason at the end.

## Open items

- S3 to S8 are fixed on their branches. S9, O1, the likely duplicate `main` after S7, and the build container's 17 GiB limit (too small for the openssl whole-program E-ACSL build alone) have no fixer.
- Merges `aa65c16` (S3 to S6), `9b1a247` (S7) and `e8ccd54` (S8) onto phase1-remediation `973e519` had no conflicts. On the result: `pytest -n auto` 7432 passed and 311 skipped, ruff clean, mypy clean (334 files), and the generated-text, skill-mirror and docs-structure checks pass. Moving phase1-remediation to them waits for the user's go-ahead.
- At the end, merge the held branches into phase1-remediation after a dry run each, then refresh this report.
- Not verified: whether the `nginx__ngx_files` E-ACSL instrumentation itself succeeded before the link failure. Its compile log keeps only the last attempt.
