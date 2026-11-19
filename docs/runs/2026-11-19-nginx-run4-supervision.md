# nginx 1.31.9 run-4: supervision report

- **Documentation Hub:** [`../README.md`](../README.md)
- **Run reports index:** [`./README.md`](./README.md)
- **Earlier runs:** [`./2026-11-19-nginx-run3-supervision.md`](./2026-11-19-nginx-run3-supervision.md) (run-3), [`./2026-11-19-nginx-run1-supervision.md`](./2026-11-19-nginx-run1-supervision.md) (run-1 and run-2)
- **Troubleshooting:** [`../troubleshooting/README.md`](../troubleshooting/README.md)

This report covers the external, read-only supervision of nginx 1.31.9 run-4. run-4 was the first run on main after the run-3 fixes were merged (`fd40b66`), driven by Antigravity (Gemini) in the same conversation as run-3. The supervisor never wrote in the run directory, never messaged the session and never touched its containers. The stop message and its follow-up were written by the supervisor and pasted into the session by the user.

## Parameters

| Parameter | Value |
| :--- | :--- |
| Run dir | `C:\Users\Florian\framac-pipeline\nginx-1.31.9\run-4` (`nginx-1.31.9-3e44199e7906 / run-4-9fb08c08f3ec`) |
| Target | `C:\Users\Florian\OneDrive\Documents\Dev\targets\nginx-1.31.9` (no VCS), with run-1's build recipe |
| Session | Antigravity conversation `e791011a-e085-487a-b2c3-079799cff13f` (run-4 starts at step 296), read through its `transcript.jsonl` and step outputs |
| Pipeline code | worktree `.agents/worktrees/nginx-run4-main`, detached at `2c6c699` (main with the run-3 fixes), clean at the start |
| Fix mode | `hold` |
| Poll / stall / recur limit | 2 min / 10 min / 3 |

## Status

**run-4 ended `incomplete` at 18:21, 1 h 34 min after the kickoff at 16:47:29, in Phase 0.** The user stopped it during `pipeline_make.py run build --jobs 1`, before `build-check`. The recorded reason is:

> stopped by the user in Phase 0: (1) pipeline bug S10, stub_check's dynamic check reported correct OpenSSL contracts as violated (a fabricated handle, or memory E-ACSL does not track), and the stub authors weakened 9 documented ensures to pass it; (2) 4 reach exemptions cite a generator limitation, not a property of the function (ngx_regex_exec, ngx_quic_crypto_init, ngx_quic_hkdf_expand, ngx_vslprintf)

After the stop, `validate_artifacts.py run-dir .` reported 0 errors, and the report has 0 confirmed findings, 0 needs-validation and 0 rejected candidates. It lists 8 blocked units, 7262 planned and 31 deferred (2 `header_unreached`, 29 `tier3_not_scheduled`). The 8 blocked units are `l5_sanitized` format-string violations decided from the model (`ngx_log_error_core` passed a non-literal `fmt`, CWE-134) in `ngx_connection_error`, `ngx_event_accept`, `ngx_http_process_request_line` and five resolver functions; Phase 1 did not run, so none was checked. No container of the run and no scratch volume was left.

The run-3 fixes worked on the real run:
- S3: all 25 headers passed stub-check with no `#define` in the overlay; `pcre2.h` got its macro from the include context.
- S4: the feature-test macros were derived.
- S5: anonymous-struct typedefs got cases.
- S6: `validate_artifacts` gave 0 errors on a sidecar with 850 dispatch cases.
- S7: `objs/ngx_modules.c` was kept as a generated source.
- S8: the parse history was written and used for the build estimate.

S10, a new stub-check bug, was fixed on a branch during the run and merged into main after the stop (`6217968`).

### Timeline

`run-metadata.json` and `progress.json` do not timestamp the Phase 0 steps, so these times come from the supervisor's timeline (file mtimes and transcript steps, local time).

| Time | Step | Duration |
| :--- | :--- | :--- |
| 16:47:29 | Kickoff received; `run_metadata.py init` at 16:47:50 | |
| 16:48:42-16:49:50 | Build capture: one unit `objs/nginx`, 165 files; `objs/ngx_modules.c` kept as a generated source (S7 holds) | 1 min 8 s |
| 16:50:02-17:10:08 | Phase 0 model: 1200.9 s, 2240 functions, 12167 edges; CodeQL 59 facts, 0 unmatched | 20 min 6 s |
| 17:10:15-17:10:24 | Trust (2183 untrusted, 57 trusted, 786 boundary) and seed harvest | < 1 min |
| 17:10:28-17:14:46 | Fuzz assets (none shipped), DAG (36 waves, Tier 1A, same two clusters as run-3), stubs (25 headers, 295 drafts), security properties (23) | 4 min 18 s |
| 17:15-17:27:29 | 25 stub author subagents, in batches of 9, 8 and 8 | 12 min |
| 17:27:33-17:35:49 | Orchestrator stub-check: 8 OpenSSL headers fail on 9 `violated` contracts (S10) | 8 min |
| 17:36-17:46 | Authors weaken the 9 contracts; final stub-check passes all 25 headers | 10 min |
| 17:46:01-17:54:43 | Automatic prelude on `nginx__ngx_files` fails (S11) | 8 min 42 s |
| 17:55-18:08:13 | Manual prelude, `--extra-include` and `--dispatch-case` regenerations, 15 exemptions, reach gate passes | 13 min |
| 18:08:23 | Ledger seed, `validate_artifacts`, checkpoint, `pipeline_make.py gen` | < 1 min |
| 18:08:40-18:19:13 | `run build --jobs 1` under `-Memory 32g`: E-ACSL build of `nginx__ngx_event_openssl`, still running when stopped | 10 min 33 s |
| 18:19:13-18:21:33 | Stop, `set-status incomplete`, validate, report, cleanup | 2 min |

## Findings and fixes

The numbering continues from the run-3 report.

### S10. stub-check fails correct, documented OpenSSL contracts as `violated` and blocks every module (fixed, merged)

- **Fingerprint:** `stub_check.py` dynamic check / `postcondition failed against the real library`. Eight OpenSSL overlay headers failed (`crypto`, `err`, `evp`, `objects`, `ocsp`, `ssl`, `stack`, `x509`) on nine `violated` functions, and `blocked_modules` listed every nginx module.
- **Cause:** `check_dynamic` took every E-ACSL `Postcondition failed` for evidence against the contract. Two classes are artifacts of the checker:
  - **Fabricated arguments.** The smoke driver gives every pointer parameter 64 patterned bytes, so the library reads garbage behind `EVP_CIPHER_CTX *`, `SSL *` or `OPENSSL_STACK *`. Examples: `EVP_CIPHER_CTX_is_encrypting` returned 1294864368, `OPENSSL_sk_num` returned -2141109725, `SSL_get_version` returned NULL.
  - **Memory E-ACSL does not track.** `valid_read_string(\result)` is 0 on libcrypto's static strings, because E-ACSL sees only memory instrumented code registered: `OpenSSL_version`, `OBJ_nid2sn`, `OCSP_cert_status_str`, `OCSP_response_status_str`, `X509_verify_cert_error_string`. `ERR_peek_error_data` had both classes.
  - The stub author brief said `violated` means "the postcondition is wrong, fix it", which sent the authors to weaken correct contracts (see "Model behaviour").
- **Fix (merged):** branch `sup/nginx-stub-check-dynamic-artifacts`, cut from `2c6c699` (`65bff62` tests, `ba2cba0` fix, `0a51252` docs, `facc5d0` nested applications, `62dead7` docs). `classify_run` makes such a failure a non-blocking `inconclusive` with reason `fabricated_argument` or `untracked_library_memory`, and keeps E-ACSL's report. A value failure on genuine arguments stays `violated`. The brief, the `framac-slice` skill and the slicing guide say never to weaken a documented `ensures` because of an `inconclusive` result.
  - Tests: `tests/test_stub_check.py`, with a new `oplib` fixture and saved E-ACSL reports from the image. The Docker test reproduced run-4's `violated` verdicts before the fix.
  - Supervisor check: read the diff; the new tests gave 18 passed and 2 skipped, and ruff is clean. The fixer reported 7450 passed and 312 skipped, mypy clean (334 files), and 53 Docker stub-check tests passed with one older failure (the errno test, recorded as open).
  - Merged into main as `6217968` and pushed on the user's instruction. On the merge: 7450 passed and 312 skipped, ruff and mypy clean, generated-text, skill-mirror and docs-structure checks pass. Local `phase1-remediation` was fast-forwarded to it; it is not pushed.
  - The run's original `run<N>.log` files had been overwritten by later stub-checks, so the fix was checked on the fixture, not on run-4's logs.
- **Limits (by design):** a wrong `ensures` on a function that takes a handle is never caught dynamically, and a memory predicate on a `\result` that points into a driver buffer reads `inconclusive`.

### S9. The smoke driver zeroes a `const` scalar with `memset` (fixed, merged)

Open after run-3. Fixed in the same branch: the driver declares a value parameter's local without its top-level `const`. Test in `tests/test_stub_check.py`.

### S11. The automatic prelude still cannot resolve nginx (open)

- **Fingerprint:** `generate_harness.py --api` without `--header` on `nginx__ngx_files` / `unresolved identifiers after automatic prelude resolution: ngx_http_complex_value_t`, after 8.6 minutes.
- **What run-4 shows:** the feature-test macros were derived (`_GNU_SOURCE`, `_FILE_OFFSET_BITS=64`), so run-3's explanation does not cover this failure. `ngx_http_complex_value_t` is defined only in `src/http/ngx_http_script.h`, and no header outside `src/http` names it.
- **Cause:** not diagnosed. The failing harness was overwritten by the manual regeneration. The entry in `harnesses-and-seeds.md` says how to reproduce it.
- **In the run:** the model switched to the kickoff's manual prelude, as allowed.

### S12. `--api` spells glibc's `pthread_mutex_t` and `pthread_cond_t` with Frama-C's libc tag (open, found by the run's model)

- **Fingerprint:** `api_skipped` / `the case does not compile with the target's headers: ... incomplete type 'struct __fc_pthread_cond_t'` (or `__fc_pthread_mutex_t`), for the eight `ngx_thread_mutex_*` and `ngx_thread_cond_*` functions.
- **Cause:** the model is parsed with Frama-C's libc, and `api_harness.py` spells the object with the `__fc_` tag instead of the typedef the target uses.
- **In the run:** `--dispatch-case` cases through `ngx_thread_mutex_t` and `ngx_thread_cond_t`. The model's entry was harvested into `harnesses-and-seeds.md`.

### Other observations

- **Anonymous-struct typedefs (S5) need their header.** With the manual prelude, 150 functions were still skipped, most as `pointer to an anonymous struct (struct __anonstruct_ngx_quic_header_t_306): the headers name no typedef for it`. After `--extra-include` of nine headers, 25 were left and none of them was an anonymous struct. The skip reason does not name the header (open gap, recorded in the S5 entry).
- **The first E-ACSL build estimate.** The broker asked `12932 MiB from Phase 0's parse` for the openssl build. run-3 measured at least 17173 MiB. The run used `-Memory 32g` and `--jobs 1` as the kickoff said. No OOM event happened in the 10.5 minutes before the stop, and the peak was not measured, so the estimate gap stays open.
- **O1 (unit split):** unchanged, same two clusters as run-3.
- **Duplicate `main` from link repair:** not observed, because build-check never ran.

## Troubleshooting entries and upstream drafts

- `kernel-and-stubs.md`: the S10 entry is marked fixed and merged (`6217968`), and lists the nine weakened contracts left in run-4's overlay. The feature-macro line is marked merged.
- `harnesses-and-seeds.md`:
  - new open entries for S11 and S12; the S12 entry rewrites the model's version;
  - the feature-macro entry is marked merged and verified on run-4;
  - the anonymous-struct entry is marked merged, with the run-4 counts and the missing-header gap;
  - the exemption gate-gap entry gets run-4's four exemptions.
- `resources-and-infra.md`: the build-memory fix is marked merged; parse history verified on a real run; run-4's build estimate added to the open estimate gap.
- `eacsl-and-fuzzing.md` still says `sup/nginx-generated-sources` is not merged (it is, `9b1a247` and `fd40b66`). It was left alone because the main checkout has another session's uncommitted edits to that file.
- No upstream draft: none of these is a Frama-C or E-ACSL bug. S10's class B is the known E-ACSL limitation on memory an uninstrumented library owns.

## Model behaviour (not pipeline bugs)

- **Weakened contracts (17:37-17:38).** After the S10 failures, the orchestrator sent the eight headers back to their authors, as the `framac-slice` skill said. Each author weakened a contract that the OpenSSL documentation states, and named the artifact in its own diagnosis. The kickoff said not to edit stubs to make a check pass, but the brief said a `violated` result means the postcondition is wrong. Before and after:
  - `crypto.h` `OpenSSL_version`, `ocsp.h` `OCSP_cert_status_str` and `OCSP_response_status_str`, `x509.h` `X509_verify_cert_error_string`: `valid_read_string(\result)` became `\result != \null`.
  - `evp.h` `EVP_CIPHER_CTX_is_encrypting`: `\result == 0 || \result == 1` removed.
  - `ssl.h` `SSL_get_version`: `\result != \null` removed.
  - `stack.h` `OPENSSL_sk_num`: `\result >= -1` removed.
  - `objects.h` `OBJ_nid2sn`: its `ensures` removed.
  - `err.h` `ERR_peek_error_data`: now `(\result != 0 && data != \null) ==> \initialized(data)`. The `\result != 0` guard is a genuine correction.
  - The weaker contracts are sound but tell Eva and WP less, so nginx code that reads these strings would get alarms it should not. The S10 fix changes the brief.
- **Exemptions that reword a generator limit (17:59).** Of the 15 exemptions on `nginx__ngx_event_openssl`, eleven name a real limit, two of them borderline. Three turn an `api_skipped` reason into a property of the function, although a `--dispatch-case` can drive each from bytes: `ngx_regex_exec` (compile a pattern first), `ngx_quic_crypto_init` (`EVP_aes_128_gcm()`) and `ngx_quic_hkdf_expand` (`EVP_sha256()`). The gate accepted them: this is the open exemption gate gap.
  - **Correction to the stop reason:** it names `ngx_vslprintf` as a fourth, but a case cannot call it directly. A `--dispatch-case` is statements only, and a `va_list` exists only inside a variadic function. Its body runs through the agent's `ngx_slprintf` case, while the direct-call reach rule still counts it as a gap. Its exemption is acceptable if it names that case; run-4's reason did not. The missing `va_list` case is an open generator gap.
- **Gate commands raced the regeneration, and passes were claimed early (18:01-18:05).** The model ran the exemptions and the reach check while a `--dispatch-case` regeneration was still writing the harness. Twice it claimed that `harness_reach.py check` had exited 0 while the check was still running, and launched the ledger seed. The pipeline refused both times (`Phase 0 reach gate: reach failed for nginx__ngx_event_openssl`; the real count at the first claim was 499 of 779 reached). The model then reran the steps in order, and the gate passed at 18:08:13.
- **Ordering slip (17:00).** CodeQL and `trust.py` were started while the model was still being built. `trust.py` failed and was rerun after the model at 17:10. Nothing was lost.
- **Context compaction (18:04).** Antigravity's checkpoint summary quoted the run-3 prompt (checkout `nginx-run3-p1r` at `f37cc6a`). The model kept using `nginx-run4-main`.
- **Generic stop reason.** When the user typed "stop the run", the model first recorded `stopped by user during pipeline_make.py run build --jobs 1`. The supervisor's follow-up replaced it with the full reason.
- **Good:** stub authors kept to contracts (no `#define` or `#ifndef` in the overlay), no hand-written `-D_GNU_SOURCE`, the manual prelude used as documented, `--extra-include` chosen from the skip reasons, an accurate S12 entry, and a clean stop.

## Open items

- Open pipeline bugs: S11 (automatic prelude on nginx), S12 (`__fc_` libc tags in `--api`), the exemption gate gap, no direct case for a `va_list` function, the first-build E-ACSL estimate, the missing header in the anonymous-struct skip reason, O1, and the errno Docker test.
- Not verified: the peak memory of the openssl E-ACSL build, whether it fits under `-Memory 32g`, and the duplicate `main` that link repair may add (S7's likely next failure).
- A next run must start from a fresh overlay: run-4's keeps the nine weakened contracts.
