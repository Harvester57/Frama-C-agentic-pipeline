# sudo run-1: supervision report

- **Target:** sudo 1.9.18, commit `082045c6` (dirty checkout), profile `quick`, whole target. Recipe `./configure && make`, with the target's `THREAT_MODEL.md` (a `framac-threat-model` block added with the user's approval before the run, SHA-256 `646f33875bbe182455f0f65e3e3961463164760df15f9920bd88c20fb7f61cf8`) and CodeQL enabled.
- **Run directory:** `~/framac-pipeline/sudo/run-1`, identity `sudo-6c1f9634acf7` / `run-1-e7bc881eee3c`, `make_jobs` 30, `max_agents` 15.
- **Driver:** a Claude Code session on Sonnet 5.5 (`sudo pipeline run (quick, threat model + CodeQL)`), started by the supervisor session at the user's request. It shares this checkout.
- **Pipeline:** `main` at `b035152` when the supervision started, plus 62 files of other sessions' uncommitted changes. The run executes those as they are.
- **Fix mode:** `live`, chosen by the user for each fix: every verified fix was merged into `main` while the run went on, so the run used it from its next step (`wrappers/framac-docker.*` mounts `scripts/`, `templates/`, `schemas/` and `skills/` from this checkout).
- **Status:** **stopped by the user** on 2026-11-22 at about 13:00 local (UTC+1), during the pause before the Phase 1 redo. `phase_done` 0, `run_status` still `in_progress`: the run directory was left as it is, so no final status, report or SARIF was written.

## Final status

- **Outcome:** stopped by the user ("Okay let's stop this run, this is going nowhere") about 23 hours after it was created. Phase 0 completed. Phase 1 built every module and fuzzed 21 of 25 modules before `run fuzz` hit its 3-hour timeout. No crash candidate was verified, and Eva, the crash verification gate and WP never ran.
- **Why it went nowhere:**
  - Phase 0 took 15 hours. It was redone three times on 13 pipeline bugs found in sudo's build: C23 attributes, string `-D` macros, flex/bison `#line`, link repair, E-ACSL printer and linker gaps.
  - **Phase 1 produced little that counts:**
    - 314 crash artifacts in 110 fingerprints. Every one the supervisor sampled was harness-induced: zeroed protobuf-c allocators, frees on stack messages, program-internal functions called without `main`'s set-up.
    - 7 modules got no fuzzing at all on one or both engines: the interposer modules, and the E-ACSL halves of the `tf_` modules.
  - The fixes for both are general pipeline fixes (14, 15). They change every cache key and the `--api` harnesses, so using them meant another full rebuild of about 2.5 hours plus harness regeneration.
- **Wall-clock time per phase** (from the supervisor's timeline; the run records no per-phase timestamps):

  | Phase | From | To | Time |
  | :--- | :--- | :--- | :--- |
  | Phase 0 (with three redos and the waits for fixes 1 to 12) | 2026-11-21 14:07 | 2026-11-22 05:16 | about 15 h 10 |
  | Phase 1 `run build` (two calls; the first timed out) | 05:16 | 09:30 | about 4 h 15 |
  | Phase 1 `run fuzz` (timed out, 21 of 25 reports) | 09:30 | 12:28 | about 3 h |
  | Paused, waiting for fixes 14 and 15, then stopped | 12:28 | about 13:00 | about 30 min |

- **Fixes:** 15 in total. All are merged on `main` (`377283c` at the end), none were pushed, and the run used fixes 1 to 12.
  - Fixes 14 and 15 were merged after the stop, at the user's request ("check and merge" once ready). Neither was exercised on a full sudo run, only on scratch copies of run-1's modules.
  - Before merging, the supervisor ran `mypy scripts tests` on each. It found one Windows typing error in fix 14's test file and fixed it (`377283c`). It also fixed fix 13's mypy errors in `5a5a4b4`.
  - A follow-up commit on `main`, `5a5a4b4`, fixes four mypy errors that fix 13's test file brought in. The supervisor's check before the merge had missed them.

## Timeline

Times are local (UTC+1), from the supervisor's timeline: run files and their mtimes, `progress.json`, containers, and the driver's transcript. The run records no per-phase timestamps.

| Time | Event |
| :--- | :--- |
| 14:07 | The driver creates the run. 14:09 the driver's own PowerShell helper passes `-ScriptFile` as a plain argument (`unknown wrapper option '-ScriptFile'`); a model error, fixed by the driver. |
| 14:11 | `build_capture` ok, 25 units; `check-threat-model` exit 0; CodeQL enabled. |
| 14:11 | `phase0_model` run 1: 19 of 25 units on the GCC fallback (syntax error at `include/sudo_fatal.h:173`). The driver first patches `restrict` (wrong cause), then finds the C23 `[[__noreturn__]]` cause itself and patches the run's `config.h` copies (run-dir workaround). |
| 14:17 | `codeql_trust` `database_failed`: the recipe's `chmod +x ... 2>/dev/null;` aborts under `set -e` in `build.sh`. The driver reruns with `--recipe-file` (open pipeline bug, see below). |
| 14:20–14:40 | Harness generation for the fallback units fails (`signature '' not understood`); the driver records 284 reach-gate exemptions (`repair/exempt_all.py`). |
| ~14:45 | **Fix 1** (C23 attributes) merged live as `9950ee3`. |
| ~14:50 | 12 stub authors dispatched. |
| 15:11 | `build-check` 1: 15 of 21 modules `build_failed`, mostly on string-valued `-D` macros (`LOCALEDIR`). The driver appends the macros to the run's `config.h` copy (run-dir workaround). |
| ~15:55 | **Fix 2** (libc gaps, unknown pragmas) merged live as `c0a495b`. |
| ~16:00 | **Fix 3** (string `-D` macros, link-repair header records) merged live as `784401d`. `build-check` 2 had already started on the old code. |
| ~16:02 | The supervisor relays the user's decision "Yes, after -D fix": redo Phase 0 from `phase0_model.py`. |
| ~15:52–16:05 | Phase 0 redo: 25 of 25 units parse, 0 on the GCC fallback. 6 stub authors; `ptrace` stays a draft (stub-check ABI failure). |
| 15:56–16:50 | Reach-gate exemption batch: one `harness_reach.py exempt` per entry, each re-running the gate (about 55 min). |
| ~16:38 | **Fix 4** (ptrace stub header and variadic prototype) merged live as `f97dd72`. |
| ~16:45 | The supervisor relays the user's decision "Relay the steps" with the ptrace recovery steps. |
| 16:52 | The driver reruns the model and `stubs`/`stub-check`: the overlay now has `sys/ptrace.h`, the stale `bits/ptrace-shared.h` is gone (97 filled, 2 drafts). |
| 16:56 | Ledger seed, `validate_artifacts`, `gen` ok; `build-check` 3 starts (timeout 5400 s). |
| ~17:20 | **Fix 5** (seed recording, security-property signatures) merged live as `63caeeb`. Run-1 recorded its seeds and properties before it. |
| 18:10 | `build-check` 3 done, `ok: false`: 3 modules build with E-ACSL, about 13 fall back to the sanitizers, about 9 `build_failed` (link-repair redefinitions, `link_globals.c` headers without `config.h`, `_Alignof` on OpenSSL opaque types, `sudoers_subsystem_names`, `struct iolog_file`, `parse_json.h`). |
| ~18:20 | The user chooses "Fix in the pipeline"; the supervisor relays it, and the driver holds at Phase 0. Fixers 6 and 7 dispatched. |
| ~19:30 | **Fix 7** (`_Alignof` on incomplete types) merged live as `9217c47`. |
| ~19:45 | **Fix 6** (link-repair globals and stub prelude) merged live as `ef2f6fb`. |
| ~20:00 | **Fix 9** (`#line` attribution of flex/bison output) merged live as `3774d95`. It changes the Phase 0 dump, so the run must redo Phase 0 from the build capture (its scratch volume is gone). |
| ~20:05 | **Fix 8** (forward array sizes, other units' `-I`, prelude order, target-fuzzer links) merged live as `126b489`. |
| ~20:08 | The supervisor relays the combined resume: build capture, model, seeds, DAG, stubs, stub-check, security properties, all harnesses, reach gate, ledger seed, `gen`, `build-check`. |
| 20:09–20:30 | Phase 0 redo: build capture ok; model 25 of 25 units, the `toke.c` threat-model warning gone (fix 9); seed recording 160 calls (fix 5); stub-check blocks nothing; 27 harnesses; reach gate 29 of 29 (4 new exemptions for lexer entry points, see below); ledger seed, validation and `gen` ok. |
| 20:30–22:00 | `build-check` 4, killed at the driver's 90-minute timeout (`rc=124`) with no `build_check.json`. Of the 18 modules it reached, 11 build with E-ACSL (3 in build-check 3), confirming fixes 6, 7 and 8. New blockers: library fuzzers pulling in sudo's front end, link repair linking `cvtsudoers.c` for `open_sudoers`, and the printer's fallthrough attribute. |
| ~22:40 | Fixers 10 and 11 dispatched. The driver asks whether to rerun now or wait; the user chooses "Wait for fixes (Recommended)", relayed at 23:20. |
| 23:24 | **Fixes 10 and 11** merged live as `7979a9f` (one dry-run merge, conflict in `skills/framac-slice/SKILL.md` resolved, 8195 tests passed). The supervisor relays the resume: regenerate the 8 `tf_` harnesses, reach gate, ledger seed, `gen`, `build-check` with a 4-hour timeout. |
| 23:32 | `tf_` harnesses regenerated (`tf_fuzz_sudo_conf` 52 sources, was 166; `tf_fuzz_iolog_json` 82, was 153; no `src/` file), reach gate 29 of 29, ledger seed, validation and `gen` ok. |
| 23:38–01:46 | `build-check` 5: `ok: false`, **22 of 25 modules build with E-ACSL** (3 in build-check 3), confirming fixes 10 and 11 (`libparsesudoers_a`, `visudo`, `tsdump`, `tf_fuzz_policy` and the `tf_` iolog fuzzers now build). Left: `cvtsudoers` (Frama-C linker, falls back), `tf_fuzz_sudoers` (falls back) and `tf_fuzz_sudoers_ldif` (`build_failed`). |
| ~01:55 | The user chooses "Fix both, then rerun (Recommended)", relayed with the sanitizers choice for `cvtsudoers`. Fixer 12 dispatched. |
| ~02:25 | Fix 12 verified (its 19 tests, full suite 8216 passed, ruff, mypy, text check) and fast-forwarded to `main` as `d158912`. Resume relayed: `build-check` 6 with the 4-hour timeout, no harness regeneration. |
| 02:27 | `build-check` 6 starts, after a `gen` rerun so the `cvtsudoers` sanitizers setting takes effect (`gen` reports 0 errors). |
| ~02:40 | The user leaves the supervision running unattended overnight. The supervisor keeps triaging, fixing and merging live, and records each decision taken in the user's absence in "Decisions taken while the user was away" below. It does not answer the run session's questions for the user. |
| 02:27–05:16 | `build-check` 6: `ok: true`, `build_returncode` 0, Phase 0 checkpoint saved (`phase_done` 0). All 24 auto-engine modules build with E-ACSL, and `cvtsudoers` with the sanitizers it was set to. This confirms fix 12: `tf_fuzz_sudoers` and `tf_fuzz_sudoers_ldif` record the `struct passwd` forward declaration, and the ldif fuzzer stubs `log_warnx` and `filters` instead of linking `cvtsudoers.c`. The quiet stretches (up to 25 minutes) were E-ACSL stage-1 Frama-C jobs at 100–215% CPU, not stalls. |
| 05:16–07:16 | Phase 1 `pipeline_make.py run build` reaches its 2-hour timeout (`rc=124`): 38 cache hits, 5 misses (the large sudoers modules, never cached: fixer 13 at 06:15), no failure. |
| 07:16– | The run session reruns `run build` with a 4-hour timeout, keeping the first output as `run_build.first.out`. `fuzz-%` depends on `build-%` in `templates/pipeline.mk`, so `run fuzz` will rebuild the 5 uncached modules once more. |
| 07:16–09:30 | Second `run build`: `rc=0`, 40 cache hits, 9 misses (the uncached sudoers modules rebuilt for about 1h25), no failure. |
| 09:30– | Phase 1 `pipeline_make.py run fuzz` with a 3-hour timeout. 18 reports so far, 314 crash artifacts in 110 fingerprints, the sampled ones harness-induced; 7 modules end `fuzzer_error` (fix 14). |
| ~12:15 | The user is back and chooses "Pause, then redo Phase 1". The supervisor relays it: no crash verification or later phase, hold until fixes 13 and 14 are merged, then `run build` and `run fuzz` again from the Phase 0 checkpoint. |
| 12:22 | **Fix 13** fast-forwarded to `main` as `b89a624` (its branch was cut from `d158912`, still the tip; its files are not in the dirty list). The redo rebuilds every module anyway, so holding it no longer saves anything. |
| 12:28 | The first `run fuzz` ends at its 3-hour timeout (`rc=124`), with 21 fuzz reports for 25 modules. As relayed, the run session does not rerun it and starts no later phase. |
| ~12:35 | The user chooses "Fix on a branch" for the `--api` harness generator bug, despite the dirty generator tests. Fixer 15 dispatched (`sup/sudo-api-harness-ownership`, `scripts/api_harness.py` and a new `tests/test_api_harness_ownership.py`). The dirty tests and `templates/harness_dual.c.template` are off-limits; it cross-checks the dirty test versions against its branch. |
| ~13:00 | The user stops the run: "Okay let's stop this run, this is going nowhere". The supervisor relays it and stops its monitor. The run session confirms that no `run-1-e7bc881eee3c` container is left and that it cancelled its wakeups. The user first chooses to keep fixes 14 and 15 on their branches, then asks the supervisor to check and merge both once ready. |
| ~13:05 | **Fix 15** merged as `cedb359` (code only). `5a5a4b4` fixes fix 13's test typing first. |
| ~13:30 | **Fix 14** merged as `6f59147`, with `377283c` for its test typing. Full suite on the result: 8269 passed. |

## Fixes

Each was reproduced by a fixer subagent in its own worktree cut from `main`, with a regression test that fails on the old code. The supervisor read each diff, reran its tests and merged it live at the user's choice.

| # | Fingerprint | Branch, commit | Merge | Tests |
| :--- | :--- | :--- | :--- | :--- |
| 1 | `phase0_model`: `syntax error ... before or at token: [` (C23 `[[...]]` in `config.h`) | `sup/sudo-c23-attributes` | `9950ee3` | `tests/test_fc_cpp_wrapper.py` |
| 2 | `phase0_model`: `Cannot find field gr_passwd`, `Cannot resolve variable RLIMIT_NPROC` / `RTLD_NEXT`, `bits/link.h`, `toke.h:2811` (`#pragma pvs`) | `sup/sudo-libc-gaps`, `e2eef7a` | `c0a495b`, around another session's uncommitted `fc_compat_types.h` hunk | `tests/test_fc_glibc_gaps.py` |
| 3 | `build-check`: `use of undeclared identifier 'LOCALEDIR'`; link repair linking header prototypes | `sup/sudo-string-defines`, `bbb8ec1` | `784401d` | `tests/test_string_macro_flags.py`, `tests/test_unit_view.py` |
| 4 | `stub-check`: `#error "Never use <bits/ptrace-shared.h> directly"`; overlay redeclares `ptrace(..., void * const *__va_params)` | `sup/sudo-stub-gen-variadic`, `d62b1fb` + `4c47d49` | `f97dd72` | `tests/test_stub_gen_variadic.py` (14 tests) |
| 5 | `seed_harvest`: every `.libs` program exits 127 (`libsudo_util.so.0`), 167 functions skipped (`return type 'int )'`); `security_props._split_params` reads the attribute's `(` | `sup/sudo-seed-harvest`, `6dfe3c0` | `63caeeb`, around another session's uncommitted `seed_harvest.py` hunk | `tests/test_seed_harvest_sudo.py` (22 tests, 1 Docker) |
| 6 | `build-check`: `global var protobuf_c_empty_string ... has different initializer`; `link_globals.c` includes `log_client.h` alone (`syntax error ... TAILQ_ENTRY`, `unknown type name 'sudo_dso_public'`) | `sup/sudo-link-repair-globals`, `29fe254` + `da420d2` | `ef2f6fb` | `tests/test_link_repair_globals_sudo.py` (1 Docker) |
| 7 | E-ACSL stage 2: `invalid application of 'alignof' to an incomplete type 'const EVP_MD'` | `sup/sudo-eacsl-alignof`, `52de90f` + `c8de66e` | `9217c47` | `tests/test_eacsl_incomplete_alignof.py` |
| 8 | E-ACSL stage 2: `use of undeclared identifier 'sudoers_subsystem_names'`; `parse_json.h: No such file`; `struct iolog_file are not isomorphic`; target fuzzer `multiple definition of 'iolog_swapids'` | `sup/sudo-harness-gaps`, `750fb00` + `200360d` | `126b489` | `tests/test_sudo_harness_gaps.py` (1 Docker) |
| 9 | Phase 0 model: `gram.c` functions recorded in `toke.h`, `toke.c` functions missing (flex/bison `#line` to a missing file) | `sup/sudo-line-directives`, `dd5193e` | `3774d95` | `tests/test_phase0_line_directives.py` |
| 10 | `build-check`: `src/sudo.c:161: use of undeclared identifier 'LOCALEDIR'`, `undefined reference to 'gc_add'` in library `tf_` fuzzers (names from comments, strings, and sudo's `getenv` interposer) | `sup/sudo-tf-snippet-sources`, `2007534`..`1699aff` | `7979a9f` | `tests/test_tf_snippet_sources.py` (12 tests) |
| 11 | E-ACSL stage 2: `fallthrough annotation does not directly precede switch label`; link repair adds `cvtsudoers.c` for `open_sudoers`; link repair re-adds `target_fuzzer.link.excluded_sources` (`audit_msg ... has different initializer`) | `sup/sudo-link-repair-pick`, `931651a`..`fada45c` | `7979a9f` | `tests/test_sudo_link_pick.py` (1 Docker) |
| 12 | Link: `multiple definition of 'open_sudoers'` (link repair adds `cvtsudoers.c`, which redefines the target fuzzer's own function); E-ACSL stage 2: `incompatible function pointer types initializing 'int (*)(..., struct passwd *)'` (forward tag declaration dropped by the printer) | `sup/sudo-link-redef-fwdtags`, `0ecf165` + `d158912` | `d158912` | `tests/test_sudo_link_redef_fwdtags.py` (19 tests, 1 Docker) |
| 13 | Build cache: `"cache": {"hit": false, "key": null}` for `sudoers_so` on every build (the dependency scan times out at a fixed 120 s on 147 sources) | `sup/sudo-deps-timeout`, `bf4348e` + `b89a624` | `b89a624` (held from 06:40 to 12:22, because a live merge would have invalidated the run's whole cache; merged for the Phase 1 redo). Follow-up `5a5a4b4` fixes four mypy errors in its test file, missed by the supervisor's check before the merge. | `tests/test_cache_deps_scaling.py` (15 tests) |
| 14 | `sudo_noexec_so` / `sudo_intercept_so`: `fuzzer_error` in 0.1 s on both engines (libFuzzer's workers start through the `system()` the target replaces); E-ACSL `SEGV ... in shadow_alloca` from target constructors before `LLVMFuzzerInitialize`; `__e_acsl_store_block((void *)(& __progname),8UL)` in `__e_acsl_globals_init` (PIE) | `sup/sudo-preinit-interposers`, `cc8451b`, `e280b71`, `445aa48` | merge `6f59147` + `377283c` (a Windows mypy error in its test file), after the stop. `sudo`'s `getenv` called from libcrypto's constructor is still open | `tests/test_fuzz_preinit_interposers.py` (21 tests, 1 Docker); `tests/test_eacsl_toolchain.py` updated |
| 15 | `liblogsrv_a` fuzz: `AddressSanitizer: SEGV on unknown address 0xfffffffffffffff8` in `do_free` and a NULL call in `do_alloc` (`protobuf-c.c`), from `--api` cases that free stack messages and pass zeroed `ProtobufCAllocator`s | `sup/sudo-api-harness-ownership`, `58e2bd1` + `6bfe475` | `cedb359` (code only, after the stop; the branch's doc text folded into the entry by hand) | `tests/test_api_harness_ownership.py` (18 tests, 1 Docker) |

## Troubleshooting entries

- [`../troubleshooting/phase0-build-and-model.md`](../troubleshooting/phase0-build-and-model.md):
  - C23 `[[...]]` attributes in `config.h` (fixed);
  - the eight units still on the GCC fallback on libc gaps (fixed, with open items);
  - the flex-generated `toke.c` functions missing from the model (fixed for the model; overlay locations for E-ACSL, Eva and WP open);
  - indirect calls never resolving to attributed functions (open).
- [`../troubleshooting/harnesses-and-seeds.md`](../troubleshooting/harnesses-and-seeds.md):
  - `LOCALEDIR` and other string-valued `-D` macros (fixed);
  - link repair of static libraries (fixed, with open items);
  - `parse_json.h` in a target fuzz harness (fixed);
  - `seed_harvest` `no_calls_recorded` (fixed);
  - `link_globals.c` redefinitions and lone headers (fixed), imported target fuzzers linking the whole unit (partly fixed, three modules open);
  - `cvtsudoers_make_pwitem` incompatible declaration (open, Frama-C linker);
  - `struct iolog_file` not isomorphic (fixed).
- [`../troubleshooting/eacsl-and-fuzzing.md`](../troubleshooting/eacsl-and-fuzzing.md):
  - `_Alignof` on an incomplete type (fixed);
  - `sudoers_subsystem_names` undeclared (fixed; Frama-C kernel printer bug);
  - fallthrough attribute before a goto label (fixed; Frama-C kernel printer bug);
  - `incompatible function pointer types` from a `struct passwd` first named in a parameter list (fixed; Frama-C multi-file merge drops the forward tag declaration);
  - the build cache never caching a large module (fixed, fix 13);
  - interposer modules ending `fuzzer_error` in 0.1 s, and E-ACSL crashing in `shadow_alloca` before `LLVMFuzzerInitialize` (fixed, fix 14; an interposer called by an uninstrumented library's constructor still open);
  - the E-ACSL PIE entry on library-owned globals, `__progname` added (fixed by a position-dependent link, fix 14; the PIE fallback open);
  - `%.*s` format false positive, seen again on `sudo_intercept_so`;
  - `\valid` / `\initialized` failures on memory from `mmap` or `waitpid` (new, open).
- [`../troubleshooting/harnesses-and-seeds.md`](../troubleshooting/harnesses-and-seeds.md): the `--api` zeroed-struct entry, seen again on `liblogsrv_a`, with the allocator-table and destructor-ownership fix (fix 15).
- [`../troubleshooting/harnesses-and-seeds.md`](../troubleshooting/harnesses-and-seeds.md), from build-check 4 and 5: library `tf_` fuzzers pulling in another program's sources (fixed); link repair picking one program's `open_sudoers` (fixed); link repair adding a file that redefines what the build defines (fixed); `build-check` killed by its caller's timeout with no report (open).
- [`../troubleshooting/kernel-and-stubs.md`](../troubleshooting/kernel-and-stubs.md): stub-check fails `bits/ptrace-shared.h` (fixed).
- [`../troubleshooting/security-properties.md`](../troubleshooting/security-properties.md):
  - return-kind secrets and state-less gates generate no property (open);
  - attributed signatures give no parameter types (fixed).

## Open pipeline bugs after this run

- **CodeQL vs `build_capture`:** `codeql_trust.py` runs the recipe under `set -e`, `build_capture` does not, so a recipe with a tolerated failing step builds in one and fails in the other. No entry or fix yet.
- **Slow reach-gate exemptions:** `harness_reach.py exempt` re-runs the gate for each entry; about 55 minutes for one batch.
- **`stub_check.py shipped`** compiles shipped stubs without `_GNU_SOURCE`; with a pre-fix model its `parse_proto` treats `__va_params` as a pointer and calls the function with a made-up one. The file has another session's uncommitted changes.
- **Attributed indirect calls** never resolve to attributed functions in the model.
- **Overlay `#line` locations:** E-ACSL, Eva and WP still report locations in the flex/bison output under the generator's file name.
- **Imported target fuzzers** `tf_fuzz_policy`, `tf_fuzz_sudoers`, `tf_fuzz_sudoers_ldif`: since fix 11 they link with aborting stubs in place of the files they override, so they fuzz less of the unit than sudo's own fuzzer build. The real fix links the driver against the target's own fuzzer object list.
- **Link repair cost and `build-check` reporting:** link repair resolves one level of missing definitions per round, each a full E-ACSL rebuild, and `build-check` writes nothing when its caller's timeout kills it.
- **Link stub message:** a stub from fix 11 still prints the address-flow wording at runtime.
- **`--api` harness limits after fix 15:**
  - A table of function pointers embedded in another struct, or passed by value, is still zeroed.
  - A destructor with extra non-table arguments is not an owner.
  - The NULL default is inferred per type.
  - Program-internal functions (cvtsudoers' `cvtsudoers_make_pwitem` without `main`'s `filters`) are still called without the program's start-up state. That gives harness-induced candidates, and no fix was dispatched.
- **E-ACSL start-up, after fix 14:**
  - An instrumented interposer called by an uninstrumented library's constructor still aborts at start: `sudo`'s `getenv_unhooked` `\initialized(name + namelen)`, called from libcrypto.
  - The PIE fallback still crashes on library data.
  - Library TLS objects are untested.
  - `mmap` and `waitpid` are not in E-ACSL's libc effects, so `sudo_intercept_so` gives false positives.
- **Cache keys hash all of `scripts/`:** any live merge makes the running run rebuild every cached binary. This is why fix 13 was held until the Phase 1 redo was decided.
- **Mypy check before merging:** the fixers ran `mypy scripts`, and CI runs `mypy scripts tests`. The supervisor's own pre-merge check must use the latter; it missed fix 13's test errors once.
- **Initialized globals in link repair:** fix 12 treats a global that two linked files define as one `-fcommon` object, because the model does not record initializers; two files that both initialize it still fail the link.
- **`cvtsudoers` E-ACSL:** Frama-C's linker unifies an incomplete struct tag with the first complete one, depending on file order. An upstream Frama-C candidate; no draft yet.
- **Upstream drafts warranted, not written:** the Frama-C kernel printer placing a sized array definition before the table it is sized from (worked around by fix 8), the printer putting a goto label before `default:` after a fallthrough attribute (worked around by fix 11; 15-line reproducer in its troubleshooting entry), the linker tag unification above, and the multi-file merge dropping a forward tag declaration (worked around by fix 12; 3-file reproducer in its troubleshooting entry).

## Decisions taken while the user was away (2026-11-22 02:40 to about 12:15)

- **06:15, fixer 13 dispatched** (`sup/sudo-deps-timeout`, `scripts/cache.py` only). `sudoers_so` is never cached, because the build cache's dependency scan times out at a fixed 120 s on its 147 sources (112 s measured on an idle machine). The cost is about one extra `sudoers_so` rebuild per build, and Phase 2 Eva would be uncached for this module too. This is within the live fix mode you chose. The fixer must leave `scripts/function_slice.py` alone, because it holds another session's uncommitted changes.
- **06:40, fix 13 held, not merged live.** It is green (its 15 tests, full suite 8232 passed, ruff, mypy). But every cache key hashes all of `scripts/`, so merging it mid-run would invalidate all 25 cached fuzz binaries and cost about 2.5 hours of rebuilds, to save one `sudoers_so` rebuild. It will be merged once the run no longer needs its build cache: at the terminal state, or earlier if the run has to rebuild everything anyway.
- **10:30, no fixer for the `liblogsrv_a` crash candidates.** Both fingerprints (`do_free`, `do_alloc` in `protobuf-c.c`) are harness-induced: the generated harness calls `*__free_unpacked` on a stack message, and passes an all-zero `ProtobufCAllocator`. This is a recurrence of the open "`--api` Cases Pass a Zeroed Struct" bug (nanopb run-1). The fix belongs in `scripts/api_harness.py`, but its tests and `templates/harness_dual.c.template` hold another session's uncommitted changes, so I recorded it and left it for you. The run's own Crash Verifiers and harness repair handle these candidates.
- **10:35, `cvtsudoers` candidates noted, not triaged further.** There are three fingerprints (UBSan `member access within null pointer of type 'struct cvtsudoers_filter'` in `cvtsudoers_make_pwitem` / `cvtsudoers_make_gritem`, and `'struct userspec_list'` in `merge_userspecs`). All come from harness cases that call the program's internal functions directly. The global `filters` is set only by cvtsudoers' `main`, so these look harness-induced too: the program's start-up state is missing. That is the Crash Verifiers' call. No pipeline fix was dispatched.
- **11:40, fixer 14 dispatched** (`sup/sudo-preinit-interposers`: `scripts/run_eacsl_fuzz.py`, `templates/eacsl_runtime/fuzz_init.c`, and tests in a new module). The reason: `sudo_noexec_so` and `sudo_intercept_so` got no fuzzing at all (`fuzzer_error` in 0.1 s on both engines). Their `exec*` interposers break libFuzzer's fork and worker modes, and their constructors crash E-ACSL before its runtime starts. `tests/test_fuzz_keep_going.py` holds another session's changes, so the fixer must not touch it. As with fix 13, merging changes every cache key (`fuzz_init.c` is under `templates/`), so the merge time will be decided when it is ready.
- **12:10, fixer 14's scope extended** to the open E-ACSL + PIE libc-global bug. `__e_acsl_globals_init` crashes registering glibc's `__progname`, which leaves the five `tf_` modules and `libsudo_util_so_0_0_0` without E-ACSL fuzzing; their sanitizer halves ran. It is the same start-up theme in neighbouring files, so one fixer avoids two branches conflicting.

## Model behaviour (not pipeline bugs)

- The driver's PowerShell helper passed `-ScriptFile` as a plain argument (14:09), and passed an artifact path, then a module name, to `--unit` (14:40). It fixed both itself.
- It first misdiagnosed the C23 parse failure as `restrict` (14:13), then found the real cause.
- An `openssl/crypto.h` stub author wrote the `OPENSSL_init_crypto` contract from its recollection of the man page rather than from a document read in the session. The stub brief may need to say where an author reads library documentation offline.
- The driver received duplicate subagent hand-back notifications (a harness quirk, not the pipeline).
- In the Phase 0 redo (20:26), fix 9 brought `toke.c`'s functions into the model, and four `libparsesudoers_a` entry points (`init_lexer`, `push_include`, `push_includedir`, `sudoers_trace_print`) did not compile in the harness (`call to undeclared function`). The driver recorded four reach-gate exemptions rather than adding `toke.h`, which declares all four, to the module's header list. It passes that list by hand (`sudoers.h parse.h`) because of the open default-header bug ("`generate_harness.py --api` Without `--header` Selects `include/compat/stdbool.h`" in [`../troubleshooting/harnesses-and-seeds.md`](../troubleshooting/harnesses-and-seeds.md)). The lexer's entry points are therefore not fuzzed in this run.

## Not verified by the supervisor

- The flex `toke.c` and attributed-indirect-call findings come from the seed-harvest fixer's read-only replay of the model; the supervisor did not re-check them.
- Fix 5 was confirmed on sudo in the Phase 0 redo (160 calls recorded, previously none). `LD_LIBRARY_PATH` on a test command that runs tools was not tested.
- Fixes 6, 7 and 8 were confirmed by build-check 4 on the modules it reached. Fixes 9, 10 and 11 were confirmed by build-check 5. Fix 12 was confirmed by build-check 6.
- Fix 13 was not exercised by the run, which stopped before rebuilding. The fixer timed it on `sudoers_so`'s sources.
- Fixes 14 and 15 were verified only by their fixers, on scratch copies of run-1's modules. The supervisor read their diffs and reran their tests, the full suite (8269 passed after both), ruff, `mypy scripts tests` and the text check, but did not rerun their Docker checks.
- After fix 14, the `tf_` modules and `libsudo_util_so_0_0_0` were not rebuilt, so their E-ACSL start-up is unverified.
