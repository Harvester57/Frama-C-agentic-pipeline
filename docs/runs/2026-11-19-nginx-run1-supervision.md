# nginx 1.31.9 run-1 and run-2: supervision report

- **Documentation Hub:** [`../README.md`](../README.md)
- **Run reports index:** [`./README.md`](./README.md)
- **Troubleshooting:** [`../troubleshooting/README.md`](../troubleshooting/README.md)

This report covers the external supervision of the opencode-driven `standard` run of nginx 1.31.9. run-1 stopped at Phase 0. The user then stopped it and allowed the supervisor to restart the session once the fixes had landed. The restart is run-2. The report is updated at each milestone.

## Parameters

| Parameter | Value |
| :--- | :--- |
| Run dirs | `C:\Users\Florian\framac-pipeline\nginx-1.31.9\run-1` (`nginx-1.31.9-3e44199e7906 / run-1-73bbe362401c`), then `run-2` |
| Target | `C:\Users\Florian\OneDrive\Documents\Dev\targets\nginx-1.31.9` (no VCS). Build recipe from the user: `./configure` with the mail, SCGI, uWSGI, gRPC, memcached, SSI and other modules off, and SSL, HTTP/2 and HTTP/3 on |
| Session | opencode `ses_e0d5bfaa9ffeWHNUnVAzr3hSv8`, model `deepseek-v4.1-flash` |
| Integration branch | `wip/main-checkout-2026-11-19`, baseline `5cbf8c2`, `680e2a8` after the fixes. The run also executes these uncommitted pipeline files: `skills/framac-{eva,slice,verify}/SKILL.md` and `templates/fc_stubs/sys/{epoll,inotify}.h` |
| Fix mode | `hold`. run-1 was terminal when the fixes landed, so they were merged at once |
| Poll / stall / recur limit | 2 min / 10 min / 3 |

## Status

- **run-1:** ended `incomplete` at 08:27:24. The model recorded the reason `phase0_no_unit_parsed`. The user then stopped the session.
- **run-2:** the supervisor sent the restart message at 09:34. The model created `run-2` with `-NewRun` and reused run-1's build recipe.
- **run-2 halted at 10:26:25, at the end of Phase 0. This is an external blocker, not a pipeline failure.** The model provider refused every request: `provider.go-limit`, HTTP 429, "OpenCode Go monthly usage limit reached", `GoUsageLimitError`, resetting in 13 days 14 hours.
  - The session is idle. `run-metadata.json` still says `in_progress`, and `progress.json` was never written: `phase_done` is not recorded, because `build-check` has not run.
  - The 25 stub-author subagents stopped mid-task. In `workspace/stubs/`, 10 headers were edited between 10:19 and 10:26: `ui.h`, `crypt.h`, `hmac.h`, `engine.h`, `sys/eventfd.h`, `dh.h`, `err.h`, `kdf.h`, `rand.h` and `objects.h`. `objects.h` was being written at 10:26:31. The other 15 are still the 10:05 drafts. Only `rand.h` reported done.
  - A run that resumes must rerun the stub authors for these headers and then `pipeline_make.py run stubs stub-check` before harness generation. It must not assume the edited headers are complete.
  - Separately, `opencode run` (the client the supervisor used to send the restart) exited 1 with `Error: Cancelled a request for input this run cannot answer: Web Search`. A subagent had asked for the Web Search permission, which a non-interactive run cannot grant. A later restart through `opencode run` needs that permission settled in advance, or has to be done from the interactive TUI.

### Timeline

Local time (CET). The times come from the supervisor's timeline and the file times in the run dirs.

| Time | Event |
| :--- | :--- |
| 08:11:19 | run-1 created |
| 08:12:18 | Build recipe recorded (`origin: user`) |
| 08:13:23-08:13:40 | Build captured. `build_capture.json` lists two units: `objs/autotest` and `objs/nginx` |
| 08:14:01-08:20:07 | Phase 0 parse. Frama-C fails on both units, and the GCC fallback for `objs/nginx` takes about 6 min |
| 08:20:15 | `progress.json` set to `no_unit_parsed` (exit 4) |
| 08:20-08:27 | The model diagnoses the failure, writes two troubleshooting entries and marks run-1 `incomplete` |
| 08:29 | Supervisor dispatches fixers S1 and S2 |
| 08:44 | S2 merged (fast-forward to `4e6ac27`) |
| 09:33 | S1 merged (`680e2a8`) after a dry-run merge with the full suite |
| 09:34 | Restart message sent to the session. run-2 created at 09:35 |
| 09:36-09:37:22 | run-2 build capture. One unit, `objs/nginx`. The warning `1 build-system probe(s) dropped ... objs/autotest` confirms that S2 works on the real tree |
| 09:37:30-09:57:18 | run-2 Phase 0 model: `objs/nginx` parse `ok` in 1171 s, against the 1800 s `parse` timeout. It holds 2240 functions, 12167 edges and 471 externals, which confirms S1 on the real run |
| 09:57-10:06 | CodeQL `ok` (59 facts), seeds (15 API calls), fuzz assets, DAG (one Tier 1A module; see O1), stub overlay (25 headers, 295 draft functions), security properties (23) |
| 10:07-10:13 | The model launches 25 stub-author subagents, one per overlay header |
| 10:25 | `rand.h` author done. Scratch volume removed (`-RemoveScratch`) |
| 10:26:25 | OpenCode Go monthly usage limit reached (HTTP 429). The session goes idle and run-2 halts mid-stub-authoring |

Phase 0 of run-1 took 9 min, from 08:11 to 08:20.

## Findings and fixes

### S1. Frama-C's libc has no `cpu_set_t`: this blocked `objs/nginx`

- **Fingerprint:** phase0 / `phase0_model.py run` / `ngx_setaffinity.h: User Error: syntax error` (`cpu_set_t`).
- **Cause:**
  - Frama-C's `share/libc/sched.h` (34.0~beta and `master`) has no `cpu_set_t`, no `CPU_*` macros and no `sched_{set,get}affinity`. nginx's configure, run on glibc, enables `NGX_HAVE_SCHED_SETAFFINITY`.
  - A pipeline `fc_stubs/sched.h` is never read, because `-I<share>/libc` comes first. The gap therefore belongs in `fc_compat_types.h`.
  - Three more gaps were hidden behind this one: `struct in_pktinfo`, `IP_BIND_ADDRESS_NO_PORT` and `struct tcp_info`.
- **Fix:** `cb78e8b` on `sup/nginx-sched-cpu-set`, merged as `680e2a8`. The branch is deleted. The `__fc_libc` branch of `fc_compat_types.h` adds the following, with opt-outs `FC_STUBS_NO_SCHED_AFFINITY_DECLS` and `FC_STUBS_NO_NETINET_LINUX_DECLS`:
  - `cpu_set_t` (glibc layout), the `CPU_*` macros and `sched_{set,get}affinity`, all with contracts;
  - `struct in_pktinfo`, `struct tcp_info` and 63 Linux `IP_`/`TCP_` constants.
- **Tests:** `tests/test_fc_stub_repairs.py`:
  - `test_sched_affinity_names_are_declared_for_eva_and_wp_after_the_netdb_block`
  - `test_sched_macros_evaluate_the_cpu_once_and_need_no_cast`
  - `test_sched_affinity_contracts_split_success_from_failure`
  - `test_sched_affinity_in_eva_wp_and_against_glibc` (Docker)
  - `test_netinet_linux_names_are_declared_for_eva_and_wp_after_the_sched_block`
  - `test_netinet_linux_names_in_eva_and_against_glibc` (Docker)
  - Also updated: `tests/test_fc_stub_contracts.py::test_parser_finds_the_known_shipped_prototypes`.
- **Verified by the fixer, in a scratch copy:** all 165 nginx sources parse alone, and the whole unit parses with rc 0 in 1159 s. That parse was not a `phase0_model.py run`: it had no dump module, and it used the uncommitted `epoll.h` and `inotify.h` from the main checkout.
- **Verified by the supervisor:**
  - read the diff;
  - the stub tests: 29 passed, 8 skipped (the Docker tests);
  - the merge dry-run on `4e6ac27`: `pytest -n auto` gave 6444 passed and 1 failed, the failure already present at base (see Open items);
  - `ruff check`, `mypy` and `check_generated_text` all clean.
- **Upstream:** draft 46, [`../upstream/frama-c/frama-c-libc-sched-cpu-set.md`](../upstream/frama-c/frama-c-libc-sched-cpu-set.md). Reproduced on 34.0~beta and on `master` `b80fcac74f`. Not filed.

### S2. Configure probe captured as a unit, and a GCC fallback that failed but was reported as `gcc_fallback`

- **Fingerprint:** build_capture / link unit from a configure probe whose source is gone.
- **Cause:**
  - nginx's hand-written configure compiles `objs/autotest.c` to `objs/autotest`, then runs `rm -rf objs/autotest objs/autotest.c`. `is_probe_path()` knows only CMake, autoconf and meson probes.
  - In `phase0_model.py`, every failed Frama-C parse was reported as `gcc_fallback` without checking whether GCC itself had failed.
  - This is the same class of bug as the libmodbus `config.guess` probe (2026-11-18).
- **Fix:** `f85de2c` and `4e6ac27` on `sup/nginx-build-probe-units`, merged by fast-forward. The branch is deleted.
  - `build_capture.drop_vanished_probes()` drops compiles and links whose sources and outputs are both gone after the build, and records them in `build.vanished_probes`.
  - A new unit parse status `unparsed`, with `parse.gcc_error`, is handled by the schema, the DAG and the report.
- **Tests:**
  - `tests/test_build_capture.py::TestRecordedEvents::test_a_probe_whose_source_and_output_are_gone_after_the_build_is_dropped`
  - `tests/test_build_capture.py::TestRecordedEvents::test_a_generated_source_the_build_deleted_is_kept_when_its_output_survives`
  - `tests/test_build_capture.py::TestRecordedEvents::test_the_capture_drops_vanished_probes_before_the_analysis`
  - `tests/test_phase0_model.py::test_a_unit_whose_gcc_fallback_failed_too_is_unparsed_not_gcc_fallback`
  - `tests/test_dag_model_view.py::test_an_unparsed_unit_is_blocked_and_reported_without_claiming_a_gcc_call_graph`
  - `tests/test_r4_model_dag_versions.py::test_the_report_lists_an_unparsed_unit_apart_from_the_gcc_fallback_ones`
- **Verified by the supervisor:** read the diff, reran the 6 tests (all pass), and checked that no other consumer compares the parse status with `gcc_fallback`. Not yet checked on the nginx tree; run-2's capture will show it.

### O1. The unit split cannot divide nginx (open gap, no fixer)

- **Seen at 10:03 in run-2's DAG:** one cluster, `nginx__ngx_event_openssl`, holds 2208 of 2240 functions and 133,900 lines. The split's own limits are 400 functions and 15,000 lines.
- **Cause:** indirect calls are resolved by signature, so 152 of the 793 entry points each reach 1548 functions. `ngx_destroy_pool` is one of them, through its `void (*)(void *)` cleanup handlers. Every cluster then overlaps every other and they all merge.
- **Status:** this is a design limit, not a defect a fixer can settle without a design choice, so no fixer was sent. Recorded as an open gap in [`../troubleshooting/phase0-build-and-model.md`](../troubleshooting/phase0-build-and-model.md). Watching Phase 1 harness generation and Phase 2 Eva for its consequences.

## Troubleshooting entries and upstream drafts

- [`../troubleshooting/kernel-and-stubs.md`](../troubleshooting/kernel-and-stubs.md): the model's `cpu_set_t` entry, updated to fixed. It now records the hidden gaps, the parse-time risk, the undeclared functions and the open E-ACSL `_GNU_SOURCE` bug.
- [`../troubleshooting/phase0-build-and-model.md`](../troubleshooting/phase0-build-and-model.md): the model's `objs/autotest` entry, updated to fixed, and a new entry for the failed fallback reported as `gcc_fallback`.
- Upstream draft 46, with its index entry in [`../upstream/frama-c/README.md`](../upstream/frama-c/README.md).

These three documents hold another session's uncommitted edits, so the supervisor's edits to them are not committed.

## Model behaviour (not pipeline bugs)

- **Messages 16-55 (08:20-08:27):**
  - After the block, the model diagnosed the failure inside the pipeline, although `framac-slice` Step 1c says to stop and report. It read `phase0_model.py`, `target_env.py` and `framac_common.py`.
  - It ran `docker run framac-analysis:latest` by hand, without the wrapper and without a `framac.run` label.
  - It wrote probe files under `run-1\workspace\p0test` and deleted them afterwards.
  - The diagnosis was correct, and it changed no pipeline file.
- **Message 25:** a `bash -lc "...$(frama-c ...)"` inside PowerShell double quotes was expanded by PowerShell. The model noticed and switched to single quotes.
- **Message 72 (run-2):** PowerShell's `ConvertFrom-Json` refuses `phase0_model.json`, because it holds keys that differ only in case (`src/core/ngx_string.c#HEX` and `src/core/ngx_string.c#hex`). The model switched to `-AsHashtable`. The JSON is valid, so this is friction rather than a bug. A skill hint to read the model with Python or `-AsHashtable` would avoid the retry.
- **Messages 50-54:** the model wrote both troubleshooting entries with the exact errors and marked them `**Open pipeline bug:**`, as `CLAUDE.md` asks.
- **Suggestion (not applied):** Step 1c of `framac-slice` could add: "Do not investigate with ad-hoc `docker run`. The parse logs in `workspace/reports/phase0_model/<job>.framac.log` and `<job>.gcc.log` are the evidence to report."

## Open items

- **`objs/nginx` parse time against the 1800 s `parse` timeout** (`scripts/resources.py:119`). run-2's real parse took 1171 s, leaving 35% margin. A slower host or a larger module set could reach the limit.
- **Skill text for `unparsed`.** `skills/framac-slice/SKILL.md` Step 1c does not list the new status. The file holds another session's uncommitted edits, so it was not edited. The fixer's proposed bullet: "`unparsed`: Frama-C could not parse the unit and the GCC fallback failed too (`parse.gcc_error`); its own parse contributes no function or edge."
- **Open pipeline bug (E-ACSL `_GNU_SOURCE`).** The force-included `fc_compat_types.h` locks `<features.h>` before a source's own `#define _GNU_SOURCE`, so GNU-only names are missing in E-ACSL builds.
- **Pre-existing test failure.** `tests/test_docs_structure.py::test_markdown_links_are_explicit_relative_and_resolve` fails on a clean checkout of `5cbf8c2`. `docs/upstream/frama-c/frama-c-libc-strlcat-contract.md` links to `frama-c-hunt-2026-11-18-candidates.md` and `filing/00-reports-overview-issue.md`, which exist only as untracked files in the main checkout.
- **Leftover folder.** `.agents/worktrees/sup-nginx-build-probe-units` is unregistered and empty, but another process holds it open. Delete it later.
