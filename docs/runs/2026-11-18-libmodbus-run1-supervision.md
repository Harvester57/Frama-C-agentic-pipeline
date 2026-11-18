# libmodbus run-1: supervision report

- **Documentation Hub:** [`../README.md`](../README.md)
- **Run reports index:** [`./README.md`](./README.md)
- **Troubleshooting:** [`../troubleshooting/README.md`](../troubleshooting/README.md)

External, read-only supervision of the opencode-driven `standard` run of libmodbus (CodeQL enabled). This report is updated at each milestone.

## Parameters

| Parameter | Value |
| :--- | :--- |
| Run dir | `C:\Users\Florian\framac-pipeline\libmodbus\run-1` (run identity `libmodbus-d4227309de07 / run-1-f3ba5cce4b09`) |
| Target | libmodbus `a9b025d` (dirty: untracked `.security-reviews/`), Windows checkout with `core.autocrlf=true` |
| Session | opencode `ses_e13dfc5feffeooCF0PFudZYlr8`, model `deepseek-v4.1-flash` |
| Integration branch | `phase1-remediation`, baseline `19c038e` |
| Fix mode | `hold`; from 02:01 the user asked to land the blocking fixes live and resume the session, then to supervise autonomously overnight |
| Poll / stall / recur limit | 2 min / 10 min / 3 |

## Status

**Phase 0, paused** (`no_unit_parsed`), waiting for the `TIOCM_*` fix to land, after which the supervisor resumes the session.

## Timeline (supervisor's observations, local time, 2026-11-18)

| Time | Event |
| :--- | :--- |
| 01:48 | Session starts, reads CLAUDE.md and the skills |
| 01:51:32 | Run dir created, metadata initialised (`standard`), build recipe and CodeQL declaration recorded |
| 01:52:43 | `build_capture.py run`: `needs_build_recipe`, `./autogen.sh: 22: Syntax error: end of file unexpected (expecting "then")` |
| 01:53:25 | User picks "strip CRs inside the recipe" |
| 01:54:29 | `build_capture.py run`: `needs_build_recipe`, `./configure: line 14962: syntax error near unexpected token` (CRLF `configure.ac`) |
| 01:55:01 | The model widens the CR strip to every text file of the scratch copy, without asking again |
| 01:55:56 | Build capture `ok`: 1 product unit (`libmodbus.so.5.1.0`, 4 sources, 71 entry points), 9 test executables, and a stray `unlinked:/tmp/cg7zzCGG` |
| 01:56:12 | `phase0_model.py run`: `no_unit_parsed`, `src/modbus-rtu.c:254: User Error: Cannot resolve variable TIOCM_RTS` |
| 02:01 | User stops the session and asks the supervisor to land the fix and resume |

## Pipeline issues and fixes

| # | Fingerprint | Category | Branch / commit | Status |
| :--- | :--- | :--- | :--- | :--- |
| 1 | `build_capture.py run`: shell `Syntax error` from a CRLF `autogen.sh`, and `configure` syntax error from a CRLF `configure.ac`, with no CRLF hint in `build_capture.json` | pipeline gap (the CRLF checkout itself is target-side) | `sup/libmodbus-crlf-dash-hint` `41c20e9`, `3738ea6` | verified, held until the run ends (the run no longer needs it) |
| 2 | `phase0_model.py run`: `unlinked:/tmp/<cgXXXXXX>` unit, `source file '/tmp/.../dummy.c' does not exist` (GNU `config.guess` libc probe captured as a product unit) | pipeline bug | `sup/libmodbus-config-guess-probe` `0b3b43b` | merged live into `phase1-remediation` (fast-forward) |
| 3 | `phase0_model.py run`: `Cannot resolve variable TIOCM_RTS` (`__fc_libc` `<sys/ioctl.h>` has `TIOCMGET` but not the `TIOCM_*` modem bits) | pipeline gap + upstream Frama-C libc gap | `sup/libmodbus-tiocm-bits` `f0bea19` (+ docs `a6e33f8`, `47fb030`), merged live as `34f8747`; also adds `TCGETS2`..`TCSETSF2`, the next missing macros; upstream draft 41 (not filed) |

Tests added:

- `tests/test_crlf_scripts.py`: `test_a_shell_syntax_error_on_a_crlf_script_gets_the_hint`, `test_a_shell_syntax_error_naming_no_crlf_script_gives_no_hint`, `test_crlf_autotools_inputs_are_found`, `test_a_configure_syntax_error_from_a_crlf_configure_ac_gets_the_hint`, `test_a_build_failing_with_a_syntax_error_in_a_crlf_script_gets_the_hint` (branch 1).
- `tests/test_build_capture.py::TestRecordedEvents::test_config_guess_temp_dir_probe_is_dropped` (merged).

## Model struggles (not pipeline bugs)

- 01:52, 02:00: inline PowerShell double-quoted commands expanded `$?` and `$(frama-c ...)` on the host. The model noticed and switched to `-ScriptFile`.
- 01:55: the model changed the confirmed recipe a second time (CR strip over every text file) on its own reading of the user's earlier answer, although the brief said not to change the recipe on its own. The change was harmless (scratch copy only).
- 01:56-02:00: on `no_unit_parsed` the model investigated pipeline code for several minutes instead of stopping and reporting as framac-slice Step 1c says. It reached the right diagnosis and did not edit pipeline files.

## Decisions taken for the user

- Fix 2 and fix 3 are landed live (user's instruction at 02:01); fix 1 stays held.
- Overnight, the supervisor answers the session's questions on the user's behalf; each answer is listed here.

Also added by fix 3: `tests/test_fc_compat_contracts.py::test_modem_line_bits_and_termios2_requests_are_defined_for_frama_c_libc_only` and `::test_modem_line_bits_and_termios2_requests_parse_with_frama_c_libc_as_gcc_reads_them` (`FRAMAC_DOCKER_TESTS=1`, rerun green by the supervisor).

## Upstream drafts

- Issue 41, [`../upstream/frama-c/frama-c-libc-ioctl-modem-bits.md`](../upstream/frama-c/frama-c-libc-ioctl-modem-bits.md): `__fc_libc` `<sys/ioctl.h>` lacks the `TIOCM_*` modem bits (34.0~beta and master `95408044f7`). Not filed; the owner decides between a new issue and a note on #2828.

## Open items

- Fix 1 (CRLF hint) is held on its branch until the run ends.
