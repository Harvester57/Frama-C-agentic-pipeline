# Frama-C libc: `<wchar.h>` alone cannot locate `__fc_stdout` / `__fc_stdin` (draft 76)

- **Upstream index:** [`./README.md`](./README.md)
- **Hunt candidate:** `N20` (plus `wscanf` / `__fc_stdin` sibling) in [`./frama-c-hunt-2026-11-18-candidates.md`](./frama-c-hunt-2026-11-18-candidates.md)
- **Issue text:** [`./filing/76-libc-wchar-stdio-streams-issue.md`](./filing/76-libc-wchar-stdio-streams-issue.md)
- **MR text:** [`./filing/76-libc-wchar-stdio-streams-mr.md`](./filing/76-libc-wchar-stdio-streams-mr.md)
- **Patch:** [`./patches/76-libc-wchar-stdio-streams.patch`](./patches/76-libc-wchar-stdio-streams.patch)
- **Reproducer:** [`./repro/76-libc-wchar-stdio-streams.sh`](./repro/76-libc-wchar-stdio-streams.sh) ([`./repro/76-libc-wchar-stdio-streams.c`](./repro/76-libc-wchar-stdio-streams.c))

**Status:** full filing package validated on `master` `189053d4a2` and `34.0~beta`; **not filed**
(filing remains paused pending maintainer response in
[#2832](https://git.frama-c.com/pub/frama-c/-/work_items/2832), annex ref `N20`). Not recommended
for our local `opam/` patch queue (low severity; preconditions are preserved, only stream
`assigns`/`\from` clauses and warnings are affected).

## Summary

ISO C11 7.29.2.10-11 declares `wprintf()` and `wscanf()` in `<wchar.h>` without requiring
`<stdio.h>`. Frama-C's Variadic translation classifies both as `StdIO` and looks up `__fc_stdout`
and `__fc_stdin`, which were declared only in `share/libc/stdio.h`. Including `<wchar.h>` alone
therefore emits `[kernel:libc:frama-c] Warning: Unable to locate global __fc_stdout / __fc_stdin`
and omits the stream `assigns` and `\from` clauses on `__fc_stdout->__fc_FILE_data` and
`__fc_stdin->__fc_FILE_data`.

## Diagnosis and sibling audit

- `src/kernel/services/ast_transformations/variadic/classify.ml:142,145` classifies `wprintf` and
  `wscanf` as `StdIO`; `standard.ml:398-406, 588-598` calls `find_global env "__fc_stdout"` and
  `find_global env "__fc_stdin"`.
- `share/libc/wchar.h:20` includes `share/libc/__fc_define_file.h` (which is included only by
  `stdio.h` and `wchar.h`), while `__fc_stderr`/`__fc_stdin`/`__fc_stdout` were declared only in
  `share/libc/stdio.h:52-59`.
- All other Variadic-classified headers (`fcntl.h`, `unistd.h`, `sys/ioctl.h`, `stropts.h`,
  `stdio.h`, and `swprintf`/`swscanf`/`fwprintf`/`fwscanf` in `wchar.h`) already have all required
  symbols in scope.
- ISO C11 7.29 forbids `<wchar.h>` from exposing the `stdin`/`stdout`/`stderr` macros, whereas
  double-underscore identifiers (`__fc_stdin`, `__fc_stdout`, `__fc_stderr`) are reserved for the
  implementation (ISO C11 7.1.3).

## Fix and validation

[`./patches/76-libc-wchar-stdio-streams.patch`](./patches/76-libc-wchar-stdio-streams.patch) is one
commit on `master` `189053d4a2`:

- Moves `__FC_EXTERN_FOR_MACRO(stderr/stdin/stdout) FILE * __fc_{stderr,stdin,stdout};` into
  `share/libc/__fc_define_file.h` while keeping `#define stderr/stdin/stdout` exclusively in
  `share/libc/stdio.h`.
- Adds `tests/libc/wchar_stdio_streams.c` + oracle (`-print` with only `<wchar.h>` included).
- Validated on `framac-master-audit:189053d` (`189053d4a2`) and `framac-analysis:latest`
  (`34.0~beta`): reproducer flips `RESULT: bug present (2 of 2 checks fail)` -> `RESULT: fixed`,
  new test fails on unpatched `master` and passes patched, full `tests/libc` and `tests/variadic`
  pass with zero existing oracle changes, `./dev/check-files.sh -p HEAD~1` passes, and stacks
  cleanly with [`./patches/72-libc-pclose-pipe-status-soundness.patch`](./patches/72-libc-pclose-pipe-status-soundness.patch)
  on `share/libc/stdio.h` in both orders.

## Duplicate check

Live read-only `glab api` search on `pub/frama-c` (project 780, issues and MRs, all states) for
`wprintf`, `wscanf`, `wchar.h`, `__fc_stdout`, `__fc_stdin`, `fwprintf`, `variadic wprintf`,
`variadic wchar`, `Unable to locate`, plus `pub-frama-c_work_items_2026-11-09.csv` and packages
`01`-`50`: zero duplicates (only `#2832`; closed `#981` and `#1160` are unrelated).
