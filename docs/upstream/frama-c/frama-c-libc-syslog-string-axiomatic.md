# Frama-C libc: `syslog` drops string preconditions with only `<syslog.h>` (draft 75)

- **Upstream index:** [`./README.md`](./README.md)
- **Hunt candidate:** `L5` in [`./frama-c-hunt-2026-11-18-candidates.md`](./frama-c-hunt-2026-11-18-candidates.md)
- **Issue text:** [`./filing/75-libc-syslog-string-axiomatic-issue.md`](./filing/75-libc-syslog-string-axiomatic-issue.md)
- **MR text:** [`./filing/75-libc-syslog-string-axiomatic-mr.md`](./filing/75-libc-syslog-string-axiomatic-mr.md)
- **Patch:** [`./patches/75-libc-syslog-string-axiomatic.patch`](./patches/75-libc-syslog-string-axiomatic.patch)
- **Reproducer:** [`./repro/75-libc-syslog-string-axiomatic.sh`](./repro/75-libc-syslog-string-axiomatic.sh) ([`./repro/75-libc-syslog-string-axiomatic.c`](./repro/75-libc-syslog-string-axiomatic.c))

**Status:** full filing package validated on `master` `189053d4a2` and `34.0~beta`; **not filed**
(filing remains paused pending maintainer response in
[#2832](https://git.frama-c.com/pub/frama-c/-/work_items/2832), annex ref `L5`). Recommended for
our local `opam/` patch queue (false-negative: missed invalid string arguments to `syslog`).

## Summary

When a translation unit includes `<syslog.h>` without also including `<stdio.h>`, `<string.h>`, or
another header that brings in `__fc_string_axiomatic.h`, Frama-C's Variadic translation cannot
locate `valid_read_string` / `valid_read_nstring`, emits `[kernel:libc:frama-c] Warning: Unable to
locate ACSL predicate ...`, and silently drops all string-validity preconditions from `syslog_va_*`.
Eva then reports 0 alarms when an unterminated buffer is passed to `syslog(LOG_ERR, "%s", buf)`.

## Diagnosis

- `src/kernel/services/ast_transformations/variadic/classify.ml:137` classifies `syslog` as
  `PrintfLike`.
- `src/kernel/services/ast_transformations/variadic/standard.ml:408-416, 445-449, 523-542` looks
  up `valid_read_string` / `valid_read_nstring` / `valid_read_wstring` / `valid_read_nwstring` in
  `Logic_env` and ignores `Not_found`.
- `share/libc/syslog.h:11-15` includes `features.h`, `__fc_define_null.h`, and `<stdarg.h>`, but
  omits `"__fc_string_axiomatic.h"`, whereas 20 other POSIX/ISO headers in `share/libc/` already
  include it.

## Fix and validation

[`./patches/75-libc-syslog-string-axiomatic.patch`](./patches/75-libc-syslog-string-axiomatic.patch)
is one commit on `master` `189053d4a2`:

- Adds `#include "__fc_string_axiomatic.h"` to `share/libc/syslog.h`.
- Adds `tests/libc/syslog_h.c` + oracle verifying valid `%s`/`%.2s` calls and invalid preconditions
  on unterminated `%s` and too-short `%.5s` buffers with only `<syslog.h>` included.
- Validated on `framac-master-audit:189053d` (`189053d4a2`) and `framac-analysis:latest`
  (`34.0~beta`): reproducer flips `RESULT: bug present (1 of 1 checks fail)` -> `RESULT: fixed`,
  new test fails on unpatched `master` and passes patched, full `tests/libc` and `tests/variadic`
  pass with zero existing oracle changes, and `./dev/check-files.sh -p HEAD~1` passes.

## Duplicate check

Live read-only `glab api` search on `pub/frama-c` (project 780, issues and MRs, all states) for
`syslog`, `syslog.h`, `valid_read_string`, `variadic syslog`, `Unable to locate`, plus
`pub-frama-c_work_items_2026-11-09.csv` and packages `01`-`50`: zero duplicates (only `#2832`).
