# Frama-C libc: `getpwnam_r`/`getpwuid_r` and `getut*_r` result pointer assigns (draft 74)

- **Upstream index:** [`./README.md`](./README.md)
- **Hunt candidate:** `N6` (plus `utmp.h` sibling) in [`./frama-c-hunt-2026-11-18-candidates.md`](./frama-c-hunt-2026-11-18-candidates.md)
- **Issue text:** [`./filing/74-libc-reentrant-result-pointer-assigns-issue.md`](./filing/74-libc-reentrant-result-pointer-assigns-issue.md)
- **MR text:** [`./filing/74-libc-reentrant-result-pointer-assigns-mr.md`](./filing/74-libc-reentrant-result-pointer-assigns-mr.md)
- **Patch:** [`./patches/74-libc-reentrant-result-pointer-assigns.patch`](./patches/74-libc-reentrant-result-pointer-assigns.patch)
- **Reproducer:** [`./repro/74-libc-reentrant-result-pointer-assigns.sh`](./repro/74-libc-reentrant-result-pointer-assigns.sh) ([`./repro/74-libc-reentrant-result-pointer-assigns.c`](./repro/74-libc-reentrant-result-pointer-assigns.c))

**Status:** full filing package validated on `master` `189053d4a2` and `34.0~beta`; **not filed**
(filing remains paused pending maintainer response in
[#2832](https://git.frama-c.com/pub/frama-c/-/work_items/2832), annex ref `N6`). Recommended for
our local `opam/` patch queue (eliminates dead success branches on `getpwnam_r`/`getpwuid_r` and
`getut*_r` in Eva).

## Summary

Five reentrant libc lookup contracts assign their output pointer parameter (`*result` / `*ubufp`)
from the address of an internal static global (`&__fc_pwd` / `&__fc_utmp`) instead of the
caller-supplied struct pointer (`pwd` / `ubuf`):

- `share/libc/pwd.h:68,85`: `getpwnam_r`, `getpwuid_r` (`assigns *pwd, *result \from &__fc_pwd;`);
- `share/libc/utmp.h:124,131,139`: `getutent_r`, `getutid_r`, `getutline_r` (`assigns *ubufp \from ... &__fc_utmp;`).

In Eva, intersecting `*result` with `ensures *result == \null || *result == pwd` eliminates `pwd`
and forces `res ∈ {0}`, killing the success branch `if (r == 0 && res != NULL)`. In `<utmp.h>`,
`*ubufp` receives a garbled mix of `&__fc_utmp`, emitting false `\aligned` and
`\pointer_comparable` alarms and making `res == &ub` dead.

## Diagnosis and sibling audit

- Every `\from &__fc_*` and every `*_r(` function in `share/libc/` was audited.
- `share/libc/grp.h:46,57` (`getgrgid_r`, `getgrnam_r`: `assigns *result \from grp;`) and
  `share/libc/dirent.h:90` (`readdir_r`: `assigns *result \from entry;`) already follow the
  correct pattern.
- `tests/libc/pwd_c.c` did not catch `pwd.h` because it `#include "pwd.c"`, and `tests/libc/pwd_h.c`
  only calls non-reentrant `getpwuid`/`getpwnam`. `tests/libc/utmp_h.c` does not call `getut*_r`.

## Fix and validation

[`./patches/74-libc-reentrant-result-pointer-assigns.patch`](./patches/74-libc-reentrant-result-pointer-assigns.patch)
is one commit on `master` `189053d4a2`:

- Splits `share/libc/pwd.h:68,85` into `assigns *pwd \from __fc_pwd, buf, indirect:buflen;` and
  `assigns *result \from pwd, indirect:__fc_pwd;`.
- Updates `share/libc/utmp.h:124,131,139` to assign `*ubufp \from ubuf` (plus `indirect:*ut` on
  `getutid_r`/`getutline_r`) and adds `ensures result_null_or_ubuf: *ubufp == \null || *ubufp == ubuf;`.
- Adds `tests/libc/reentrant_result_ptr.c` + oracle covering all five functions (5/5 valid
  assertions, 0 alarms).
- Validated on `framac-master-audit:189053d` (`189053d4a2`) and `framac-analysis:latest`
  (`34.0~beta`): reproducer flips `RESULT: bug present (1 of 1 checks fail)` -> `RESULT: fixed`,
  new test fails on unpatched `master` and passes patched, full `tests/libc` passes with zero
  existing oracle changes, and `./dev/check-files.sh -p HEAD~1` passes.

## Duplicate check

Live read-only `glab api` search on `pub/frama-c` (project 780, issues and MRs, all states) for
`getpwnam_r`, `getpwuid_r`, `getpwuid`, `pwd.h`, `getgrnam_r`, `utmp.h`, `getutent_r`, plus
`pub-frama-c_work_items_2026-11-09.csv` and packages `01`-`50`: zero duplicates (only `#2832`).
