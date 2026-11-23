# [libc] pwd.h/utmp.h: assign reentrant result pointer from caller struct

- Source branch: `fix/libc-reentrant-result-pointer-assigns` on the fork of `pub/frama-c`; target branch `master`.
- Based on: `189053d4a2`. Patch: [`../patches/74-libc-reentrant-result-pointer-assigns.patch`](../patches/74-libc-reentrant-result-pointer-assigns.patch)

<!-- Everything below this line is the merge request description. -->

Before submitting the merge request, please confirm (by adding a X in the [ ]):

- [ ] you contributed to Frama-C as prescribed in the [instructions](https://git.frama-c.com/pub/frama-c/-/blob/master/CONTRIBUTING.md).
- [ ] if the size of the PR requires it, you have signed the
  [Contributor Licensing Agreement](https://git.frama-c.com/pub/frama-c/-/blob/master/CLA.md)

Closes #<issue>.

## Problem

In `share/libc/pwd.h:68,85` (`getpwnam_r`, `getpwuid_r`) and `share/libc/utmp.h:124,131,139`
(`getutent_r`, `getutid_r`, `getutline_r`), the output pointer parameter (`*result` / `*ubufp`)
was assigned `\from &__fc_pwd` / `\from &__fc_utmp` instead of the caller-supplied struct pointer
(`pwd` / `ubuf`). In Eva, this forced `*result` to `{0}` (killing every `getpwnam_r`/`getpwuid_r`
success branch) and turned `*ubufp` into a garbled mix of `&__fc_utmp` (raising spurious alignment
and pointer-comparison alarms and killing `res == &ub`).

## Change

- **`share/libc/pwd.h` (lines 68 and 85):** split `assigns *pwd, *result \from &__fc_pwd;` into
  `assigns *pwd \from __fc_pwd, buf, indirect:buflen;` and
  `assigns *result \from pwd, indirect:__fc_pwd;` (matching `grp.h:46,57` and `dirent.h:90`).
- **`share/libc/utmp.h` (lines 124, 131, and 139):** change `assigns *ubufp` to depend on `ubuf`
  (plus `indirect:*ut` for `getutid_r` / `getutline_r`) and add
  `ensures result_null_or_ubuf: *ubufp == \null || *ubufp == ubuf;`.
- **New test `tests/libc/reentrant_result_ptr.c` + oracle:** exercises all five functions in Eva
  and checks that all five success branches are reached and valid with zero alarms.

## Testing

Validated on a fresh build of `master` `189053d4a2` (Debian 13, OCaml 5.5 switch, gcc 14.2.0, glibc 2.41):

- **Reproducer (`74-libc-reentrant-result-pointer-assigns.sh`):** fails before on both `189053d4a2`
  and `34.0~beta` (`RESULT: bug present (1 of 1 checks fail)`); passes after installing the patch
  (`RESULT: fixed`).
- **New test on unpatched `master`:** `tests/libc/reentrant_result_ptr.c` fails on unpatched
  `master` and passes with the patch.
- **ptests, default configuration:** `tests/libc` (including `fc_libc`, `pwd_h`, `pwd_c`, `utmp_h`,
  and all `check_*` checks) passes with zero existing oracle diffs.
- **`./dev/check-files.sh -p HEAD~1`:** clean (`exit=0`).
- **Not run:** unrelated plugin test suites outside `tests/libc`.

The analysis and fix were prepared with LLM assistance (Antigravity / Gemini); I reviewed them and
ran the reproducer and tests described above.
