# [libc] syslog.h: include __fc_string_axiomatic.h for Variadic

- Source branch: `fix/libc-syslog-string-axiomatic` on the fork of `pub/frama-c`; target branch `master`.
- Based on: `189053d4a2`. Patch: [`../patches/75-libc-syslog-string-axiomatic.patch`](../patches/75-libc-syslog-string-axiomatic.patch)

<!-- Everything below this line is the merge request description. -->

Before submitting the merge request, please confirm (by adding a X in the [ ]):

- [ ] you contributed to Frama-C as prescribed in the [instructions](https://git.frama-c.com/pub/frama-c/-/blob/master/CONTRIBUTING.md).
- [ ] if the size of the PR requires it, you have signed the
  [Contributor Licensing Agreement](https://git.frama-c.com/pub/frama-c/-/blob/master/CLA.md)

Closes #<issue>.

## Problem

The Variadic translation classifies `syslog()` as `PrintfLike` and generates `valid_read_string` /
`valid_read_nstring` preconditions on its format string and string arguments. Because
`share/libc/syslog.h` did not include `__fc_string_axiomatic.h`, a file including only `<syslog.h>`
emitted `[kernel:libc:frama-c] Warning: Unable to locate ACSL predicate valid_read_string` and
silently dropped all string-validity preconditions, letting Eva report 0 alarms on unterminated
buffers passed to `syslog()`.

## Change

- **`share/libc/syslog.h`:** add `#include "__fc_string_axiomatic.h"` next to
  `#include "__fc_define_null.h"` (matching `stdio.h`, `pwd.h`, `fcntl.h`, `unistd.h`, `wchar.h`,
  and other POSIX headers).
- **New test `tests/libc/syslog_h.c` + oracle:** includes only `<syslog.h>` and verifies valid
  `syslog("%s %.2s", ...)` calls as well as invalid preconditions caught on unterminated `%s` and
  too-short `%.5s` buffers.

## Testing

Validated on a fresh build of `master` `189053d4a2` (Debian 13, OCaml 5.5 switch, gcc 14.2.0, glibc 2.41):

- **Reproducer (`75-libc-syslog-string-axiomatic.sh`):** fails before on both `189053d4a2` and
  `34.0~beta` (`RESULT: bug present (1 of 1 checks fail)`); passes after installing the patch
  (`RESULT: fixed`).
- **New test on unpatched `master`:** `tests/libc/syslog_h.c` fails on unpatched `master` and
  passes with the patch.
- **ptests, default configuration:** `tests/libc` (including `fc_libc` and all `check_*` checks)
  and `tests/variadic` pass with zero existing oracle diffs.
- **`./dev/check-files.sh -p HEAD~1`:** clean (`exit=0`).
- **Not run:** unrelated plugin test suites outside `tests/libc` and `tests/variadic`.

The analysis and fix were prepared with LLM assistance (Antigravity / Gemini); I reviewed them and
ran the reproducer and tests described above.
