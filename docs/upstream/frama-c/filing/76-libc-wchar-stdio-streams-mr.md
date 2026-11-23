# [libc] __fc_define_file.h: declare __fc_stdin/__fc_stdout for <wchar.h>

- Source branch: `fix/libc-wchar-stdio-streams` on the fork of `pub/frama-c`; target branch `master`.
- Based on: `189053d4a2`. Patch: [`../patches/76-libc-wchar-stdio-streams.patch`](../patches/76-libc-wchar-stdio-streams.patch)

<!-- Everything below this line is the merge request description. -->

Before submitting the merge request, please confirm (by adding a X in the [ ]):

- [ ] you contributed to Frama-C as prescribed in the [instructions](https://git.frama-c.com/pub/frama-c/-/blob/master/CONTRIBUTING.md).
- [ ] if the size of the PR requires it, you have signed the
  [Contributor Licensing Agreement](https://git.frama-c.com/pub/frama-c/-/blob/master/CLA.md)

Closes #<issue>.

## Problem

ISO C11 7.29.2.10-11 declares `wprintf()` and `wscanf()` in `<wchar.h>` without requiring
`<stdio.h>`. The Variadic translation classifies both as `StdIO` and looks up `__fc_stdout` and
`__fc_stdin`, which were declared only in `share/libc/stdio.h`. Including `<wchar.h>` alone
therefore emitted `[kernel:libc:frama-c] Warning: Unable to locate global __fc_stdout / __fc_stdin`
and dropped the stream `assigns` / `\from` clauses on `__fc_stdout->__fc_FILE_data` and
`__fc_stdin->__fc_FILE_data`.

## Change

- **`share/libc/__fc_define_file.h` and `share/libc/stdio.h`:** move the three internal
  `__FC_EXTERN_FOR_MACRO` declarations (`__fc_stderr`, `__fc_stdin`, `__fc_stdout`, reserved under
  ISO C11 7.1.3) into `share/libc/__fc_define_file.h` (included only by `stdio.h` and `wchar.h`),
  while keeping `#define stderr/stdin/stdout` exclusively in `share/libc/stdio.h` so `<wchar.h>`
  does not expose the `<stdio.h>` macros.
- **New test `tests/libc/wchar_stdio_streams.c` + oracle:** includes only `<wchar.h>` with `-print`,
  verifying zero warnings and generated `assigns`/`\from` clauses on `__fc_stdout->__fc_FILE_data`
  and `__fc_stdin->__fc_FILE_data` for `wprintf` and `wscanf`.

## Testing

Validated on a fresh build of `master` `189053d4a2` (Debian 13, OCaml 5.5 switch, gcc 14.2.0, glibc 2.41):

- **Reproducer (`76-libc-wchar-stdio-streams.sh`):** fails before on both `189053d4a2` and
  `34.0~beta` (`RESULT: bug present (2 of 2 checks fail)`); passes after installing the patch
  (`RESULT: fixed`).
- **New test on unpatched `master`:** `tests/libc/wchar_stdio_streams.c` fails on unpatched
  `master` and passes with the patch.
- **ptests, default configuration:** `tests/libc` (including `fc_libc`, `wchar_h`, `stdio_h`, and
  all `check_*` checks) and `tests/variadic` pass with zero existing oracle diffs.
- **Stacking:** stacks cleanly with the `pclose` patch (which also modifies `share/libc/stdio.h`)
  via `git am --3way --keep-non-patch` in both orders.
- **`./dev/check-files.sh -p HEAD~1`:** clean (`exit=0`).
- **Not run:** unrelated plugin test suites outside `tests/libc` and `tests/variadic`.

The analysis and fix were prepared with LLM assistance (Antigravity / Gemini); I reviewed them and
ran the reproducer and tests described above.
