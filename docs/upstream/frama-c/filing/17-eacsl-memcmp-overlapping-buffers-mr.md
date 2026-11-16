# [e-acsl] memcmp replacement: do not reject overlapping arguments

- Source branch: `fix/eacsl-memcmp-overlap` on the fork of `pub/frama-c`; target branch `master`.
- Based on: `3dff90fc70`. Patch: [`../patches/17-eacsl-memcmp-overlapping-buffers.patch`](../patches/17-eacsl-memcmp-overlapping-buffers.patch)

<!-- Everything below this line is the merge request description. -->

Before submitting the merge request, please confirm (by adding a X in the [ ]):

- [ ] you contributed to Frama-C as prescribed in the [instructions](https://git.frama-c.com/pub/frama-c/-/blob/master/CONTRIBUTING.md).
- [ ] if the size of the PR requires it, you have signed the
  [Contributor Licensing Agreement](https://git.frama-c.com/pub/frama-c/-/blob/master/CLA.md)

Closes #2803.

## Problem

With `-e-acsl-replace-libc-functions` (`e-acsl-gcc --libc-replacements`), `eacsl_builtin_memcmp`
(`plugins/e-acsl/share/e-acsl/libc_replacements/e_acsl_string.c`) calls
`validate_overlapping_spaces(..., "memcpy")` on its two arguments, a line copied from
`eacsl_builtin_memcpy`. Every `memcmp(s1, s2, n)` with `n > 0` and overlapping ranges, including
`memcmp(p, p, n)`, aborts the program with `memcpy: overlapping memory areas`. `memcmp` only reads
its arguments and has no `restrict` parameter (C17 7.24.4.1), so these calls are valid.

## Change

- Remove the overlap check from `eacsl_builtin_memcmp`. The checks that both ranges are allocated
  stay, as in the `strcmp` and `strncmp` replacements.
- New test `plugins/e-acsl/tests/builtin/memcmp.c`, in the suite of the libc replacements (which
  had no `memcmp` test): compares identical, overlapping and disjoint ranges of one array and
  asserts the results. New oracles `builtin/oracle/memcmp.0.res.oracle` and
  `builtin/oracle/gen_memcmp.0.c`. No other oracle changes.

The diagnostics of `eacsl_builtin_memmove` (`"memcmp"`), `eacsl_builtin_strcpy` (`"strlen"`) and
`eacsl_builtin_strncat` (`"strcat"`) name the wrong function too; this MR leaves them alone.

## Testing

On a build of this branch (Debian 13, OCaml 5.5 switch, gcc 14):

- Reproducer of the issue: `prog.e-acsl` aborted with `memcpy: overlapping memory areas` (exit 134)
  before the change; it exits with 0 after.
- `builtin/memcmp.c`, `dev` configuration: fails before the change (same abort), passes after.
- E-ACSL ptests, every suite, default and `dev` configurations, on this branch and on `master`:
  the only difference is the new test (fails on `master`, passes here). In my environment
  `format/printf.c` hangs in the `dev` configuration on `master` as well (no progress after its
  28th check), so the `format` suite was compared in the default configuration only.
- `git diff --check` reports only the new oracle files (the trailing space after `Warning:` and the
  trailing blank line that ptests writes in every oracle). The patch applies with
  `git apply --check` on `3dff90fc70`.
- `make check-lint` and `make check-headers` were not run (my build tree is not a Git checkout);
  `clang-format` 19 (`--dry-run -Werror`, with `plugins/e-acsl/.clang-format`) on
  `e_acsl_string.c` and the new test is clean.

The analysis and fix were prepared with LLM assistance (Claude Code); I reviewed them and ran the
reproducer and tests described above.
