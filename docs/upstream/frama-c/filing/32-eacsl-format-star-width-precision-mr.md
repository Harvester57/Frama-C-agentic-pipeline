# [e-acsl] skip the '*' arguments of format directives

- Source branch: `fix/eacsl-format-star` on the fork of `pub/frama-c`; target branch `master`.
- Based on: `95408044f7`. Patch: [`../patches/32-eacsl-format-star-width-precision.patch`](../patches/32-eacsl-format-star-width-precision.patch)

<!-- Everything below this line is the merge request description. -->

Before submitting the merge request, please confirm (by adding a X in the [ ]):

- [ ] you contributed to Frama-C as prescribed in the [instructions](https://git.frama-c.com/pub/frama-c/-/blob/master/CONTRIBUTING.md).
- [ ] if the size of the PR requires it, you have signed the
  [Contributor Licensing Agreement](https://git.frama-c.com/pub/frama-c/-/blob/master/CLA.md)

Closes #<issue>.

## Problem

With `--validate-format-strings`, `validate_format`
(`plugins/e-acsl/share/e-acsl/libc_replacements/e_acsl_stdio.c`) checks each directive against the
argument at the directive's own position. A `*` field width or precision takes an `int` argument
first, so every directive from the first `*` on is checked against the wrong argument:

- `printf("RECORD:%.*s\n", n, buf)` aborts with
  `directive 1 ('%.*s') expects argument of type 'char*' but the corresponding argument has type 'int'`;
- the value of a `*` precision is not read, so a `"%.*s"` on a buffer without a NUL would be
  reported as unterminated even with the argument skipped.

In the same pass, a directive starting with the `0` flag had no index (`fetch_format_argno` returns
early on `'0'`): in `"%s %05d"`, the `"%05d"` was checked against the first argument.

## Change

Only the runtime; the instrumentation already describes the `*` arguments in `fmtdesc`.

- `validate_format` takes a `va_copy` of its arguments; `fetch_int_arguments` reads it with each
  argument's own type (from `fmtdesc`) and keeps the values of the `int`-class arguments.
- `fetch_star_arguments`, called for each directive: sets the index of a non-numbered directive to
  its ordinal; for each `*`, checks the argument against `int` with `validate_format_type` (on
  `fmtdesc` shifted by the number of `*` arguments so far, so messages still give the directive
  number), and replaces a `*` precision by its value, a negative one meaning omitted. The
  directive's own argument is then at its index plus the number of `*` arguments taken so far.
- A numbered directive with an unnumbered `*` (`"%1$*d"`) aborts with the existing "numbered and
  non-numbered" format error.

Every change is below line 549, so the `e_acsl_stdio.c:549` printed in
`oracle_dev/printf.0.e-acsl.err.log` does not move and no existing oracle changes.

Not covered: numbered `*` arguments (`"%2$*1$d"`) are still rejected by the parser
(`illegal format specifier '1'`). Supporting them changes the parser and the struct above line 549,
which would move that line number; I can do it in a follow-up if you want it. The `"%n"` message
that prints `argno` (see #ISSUE-31) is not touched.

New test `format/printf_star.c`: `"%.*s"`, `"%*d"`, `"%-*.*f"`, `"%*s|%s"`, `"%*.*s %p"`,
`"%.*s%n"`, a `*` precision on a buffer without a NUL, and `"%s %05d"`, which pass; a `long` width,
an `int` for `"%*s"`, a precision longer than the buffer, a negative precision on an unterminated
buffer and an unterminated `"%s"` after a `*`, which abort on their own directive.

This merge request and the ones for #ISSUE-30 and #ISSUE-31 change `e_acsl_stdio.c` in different
places and add different tests. They apply together in any order (`git am --3way`). With #ISSUE-30,
a promoted `unsigned char` is accepted as a `*` argument. Without #ISSUE-31, a `"%s"` after a
`double` is still shifted by that bug, but the `*` values themselves are read with their own types.
If both land, the typed loop of #ISSUE-31 and `fetch_int_arguments` could be merged.

## Testing

All on Debian 13 (gcc 14.2.0, x86_64), `master` at `95408044f7` built with dune, then the same tree
with this patch:

- Reproducer from #<issue> and its cases. Before: `rec.c` aborts with the message above;
  `"%-*.*f"`, `"%*s|%s"`, `"%.*s"` on a buffer without a NUL and `"%s %05d"` abort on correct
  arguments. After: `rec.c` prints `RECORD:abcdefgh` and those run; a `long` width aborts as
  before, a precision of 4 on a 3-byte buffer aborts with
  `attempt to access partially unallocated memory via directive 1 ('%.*s')`, and `"%*d %s"` with an
  unterminated string aborts with `unterminated string in directive 2 ('%s')`. 34.0~beta gives the
  `master` output.
- The new test `format/printf_star.c` fails on unpatched `master` in the `dev` configuration
  (`TEST 1: FAIL: Unexpected signal at printf_star.c:24`) and passes with the patch (15 sub-tests, 5
  of them expected aborts). Its default-configuration oracles are the same before and after, since
  the instrumentation is not changed.
- `frama-c-ptests -create-missing-oracles plugins/e-acsl/tests`, then
  `dune build --release -j 6 @plugins/e-acsl/tests/format/ptests_config`: all 5 tests of `format/`
  pass. In the `dev` configuration I ran `printf_star.c` and `fprintf.c` one at a time: both match.
  Not run: the `dev` configuration of `printf.c` and `sprintf.c`, and the other directories (the
  changed function is only compiled with `--validate-format-strings`). `printf.c` has no `*`
  directive and no non-first directive with the `0` flag, so its results should not change.
- The new aborts: `printf("[%1$*d]\n", 5, 42)` gives
  `Format error: "...": numbered and non-numbered arguments cannot be mixed`, and `printf("[%*d]\n")`
  or `printf("[%d %*d]\n", 1)` give `directive N (%*d) in format "..." has no argument for '*'`.
- With the patches for #ISSUE-30 and #ISSUE-31 applied too: the default configuration of `format/`
  (7 tests) and the `dev` configuration of the three new tests and `fprintf.c` pass;
  `snprintf(t, n, "%f %.*s %u %Lf %*s|", 1.5, 2, s, uc, 2.5L, 6, s)` prints
  `1.500000 ab 200 2.500000    abc|`.
- `./dev/check-files.sh -p HEAD~1` (`make check-lint` and `make check-headers` on the changed files,
  clang-format 19.1.7) passes; the new test and the runtime are clang-formatted.
- Not tested with `-G clang`: the runtime does not build with clang 19 under
  `--validate-format-strings` (#2810).

The analysis and fix were prepared with LLM assistance (Claude Code); I reviewed them and ran the
reproducer and tests described above.
