# E-ACSL `--validate-format-strings`: a `*` field width or precision shifts every later argument

Draft for the Frama-C tracker (https://git.frama-c.com/pub/frama-c/-/issues). **Filed on 2026-11-18 as [#2822](https://git.frama-c.com/pub/frama-c/-/work_items/2822), with merge request [!50](https://git.frama-c.com/pub/frama-c/-/merge_requests/50).** Number 32
in this folder's [index](./README.md). Same runtime function as Issues 30
([`./frama-c-eacsl-format-promoted-argument-signedness.md`](./frama-c-eacsl-format-promoted-argument-signedness.md))
and 31 ([`./frama-c-eacsl-format-fp-argument-slots.md`](./frama-c-eacsl-format-fp-argument-slots.md))
(`validate_format`, `share/e-acsl/libc_replacements/e_acsl_stdio.c`); independent fix.

## Summary

With `--validate-format-strings`, the runtime checks directive `i` against variadic argument `i`.
A field width or precision given as `*` takes an `int` argument before the directive's own
argument, so from the first `*` on every directive is checked against the wrong argument. A
`"%.*s"`, the usual way to print a buffer that is not NUL-terminated, aborts on correct code:

```text
printf: directive 1 ('%.*s') expects argument of type 'char*' but the corresponding argument has type 'int'
Aborted
```

The value of a `*` precision is never read either: the runtime records `*` as -1, which
`validate_format_string_argument` treats as "no precision", so even once the argument is skipped a
`"%.*s"` on a buffer without a NUL would be reported as an unterminated string.

Second symptom, same pass, different cause: a directive that starts with the `0` flag gets no
argument index (`fetch_format_argno` returns early on `'0'`, the struct is `calloc`ed), so in
`"%s %05d"` the `"%05d"` is checked against argument 1:
`directive 1 ('%05d') expects argument of type 'int' but the corresponding argument has type 'char*'`.

Seen in the pipeline as `printf("RECORD:%.*s\n", (int)n, buf)` (troubleshooting entry "Every Input
That Prints With a `*` Width or Precision Aborts" in
[`../../troubleshooting/eacsl-and-fuzzing.md`](../../troubleshooting/eacsl-and-fuzzing.md)).

## Versions

| | Result |
|---|---|
| `34.0~beta (Selenium)`, image `framac-analysis:latest` (2026-11-17) | **aborts**, same output as `master` (`-M -G gcc`; the installed `e_acsl_stdio.c` has the same md5 as `master`'s: the pipeline patches only a copy it passes with `--e-acsl-share`) |
| `master` `95408044f7` (34.0 merged, 2026-11-17), image `framac-master-audit:9540804` | **aborts** |
| `master` `95408044f7` + the patch (built in that image's container) | prints `RECORD:abcdefgh`, exit 0 |

Debian 13, gcc 14.2.0. With `-G clang`, the runtime does not compile under
`--validate-format-strings` on either version (implicit declarations, clang 19); that is #2810 /
!41, not this bug.

## Reproduction

`rec.c` ([`./repro/32-eacsl-format-star-width-precision.c`](./repro/32-eacsl-format-star-width-precision.c)):

```c
#include <stdio.h>

int main(void) {
  char buf[8] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'}; /* no NUL */
  int n = 8;
  return printf("RECORD:%.*s\n", n, buf) < 0;
}
```

```text
$ e-acsl-gcc -q -c -M -G gcc --validate-format-strings -o m.c -O m rec.c && ./m.e-acsl; echo rc=$?
printf: directive 1 ('%.*s') expects argument of type 'char*' but the corresponding argument has type 'int'
Aborted
rc=134
```

`-M` rules out Issue 33 (without it, every literal format string aborts first).

Cases on `master` (`-M -G gcc`, script [`./repro/32-eacsl-format-star-width-precision.sh`](./repro/32-eacsl-format-star-width-precision.sh)):

| Call | `master` | patched |
|---|---|---|
| `"[%*d]"`, `5, 42` | runs (by luck: the width `int` is checked for `"%d"`) | runs |
| `"[%-*.*f]"`, `10, 2, 3.14159` | abort, `'double'` vs `'int'` | runs |
| `"[%*s\|%s]"`, `4, s, s` | abort, `'char*'` vs `'int'` | runs |
| `"[%.*s]"`, `3, u` (`char u[3]`, no NUL) | abort, `'char*'` vs `'int'` | runs, prints `[xyz]` |
| `"[%s %05d]"`, `s, 5` | abort, directive 1 `'%05d'` vs `'char*'` | runs |
| `"[%*d]"`, `5L, 42` | abort, `'int'` vs `'long'` | same abort |
| `"[%.*s]"`, `4, u` | abort, `'char*'` vs `'int'` (wrong reason) | abort, `attempt to access partially unallocated memory via directive 1 ('%.*s')` |
| `"[%*d %s]"`, `3, 1, u` | abort, directive 2 `'char*'` vs `'int'` (wrong reason) | abort, `unterminated string in directive 2 ('%s')` |
| `"[%2$*1$d]"`, `5, 42` (POSIX numbered `*`) | `Format error: illegal format specifier '1'` | same (not fixed, see below) |

## Root cause

- The instrumentation is right: `Functions.Libc.get_printf_argument_str`
  (`src/libraries/functions.ml`) emits one letter per variadic argument, the `*` ones included
  (`"ds"` for `"%.*s", n, buf`). Nothing to change there.
- The parser records `*` as -1 (`fetch_format_field_width`, `fetch_format_precision`) and gives
  each non-numbered directive its position among the directives (`fetch_format_argno`, `ind`).
  `validate_format` then uses `dir->arg.index` for `fmtdesc[]` and `args[]`, never counting the
  `*` arguments, and never reads their values.
- `fetch_format_argno` returns before setting `arg.index` when the directive starts with `0`.

## Proposed fix

Patch [`./patches/32-eacsl-format-star-width-precision.patch`](./patches/32-eacsl-format-star-width-precision.patch),
runtime only, all of it after line 549 so that the `e_acsl_stdio.c:549` line printed in 85 lines of
`format/oracle_dev/printf.0.e-acsl.err.log` does not move:

- `validate_format` takes a `va_copy` of the arguments on entry; before the directive loop,
  `fetch_int_arguments` walks it with each argument's own type (from `fmtdesc`) and keeps the
  value of the `int`-class ones.
- In the loop, `fetch_star_arguments` sets the index of a non-numbered directive to its ordinal
  (which fixes the `0` flag case), checks each `*` argument against `int` with
  `validate_format_type` on `fmtdesc + stars` (so with Issue 30's patch a promoted `unsigned char`
  width is accepted), replaces a `*` precision by its value (negative means omitted, C11
  7.21.6.1p5), and counts the `*` arguments in `stars`. The directive's own argument is then at
  `arg.index + stars`.
- Messages keep the directive number: a wrong `*` reads
  `directive 1 ('%*d') expects argument of type 'int' but the corresponding argument has type 'long'`.
- A numbered directive with an unnumbered `*` (`"%1$*d"`) aborts with the existing "numbered and
  non-numbered" format error.

Not fixed: numbered `*` arguments (`"%2$*1$d"`, which the comment above `fetch_format_argno` cites
as supported). The parser stops at the `1` after `*`. Supporting it means changing
`fetch_format_field_width` / `fetch_format_precision` and the struct, above line 549, which moves
the line number in the existing `dev` oracle; I could not regenerate that oracle (the `printf.c`
`dev` run is reserved for 30/31 re-validation). Mentioned in the issue as a separate limitation.

The `"%n"` message (`argument %d of directive %n`, printing `argno` where the others print
`arg.index + 1`; noted in Issue 31) is not touched: `argno` is still the directive's own index.

## Validation (`master` `95408044f7`, 2026-11-17)

All in one container of `framac-master-audit:9540804` (dune build of the clone, installed into the
opam prefix), `--cpus 6 --memory 10g`, core limit 1 byte (set by the container; `ulimit -c 1` is
refused because the hard limit is already 1 byte).

- **Reproducer** before/after: outputs in the script header; 34.0~beta gives the `master` output.
- **New test** `tests/format/printf_star.c` (15 sub-tests, 5 expected aborts): on `master` without
  the runtime change, `dev` stops at `TEST 1: FAIL: Unexpected signal at printf_star.c:24`
  (`snprintf: directive 1 ('%.*s') expects argument of type 'char*' but the corresponding argument has type 'int'`);
  the default configuration passes there (runtime-only change). With the patch, both pass.
- **ptests:** `dune build --release -j 6 @plugins/e-acsl/tests/format/ptests_config` (default, 5
  tests): exit 0. `dev`, one at a time: `printf_star.diff` and `fprintf.diff`, exit 0. Not run:
  `dev` of `printf.c` (reserved) and `sprintf.c`, other directories.
- **Lint:** `./dev/check-files.sh -p HEAD~1`: exit 0 (`Lint 5 file(s)`).
- **Negative controls:** a `long` width, an `int` for `"%*s"`, a precision longer than the buffer,
  a negative precision on an unterminated buffer, and an unterminated `"%s"` after a `*` all abort,
  each on its own directive (test lines 38 to 46, and reproducer cases 5 to 7).
- **With 30 and 31:** `git am --3way --keep-non-patch` applies in every order tried (32 alone; 30
  31 32; 31 30 32; 32 30 31; 32 31 30; 30 32 31; 31 32 30; and each pair both ways); orders 30 31
  32, 32 31 30 and 31 32 30 give the same tree. `git apply --check` of 32 also passes on `master`,
  after 30 and after 31, and of 31 after 32. On the 30+31+32 tree: default
  `format/` (7 tests) exit 0; `dev` of `printf_star`, `printf_promoted`, `printf_fp_args` and
  `fprintf` exit 0; lint `-p HEAD~3` exit 0 (14 files); a mixed call
  `"%f %.*s %u %Lf %*s|"` with `(1.5, 2, s, uc, 2.5L, 6, s)` prints `1.500000 ab 200 2.500000    abc|`,
  an `unsigned char` width is accepted, and `"%f %.*s"` with `(1.5, 4, u)` aborts on directive 2.
- **The new abort branches** (probed on the 30+31+32+33 install, with and without `-M`):
  `printf("[%1$*d]\n", 5, 42)` gives `Format error: "[%1$*d]\n": numbered and non-numbered arguments cannot be mixed`;
  `printf("[%*d]\n")` gives `printf: directive 1 (%*d) in format "[%*d]\n" has no argument for '*'`;
  `printf("[%d %*d]\n", 1)` the same on directive 2; `printf("[%.*s]\n", 2)` gives the existing
  `directive 1 (%.*s) in format "[%.*s]\n" has no argument`.
- **Without 31**, a `*` after a `double` is still shifted by Issue 31's bug (`args[]`); the `*`
  values themselves are read with their own types, so they are right in both cases. When both land,
  31's typed loop and `fetch_int_arguments` read the arguments twice and could be merged.

## Filing package

- Issue: [`./filing/32-eacsl-format-star-width-precision-issue.md`](./filing/32-eacsl-format-star-width-precision-issue.md)
- MR: [`./filing/32-eacsl-format-star-width-precision-mr.md`](./filing/32-eacsl-format-star-width-precision-mr.md)
- Patch: [`./patches/32-eacsl-format-star-width-precision.patch`](./patches/32-eacsl-format-star-width-precision.patch)
- Repro: [`./repro/32-eacsl-format-star-width-precision.sh`](./repro/32-eacsl-format-star-width-precision.sh)
  with `32-eacsl-format-star-width-precision.c` and `-cases.c`

## Tracker

Searched on 2026-11-17 with the authenticated API (`pub/frama-c`, issues and merge requests, all
states) for `format string`, `validate-format`, `format-strings`, `precision`, `field width`,
`asterisk` and `printf`. No duplicate: the format hits are this folder's own reports (#2802,
#2803, #2810, !33, !34, !41), and the `precision` and `printf` hits are about Eva, WP, slicing and
the kernel.
