# [E-ACSL] --validate-format-strings: a "*" field width or precision makes every later directive be checked against the wrong argument

<!-- Everything below this line is the issue description. -->

### Summary

With `--validate-format-strings`, the runtime checks the i-th directive against the i-th variadic argument. A field width or precision given as `*` takes an `int` argument before the directive's own argument, so from the first `*` on, every directive is checked against the wrong argument. `printf("%.*s\n", n, buf)` aborts on correct code, and the value of a `*` precision is never used.

### Steps to reproduce the issue

`rec.c`:

```c
#include <stdio.h>

int main(void) {
  char buf[8] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'}; /* no NUL */
  int n = 8;
  return printf("RECORD:%.*s\n", n, buf) < 0;
}
```

```sh
e-acsl-gcc -q -c -M -G gcc --validate-format-strings -o m.c -O m rec.c && ./m.e-acsl
```

(`-M` is `--full-mtracking`; without it every literal format string is rejected first with
`invalid format string (unallocated or unterminated)`, which I report separately in #ISSUE-33.)

### Expected behaviour

The program prints `RECORD:abcdefgh` and exits 0: `"%.*s"` reads at most `n` characters, so `buf`
needs no NUL.

### Actual behaviour

```text
printf: directive 1 ('%.*s') expects argument of type 'char*' but the corresponding argument has type 'int'
```

and the program aborts (exit 134). More cases, same flags, `const char *s = "abc"` and
`char u[3] = {'x', 'y', 'z'}` (not NUL-terminated):

| Call | `master` |
|---|---|
| `printf("[%*d]\n", 5, 42)` | runs, but only because the width is checked against `"%d"` |
| `printf("[%-*.*f]\n", 10, 2, 3.14159)` | abort, `directive 1 ('%-*.*f') expects argument of type 'double' but the corresponding argument has type 'int'` |
| `printf("[%*s\|%s]\n", 4, s, s)` | abort, `directive 1 ('%*s') expects argument of type 'char*' ... 'int'` |
| `printf("[%.*s]\n", 3, u)` | abort, same message (and with the argument skipped, the precision would still be ignored: `u` would be reported as unterminated) |
| `printf("[%*d %s]\n", 3, 1, u)` | abort, `directive 2 ('%s') expects argument of type 'char*' ... 'int'`, not the unterminated `u` |
| `printf("[%s %05d]\n", s, 5)` (no `*`) | abort, `directive 1 ('%05d') expects argument of type 'int' but the corresponding argument has type 'char*'` |
| `printf("[%2$*1$d]\n", 5, 42)` | abort, `Format error: illegal format specifier '1'` |

### Contextual information

- Frama-C installation mode: from source (`master`) and opam (Docker image based on `framac/frama-c:dev`)
- Frama-C version: 35.0~~dev (Bromine), `master` at 95408044f7; also 34.0~beta (Selenium), same output
- Plug-in used: E-ACSL (`e-acsl-gcc --validate-format-strings`)
- OS name: Debian GNU/Linux
- OS version: 13 (trixie), gcc 14.2.0, x86_64

### Additional information (optional)

**Cause.** In `plugins/e-acsl/share/e-acsl/libc_replacements/e_acsl_stdio.c`, the parser records a
`*` width or precision as -1 (`fetch_format_field_width`, `fetch_format_precision`) and gives each
non-numbered directive its position among the directives (`fetch_format_argno`). `validate_format`
looks up `fmtdesc[dir->arg.index]` and `args[dir->arg.index]` without counting the arguments taken
by `*`, and never reads their values, so `validate_format_string_argument` sees precision -1 ("no
precision"). The instrumentation is fine: the format description string already has a letter for
each `*` argument (`"ds"` for the call above).

The `"%05d"` row has another cause in the same place: `fetch_format_argno` returns before setting
`dir->arg.index` when the directive starts with `0`, so the index stays 0 from `calloc`.

**Fix.** In `validate_format`: read the `int` arguments from a `va_copy` with each argument's own
type, count the arguments taken by `*` while walking the directives, check that each is an `int`,
use the value of a `*` precision (negative means omitted), and look up the directive's argument at
its index plus that count. Setting the index of each non-numbered directive in the same pass fixes
the `0` flag case. A merge request with this fix and a regression test follows.

Not covered by it: numbered `*` arguments (`"%2$*1$d"`, POSIX), which the parser rejects. Supporting
them needs parser and struct changes above the line whose number is printed in
`tests/format/oracle_dev/printf.0.e-acsl.err.log` (`e_acsl_stdio.c:549`), so I left it out.

The analysis and fix were prepared with LLM assistance (Claude Code); I reviewed them and ran the
reproducer and tests described above.
