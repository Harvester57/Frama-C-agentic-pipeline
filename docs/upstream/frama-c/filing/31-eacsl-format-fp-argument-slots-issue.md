# [E-ACSL] --validate-format-strings: after a double or long double argument, "%s", "%p" and "%n" are checked against the next argument

<!-- Everything below this line is the issue description. -->

### Summary

With `--validate-format-strings`, the runtime reads every variadic argument as a `void *` before it validates the directives. A `double` or `long double` is not passed where a `void *` is, so from that argument on, the pointer checked for `"%s"`, `"%p"` or `"%n"` is the one of the following argument. `snprintf(t, sizeof t, "%f %s", 1.5, s)` with a valid `s` aborts, and an invalid string after a `double` can go unchecked.

### Steps to reproduce the issue

`dbl.c`:

```c
#include <stdio.h>

int main(void) {
  char t[64];
  const char *s = "abc";
  snprintf(t, sizeof t, "%f %s", 1.5, s);
  return puts(t) < 0;
}
```

```sh
e-acsl-gcc -q -c -M -G gcc --validate-format-strings -o m.c -O m dbl.c && ./m.e-acsl
```

(`-M` is `--full-mtracking`. Without it, the literal format string is rejected earlier with
`invalid format string (unallocated or unterminated)`; the `format/` tests also pass
`--full-mtracking`, with the comment "Remove --full-mtracking once e-acsl#118 is fixed".)

### Expected behaviour

The program prints `1.500000 abc` and exits 0.

### Actual behaviour

```text
snprintf: attempt to access unallocated memory via directive 2 ('%s')
```

and the program aborts (exit 134). More cases, same flags, with `char u[3] = {'x', 'y', 'z'}` (not
NUL-terminated):

| Call | `master` |
|---|---|
| `snprintf(t, sizeof t, "%Lf %s", 2.5L, s)` | abort, `attempt to access unallocated memory via directive 2 ('%s')` |
| `snprintf(t, sizeof t, "%f%n", 1.5, &n)` | abort, `argument 1 of directive %n not allocated or writeable` |
| `snprintf(t, sizeof t, "%s", u)` | abort, `unterminated string in directive 1 ('%s')` (right) |
| `snprintf(t, sizeof t, "%f %s %s", 1.5, u, s)` | abort, `attempt to access unallocated memory via directive 3 ('%s')`: `u` is not checked, directive 3 is checked against whatever follows `s` |
| `snprintf(t, sizeof t, "%f %s", 1.5, u, s)` (one argument too many, which C allows) | **runs**, exit 0: `u` is never checked, and `vsnprintf` reads past it |

### Contextual information

- Frama-C installation mode: from source (`master`) and opam (Docker image based on `framac/frama-c:dev`)
- Frama-C version: 35.0~~dev (Bromine), `master` at 95408044f7 (and 3dff90fc70); also 34.0~beta (Selenium), same output
- Plug-in used: E-ACSL (`e-acsl-gcc --validate-format-strings`)
- OS name: Debian GNU/Linux
- OS version: 13 (trixie), gcc 14.2.0, x86_64

### Additional information (optional)

**Cause.** `validate_format` (`plugins/e-acsl/share/e-acsl/libc_replacements/e_acsl_stdio.c`)
collects the arguments first:

```c
  for (int i = 0; i < arglen; i++)
    args[i] = va_arg(ap, void *);
```

On x86_64, `va_arg(ap, void *)` takes the next general-purpose slot. A `double` is passed in an SSE
register and a `long double` in memory, so the read meant for the floating-point argument takes the
next pointer, and each later `args[i]` holds argument `i + 1`. Only `"%s"`, `"%p"` and `"%n"` use
`args[]`, which is why only they are affected. On a 32-bit target (`e-acsl-gcc --mbits 32`, machdep
`gcc_x86_32`), a `double` and a `long long` take two stack words and would shift the arguments in the
same way (not tested: my image has no 32-bit libc).

**Fix.** The instrumentation already passes the type of each argument (the format description string,
one letter per argument, from `Functions.Libc.get_printf_argument_str`: `e` for `double`, `E` for
`long double`, `l`/`L` and `r`/`R` for `long` and `long long`, `s`, `i`, `p` and eight more letters for
pointers). Read each argument with that type, and keep only the pointers. A merge request with this
fix and a regression test follows.

Separately (not changed by the merge request): the `"%n"` message above says "argument 1" for
directive 2, because it prints `argno` where the other messages print `dir->arg.index + 1`.

The analysis and fix were prepared with LLM assistance (Claude Code); I reviewed them and ran the
reproducer and tests described above.
