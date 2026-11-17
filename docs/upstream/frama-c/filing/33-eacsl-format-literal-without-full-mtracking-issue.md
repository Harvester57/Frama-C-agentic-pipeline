# [E-ACSL] --validate-format-strings without --full-mtracking: every printf call aborts with "invalid format string (unallocated or unterminated)"

<!-- Everything below this line is the issue description. -->

### Summary

Without `-M` (`--full-mtracking`), a program built with `e-acsl-gcc --validate-format-strings` aborts at its first call to a format function, even with a literal format string. The memory tracking analysis does not monitor the blocks that the runtime's format checks look up: the format string, and the strings and pointers passed for `"%s"`, `"%n"` and `"%p"`. The example of the user manual is affected.

The `format/` and `builtin/` test configurations already pass `--full-mtracking` with the comment "Remove --full-mtracking once e-acsl#118 is fixed", so this is probably known as e-acsl#118, but I could not find it on the public tracker and the manual does not mention it.

### Steps to reproduce the issue

`ip.c`:

```c
#include <stdio.h>

int main(void) {
  unsigned a = 192, b = 168, c = 1, d = 200;
  char t[16];
  snprintf(t, sizeof t, "%u.%u.%u.%u", a, b, c, d);
  return puts(t) < 0;
}
```

```sh
e-acsl-gcc -q -c -G gcc --validate-format-strings -o m.c -O m ip.c && ./m.e-acsl
```

### Expected behaviour

The program prints `192.168.1.200` and exits 0, as it does with `-M`.

### Actual behaviour

```text
snprintf: invalid format string (unallocated or unterminated)
```

and the program aborts (exit 134). Every format call does the same without `-M`, among them:

| Call | Without `-M` | With `-M` |
|---|---|---|
| `printf("lit %d\n", 1)` | abort, `invalid format string` | runs |
| `printf("%s\n", b)`, `char b[8] = "hey"` | abort, `invalid format string` | runs |
| `show(b)` with `void show(const char *p) { printf("[%s]\n", p); }` | abort, `invalid format string` | runs |
| `printf("is %d really an int?", "foo")` (the user manual's `printf.c`) | abort, `invalid format string` | abort, `directive 1 ('%d') expects argument of type 'int' but the corresponding argument has type 'char*'` (the output shown in the manual) |

### Contextual information

- Frama-C installation mode: from source (`master`) and opam (Docker image based on `framac/frama-c:dev`)
- Frama-C version: 35.0~~dev (Bromine), `master` at 95408044f7; also 34.0~beta (Selenium), same output
- Plug-in used: E-ACSL (`e-acsl-gcc --validate-format-strings`)
- OS name: Debian GNU/Linux
- OS version: 13 (trixie), gcc 14.2.0, x86_64

### Additional information (optional)

**Cause.** `validate_format` (`share/e-acsl/libc_replacements/e_acsl_stdio.c`) first checks
`valid_string(fmt)`, and its `"%s"`, `"%p"` and `"%n"` checks need the argument's block in the
shadow memory too. Without `-e-acsl-full-mtracking`, the blocks recorded are those the dataflow
analysis of `src/analyses/memory_tracking.ml` selects. For a call to a function without a body,
`do_call` only handles `Functions.Libc.has_replacement` names (it forces string literal arguments
to be monitored). The format functions that `injector.ml` replaces under
`Options.Validate_format_strings` have no such case, so neither the literal format string nor a
local array passed for `"%s"` is monitored.

**Fix.** In `do_call`, when `Options.Validate_format_strings.get ()` holds and the callee is a format
function (`Functions.Libc.is_printf_name`), monitor the base variable of every pointer or array
argument, string literals included, as is done for the actuals of a function whose formals are
monitored. A merge request follows. With it, the cases above give the `-M` results, and
unterminated arrays passed directly, through a pointer or through a formal are still reported.
Another option would be to make `--validate-format-strings` imply `-e-acsl-full-mtracking`, as
`-e-acsl-concurrency` does; tell me if you prefer that.

The same comment in `tests/builtin/test_config_dev` suggests that `--libc-replacements` has a
similar gap for non-literal arguments. I have not looked at that part.

The analysis and fix were prepared with LLM assistance (Claude Code); I reviewed them and ran the
reproducer and tests described above.
