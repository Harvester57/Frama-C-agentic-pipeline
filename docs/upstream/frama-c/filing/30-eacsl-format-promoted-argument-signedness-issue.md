# [E-ACSL] --validate-format-strings: "%u" or "%x" with an unsigned char or unsigned short argument aborts ("expects 'unsigned int' but ... has type 'int'")

<!-- Everything below this line is the issue description. -->

### Summary

With `--validate-format-strings`, an `unsigned char` or `unsigned short` argument for `"%u"`, `"%o"`, `"%x"` or `"%X"` aborts the program: the argument is promoted to `int`, and the runtime requires an `unsigned int`. Printing an IPv4 address or a hex dump byte by byte (`"%u.%u.%u.%u"`) stops every run. gcc and clang accept the call even with `-Wformat=2 -Wformat-signedness`, and glibc prints the right value. This report also asks how strict the check should be for `int` against `unsigned int`.

### Steps to reproduce the issue

`ntop.c`:

```c
#include <stdio.h>

int main(void) {
  const unsigned char a[4] = {192, 168, 1, 200};
  char t[16];
  snprintf(t, sizeof t, "%u.%u.%u.%u", a[0], a[1], a[2], a[3]);
  return puts(t) < 0;
}
```

```sh
gcc -Wall -Wextra -Wformat=2 -Wformat-signedness ntop.c -o plain && ./plain
e-acsl-gcc -q -c -M -G gcc --validate-format-strings -o m.c -O m ntop.c && ./m.e-acsl
```

(`-M` is `--full-mtracking`. Without it, this program stops earlier with
`snprintf: invalid format string (unallocated or unterminated)` on the literal format string; the
`format/` tests also pass `--full-mtracking`, with the comment "Remove --full-mtracking once
e-acsl#118 is fixed".)

### Expected behaviour

The instrumented program prints `192.168.1.200` and exits 0, like the plain build (no warning from
gcc 14).

### Actual behaviour

```text
snprintf: directive 1 ('%u') expects argument of type 'unsigned int' but the corresponding argument has type 'int'
```

and the program aborts (exit 134). More cases, with the same flags:

| Call | `master` |
|---|---|
| `printf("%x\n", uc)`, `unsigned char uc = 200` | abort, `expects 'unsigned int'` ... `'int'` |
| `printf("%u\n", us)`, `unsigned short us = 60000` | abort, same message |
| `printf("%hhu\n", uc)` | prints `200` |
| `printf("%u\n", sc)`, `signed char sc = -1` | abort, same message |
| `printf("%u\n", 7)` | abort, same message |
| `printf("%d\n", 7u)` | abort, `expects 'int'` ... `'unsigned int'` |

### Contextual information

- Frama-C installation mode: from source (`master`) and opam (Docker image based on `framac/frama-c:dev`)
- Frama-C version: 35.0~~dev (Bromine), `master` at 3dff90fc70; also 34.0~beta (Selenium), same output
- Plug-in used: E-ACSL (`e-acsl-gcc --validate-format-strings`)
- OS name: Debian GNU/Linux
- OS version: 13 (trixie), gcc 14.2.0

### Additional information (optional)

**Cause.** `Functions.Libc.get_printf_argument_str` (`plugins/e-acsl/src/libraries/functions.ml`)
describes each variadic argument by one letter of its static type. An `unsigned char` argument reaches
it already cast to `int` by the default argument promotions (`(int)a[0]`), so it gets `d`, and the
runtime (`validate_format_type`, `share/e-acsl/libc_replacements/e_acsl_stdio.c`) compares that
letter for equality with the type the directive expects: `D` (`unsigned int`) for `[ouxX]` without a
length modifier. The runtime is not consistent here: `"%hhu"` and `"%hu"` expect a promoted `int`
(`infer_integral_abbr`, "short/char: promoted to int"), so the same byte passes `"%hhu"` and fails
`"%u"`.

**What the standard says, and a question.** C11 7.21.6.1p9 says that if an argument "is not the
correct type for the corresponding conversion specification, the behavior is undefined", and
`"%u"` takes an `unsigned int`. Read literally, an `int` argument is wrong for `"%u"`, and the
`format/printf.c` test follows that reading (`ABRT(printf("%d\n", ui))` with `unsigned ui = 516`,
"Undef 19"). On the other hand, 7.16.1.1p2 lets `va_arg` read an argument of the corresponding signed
or unsigned type "when the value is representable in both types", which is how a libc reads it, and
the footnote to 6.2.5p9 says the shared representation is "meant to imply interchangeability as
arguments to functions". Compilers do not flag it by default: with `-Wall -Wextra -Wformat=2`,
neither gcc 14 nor clang 19 warns on any case of the table above. With the opt-in
`-Wformat-signedness`, both warn on `"%u"` with an `int` and `"%d"` with an `unsigned int`, gcc also
warns on `"%u"` with a `signed char`, and neither warns on an `unsigned char` or `unsigned short`.
The E-ACSL user manual (section on format string vulnerabilities) shows only a `char *` passed to
`"%d"`, so it does not settle the rule.

- **The promoted unsigned small types** (`unsigned char`, `unsigned short`, `_Bool`) are a false
  positive under either reading: the program never passes an `int` of its own, and every value of
  these types is representable in both `int` and `unsigned int`.
- **`int` against `unsigned int`** (`"%u"` with an `int`, `"%d"` with an `unsigned int`) is your
  call: keep the strict reading of the test, or accept the argument when its value is representable
  in both types.

**Possible fixes.**

1. **Static (merge request follows; keeps the `printf.c` expectations).** In
   `get_printf_argument_str`, look through the promotion cast and describe an argument whose type
   before promotion is `unsigned char`, `unsigned short` or `_Bool` (and `char` where `char` is
   unsigned) by the letter of its own type (`C`, also used for `_Bool`, and `H`; both are defined in
   the runtime but never generated today). The runtime accepts these letters where it
   expects `int` or `unsigned int`, and reports them by their own type elsewhere
   (`expects 'unsigned long' but the corresponding argument has type 'unsigned char'`). Signed types
   smaller than `int` keep `d`: they are accepted wherever an `int` is, and still rejected for `"%u"`,
   since a negative value is not representable in `unsigned int`. `int` and `unsigned int` stay
   distinct. This is the rule gcc's `-Wformat-signedness` applies. No existing oracle changes.
2. **Value-based (the 7.16.1.1p2 rule).** In `validate_format`, read each integer argument with its
   own type and accept `d`/`D`, `l`/`L` and `r`/`R` for each other when the value is representable in
   both. This also covers option 1's cases (a promoted byte is a non-negative `int`), and keeps
   rejecting a negative `int` for `"%u"` and an `unsigned` above `INT_MAX` for `"%d"`. It changes two
   lines of the `printf.c` expectations (`printf("%i\n", ui)` and `printf("%d\n", ui)` become OK). I
   tested a version of it on 34.0~beta, not on `master`.

The two combine: option 1 can be kept with option 2 for the same-rank case if you choose it.

The analysis and fix were prepared with LLM assistance (Claude Code); I reviewed them and ran the
reproducer and tests described above.
