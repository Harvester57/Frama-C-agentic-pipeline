# E-ACSL `--validate-format-strings`: `"%u"` with a promoted `unsigned char` aborts, and a `"%s"` after a `"%f"` reads the wrong argument

Draft for the Frama-C tracker (https://git.frama-c.com/pub/frama-c/-/issues). Not filed. No issue
number yet: the next free number in [`./frama-c-e-acsl-issues.md`](./frama-c-e-acsl-issues.md) is given
when it is merged into the catalog. Two defects in the same runtime function (`validate_format`,
`share/e-acsl/libc_replacements/e_acsl_stdio.c`). They could be filed as two issues; part A is the
one that stops real programs on every run.

## Summary

**A. Signedness of promoted arguments.** With `--validate-format-strings`
(`-e-acsl-validate-format-strings`), the runtime compares each directive's type with the argument's
static type exactly. An `unsigned char` or `unsigned short` argument is promoted to `int`, so
formatting a byte with `"%u"` or `"%x"`, which is how most C code prints an IPv4 address or a hex dump,
aborts on every run:

```
snprintf: directive 1 ('%u') expects argument of type 'unsigned int' but the corresponding argument has type 'int'
Aborted
```

gcc 14 and clang 19 accept the call even with `-Wformat=2 -Wformat-signedness`, and glibc prints the
right value. The same rule rejects `"%d"` with a small `unsigned int` and `"%u"` with a
non-negative `int` (`-Wformat-signedness` warns on these two, `-Wall -Wextra -Wformat=2` does not).

**B. Argument collection after a floating-point argument.** `validate_format` reads every variadic
argument with `va_arg(ap, void *)`. On x86_64 a `double` travels in an SSE register and a `long
double` on the stack, so the pointer of a `"%s"`, `"%p"` or `"%n"` after one is taken from the wrong
slot:

```
snprintf: attempt to access unallocated memory via directive 2 ('%s')
Aborted
```

for `snprintf(t, sizeof t, "%f %s", 1.5, s)` with a valid `s`.

We hit A in c-ares (`inet_ntop4`, `src/lib/inet_ntop.c`):

```c
static const char fmt[] = "%u.%u.%u.%u";
...
if ((size_t)snprintf(tmp, sizeof(tmp), fmt, src[0], src[1], src[2], src[3]) >= size) {  /* src: const unsigned char * */
```

Every input that formats an address stopped the fuzzing campaign at that call, so nothing after it was
reached.

## Versions

| | Result |
|---|---|
| `34.0~beta (Selenium)`, opam build, image `framac-analysis:latest` (2026-11-16) | **A and B abort** |
| `master` `3dff90fc70` (2026-11-13), source only | `e_acsl_stdio.c` is byte-identical to the 34.0~beta one; not built |

Debian 13, gcc 14.2.0, clang 19.1.7.

## Reproduction

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

```
$ gcc -Wall -Wextra -Wformat=2 -Wformat-signedness ntop.c -o plain && ./plain
192.168.1.200
$ e-acsl-gcc -c -M -G gcc --validate-format-strings -O m ntop.c && ./m.e-acsl; echo rc=$?
snprintf: directive 1 ('%u') expects argument of type 'unsigned int' but the corresponding argument has type 'int'
Aborted
rc=134
$ e-acsl-gcc -c -M -G gcc -O m2 ntop.c && ./m2.e-acsl
192.168.1.200
```

For B, `dbl.c`:

```c
#include <stdio.h>

int main(void) {
  char t[64];
  const char *s = "abc";
  snprintf(t, sizeof t, "%f %s", 1.5, s);
  return puts(t) < 0;
}
```

```
$ e-acsl-gcc -c -M -G gcc --validate-format-strings -O m dbl.c && ./m.e-acsl; echo rc=$?
snprintf: attempt to access unallocated memory via directive 2 ('%s')
Aborted
rc=134
```

`-M` (full memory tracking) is there to rule out an unrelated stop: without it, `ntop.c` aborts
earlier with `snprintf: invalid format string (unallocated or unterminated)` on the literal format
string. We have not analysed that one.

### More cases (`-G clang`, `-M`, `--libc-replacements --validate-format-strings`)

| Call | Result |
|---|---|
| `snprintf(t, n, "%u", uc)`, `unsigned char uc = 200` | abort, `'unsigned int'` vs `'int'` |
| `snprintf(t, n, "%x", uc)` | abort, `'unsigned int'` vs `'int'` |
| `printf("%u\n", uc)` | abort, `printf: directive 1 ('%u') ...` |
| `snprintf(t, n, "%u", 7)` (an `int`) | abort, `'unsigned int'` vs `'int'` |
| `snprintf(t, n, "%u", -1)` (an `int`) | abort, same message |
| `snprintf(t, n, "%d", (unsigned)200)` | abort, `'int'` vs `'unsigned int'` |
| `snprintf(t, n, "%d", us)`, `unsigned short us = 60000` | runs |
| `snprintf(t, n, "%hhu", uc)` | runs |
| `snprintf(t, n, "%u", (unsigned)uc)` | runs |

## Root cause

The instrumentation passes the runtime a description of the arguments' static types, one letter per
argument (`Functions.Libc.get_printf_argument_str`, `plugins/e-acsl/src/libraries/functions.ml`). An
argument of type `unsigned char` or `unsigned short` reaches it already cast to `int` by the kernel
(`(int)uc`), and the function maps `IUChar`/`IUShort` to `"d"` anyway (comment: "promoted to int").
The runtime then requires the directive's type to equal that letter (`e_acsl_stdio.c`, `master`):

```c
static void validate_format_type(abbrev_t expected_t, const char *fmtdesc,
                                 format_directive *dir, const char *func) {
  abbrev_t actual_t = fmtdesc[dir->arg.index];
  if (actual_t != expected_t) {
    private_abort("%s: directive %d ('%s') expects argument of type '%s'"
```

`[ouxX]` without a length modifier expect `IUInt` (`infer_integral_abbr`), so a promoted byte (`IInt`)
never matches. The runtime is inconsistent with itself here: `"%hhu"` and `"%hu"` expect `IInt`
("short/char: promoted to int"), so the same promoted byte passes `"%hhu"` and fails `"%u"`. Likewise
`"%d"` accepts a promoted `unsigned short` because promotion keeps its value, and that same fact is
what makes `"%u"` safe for it.

For B, `validate_format` collects the arguments before validating them:

```c
  for (int i = 0; i < arglen; i++)
    args[i] = va_arg(ap, void *);
```

`va_arg(ap, void *)` takes the next general-purpose slot. A `double` argument sits in the SSE save
area and a `long double` in the overflow area, so they are skipped, and every pointer after them is
read one slot early. Only `"%s"`, `"%p"` and `"%n"` use `args[]`, which is why only they fail.

## What the standard says

C11 7.21.6.1p8 says `"%u"` converts "the `unsigned int` argument" and p9 says "If any argument is not
the correct type for the corresponding conversion specification, the behavior is undefined." Read
literally, an `int` is not the correct type for `"%u"`, and the upstream test
`plugins/e-acsl/tests/format/printf.c` follows that reading (`ABRT(printf("%d\n", ui))` with
`unsigned ui = 516`, under "Undef 19").

The other reading, which implementations follow: trailing arguments of a variadic call only get the
default argument promotions (6.5.2.2p7), and 7.16.1.1p2 lets `va_arg` read an argument whose type is
the corresponding signed or unsigned integer type "when the value is representable in both types",
which is how a libc's `printf` reads them. 6.5.2.2p6 gives calls without a prototype the same
exception, and the footnote to 6.2.5p9 says the shared representation is "meant to imply
interchangeability as arguments to functions". 7.21.6.1 does not refer to either, and the footnote is
not normative, so the strict reading is defensible;
it is also not what compilers check (`-Wformat` never warns on it, `-Wformat-signedness` exists as an
opt-in and does not warn on a promoted `unsigned char` either), nor what glibc does.

Whatever the reading for `"%d"` with an `unsigned`, the promoted `unsigned char` case is the one that
matters in practice: the program never passes an `int` of its own, the value is in `0..255`, and the
only spelling the runtime accepts is `"%hhu"` or an explicit cast.

## Proposed fix (validated in our pipeline, not on `master`)

**A, value-based (what we ship as a runtime patch; the 7.16.1.1p2 rule).** In `validate_format`, walk a `va_copy` of the
arguments with each one's own promoted type (the letter in `fmtdesc`) and record whether an integer
argument's value is representable in both the signed and the unsigned type of its rank. Skip the
`validate_format_type` comparison when the expected and actual letters are `d`/`D`, `l`/`L` or `r`/`R`
and the value is representable in both. A negative `int` for `"%u"` and an `unsigned` above `INT_MAX`
for `"%d"` keep aborting with today's message. This changes two lines of the upstream oracle
(`printf("%i\n", ui)` and `printf("%d\n", ui)` become OK) and adds none. Our patch, applied by text to
a copy of the share directory (`scripts/eacsl_toolchain.py`, `_FMT_HUNKS`), is about 90 lines.

**A, static alternative (not validated).** Keep the exact comparison, but let
`get_printf_argument_str` look through the promotion cast and emit a distinct letter for an argument
whose type before promotion is `unsigned char`, `unsigned short`, `char`, `signed char`, `short` or
`_Bool`; the runtime then accepts such a letter for both `[di]` and `[ouxX]`, since every value of
these types is representable in both `int` and `unsigned int`. This leaves the `"%d"`/`unsigned`
oracle lines as they are and fixes the c-ares case.

**B.** Collect the arguments with their own types:

```c
  for (int i = 0; i < arglen; i++) {
    if (fmtdesc[i] == 'f' || fmtdesc[i] == 'e') {
      (void)va_arg(ap, double);
      args[i] = NULL;
    } else if (fmtdesc[i] == 'E') {
      (void)va_arg(ap, long double);
      args[i] = NULL;
    } else
      args[i] = va_arg(ap, void *);
  }
```

## Validation

The patched runtime (both fixes), built through `e-acsl-gcc -C --e-acsl-share <patched copy>` with
`-G clang -M --libc-replacements --validate-format-strings`, on a libFuzzer probe with one call per
input (`tests/test_eacsl_format_signedness.py` in our pipeline). The test builds the probe twice, once
with the image's runtime ("Unpatched") and once with the patched copy, and runs every case on both:

| Call | Unpatched | Patched |
|---|---|---|
| `"%u"` / `"%x"` with `unsigned char 200`; `"%u"` with `7`; `"%d"` with `5u`; the `inet_ntop4` call; `"%lu"` with `9L` | abort | runs |
| `"%f %u"` with `(1.5, uc)`; eight `"%u"` with eight promoted bytes (stack-passed arguments) | abort | runs |
| `"%f %s"` with `(1.5, "abc")`; `"%Lf %s %p"` with `(2.5L, "abc", &uc)` | abort (B: `attempt to access unallocated memory via directive 2 ('%s')`, and `unterminated string in directive 2 ('%s')` for the `long double`) | runs |
| `"%u"` with `-1`; `"%f %u"` with `(1.5, -1)`; `"%d"` with `3000000000u`; eight `"%u"`, the last `-1` | abort | abort, same message |
| `"%ld"` with an `int` | abort | abort, same message |

Not run: the upstream ptests (`plugins/e-acsl/tests/format`), which would need the two oracle changes
above.
