# E-ACSL `--validate-format-strings`: a `"%s"`, `"%p"` or `"%n"` after a floating-point argument is checked against the wrong argument

Draft for the Frama-C tracker (https://git.frama-c.com/pub/frama-c/-/issues). **Not filed.** Number 31
in this folder's [index](./README.md). It was first written together with Issue 30
([`./frama-c-eacsl-format-promoted-argument-signedness.md`](./frama-c-eacsl-format-promoted-argument-signedness.md)),
a different defect in the same runtime function (`validate_format`,
`share/e-acsl/libc_replacements/e_acsl_stdio.c`); the two have independent fixes.

## Summary

`validate_format` reads every variadic argument with `va_arg(ap, void *)` before it validates the
directives. On x86_64 a `double` travels in an SSE register and a `long double` in the overflow
area (the stack), so `va_arg(ap, void *)` does not consume them: the `void *` read for the
floating-point argument takes the next general-purpose slot, which belongs to the following
argument. From there on, `args[i]` holds argument `i + 1`, and the pointer checked for a `"%s"`,
`"%p"` or `"%n"` is the one of the next argument, or garbage after the last one:

```text
snprintf: attempt to access unallocated memory via directive 2 ('%s')
Aborted
```

for `snprintf(t, sizeof t, "%f %s", 1.5, s)` with a valid `s`. The message depends on what the
shifted read finds: with `-G gcc`, a `long double` also gives `attempt to access unallocated memory`
(both versions); the first 34.0~beta probe, built with `-G clang`, printed
`unterminated string in directive 2 ('%s')`.

The same shift can hide a real error. Checked on `master` and 34.0~beta with an unterminated
`char u[3]`: `snprintf(t, sizeof t, "%f %s %s", 1.5, u, s)` aborts, but on directive 3
(`attempt to access unallocated memory via directive 3`), so `u` itself is never checked; and
`snprintf(t, sizeof t, "%f %s", 1.5, u, s)` (one argument too many, which C allows) runs with exit 0,
`vsnprintf` reading past `u`.

## Versions

| | Result |
|---|---|
| `34.0~beta (Selenium)`, opam build, images `framac-analysis:latest` and `framac-analysis:fc34` (2026-11-16) | **aborts** |
| `master` `3dff90fc70` (2026-11-13; still `master`'s head on 2026-11-16), image `framac-master-audit:3dff90f` | **aborts**, same message (`dbl.c` below, run 2026-11-16) |
| `master` `3dff90fc70` + the patch, image `framac-master-audit:3dff90f-p31` | prints `1.500000 abc`, exit 0 |

Debian 13, gcc 14.2.0, clang 19.1.7.

## Reproduction

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

```text
$ e-acsl-gcc -c -M -G gcc --validate-format-strings -O m dbl.c && ./m.e-acsl; echo rc=$?
snprintf: attempt to access unallocated memory via directive 2 ('%s')
Aborted
rc=134
```

`-M` (full memory tracking) rules out the unrelated "invalid format string" stop on literal format
strings without it (see Issue 30).

## Root cause

`validate_format` collects the arguments before validating them (`e_acsl_stdio.c`, `master`):

```c
  for (int i = 0; i < arglen; i++)
    args[i] = va_arg(ap, void *);
```

`va_arg(ap, void *)` takes the next general-purpose slot. The instrumentation already tells the
runtime each argument's type: `fmtdesc` holds one letter per argument
(`Functions.Libc.get_printf_argument_str`), `e` for `double` (a `float` is promoted) and `E` for
`long double`. Only `"%s"`, `"%p"` and `"%n"` use `args[]`, which is why only they fail.

## Proposed fix

Collect every argument with its own type, as given by `fmtdesc` (patch
[`./patches/31-eacsl-format-fp-argument-slots.patch`](./patches/31-eacsl-format-fp-argument-slots.patch)):
the pointer letters as `void *` (the only values kept in `args[]`), `e`/`f` as `double`, `E` as
`long double`, `l`/`L` as `long`, `r`/`R` as `long long`, and any other letter as `int` (`int`,
`unsigned int` and the types promoted to `int`, including the `C`/`H` letters Issue 30's patch
starts generating).

The general form, rather than testing only `e`/`E` as the pipeline's runtime patch does, is needed
because E-ACSL documents 32-bit targets: `e-acsl-gcc --mbits 32` (default from `getconf LONG_BIT`)
selects `-machdep gcc_x86_32` and `-m32` (user manual, "e-acsl-gcc" section; the segment model has
"very limited support" for them). There, a `double` or a `long long` takes two stack words and
`va_arg(ap, void *)` reads one, so the same shift happens. Not tested: the images have no 32-bit
libc.

## Validation of the patch (`master` `3dff90fc70`, 2026-11-16)

Patch [`./patches/31-eacsl-format-fp-argument-slots.patch`](./patches/31-eacsl-format-fp-argument-slots.patch),
built with dune in `framac-master-audit:3dff90f` and installed; the result is the image
`framac-master-audit:3dff90f-p31`.

- **Reproducer** [`./repro/31-eacsl-format-fp-argument-slots.sh`](./repro/31-eacsl-format-fp-argument-slots.sh)
  (`dbl.c` plus five cases): before, on `master` and on 34.0~beta (`framac-analysis:fc34`, same
  output), `dbl.c`, `"%Lf %s"` and `"%f%n"` abort on valid arguments, `"%f %s %s"` with an
  unterminated first string aborts on directive 3, and `"%f %s"` with the unterminated string plus a
  spare valid one exits 0; after, the valid calls run and both unterminated cases abort with
  `unterminated string in directive 2 ('%s')`. The script's header holds the full output.
- **New test** `tests/format/printf_fp_args.c` (9 sub-tests, 2 expected aborts): on a pristine
  `master` with only the test and its oracles added, the `dev` configuration stops at
  `TEST 1: FAIL: Unexpected signal at printf_fp_args.c:24`; the default configuration passes there
  too (runtime-only change). With the patch both pass.
- **ptests:** `@plugins/e-acsl/tests/format/ptests_config` (default, 4 tests) passes. `dev`:
  `printf_fp_args.c`, `printf.c` (716 s, with `ulimit -c 1`) and `fprintf.c` one by one: all match
their oracles. (A first `printf.c` run, in parallel with Issue 30's, hit the 30-minute timeout at
line 559 of 575.) Not run: `dev` of
  `sprintf.c`, other directories.
- **Together with patch 30:** see Issue 30's draft (default `format/`, both new tests in `dev`, and
  a mixed `"%f %u %s %Lf %x %s"` call, all pass).
- **Lint:** `./dev/check-files.sh -p HEAD~1` in `framac-lint:3dff90f` as user `opam`: exit 0 (5
  files).
- **`git am`:** applies alone with `--keep-non-patch`; `--3way` with 30 in either order; after the 22
  existing patches, alone and with 30 in either order.
- **32-bit:** not tested (the images have no 32-bit libc).
- **!28 (Issue 13):** if it lands first, `gen_printf_fp_args.0.c` needs regenerating (`signal_eval`
  from `utils/signalled.h` has formals). Said in the MR text.
- **Re-checked from the committed image** `framac-master-audit:3dff90f-p31` with the reproducer's
  header command: same "after" output.
- Seen on the way, not changed: the `"%n"` message prints `argno` ("argument 1 of directive %n" for
  directive 2) where the other messages print `dir->arg.index + 1`. Mentioned in the issue.

## Filing package

- Issue: [`./filing/31-eacsl-format-fp-argument-slots-issue.md`](./filing/31-eacsl-format-fp-argument-slots-issue.md)
- MR: [`./filing/31-eacsl-format-fp-argument-slots-mr.md`](./filing/31-eacsl-format-fp-argument-slots-mr.md)
- Patch: [`./patches/31-eacsl-format-fp-argument-slots.patch`](./patches/31-eacsl-format-fp-argument-slots.patch)
- Repro: [`./repro/31-eacsl-format-fp-argument-slots.sh`](./repro/31-eacsl-format-fp-argument-slots.sh)
  with `31-eacsl-format-fp-argument-slots.c` and `-cases.c`

## Validation so far (34.0~beta, pipeline patch)

The pipeline's patched runtime (with Issue 30's value-based fix), built through
`e-acsl-gcc -C --e-acsl-share <patched copy>` with `-G clang -M --libc-replacements
--validate-format-strings`, on a libFuzzer probe with one call per input:

| Call | Unpatched | Patched |
|---|---|---|
| `"%f %s"` with `(1.5, "abc")`; `"%Lf %s %p"` with `(2.5L, "abc", &uc)` | abort (`attempt to access unallocated memory via directive 2 ('%s')`; `unterminated string in directive 2 ('%s')` for the `long double`) | runs |

(The probe's `"%f %u"` cases abort unpatched because of Issue 30, not this one.)

Not run on 34.0~beta: the upstream ptests (`plugins/e-acsl/tests/format`); see the `master`
validation above.

## Workaround

Same runtime patch as Issue 30 (`_FMT_HUNKS` in `scripts/eacsl_toolchain.py`, branch
`sup/c-ares-eacsl-format-promotion`, not merged as of 2026-11-16).

## Tracker

Searched on 2026-11-16 with the authenticated API of git.frama-c.com (`pub/frama-c`, issues and merge
requests, all states) for `va_arg`, `validate-format`, `format-strings` and `format string`. No
duplicate: the `va_arg` hits are about the kernel, slicing and Eva (#2742, #2748, #2716 and older).
