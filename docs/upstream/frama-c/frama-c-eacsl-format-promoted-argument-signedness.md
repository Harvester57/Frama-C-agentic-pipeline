# E-ACSL `--validate-format-strings`: `"%u"` / `"%x"` with a promoted `unsigned char` or `unsigned short` aborts on correct code

Draft for the Frama-C tracker (https://git.frama-c.com/pub/frama-c/-/issues). **Not filed.** Number 30
in this folder's [index](./README.md). It was first written together with Issue 31
([`./frama-c-eacsl-format-fp-argument-slots.md`](./frama-c-eacsl-format-fp-argument-slots.md)), a
second defect in the same runtime function (`validate_format`,
`share/e-acsl/libc_replacements/e_acsl_stdio.c`); the two have independent fixes and are filed
separately. This one stops real programs on every run.

## Summary

With `--validate-format-strings` (`-e-acsl-validate-format-strings`), the runtime compares each
directive's type with the argument's static type exactly. An `unsigned char` or `unsigned short`
argument is promoted to `int`, so formatting a byte with `"%u"` or `"%x"`, which is how most C code
prints an IPv4 address or a hex dump, aborts on every run:

```text
snprintf: directive 1 ('%u') expects argument of type 'unsigned int' but the corresponding argument has type 'int'
Aborted
```

gcc 14 and clang 19 accept the call even with `-Wformat=2 -Wformat-signedness`, and glibc prints the
right value. The same rule rejects `"%d"` with a small `unsigned int` and `"%u"` with a
non-negative `int` (`-Wformat-signedness` warns on these two, `-Wall -Wextra -Wformat=2` does not).

We hit it in c-ares 1.34.5 (`inet_ntop4`, `src/lib/inet_ntop.c`):

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
| `34.0~beta (Selenium)`, opam build, images `framac-analysis:latest` and `framac-analysis:fc34` (2026-11-16) | **aborts** |
| `master` `3dff90fc70` (2026-11-13; still `master`'s head on 2026-11-16), image `framac-master-audit:3dff90f` | **aborts**, same message (`ntop.c` below, run 2026-11-16; without `-M` it also stops at the same "invalid format string" as 34.0~beta) |
| `master` `3dff90fc70` + the static patch, image `framac-master-audit:3dff90f-p30` | prints `192.168.1.200`, exit 0 |

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

```text
$ gcc -Wall -Wextra -Wformat=2 -Wformat-signedness ntop.c -o plain && ./plain
192.168.1.200
$ e-acsl-gcc -c -M -G gcc --validate-format-strings -O m ntop.c && ./m.e-acsl; echo rc=$?
snprintf: directive 1 ('%u') expects argument of type 'unsigned int' but the corresponding argument has type 'int'
Aborted
rc=134
$ e-acsl-gcc -c -M -G gcc -O m2 ntop.c && ./m2.e-acsl
192.168.1.200
```

`-M` (full memory tracking) is there to rule out an unrelated stop: without it, `ntop.c` aborts
earlier with `snprintf: invalid format string (unallocated or unterminated)` on the literal format
string. That one is not analysed; it is listed under "Seen during the audit, not drafted" in the
[index](./README.md).

### More cases (`-G clang`, `-M`, `--libc-replacements --validate-format-strings`, 34.0~beta)

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
(`(int)uc`), and the function maps `IUChar`/`IUShort` to `"d"` anyway (line 119, comment: "promoted
to int"). The runtime then requires the directive's type to equal that letter (`e_acsl_stdio.c`,
`master`):

```c
static void validate_format_type(abbrev_t expected_t, const char *fmtdesc,
                                 format_directive *dir, const char *func) {
  abbrev_t actual_t = fmtdesc[dir->arg.index];
  if (actual_t != expected_t) {
    private_abort("%s: directive %d ('%s') expects argument of type '%s'"
```

`[ouxX]` without a length modifier expect `IUInt` (`infer_integral_abbr`), so a promoted byte (`IInt`)
never matches. The runtime is inconsistent with itself here: `"%hhu"` and `"%hu"` expect `IInt`
(line 653, "short/char: promoted to int"), so the same promoted byte passes `"%hhu"` and fails
`"%u"`. Likewise `"%d"` accepts a promoted `unsigned short` because promotion keeps its value, and
that same fact is what makes `"%u"` safe for it.

## What the standard says

C11 7.21.6.1p8 says `"%u"` converts "the `unsigned int` argument" and p9 says "If any argument is not
the correct type for the corresponding conversion specification, the behavior is undefined." Read
literally, an `int` is not the correct type for `"%u"`, and the upstream test
`plugins/e-acsl/tests/format/printf.c` follows that reading (`ABRT(printf("%d\n", ui))` with
`unsigned ui = 516`, lines 367-368, under "Undef 19").

The other reading, which implementations follow: trailing arguments of a variadic call only get the
default argument promotions (6.5.2.2p7), and 7.16.1.1p2 lets `va_arg` read an argument whose type is
the corresponding signed or unsigned integer type "when the value is representable in both types",
which is how a libc's `printf` reads them. 6.5.2.2p6 gives calls without a prototype the same
exception, and the footnote to 6.2.5p9 says the shared representation is "meant to imply
interchangeability as arguments to functions". 7.21.6.1 does not refer to either, and the footnote is
not normative, so the strict reading is defensible; it is also not what compilers check (`-Wformat`
never warns on it, `-Wformat-signedness` exists as an opt-in and does not warn on a promoted
`unsigned char` either), nor what glibc does.

Whatever the reading for `"%d"` with an `unsigned`, the promoted `unsigned char` case is the one that
matters in practice: the program never passes an `int` of its own, the value is in `0..255`, and the
only spelling the runtime accepts is `"%hhu"` or an explicit cast.

## Proposed fixes

**Static (keeps the strict reading of the upstream test; the patch proposed upstream).**
`get_printf_argument_str` looks through a cast to `int` whose operand has an unsigned type smaller
than `int`, and describes the argument by that type: `C` for `unsigned char` (also `_Bool`, and plain
`char` where `Machine.char_is_unsigned ()`), `H` for `unsigned short`. Both letters were already in
the runtime's `abbreviated_types` table but never generated. The runtime (`compatible_abbr`, called
by `validate_format_type`) accepts `C` and `H` wherever it expects `int` or `unsigned int`
(`[di]`, `[ouxX]`, `%c`, `%hh*`, `%h*`, `%lc`), and names them by their own type in the other
messages. Signed small types (`signed char`, `short`, signed `char`) keep `d`: every value is
representable in `int`, but a negative one is not in `unsigned int`, so `"%u"` still rejects them,
as it does today. This is also the rule of gcc's `-Wformat-signedness` (checked with gcc 14.2:
it warns on `"%u"` with a `signed char`, an `int`, and `"%d"` with an `unsigned int`, not on an
`unsigned char` or `unsigned short`; clang 19 does not warn on the `signed char`).

Design notes:

- `_Bool` reuses `C` instead of a new letter: a new entry at the top of `e_acsl_stdio.c` shifts the
  line number `e_acsl_stdio.c:549` printed by `private_abort` in 85 lines of the existing
  `format/oracle_dev/printf.0.e-acsl.err.log` (seen with a first version that added `B`). With all
  changes placed after line 549, no existing oracle changes.
- CIL does not distinguish the implicit promotion from a user's `(int)uc`; both are accepted, which
  is sound (the value is still in `0..255`). A user's `(int)i` with an `int` `i` is not a cast from a
  small type and keeps `d`.
- A bit-field `unsigned b : 3` is typed `unsigned int` by the kernel (`(unsigned int)v.b`), so it is
  `D` before and after (`"%u"` accepts it, `"%d"` rejects it). Not changed.
- On a 16-bit machdep, `unsigned short` would promote to `unsigned int`: the cast is not to `int`,
  so the argument would stay `D`. Not exercised: with `-machdep x86_16` (and `ppc_32`, the only
  unsigned-`char` machdep tried), E-ACSL's own `e_acsl.h` does not parse ("Array length is too
  large"), so the `Machine.char_is_unsigned ()` branch is untested too. `macos_arm` instruments and
  gives the same letters as `x86_64` (signed `char`).
- Probes on the `-p30` image (`x86_64`): `printf("%lc\n", uc)` runs (`wint_t` is `unsigned int`, `C`
  accepted); `printf("%lu\n", b)` with a `_Bool` aborts with `... has type 'unsigned char'`.
- If !28 (Issue 13) lands first, `gen_printf_promoted.0.c` needs regenerating: `signal_eval` from
  `utils/signalled.h` has formals, and !28 already changes `gen_printf.0.c` for the same reason
  (`__e_acsl_full_init((void *)(& status));`). Said in the MR text.

The `"%d"`/`unsigned` oracle lines of `tests/format/printf.c` stay as they are, and
`gen_printf.0.c` is byte-identical (the test only passes signed `chr` and `shrt`).

**Value-based (the 7.16.1.1p2 rule; what the pipeline ships as a runtime patch; offered in the
issue as option 2, for the maintainers to choose for the same-rank case).** In
`validate_format`, walk a `va_copy` of the arguments with each one's own promoted type (the letter in
`fmtdesc`) and record whether an integer argument's value is representable in both the signed and the
unsigned type of its rank. Skip the `validate_format_type` comparison when the expected and actual
letters are `d`/`D`, `l`/`L` or `r`/`R` and the value is representable in both. A negative `int` for
`"%u"` and an `unsigned` above `INT_MAX` for `"%d"` keep aborting with today's message. This changes
exactly two lines of the upstream oracle (`printf.c:367-368`, `printf("%i\n", ui)` and
`printf("%d\n", ui)` become OK; checked against `master`: every other integer `ABRT` case of the file
differs in size, not only in signedness) and adds none.

## Validation of the static patch (`master` `3dff90fc70`, 2026-11-16)

Patch [`./patches/30-eacsl-format-promoted-argument-signedness.patch`](./patches/30-eacsl-format-promoted-argument-signedness.patch),
built with dune in `framac-master-audit:3dff90f` and installed; the result is the image
`framac-master-audit:3dff90f-p30`.

- **Reproducer** [`./repro/30-eacsl-format-promoted-argument-signedness.sh`](./repro/30-eacsl-format-promoted-argument-signedness.sh)
  (`ntop.c` plus six cases): before, on `master` and on 34.0~beta (`framac-analysis:fc34`), every
  case aborts except `"%hhu"`; after, `ntop.c` prints `192.168.1.200`, `"%x"`/`unsigned char` and
  `"%u"`/`unsigned short` run, and a negative `signed char`, an `int` for `"%u"` and an `unsigned`
  for `"%d"` still abort with the same message. The script's header holds the full output.
- **New test** `tests/format/printf_promoted.c` (14 sub-tests, 6 expected aborts). On a pristine
  `master` with only the test and its oracles added: the default configuration fails
  (`gen_printf_promoted.0.c` has `"dddd"` where the oracle has `"CCCC"`), the `dev` one stops at
  `TEST 1: FAIL: Unexpected signal at printf_promoted.c:26`. With the patch both pass.
- **ptests:** `@plugins/e-acsl/tests/format/ptests_config` (default, 4 tests) passes, so
  `gen_printf.0.c` is byte-identical. `dev`: `printf.c` (836 s), `fprintf.c` and `printf_promoted.c`
  run one by one and match their oracles. Not run: `dev` of `sprintf.c`, other directories (only
  `format/` uses `--validate-format-strings`).
- **The `format/` `dev` "hang"** (README "How to file", item 7) is the host's crash handler: with
  `ulimit -c 1` (which disables a piped `core_pattern`, here `|/wsl-capture-crash`), `printf.c`
  completes in about 14 minutes when run alone. Run in parallel with a second `printf.c` in another
  container, both exceeded a 30-minute timeout.
- A first version added a letter `B` for `_Bool` at the top of `e_acsl_stdio.c`; it shifted the
  `e_acsl_stdio.c:549` line number printed in 85 lines of `oracle_dev/printf.0.e-acsl.err.log`.
  The final patch reuses `C` for `_Bool` and adds nothing before line 692.
- **Together with patch 31** (31's diff applied on the `-p30` tree, rebuilt): `format/` default
  (5 tests), `dev` of both new tests and of `fprintf.c` pass; `"%f %u %s %Lf %x %s"` with
  `(1.5, uc, s, 2.5L, us, s)` prints `1.500000 200 abc 2.500000 ea60 abc`.
- **Lint:** `./dev/check-files.sh -p HEAD~1` in `framac-lint:3dff90f` as user `opam`: exit 0 (6
  files); also with 30 and 31 together (`-p HEAD~2`, 10 files).
- **`git am`:** applies alone with `--keep-non-patch`; `--3way` 30 then 31 and 31 then 30; after the
  22 existing patches (order 01 03 04 04b 05 08 09 12 10 13 14 16 17 18 19 20 21 22 24 25 26 27),
  alone and with 31 in either order.
- Probes: a user's `(int)uc` is described as `C` (accepted for `"%u"`); `(unsigned char)argc` too; a
  bit-field `unsigned b : 3` stays `D` (`(unsigned int)v.b`), so `"%d"` still rejects it.

## Filing package

- Issue: [`./filing/30-eacsl-format-promoted-argument-signedness-issue.md`](./filing/30-eacsl-format-promoted-argument-signedness-issue.md)
  (framed partly as a question: options 1 static and 2 value-based)
- MR: [`./filing/30-eacsl-format-promoted-argument-signedness-mr.md`](./filing/30-eacsl-format-promoted-argument-signedness-mr.md)
- Patch: [`./patches/30-eacsl-format-promoted-argument-signedness.patch`](./patches/30-eacsl-format-promoted-argument-signedness.patch)
- Repro: [`./repro/30-eacsl-format-promoted-argument-signedness.sh`](./repro/30-eacsl-format-promoted-argument-signedness.sh)
  with `30-eacsl-format-promoted-argument-signedness.c` and `-cases.c`

## Validation so far (34.0~beta, value-based fix)

The pipeline's patched runtime, built through `e-acsl-gcc -C --e-acsl-share <patched copy>` with
`-G clang -M --libc-replacements --validate-format-strings`, on a libFuzzer probe with one call per
input, each case run with the image's runtime and with the patched copy:

| Call | Unpatched | Patched |
|---|---|---|
| `"%u"` / `"%x"` with `unsigned char 200`; `"%u"` with `7`; `"%d"` with `5u`; the `inet_ntop4` call; `"%lu"` with `9L` | abort | runs |
| eight `"%u"` with eight promoted bytes (stack-passed arguments); `"%f %u"` with `(1.5, uc)` | abort | runs |
| `"%f %u"` with `(1.5, -1)` | abort | abort, same message |
| `"%u"` with `-1`; `"%d"` with `3000000000u`; eight `"%u"`, the last `-1` | abort | abort, same message |
| `"%ld"` with an `int` | abort | abort, same message |

Not run for the value-based fix: the upstream ptests (`plugins/e-acsl/tests/format`); the static
patch's ptests are above.

## Workaround

The pipeline patches a copy of the runtime (value-based fix, together with Issue 31's fix):
`_FMT_HUNKS` in `scripts/eacsl_toolchain.py`, test `tests/test_eacsl_format_signedness.py`,
commits `e66a68c` and `99a6871` on branch `sup/c-ares-eacsl-format-promotion` (not merged as of
2026-11-16). Without it, cast the argument (`(unsigned)uc`) or use `"%hhu"`.

## Tracker

Searched on 2026-11-16 with the authenticated API of git.frama-c.com (`pub/frama-c`, issues and merge
requests, all states) for `validate-format`, `format-strings`, `format string`, `signedness` and
`unsigned char printf`. No duplicate.

- The 2026 hits are this folder's own reports (#2802, #2803, #2810 and their merge requests).
- #2604 and #2605 (2022, closed) are segmentation faults of `e-acsl-gcc.sh` from a broken setup, not
  format validation.
