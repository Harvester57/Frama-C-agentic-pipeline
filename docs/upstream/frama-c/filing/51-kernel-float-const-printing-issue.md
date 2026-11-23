# [Kernel] Pretty-printer truncates synthesized `double` constants to 12 digits and prints non-finite floats as undeclared `inf`/`nan`

<!-- Everything below this line is the issue description. -->

### Summary

When `Cil_printer.constant` prints a synthesized `CReal(f, fsize, None)` constant (one without
retained source text, produced by `-constfold`, `-scf`, or E-ACSL translation), it delegates
directly to `Floating_point.pretty`. That formatter prints with `"%.*g" 12` in default mode and
emits non-C tokens (`inf`, `-inf`, `nan`, `-nan`, `NaN`) for non-finite values in every
`-float-print` mode (including `-float-print hex`).

This causes two user-visible failures whenever pretty-printed C code is compiled or re-parsed,
including under `e-acsl-gcc` (which passes `-constfold` by default since commit `d88e9bec7b`):

1. **Silent value corruption (12-digit truncation):** `double` constants lose up to five
   significant decimal digits, so the printed/instrumented program computes different values than
   the original C program and true E-ACSL assertions abort at run time even with `--no-constfold`.
2. **Uncompilable C for non-finite constants:** folded infinities and NaNs (`1.0 / 0.0`,
   `-1.0 / 0.0`, `0.0 / 0.0`, `1e38f * 10`, `INFINITY`, `NAN`) are emitted as undeclared
   identifiers (`inf`, `-inf`, `-nan`, `inff`, `-nanf`, `inff32`, or `NaN`/`NaNf` under
   `-float-print hex`), causing compilation and Frama-C re-parsing to fail.

### Steps to reproduce the issue

#### 1. Truncated `double` constants under `-constfold` and default `e-acsl-gcc`

`fold.c`:

```c
#include <stdio.h>
static const double third = 1.0 / 3.0;
double scale(unsigned char c) { return c * (1.0 / 255.0); }
int main(void) {
  double t = 1.0 / 3.0;
  double h = 2 * 3.141592653589793;
  double g = 0.1f;
  double nz = -0.0;
  printf("%a %a %a %a %a %a\n", third, scale(255), t, h, g, nz);
  return 0;
}
```

```sh
gcc fold.c -o fold_gcc && ./fold_gcc
frama-c -machdep gcc_x86_64 -no-frama-c-stdlib -constfold fold.c -print -ocode fold_out.c
gcc fold_out.c -o fold_out && ./fold_out
e-acsl-gcc -c fold.c -o fold.gen.c -O fold_e && ./fold_e.e-acsl
```

#### 2. True E-ACSL assertions failing even with `--no-constfold`

`annot.c`:

```c
int main(void) {
  float f = 0.1f;
  double d = 0x1p-68;
  double d2 = 123456789012345.0;
  /*@ assert a1: f == 0.1f; */
  /*@ assert a2: d == 0x1p-68; */
  /*@ assert a3: d2 == 123456789012345; */
  return 0;
}
```

```sh
e-acsl-gcc --no-constfold --keep-going -c annot.c -o annot.gen.c -O annot_e && ./annot_e.e-acsl
```

#### 3. Non-finite constants printed as undeclared `inf`/`nan` (both default and `-float-print hex`)

`inf.c`:

```c
#include <stdio.h>
int main(void) {
  double a = 1.0 / 0.0;
  double b = -1.0 / 0.0;
  double c = 0.0 / 0.0;
  float d = 1e38f * 10;
  float e = 0.0f / 0.0f;
  printf("%a %a %d %a %d\n", a, b, c != c, (double)d, e != e);
  return 0;
}
```

```sh
gcc inf.c -o inf_gcc && ./inf_gcc
frama-c -constfold -print inf.c
frama-c -constfold -float-print hex -print inf.c
e-acsl-gcc -c inf.c -o inf.gen.c -O inf_e
e-acsl-gcc -c -F "-float-print hex" inf.c -o inf_h.gen.c -O inf_h
```

Host headers are used with `e-acsl-gcc` / `-no-frama-c-stdlib` on Debian 13 (trixie; glibc 2.41,
gcc 14.2.0).

### Expected behaviour

1. `fold_out` and `fold_e.e-acsl` print the exact same IEEE 754 `double` values as `fold_gcc`:
   `0x1.5555555555555p-2 0x1p+0 0x1.5555555555555p-2 0x1.921fb54442d18p+2 0x1.99999ap-4 -0x0p+0`
   (in particular `scale(255)` equals `1.0`).
2. `annot_e.e-acsl` passes all three true assertions and exits 0 with no failure output.
3. `frama-c -constfold -print inf.c` (with or without `-float-print hex`) emits valid C
   expressions for non-finite constants (such as `(1.0 / 0.0)`, `(-1.0 / 0.0)`, `(0.0 / 0.0)`,
   `(1.0f / 0.0f)`, `(0.0f / 0.0f)`) that compile cleanly under `gcc`/`clang`, re-parse in
   Frama-C, and print `inf -inf 1 inf 1` under `e-acsl-gcc -c`.

### Actual behaviour

#### 1. `fold.c`

Original `gcc` output:

```text
0x1.5555555555555p-2 0x1p+0 0x1.5555555555555p-2 0x1.921fb54442d18p+2 0x1.99999ap-4 -0x0p+0
```

`frama-c -constfold -print fold.c` emits 12-digit constants:

```c
static double const third = 0.333333333333;
  double t = 0.333333333333;
  double h = 6.28318530718;
  double g = 0.10000000149;
  double nz = -0.;
```

Both `fold_out` and `fold_e.e-acsl` print corrupted `double` values (`scale(255)` is no longer 1):

```text
0x1.5555555553de1p-2 0x1.ffffffffff735p-1 0x1.5555555553de1p-2 0x1.921fb54442eeap+2 0x1.999999fffdf51p-4 -0x0p+0
```

`-scf -then-last -print` exhibits the same 12-digit truncation.

#### 2. `annot.c`

`e-acsl-gcc --no-constfold --keep-going -c annot.c` generates comparisons against 12-digit `double`
constants:

```c
__e_acsl_assert((double)f == 0.10000000149,& __gen_e_acsl_assert_data);
__e_acsl_assert(d == 3.38813178902e-21,& __gen_e_acsl_assert_data_2);
__e_acsl_assert(d2 == 1.23456789012e+14,& __gen_e_acsl_assert_data_3);
```

Running `./annot_e.e-acsl` fails all three true assertions (and aborts with exit 134 without
`--keep-going`):

```text
annot.c: In function 'main'
annot.c:5: Error: Assertion failed:
	The failing predicate is:
	a1:
		f ≡ 0.1f.
	With values at failure point:
	- f: 1.000000e-01
annot.c: In function 'main'
annot.c:6: Error: Assertion failed:
	The failing predicate is:
	a2:
		d ≡ 0x1p-68.
	With values at failure point:
	- d: 3.388132e-21
annot.c: In function 'main'
annot.c:7: Error: Assertion failed:
	The failing predicate is:
	a3:
		d2 ≡ 123456789012345.
	With values at failure point:
	- d2: 1.234568e+14
```

#### 3. `inf.c`

Original `gcc` prints `inf -inf 1 inf 1`.

`frama-c -constfold -print inf.c` emits:

```c
  double a = inf;
  double b = -inf;
  double c = -nan;
  float d = inff;
  float e = -nanf;
```

`frama-c -constfold -float-print hex -print inf.c` emits:

```c
  double a = inf;
  double b = -inf;
  double c = NaN;
  float d = inff;
  float e = NaNf;
```

`e-acsl-gcc -c inf.c` (with or without `-F "-float-print hex"`) fails to compile (exit 1):

```text
inf.gen.c:210:14: error: 'inf' undeclared (first use in this function); did you mean 'int'?
inf.gen.c:212:15: error: 'nan' undeclared (first use in this function)
inf.gen.c:213:13: error: 'inff' undeclared (first use in this function)
inf.gen.c:214:14: error: 'nanf' undeclared (first use in this function)
e-acsl-gcc: fatal error: fail to compile/link instrumented code
```

The same happens for `<math.h>` `INFINITY`/`NAN` under `-constfold`, and for `_Float32` (`inff32`)
and `_Float64` (`inff64`).

### Contextual information

- Frama-C installation mode: from source (`master`) and opam (Docker image based on `framac/frama-c:dev`)
- Frama-C version: 35.0~~dev (Bromine), `master` at 189053d4a2; also 34.0~beta (Selenium), identical output
- Plug-in used: kernel (`Cil_printer`, `-constfold`, `-float-print`), also surfaced via E-ACSL (`e-acsl-gcc`) and `-scf`
- OS name: Debian GNU/Linux
- OS version: 13 (trixie; glibc 2.41, gcc 14.2.0, clang 19.1.7)

### Additional information (optional)

**Cause.** In `src/kernel/services/ast_printing/cil_printer.ml` (lines 640-648), `CReal(f, fsize, None)`
delegates directly to `Floating_point.pretty` (`src/lib/floating_point/floating_point.ml`, lines
123-135), which is designed for human-readable analysis output (Eva intervals, WP display):

- In `Default` mode, `Floating_point.pretty` formats with `Format.sprintf "%.*g" 12 f`. IEEE 754
  binary64 (`double`) requires up to 17 significant decimal digits to round-trip every finite value
  (as `src/kernel/services/ast_queries/logic_utils.ml:264-267` already accounts for with `%.8ef`
  and `%.16ed`).
- `Cil.constFoldBinOp` (`src/kernel/services/ast_queries/cil.ml:3960-3969`) intentionally folds
  floating-point operations to infinity or NaN, and neither `Default` nor `NormHex`
  (`pretty_normal ~use_hex:true`) formats non-finite values as C expressions.
- E-ACSL (`plugins/e-acsl/src/code_generator/translate_terms.ml:104-105, 128-130`) synthesizes
  `CReal(_, FDouble, None)` constants via `Cil.kfloat` for exact real and float-typed integer
  constants in annotations, triggering the 12-digit truncation even with `--no-constfold`.

**Fix.** Keep `Floating_point.pretty` unchanged for Eva/WP display, and handle `CReal(f, fsize, None)`
in `Cil_printer` with a dedicated C printer:

1. For non-finite values in all `-float-print` modes, emit parenthesized C constant expressions
   `(1.0<suf> / 0.0<suf>)`, `(-1.0<suf> / 0.0<suf>)`, or `(0.0<suf> / 0.0<suf>)` matching `fsize`
   (`"f"`, `"f32"`, `"f64"`, `""`, `"L"`). Both GCC and Clang accept these in static initializers
   and expressions with zero warnings under `-std=c99` and `-std=c11`, and Frama-C re-parses them
   cleanly.
2. For finite values in `Default` mode, keep the 12-digit output whenever it already round-trips
   bit-identically under `Nearest_even` rounding (preserving existing formatting and test oracles
   for short decimals such as `0.1` and `-0.`), and otherwise increase precision up to 17
   significant digits (minimum precision that round-trips bit-identically).

A merge request with this fix and regression test `tests/pretty_printing/float_const.c` is ready.

**Workaround.** For finite constants only, `-float-print hex` (e.g. `e-acsl-gcc -F "-float-print hex"`)
round-trips bit-identically, but does not avoid the `inf`/`NaN` compile error. For `-constfold`
only, `e-acsl-gcc --no-constfold` avoids folding C expressions, but does not avoid the 12-digit
truncation on E-ACSL annotation constants (`annot.c`).

**Related notes.** Closed issues #1304 and #2084 tracked earlier cases where printed programs
computed differently from the original under `-scf`. Separately, `doc/userman/user-start.tex`
(lines 434-437) still documents removed options `-float-hex` and `-float-normal` instead of
`-float-print`.

The analysis and fix were prepared with LLM assistance; I reviewed them and ran the reproducer and
tests described above.
