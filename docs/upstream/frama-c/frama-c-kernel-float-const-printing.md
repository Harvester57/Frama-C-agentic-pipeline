# Kernel (`Cil_printer`): Synthesized `CReal` Constants Truncated to 12 Digits and Non-Finite Floats Printed as Undeclared `inf`/`nan`

- **Parent index:** [`./README.md`](./README.md)
- **Filing issue:** [`./filing/51-kernel-float-const-printing-issue.md`](./filing/51-kernel-float-const-printing-issue.md)
- **Filing MR:** [`./filing/51-kernel-float-const-printing-mr.md`](./filing/51-kernel-float-const-printing-mr.md)
- **Standalone reproducer:** [`./repro/51-kernel-float-const-printing.sh`](./repro/51-kernel-float-const-printing.sh) + [`./repro/51-kernel-float-const-printing.c`](./repro/51-kernel-float-const-printing.c)
- **Patch:** [`./patches/51-kernel-float-const-printing.patch`](./patches/51-kernel-float-const-printing.patch)
- **Hunt origin:** Candidates `H10` + `N4` in [`./frama-c-hunt-2026-11-18-candidates.md`](./frama-c-hunt-2026-11-18-candidates.md)

## 1. Summary

In `src/kernel/services/ast_printing/cil_printer.ml:640-648`, printing a synthesized floating-point
constant `CReal(f, fsize, None)` (one without original source text) delegates directly to
`Floating_point.pretty` (`src/lib/floating_point/floating_point.ml:123-135`), a display formatter
intended for Eva intervals and WP output.

This produces two coupled bugs whenever Frama-C emits C code that is compiled or re-parsed
(including `-constfold`, `-scf`, and default `e-acsl-gcc`, which enables `-constfold` since commit
`d88e9bec7b`):

1. **12-digit truncation (`H10`):** In `Default` mode, `Floating_point.pretty` formats with
   `Format.sprintf "%.*g" 12 f`. IEEE 754 binary64 (`double`) requires up to 17 significant decimal
   digits for exact round-trip. Folded `double` constants (`1.0 / 3.0`, `1.0 / 255.0`,
   `2 * 3.141592653589793`, `(double)0.1f`) silently change value in the emitted C program, and
   E-ACSL annotation translations (`plugins/e-acsl/src/code_generator/translate_terms.ml:104-105,128-130`)
   fail true assertions (`f == 0.1f`, `d == 0x1p-68`, `d2 == 123456789012345`) even under
   `--no-constfold`.
2. **Non-finite identifiers (`N4`):** `Cil.constFoldBinOp` (`src/kernel/services/ast_queries/cil.ml:3960-3969`)
   folds `1.0 / 0.0`, `-1.0 / 0.0`, `0.0 / 0.0`, `1e38f * 10`, `0.0f / 0.0f`, `<math.h>` `INFINITY`/`NAN`,
   and `_Float32`/`_Float64` equivalents into non-finite `CReal(_, _, None)`. `Floating_point.pretty`
   prints them as `inf`, `-inf`, `-nan`, `inff`, `-nanf`, `inff32`, or (under `-float-print hex`)
   `inf`, `-inf`, `NaN`, `inff`, `NaNf`, causing GCC, Clang, and Frama-C re-parsing to fail with
   undeclared identifier errors.

Combining `H10` and `N4` into one package is natural because both stem from the exact same 9-line
match arm (`cil_printer.ml:640-648`) and share `-float-print hex` as a partial workaround (fixes
`H10` while still failing on `N4`). Candidate `H15` (E-ACSL `1e40f` -> `inf` / `mpq_set_d(INFINITY)`
`SIGFPE`) is tracked separately in package `53`.

## 2. Diagnosis (`master` `189053d4a2`)

- `src/kernel/services/ast_printing/cil_printer.ml:640-648`: `CReal(f, fsize, None)` calls
  `Floating_point.pretty f` followed by the `fsize` suffix (`f`, `f32`, `f64`, `""`, `L`).
- `src/lib/floating_point/floating_point.ml:123-135`: `Default` uses `Format.sprintf "%.*g" 12 f`;
  `NormHex` (`pretty_normal ~use_hex:true`, line 98) prints `inf`, `-inf`, `NaN` for `exp = 2047`.
- `src/kernel/services/ast_queries/logic_utils.ml:264-267` already uses `%.8ef` (9 significant
  digits) and `%.16ed` (17 significant digits) when converting `CReal` to `LReal`.
- `doc/userman/user-start.tex:434-437` still documents removed `-float-hex` and `-float-normal`
  (both rejected as unknown options on `34.0~beta` and `master`).

## 3. Duplicate Check

Live read-only `glab api` search against `pub/frama-c` (project 780, issues and MRs, all states,
2026-11-22) for `float-print`, `constfold`, `Floating_point.pretty`, `12 digits`,
`significant digits`, `inf undeclared`, `print nan`, `CReal`, plus
[`./pub-frama-c_work_items_2026-11-09.csv`](./pub-frama-c_work_items_2026-11-09.csv) and packages
`01`-`50` in [`./README.md`](./README.md): **0 duplicates** (related closed `#1304` and `#2084`
on `-scf`; overview `#2832`).

## 4. Fix & Validation

In `src/kernel/services/ast_printing/cil_printer.ml`, add `pretty_c_real`:

- For `Floating_point.is_infinite f`: emit `(%s1.0%s / 0.0%s)` (with `"-"` if `f < 0.`) matching
  `fsize` in all `-float-print` modes.
- For `Floating_point.is_nan f`: emit `(0.0%s / 0.0%s)` matching `fsize` in all `-float-print`
  modes.
- For finite `f` under `Floating_point.Default`: temporarily set `Nearest_even` rounding mode (via
  `Fun.protect`), check whether `Format.sprintf "%.*g" 12 f` already round-trips bit-identically
  (preserving existing oracle output for short decimals like `0.1` and `-0.`), and otherwise
  increase precision from `13` up to `17` until `Int64.bits_of_float (round (float_of_string s))`
  matches `Int64.bits_of_float (round f)`.
- Leave `Floating_point.pretty` unchanged for Eva/WP display.

Verified GCC 14.2.0 and Clang 19.1.7 (`-std=c99` and `-std=c11`, `-Wall -Wextra`) on static and
local initializers for `double`, `float`, `long double` (zero warnings) and GCC on `_Float32` and
`_Float64` (Clang 19 does not implement `_Float32`/`_Float64`).

### Validation Log

- **Before (`master` `189053d4a2` and `34.0~beta`, stock images):** Reproducer `51` fails 11 of 11
  cases identically on both versions (`constfold_double_gcc`, `constfold_double_clang`,
  `eacsl_constfold`, `eacsl_annot`, `scf_double`, `nonfinite_gcc`, `nonfinite_clang`,
  `nonfinite_reparse`, `nonfinite_hex_gcc`, `nonfinite_eacsl`, `ext_f32_f64_gcc`).
- **After (`master` `189053d4a2` + patch `51`, commit `f2f4875b1a`):**
  - Reproducer `51`: `RESULT: fixed` (11/11 cases pass: `constfold_double_gcc`,
    `constfold_double_clang`, `eacsl_constfold`, `eacsl_annot`, `scf_double`, `nonfinite_gcc`,
    `nonfinite_clang`, `nonfinite_reparse`, `nonfinite_hex_gcc`, `nonfinite_eacsl`,
    `ext_f32_f64_gcc`).
  - Regression test `tests/pretty_printing/float_const.c` fails on unpatched `master` (`Cannot
    resolve variable inf`, exit 1, and truncated 12-digit constants) and passes patched in both
    configurations (`-constfold` and `-constfold -float-print hex`).
  - Default test suites: `tests/pretty_printing`, `plugins/constant_propagation/tests`,
    `tests/syntax`, `plugins/e-acsl`, and `plugins/eva/tests/float` all pass with 0 existing
    oracle diffs.
  - `./dev/check-files.sh -p HEAD~1`: passes (`Lint 4 file(s)`), 0 file-mode changes.
- **Pipeline / `opam/` recommendation:** Recommended for the local `opam/` patch queue (directly
  impacts default `e-acsl-gcc` and E-ACSL assertion translation on floating-point code; currently
  worked around in part by `--no-constfold`, which does not cover E-ACSL annotation constants).
