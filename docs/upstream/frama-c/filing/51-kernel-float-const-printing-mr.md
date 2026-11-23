# [kernel] print synthesized CReal constants with exact precision and valid C inf/nan

- Source branch: `fix/kernel-float-const-printing` on the fork of `pub/frama-c`; target branch `master`.
- Based on: `189053d4a2`. Patch: [`../patches/51-kernel-float-const-printing.patch`](../patches/51-kernel-float-const-printing.patch)

<!-- Everything below this line is the merge request description. -->

Before submitting the merge request, please confirm (by adding a X in the [ ]):

- [ ] you contributed to Frama-C as prescribed in the [instructions](https://git.frama-c.com/pub/frama-c/-/blob/master/CONTRIBUTING.md).
- [ ] if the size of the PR requires it, you have signed the
  [Contributor Licensing Agreement](https://git.frama-c.com/pub/frama-c/-/blob/master/CLA.md)

Closes #<issue>.

## Problem

`Cil_printer.constant` (`src/kernel/services/ast_printing/cil_printer.ml`, lines 640-648) delegated
synthesized `CReal(f, fsize, None)` constants directly to `Floating_point.pretty`, which prints
with `"%.*g" 12` in `Default` mode and emits non-C tokens (`inf`, `-inf`, `nan`, `-nan`, `NaN`) for
non-finite values in all `-float-print` modes:

- `double` constants synthesized by `-constfold` (enabled by default in `e-acsl-gcc`), `-scf`, or
  E-ACSL annotation translation lost up to five significant decimal digits, silently changing
  computed values and failing true E-ACSL assertions even under `--no-constfold`.
- Non-finite constants folded by `Cil.constFoldBinOp` (`1.0 / 0.0`, `-1.0 / 0.0`, `0.0 / 0.0`,
  `1e38f * 10.0f`, `INFINITY`, `NAN`, `_Float32`/`_Float64`) were printed as undeclared identifiers
  (`inf`, `-inf`, `-nan`, `inff`, `-nanf`, `inff32`, `NaN`, `NaNf`), failing both C compilation and
  Frama-C re-parsing even under `-float-print hex`.

## Change

`src/kernel/services/ast_printing/cil_printer.ml` (41 lines added, 9 lines replaced by call to
`pretty_c_real`):

- Print non-finite `CReal(f, fsize, None)` values as parenthesized C expressions
  `(1.0<suf> / 0.0<suf>)`, `(-1.0<suf> / 0.0<suf>)`, or `(0.0<suf> / 0.0<suf>)` matching `fsize`
  (`f`, `f32`, `f64`, `""`, `L`) in all `-float-print` modes.
- For finite `CReal(f, fsize, None)` values in `Default` mode, switch to `Nearest_even` rounding
  via `Fun.protect`, keep the 12-digit string whenever it already round-trips bit-identically
  (preserving existing test oracles), and otherwise increase precision up to 17 significant digits.
- Leave `Floating_point.pretty` unchanged for Eva/WP display.

New regression test `tests/pretty_printing/float_const.c` with two configurations (`-constfold`
and `-constfold -float-print hex`) that write `-ocode` and re-parse it, plus its two oracles.

No existing oracle changes.

Interaction with open merge requests:

- **!43 (#2812, `_Alignas` printing in `cil_printer.ml`):** touches lines 1893-2195 (`fieldinfo`
  and `typ`), completely disjoint from this change (`cil_printer.ml:147, 640`).

## Testing

All on Debian 13 (OCaml 5.5, gcc 14.2.0, clang 19.1.7), upstream `master` at `189053d4a2`:

- **Reproducer (11 cases: `-constfold` `double` with gcc and clang, default `e-acsl-gcc`,
  `e-acsl-gcc --no-constfold` assertions, `-scf`, non-finite with gcc/clang/re-parse/`-float-print
  hex`/`e-acsl-gcc`, and `_Float32`/`_Float64` with gcc):**
  - Before (`master` `189053d4a2` and `34.0~beta`): 11 of 11 cases fail.
  - After (installed patched `master`): 11 of 11 cases pass (`RESULT: fixed`).
- **New test on unpatched `master`:** `tests/pretty_printing/float_const.c` fails in both
  configurations (`Cannot resolve variable inf`, exit 1, and truncated 12-digit constants). With
  the patch, both configurations pass and re-parsing is idempotent.
- **ptests, default configuration:** `./dev/test.sh -p tests/pretty_printing`,
  `./dev/test.sh -p plugins/constant_propagation/tests`, `./dev/test.sh -p tests/syntax`,
  `./dev/test.sh -p plugins/e-acsl`, and `./dev/test.sh -p plugins/eva/tests/float` all pass with
  zero diffs on existing oracles.
- **`./dev/check-files.sh -p HEAD~1`:** passes (`Lint 4 file(s)`).
- **Not run:** 32-bit targets and `make default-tests` outside the suites listed above.

The analysis and fix were prepared with LLM assistance; I reviewed them and ran the reproducer and
tests described above.
