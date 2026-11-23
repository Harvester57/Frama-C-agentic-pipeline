# [eva] numerors: parse hex/suffixed float literals and handle non-finite constants

- Source branch: `fix/eva-numerors-float-literal-parsing` on the fork of `pub/frama-c`; target branch `master`.
- Based on: `189053d4a2`. Patch: [`../patches/55-eva-numerors-float-literal-parsing.patch`](../patches/55-eva-numerors-float-literal-parsing.patch)

<!-- Everything below this line is the merge request description. -->

Before submitting the merge request, please confirm (by adding a X in the [ ]):

- [ ] you contributed to Frama-C as prescribed in the [instructions](https://git.frama-c.com/pub/frama-c/-/blob/master/CONTRIBUTING.md).
- [ ] if the size of the PR requires it, you have signed the
  [Contributor Licensing Agreement](https://git.frama-c.com/pub/frama-c/-/blob/master/CLA.md)

Closes #<issue>.

## Problem

`Rational.of_string` (`src/lib/arithmetic/rational.ml`) split strings only on `'e'` and `'.'` (with
powers of 10) and stripped only `f`/`l`/`f32`/`f64` suffixes. `IEEE754.Make.constant`
(`plugins/eva/src/values/non_integer_arithmetic/IEEE754.ml`) also passed non-finite `CReal` source
text directly to `Scalar.of_string`. Under `-eva -eva-domains numerors`:

- Hexadecimal floating-point literals without hex digit `'e'` were silently misparsed: `0x1.8p1`
  evaluated to `0.048` instead of `3.0`, and `<float.h>` `DBL_MAX` (`0x1.fffffffffffffp+1023`)
  evaluated to `8.096e+304`, causing Eva to drop a sure out-of-bounds alarm on `if (x < DBL_MAX)`.
- Hexadecimal floating-point literals containing `'e'` (`0x1.ep0`, `<float.h>` `FLT_MAX`) crashed
  with `Failure("int_of_string")`.
- GCC `d`-suffixed literals (`1.5d`) and `<math.h>` `INFINITY`, `NAN`, and `HUGE_VAL` crashed with
  `Invalid_argument("Z.of_substring_base: invalid digit")`.

## Change

- `src/lib/arithmetic/rational.ml`: replace the manual decimal-only splitter with
  `remove_float_suffix` followed by Zarith `Q.of_string` (which parses decimal, scientific,
  hexadecimal floating-point `0x...p...`, and `a/b` rational strings natively). `remove_float_suffix`
  handles `f`, `d`, `l`, `f32`, `f64` (case-insensitively) while guarding against stripping hex
  digits (`f`, `d`) from hexadecimal integer literals without a `p` exponent or non-numeric words.
- `plugins/eva/src/values/non_integer_arithmetic/IEEE754.ml` (`Make.constant`): add
  `| CReal (f, _, _) when not (Float.is_finite f) -> Top` so non-finite constants (`INFINITY`,
  `NAN`, `HUGE_VAL`, and folded non-finite values) yield `Top` in `numerors` while Eva's standard
  non-finite alarms continue to fire.
- New test `plugins/eva/tests/numerors/float_literals.c` (plus oracle
  `oracle/float_literals.0.res.oracle`) exercising `0x1.8p1` vs `3.0`, `0x1.ep0`, `1.5d`, `FLT_MAX`,
  `DBL_MAX`, preservation of the sure out-of-bounds alarm on `x < DBL_MAX`, and `INFINITY`, `NAN`,
  and `HUGE_VAL`.

No existing oracle changes.

## Testing

All on Debian 13 (OCaml 5.5, gcc 14.2.0), upstream `master` at `189053d4a2`:

- **Reproducer (6 cases: `DBL_MAX` sure alarm, `0x1.8p1` interval, `0x1.ep0`, `FLT_MAX`, `1.5d`,
  `INFINITY`):**
  - Before (on `master` `189053d4a2` and `34.0~beta`): 6 of 6 cases fail (sure alarm dropped,
    `0x1.8p1` gives `[0.048 .. 0.096]`, and 4 crashes with exit 125).
  - After (installed patched `master`): 6 of 6 cases pass (sure alarm restored, `0x1.8p1` gives
    `[3. .. 6.]`, all 4 crash cases exit 0 with exact values / expected `is_nan_or_infinite`
    alarm).
- **New test on unpatched `master`:** `plugins/eva/tests/numerors/float_literals.c` fails with exit
  125 (`Failure("int_of_string")`). With the patch, it passes.
- **ptests, default configuration:** `./dev/test.sh -p plugins/eva/tests/numerors` passes with zero
  diffs on any existing oracle.
- **`./dev/check-files.sh -p HEAD~1`:** passes (`Lint 4 file(s)`).
- **Not run:** 32-bit targets, and `make default-tests` outside `plugins/eva/tests/numerors`.

The analysis and fix were prepared with LLM assistance; I reviewed them and ran the reproducer and
tests described above.
