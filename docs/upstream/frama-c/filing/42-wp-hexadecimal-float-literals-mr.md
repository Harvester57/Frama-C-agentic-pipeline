# [wp] read hexadecimal floating-point literals and the f32/f64 suffixes

- Source branch: `fix/wp-hexadecimal-float-literals` on the fork of `pub/frama-c`; target branch `master`.
- Based on: `b80fcac74f`. Patch: [`../patches/42-wp-hexadecimal-float-literals.patch`](../patches/42-wp-hexadecimal-float-literals.patch)

<!-- Everything below this line is the merge request description. -->

Before submitting the merge request, please confirm (by adding a X in the [ ]):

- [ ] you contributed to Frama-C as prescribed in the [instructions](https://git.frama-c.com/pub/frama-c/-/blob/master/CONTRIBUTING.md).
- [ ] if the size of the PR requires it, you have signed the
  [Contributor Licensing Agreement](https://git.frama-c.com/pub/frama-c/-/blob/master/CLA.md)

Closes #2831.

The first symptom below was reported by Linglong Meng on the `frama-c-discuss` list, with
Frama-C 33.0: https://groupes.renater.fr/sympa/arc/frama-c-discuss/2026-10/msg00002.html

## Problem

`Cfloat.parse_literal` reads decimal digits only, then accepts whatever follows if it ends with
`f`, `l` or `d`. So:

- a hexadecimal literal without suffix (`0x1.8p1`, `DBL_MAX` from Frama-C's `<float.h>`, the bounds
  in the contracts of `exp` and `expf`) is rejected with `Unexpected constant literal`: a
  hypothesis that uses it is lost, and a lemma stops WP;
- with `-wp-model +real`, a suffixed one (`0x1.8p1f`) is read as 0 without any message, and
  `0x1.8p1f == 0.0` is proved by Qed;
- the `f32` and `f64` suffixes are rejected (`1.5f32`).

## Change

`plugins/wp/src/Cfloat.ml`, 24 lines added and 4 removed:

- `parse_literal` removes the suffix with the kernel's `Floating_point.extract_suffix`, and the
  rest must be read entirely. This replaces the `.*[fldFLD]$` check, which is what let `0x1.8p1f`
  through as `0`.
- New `parse_hexadecimal`: the exact rational value of `[+-]?0x<hex>[.<hex>]p<exponent>` (at least
  one hex digit required; the optional leading sign `[-+]?` matches `re_mantissa` and handles
  negative hexadecimal literals emitted by `Logic_const.treal` under `-float-print hex`, e.g. from
  `reduc`).
- The decimal code is unchanged. In the Float model a suffixed literal still denotes the value
  rounded by the kernel, as before; only the test for "has a suffix" changed, so `f32` and `f64`
  are now treated as `f` and `d` are.

New test `plugins/wp/tests/wp_acsl/float_literals.i`, in the default and `qualif` configurations,
each with three runs (Float model, Real model, and `eva` + `reduc` with `-float-print hex`; six
oracles). Every goal is decided by Qed: literals with and without a dot, leading sign, exponent sign
or suffix, `0x1.fffffffffffffp+1023 == 0x1p1024 - 0x1p971`, `0x1.8p1f != 0.0`, non-exact suffixed
literals (`0.1f32` and `0.1F64`, verifying they denote the rounded float values in the Float model
and exact `1/10` in the Real model), a contract with hexadecimal bounds, a function returning
`0x1.8p1f`, and a `reduc` run under `-float-print hex` producing negative hexadecimal literal
assertions consumed by WP.

No existing oracle changes.

## Testing

On a build of `b80fcac74f` with the patch (Debian 13, OCaml 5.5 switch, Alt-Ergo 2.6.4):

- **Reproducer from the issue**, with `-wp-prover none -wp-print`:
  - `max.c`: before, two warnings and `Prove: r <= w.`; after, no warning and `Prove: true.`.
  - `lemma.c` and `suffix.c`: before, `User Error`; after, `Prove: true.`.
  - `real.c` with `-wp-model +real`: before, both goals `Prove: true.`; after, both
    `Prove: false.`. With Alt-Ergo instead of `-wp-prover none`, the run after the patch ends
    with 3 of 4: the lemma is `Unknown`, and the postcondition is discharged only because WP
    gives the prover the unproved lemma `three_is_zero` as a hypothesis.
- **New test on master:** with `master`'s `Cfloat.ml`, all runs of the new test fail
  (`User Error: Unexpected constant literal`). With the patch all six runs (default and `qualif`)
  pass.
- **ptests, default configuration:** `plugins/wp` and `plugins/e-acsl` pass with no other
  difference.
- **ptests, `qualif` configuration:** the new test (all three runs) and `wp_typed/unit_float.i`
  pass. I have no WP cache, so the tests that need a prover stop at `Missing Test Results`:
  `wp_acsl/float_const.i`, `wp_plugin/float_real.i` and `wp_plugin/float_format.i` do so with and
  without the patch, with the same output. The rest of `qualif` was not run.
- **Literals that were already read** give the same result before and after, in both models:
  `1.5e1`, `1.5e1f`, `1e+2`, `1.`, `.5`, and `0.1f == 0.1` (not provable in the Float model,
  provable in the Real one). In the Float model, `0x1.8p1f`, `0x1.8p1d` and `0x1.8p1L` are
  unchanged too.
- **`<float.h>`:** `FLT_MAX`, `DBL_MAX`, `FLT_MIN`, `DBL_MIN`, `FLT_EPSILON` and `DBL_EPSILON`
  in a `requires` no longer warn.
- **`<math.h>`:** on a function that calls `exp(x)` with `-1 <= x <= 1`, the four warnings are
  gone and `call_exp_requires_not_overflow_argument` goes from `Timeout (Stronger)` to `Valid`
  (Alt-Ergo). The other goal that timed out, `assigns_normal_part1`, still does, without the
  `Stronger` tag. A caller of `expf` behaves the same: four warnings and 6 of 8 goals before,
  no warning and 7 of 8 after.
- **`./dev/check-files.sh -p HEAD~1`** (ocp-indent 1.10.0, clang-format 19.1.7): clean
  (`Lint 8 file(s)`).
- **Not run:** the other plugins' tests, the kernel tests and the WP `ce` configuration. The
  change is local to `Cfloat.parse_literal`.

Two things the patch does not change: `NAN` and `INFINITY` in a term still give
`Builtin \NaN not defined`, and a very large exponent is still expanded in memory, as the
decimal code already does.

The analysis and fix were prepared with LLM assistance (Claude Code); I reviewed them and ran the
reproducer and tests described above.
