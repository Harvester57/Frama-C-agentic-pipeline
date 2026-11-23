# [wp] avoid double rounding when converting rational constants to float32

- Source branch: `fix/wp-float-constant-double-rounding` on the fork of `pub/frama-c`; target branch `master`.
- Based on: `189053d4a2`. Patch: [`../patches/67-wp-float-constant-double-rounding.patch`](../patches/67-wp-float-constant-double-rounding.patch)

<!-- Everything below this line is the merge request description. -->

Before submitting the merge request, please confirm (by adding a X in the [ ]):

- [ ] you contributed to Frama-C as prescribed in the [instructions](https://git.frama-c.com/pub/frama-c/-/blob/master/CONTRIBUTING.md).
- [ ] if the size of the PR requires it, you have signed the
  [Contributor Licensing Agreement](https://git.frama-c.com/pub/frama-c/-/blob/master/CLA.md)

Closes #<issue>.

## Problem

`Cfloat.qmake` (`plugins/wp/src/Cfloat.ml:131`) converted exact rationals `Q.t` to `Float32` by computing `fmake Float32 (Q.to_float q)`, rounding first to binary64 `double` and then a second time to binary32 `float`. Constants near a binary32 midpoint (or just below the `FLT_MAX` overflow midpoint) were rounded to the wrong `float`, causing Qed to prove `(float)1.0000000596046447753906250000000000000001 == 1.0` and `(float)1152921573326323713LL == 1152921504606846976.0`, and to refute `(float)340282356779733661637539395458142568447.0 == FLT_MAX`.

## Change

`plugins/wp/src/Cfloat.ml` (43 lines added, 1 line removed):

- Add `q_to_float32` performing exact single round-to-nearest-even directly from `Q.t` to IEEE 754 binary32 in Zarith (handling normals, subnormals, zero, negative values, ties to even, and overflow).
- Call `q_to_float32` in `qmake Float32` (keeping `Q.to_float` for `Float64`, which Zarith already rounds directly to binary64).

New test `plugins/wp/tests/wp_acsl/float_double_rounding.i` (1 oracle) covering positive and negative values just above a binary32 midpoint, exact ties-to-even (down and up), the `FLT_MAX` overflow boundary, a subnormal midpoint, and C `long long` to `float` casts.

No existing oracle changes.

Interaction with open merge requests:

- **!59 (#2831, hexadecimal float literals):** touches adjacent lines in `plugins/wp/src/Cfloat.ml`; applies cleanly together via `git am --3way --keep-non-patch` in either order.

## Testing

All on Debian 13 (OCaml 5.5, Zarith 1.14, gcc 14.2.0), upstream `master` at `189053d4a2`:

- **Reproducer (6 goals covering ACSL midpoint, `FLT_MAX` threshold, subnormal midpoint, and C `(float)` cast of `2^60 + 2^36 + 1`):**
  - Before (stock `master` `189053d4a2` and stock `34.0~beta`): 6 of 6 goals fail.
  - After (patched `master`): 6 of 6 goals pass (`RESULT: fixed`).
- **New test on unpatched `master`:** `plugins/wp/tests/wp_acsl/float_double_rounding.i` fails on unpatched `master` and passes with the patch.
- **ptests, default configuration:** `./dev/test.sh -p plugins/wp` passes with zero existing oracle diffs.
- **Stacked with !59:** `git am --3way --keep-non-patch` stacks cleanly with `!59` in either order and passes both `float_literals.i` and `float_double_rounding.i`.
- **`./dev/check-files.sh -p HEAD~1`:** passes (`Lint 3 file(s)`).
- **Not run:** `make default-tests` outside `plugins/wp` and the WP `qualif` configuration (the change is local to `Cfloat.qmake`).

The analysis and fix were prepared with LLM assistance; I reviewed them and ran the reproducer and tests described above.
