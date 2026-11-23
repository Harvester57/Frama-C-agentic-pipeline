# [e-acsl] reject non-finite floating-point constants as not yet supported

- Source branch: `fix/eacsl-non-finite-real-constant` on the fork of `pub/frama-c`; target branch `master`.
- Based on: `189053d4a2`. Patch: [`../patches/53-eacsl-non-finite-real-constant.patch`](../patches/53-eacsl-non-finite-real-constant.patch)

<!-- Everything below this line is the merge request description. -->

Before submitting the merge request, please confirm (by adding a X in the [ ]):

- [ ] you contributed to Frama-C as prescribed in the [instructions](https://git.frama-c.com/pub/frama-c/-/blob/master/CONTRIBUTING.md).
- [ ] if the size of the PR requires it, you have signed the
  [Contributor Licensing Agreement](https://git.frama-c.com/pub/frama-c/-/blob/master/CLA.md)

Closes #<issue>.

## Problem

When an ACSL annotation contains a suffixed floating-point literal that overflows its target format
(such as `1e40f`, `1e400d`, or `0x1p2000d`), `Logic_utils.parse_float` builds a `logic_real` with
`r_lower = r_upper = r_nearest = infinity`.

Both `Interval.infer_term` (`plugins/e-acsl/src/analyses/interval.ml:530-532`) and
`Translate_terms.constant_to_exp_old` (`plugins/e-acsl/src/code_generator/translate_terms.ml:128-131`)
only checked `lr.r_lower = lr.r_upper` without testing `Floating_point.is_finite lr.r_nearest`
(unlike the kernel's `Cil.isExactFloat`). Because `infinity = infinity` in OCaml, E-ACSL emitted
`CReal(infinity, FDouble, None)`:

- In float comparisons (`assert x < 1e40f;`), the generated C prints bare `inf` (even without
  `-constfold` and even with `-float-print hex`), causing `e-acsl-gcc` compilation to fail with
  `error: 'inf' undeclared`.
- In rational contexts (`assert 0.1 < 1e40f;`), E-ACSL emits
  `__gmpq_set_d(__gen_e_acsl__3, (double)((float)inf));`, where passing an IEEE infinity to GMP's
  `mpq_set_d` raises `SIGFPE` (exit 136) at run time even if the kernel printer emits a valid C
  infinity expression.

## Change

- `plugins/e-acsl/src/analyses/interval.ml` (`Interval.infer`, `TConst (LReal lr)`): guard the
  `lr.r_lower = lr.r_upper` branch with `Floating_point.is_finite lr.r_nearest`; call
  `Error.not_yet "non-finite floating-point constant"` otherwise.
- `plugins/e-acsl/src/code_generator/translate_terms.ml` (`constant_to_exp_old`, `LReal lr`):
  apply the matching `Floating_point.is_finite lr.r_nearest` guard with the same `Error.not_yet`.
- Unsuffixed overflowing real literals (such as `1e400`) have
  `r_lower = max_float <> infinity = r_upper` and remain on the `Rational` path unchanged.
- New test `plugins/e-acsl/tests/arith/non_finite_real.c` (plus oracles
  `oracle/gen_non_finite_real.0.c` and `oracle/non_finite_real.0.res.oracle`) covering `1e40f`,
  `1e400d`, `0x1p2000d`, `0.1 < 1e40f`, `(float)1e40f > 0`, and confirming that a following valid
  assertion `x == 0.5` is still instrumented and checked.

No existing oracle changes.

## Testing

All on Debian 13 (OCaml 5.5, gcc 14.2.0), upstream `master` at `189053d4a2`:

- **Reproducer (5 cases: `1e40f`, `1e400d`, `0x1p2000d`, `0.1 < 1e40f`, and `1e40f` with
  `-float-print hex`):**
  - Before (on `master` `189053d4a2` and `34.0~beta`): 5 of 5 cases fail to compile (`error: 'inf'
    undeclared`, `e-acsl-gcc` exits 1).
  - After (installed patched `master`): 5 of 5 cases pass (E-ACSL emits the `not yet supported`
    warning, compiles cleanly, and exits 0 at run time).
- **New test on unpatched `master`:** `plugins/e-acsl/tests/arith/non_finite_real.c` fails in both
  the default (oracle diff: emits `x < inf` and `__gmpq_set_d(..., (double)((float)inf))`) and
  `dev` (`e-acsl-gcc` fails with `error: 'inf' undeclared`) configurations. With the patch, it
  passes in both.
- **ptests, default configuration:** `./dev/test.sh -p plugins/e-acsl` passes with zero diffs on
  any existing oracle.
- **`./dev/check-files.sh -p HEAD~1`:** passes (`Debian clang-format version 19.1.7`,
  `Lint 5 file(s)`).
- **Not run:** 32-bit targets, and `make default-tests` outside `plugins/e-acsl` (the change is
  local to E-ACSL `LReal` handling in `interval.ml` and `translate_terms.ml`).

The analysis and fix were prepared with LLM assistance; I reviewed them and ran the reproducer and
tests described above.
