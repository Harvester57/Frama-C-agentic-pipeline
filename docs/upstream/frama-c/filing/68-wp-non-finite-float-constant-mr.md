# [wp] reject non-finite float constants from Qed real simplification

- Source branch: `fix/wp-non-finite-float-constant` on the fork of `pub/frama-c`; target branch `master`.
- Based on: `189053d4a2`. Patch: [`../patches/68-wp-non-finite-float-constant.patch`](../patches/68-wp-non-finite-float-constant.patch)

<!-- Everything below this line is the merge request description. -->

Before submitting the merge request, please confirm (by adding a X in the [ ]):

- [ ] you contributed to Frama-C as prescribed in the [instructions](https://git.frama-c.com/pub/frama-c/-/blob/master/CONTRIBUTING.md).
- [ ] if the size of the PR requires it, you have signed the
  [Contributor Licensing Agreement](https://git.frama-c.com/pub/frama-c/-/blob/master/CLA.md)

Closes #<issue>.

## Problem

`Cfloat.fmake` (`plugins/wp/src/Cfloat.ml:127-130`), `Cfloat.parse_literal`/`acsl_lit` (`:140, 177-179`), and `Cfloat.code_lit` (`:181-186`) passed non-finite OCaml `float` values (`+inf`, `-inf`, `nan`) directly into `F.e_float` and `Q.of_float`, creating non-finite `Kreal` constants (`Q.inf`, `Q.minus_inf`, `Q.undef`) inside Qed's real arithmetic. As a result:

- Qed proved impossible real equalities (`1e308 * 10.0 + 1.0 == 1e308 * 20.0`, `(float)1e39 + 1.0 == (float)1e39`, `1e40f + 1.0 == 1e40f`) and refuted the true identity `(float)1e39 - (float)1e39 == 0.0`.
- Any goal exported to Why3 while still containing such a constant — including the RTE `is_nan_or_infinite` guard itself, as well as `float f = 1e40f;` and `-constfold` `1.0 / 0.0` — failed with `[Why3 Error] anomaly: Invalid_argument("Wp.Cfloat.const_float")`.

## Change

`plugins/wp/src/Cfloat.ml` (21 lines added, 7 lines removed):

- In `fmake`, check `Float.is_finite v` after rounding and `raise Not_found` when non-finite, letting Why3 handle overflow symbolically (matching the existing `DIV` guard at line 330-331).
- In `acsl_lit`, check `Q.is_real q` before calling `F.e_real q`, emitting `Warning.error "Unexpected constant literal %S"` when non-finite (e.g., `1e40f`).
- In `code_lit`, guard `F.e_float value` on `Float.is_finite value`, emitting `Warning.error "Non-finite floating-point constant"` otherwise.

New test `plugins/wp/tests/wp_acsl/float_non_finite.i` (2 runs, 2 oracles: Qed simplification and `-wp-rte -wp-gen -wp-prover alt-ergo` Why3 export).

No existing oracle changes.

Interaction with open merge requests:

- **!59 (#2831, hexadecimal float literals):** guarding in `acsl_lit` rather than `parse_literal` leaves `!59`'s hunk untouched; `!59`, the companion binary32 double-rounding fix in `Cfloat.qmake`, and this patch stack cleanly via `git am --3way --keep-non-patch` in both forward and reverse orders.

## Testing

All on Debian 13 (OCaml 5.5, Zarith 1.14, gcc 14.2.0, Alt-Ergo 2.6.4), upstream `master` at `189053d4a2`:

- **Reproducer (Qed real equalities + `-wp-rte -wp-prover alt-ergo` Why3 export):**
  - Before (stock `master` `189053d4a2` and stock `34.0~beta`): 6 checks fail (false Qed proofs + `Invalid_argument("Wp.Cfloat.const_float")` `[Failure]` on `ovf_mul` and `ovf_lit`).
  - After (patched `master`): 0 failures (`RESULT: fixed`), zero `const_float` anomalies.
- **New test on unpatched `master`:** `plugins/wp/tests/wp_acsl/float_non_finite.i` fails on unpatched `master` and passes with the patch.
- **ptests, default configuration:** `./dev/test.sh -p plugins/wp` passes with zero existing oracle diffs.
- **Stacked with !59 and the binary32 double-rounding fix:** `git am --3way --keep-non-patch` applies cleanly in both forward and reverse orders, builds, and passes `float_literals.i`, `float_double_rounding.i`, and `float_non_finite.i`.
- **`./dev/check-files.sh -p HEAD~1`:** passes (`Lint 4 file(s)`).
- **Not run:** `make default-tests` outside `plugins/wp` and the WP `qualif` configuration (offline cache).

The analysis and fix were prepared with LLM assistance; I reviewed them and ran the reproducer and tests described above.
