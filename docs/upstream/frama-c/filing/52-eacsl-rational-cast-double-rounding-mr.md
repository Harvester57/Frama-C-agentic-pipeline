# [e-acsl] round rational casts to double and float to nearest-even

- Source branch: `fix/eacsl-rational-cast-double-rounding` on the fork of `pub/frama-c`; target branch `master`.
- Based on: `189053d4a2`. Patch: [`../patches/52-eacsl-rational-cast-double-rounding.patch`](../patches/52-eacsl-rational-cast-double-rounding.patch)

<!-- Everything below this line is the merge request description. -->

Before submitting the merge request, please confirm (by adding a X in the [ ]):

- [ ] you contributed to Frama-C as prescribed in the [instructions](https://git.frama-c.com/pub/frama-c/-/blob/master/CONTRIBUTING.md).
- [ ] if the size of the PR requires it, you have signed the
  [Contributor Licensing Agreement](https://git.frama-c.com/pub/frama-c/-/blob/master/CLA.md)

Closes #<issue>.

## Problem

`Gmp.Q.add_cast` (`plugins/e-acsl/src/code_generator/gmp.ml`, lines 339-376) translated ACSL casts
`(double)r` and `(float)r` on GMP rationals by emitting `__gmpq_get_d` (and casting the resulting
`double` to `float` for `(float)r`).

GMP's `mpq_get_d` truncates toward zero regardless of the active rounding mode, violating ACSL
Section 2.2.5 (which specifies IEEE 754 round-to-nearest-even):

- valid assertions such as `double d = 0.1; assert d == (double)0.1;` aborted at run time;
- false assertions such as `assert (double)0.1 < 0.1;` and
  `assert 0x1.9999999999999p-4 == (double)0.1;` passed silently without warning;
- `(float)` casts suffered from both truncation and double rounding (for example,
  `assert 16777218.0f == (float)16777217.0000000001;` aborted at run time).

## Change

- `plugins/e-acsl/share/e-acsl/numerical_model/e_acsl_gmp_api.h`: declare exported RTL builtins
  `eacsl_mpq_get_d` (`__e_acsl_mpq_get_d`) and `eacsl_mpq_get_f` (`__e_acsl_mpq_get_f`).
- `plugins/e-acsl/share/e-acsl/numerical_model/e_acsl_floating_point.c`: implement
  `eacsl_mpq_get_ieee`, `eacsl_mpq_get_d` (`prec = 53, emin = -1022, emax = 1023`), and
  `eacsl_mpq_get_f` (`prec = 24, emin = -126, emax = 127`) using exact `mpz_t` integer division and
  remainder comparison (`__gmpz_tdiv_qr`, `__gmpz_tstbit`, `__gmpz_add_ui`, `ldexp`), handling
  zero, sign, exact ties-to-even, subnormals, carry across exponent boundaries, underflow to
  `+-0.0`, and overflow to `+-INFINITY` in a single rounding step (eliminating double rounding for
  `float`).
- `plugins/e-acsl/src/code_generator/gmp.ml` (`Gmp.Q.add_cast`): emit `Smart_stmt.rtl_call` to
  `mpq_get_d` for `TFloat FDouble` and `mpq_get_f` for `TFloat FFloat`, removing the now-obsolete
  `R to float: double rounding might cause unsoundness` warning.
- New test `plugins/e-acsl/tests/arith/rational_cast.c` (with oracles
  `oracle/gen_rational_cast.0.c` and `oracle/rational_cast.0.res.oracle`) covering `double` and
  `float` casts, negative rationals, exact ties-to-even midpoints, single-rounding binary32
  midpoints, subnormals, overflow to `+-INFINITY`, and exact zero.
- Updated the 5 existing E-ACSL oracles referencing `__gmpq_get_d` / `R to float`:
  `tests/acsl-rte/oracle/gen_rte.0.c`, `tests/arith/oracle/gen_rationals.0.c`,
  `tests/arith/oracle/rationals.0.res.oracle`, `tests/constructs/oracle/gen_functions.0.c`, and
  `tests/constructs/oracle/gen_functions.1.c`.

Interaction with open merge requests: leaves `Gmp.Q.create_from_str` in `gmp.ml` untouched, so it
stacks cleanly with the real-constant parsing fix (`gmp.ml` hex/scientific constant parsing) via
`git am --3way --keep-non-patch` in either order.

## Testing

All on Debian 13 (OCaml 5.5, gcc 14.2.0), upstream `master` at `189053d4a2`:

- **Reproducer (7 cases: `(double)0.1` equality, false equality against truncated double, false
  `(double)0.1 < 0.1`, negative `-0.1`, exact double ties-to-even, `float` single rounding at
  `16777217.0000000001`, and `double`/`float` subnormals):**
  - Before (on `master` `189053d4a2` and `34.0~beta`): 7 of 7 cases fail (5 true assertions abort
    with exit 134; 2 false assertions pass with exit 0).
  - After (installed patched `master`): 7 of 7 cases pass (5 true assertions exit 0 without any
    double-rounding warning; 2 false assertions abort with exit 134).
- **New test on unpatched `master`:** `plugins/e-acsl/tests/arith/rational_cast.c` fails in both
  the default (oracle diff) and `dev` (`d == (double)0.1` aborts with exit 134) configurations.
  With the patch, it passes in both.
- **ptests, default configuration:** `./dev/test.sh -p plugins/e-acsl` passes with only the 5
  expected existing oracle updates above.
- **ptests, `dev` configuration:** `./dev/test.sh -p -c dev plugins/e-acsl/tests/arith/rationals.c`
  and `plugins/e-acsl/tests/arith/rational_cast.c` both pass.
- **Stacking with real-constant parsing (`gmp.ml`):** `git am --3way --keep-non-patch` applies
  cleanly in both orders with zero conflicts, builds, and passes both `real_constants.c` and
  `rational_cast.c` in `dev`.
- **`./dev/check-files.sh -p HEAD~1`:** passes (`Debian clang-format version 19.1.7`,
  `Lint 11 file(s)`).
- **Not run:** 32-bit targets, and `make default-tests` outside `plugins/e-acsl` (the change is
  local to E-ACSL rational-to-float conversion).

The analysis and fix were prepared with LLM assistance; I reviewed them and ran the reproducer and
tests described above.
