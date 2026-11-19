# [e-acsl] read real constants with an exponent or in hexadecimal

- Source branch: `fix/eacsl-real-constants` on the fork of `pub/frama-c`; target branch `master`.
- Based on: `b80fcac74f`. Patch: [`../patches/43-eacsl-real-constant-notation.patch`](../patches/43-eacsl-real-constant-notation.patch)

<!-- Everything below this line is the merge request description. -->

Before submitting the merge request, please confirm (by adding a X in the [ ]):

- [ ] you contributed to Frama-C as prescribed in the [instructions](https://git.frama-c.com/pub/frama-c/-/blob/master/CONTRIBUTING.md).
- [ ] if the size of the PR requires it, you have signed the
  [Contributor Licensing Agreement](https://git.frama-c.com/pub/frama-c/-/blob/master/CLA.md)

Closes #<issue>.

## Problem

A real constant that is not exactly a `double` is given to GMP as a fraction, and
`Gmp.Q.normalize_str` only converts plain decimal expansions:

- with an exponent or in hexadecimal notation (`1e-9`, `0x1.00000000000000001p0`),
  `decimal_to_fractional` raises `Not_a_decimal`. The handler of `normalize_str` has been on
  `Invalid_argument` since 11b9381ab0 (2019), so nothing catches it and Frama-C stops with
  `Unexpected error (E_ACSL__Gmp.Q.Not_a_decimal("1e-9"))`;
- with a suffix, that is for a `long double` constant such as `0.1L`, the text is passed
  unchanged to `__gmpq_set_str`, which rejects it and leaves 0. At run time `0.1L > 0.05` fails
  and `0.1L == 0` holds, without any message.

## Change

`plugins/e-acsl/src/code_generator/gmp.ml`, 12 lines added and 20 removed:

- `normalize_str` first looks at the suffix with the kernel's `Floating_point.extract_suffix`.
- Without suffix, the decimal conversion is tried as before, so the strings generated for plain
  decimals are unchanged (`"01/10"`). When it does not apply, Zarith's `Q.of_string` gives the
  exact fraction: it reads decimal exponents since Zarith 1.10 and hexadecimal notation since
  1.11, and Frama-C requires 1.13 or later.
- With a suffix, the constant is reported with `Error.not_yet`, and the annotation is ignored
  with a warning. A suffixed constant only gets there when it is not exactly a `double`, in
  practice a `long double`, whose value depends on the target.
- The suffix cases of `decimal_to_fractional` (`Is_a_float`, `float_suffixes`) are no longer
  reachable and are removed.

New test `plugins/e-acsl/tests/arith/real_constants.c`: constants with an exponent, in hexadecimal
notation, and two `long double` ones. No existing oracle changes.

## Testing

On a build of `b80fcac74f` with the patch (Debian 13, OCaml 5.5 switch):

- **Reproducer from the issue:**
  - `exp.c`: before, `Unexpected error`; after, the assertion is translated with
    `__gmpq_set_str(..., "1/1000000000", 10)` and holds at run time.
  - `ld.c` and its true variant: before, built silently, and the wrong verdict at run time;
    after, ``E-ACSL construct `suffixed floating-point constant that is not a double' is not yet
    supported. Ignoring annotation.``
  - A false assertion with an exponent (`1e-1 != 0.1`) aborts at run time, as it should.
- **New test on master:** with `master`'s `gmp.ml`, the new test fails in the default and in the
  `dev` configuration (`Unexpected error`). With the patch it passes in both.
- **ptests, default configuration:** `plugins/e-acsl` passes, with no change to an existing
  oracle.
- **ptests, `dev` configuration:** `plugins/e-acsl/tests/arith` passes. The other directories were
  not run in `dev`.
- **`./dev/check-files.sh -p HEAD~1`:** clean (`Lint 5 file(s)`).
- **Not run:** the tests of the other plug-ins and of the kernel. The change is local to
  `Gmp.Q.normalize_str`.

Two things the patch does not change: a unary minus on a rational (`-1e-2`) is still not
supported, and a very large exponent (`1e2000`) gives a fraction with as many digits, as the
decimal code does for a long expansion.

The analysis and fix were prepared with LLM assistance (Claude Code); I reviewed them and ran the
reproducer and tests described above.
