# [kernel] avoid double rounding when parsing hexadecimal float constants

- Source branch: `fix/kernel-hex-float-double-rounding` on the fork of `pub/frama-c`; target branch `master`.
- Based on: `189053d4a2`. Patch: [`../patches/80-kernel-hex-float-double-rounding.patch`](../patches/80-kernel-hex-float-double-rounding.patch)

<!-- Everything below this line is the merge request description. -->

Before submitting the merge request, please confirm (by adding a X in the [ ]):

- [ ] you contributed to Frama-C as prescribed in the [instructions](https://git.frama-c.com/pub/frama-c/-/blob/master/CONTRIBUTING.md).
- [ ] if the size of the PR requires it, you have signed the
  [Contributor Licensing Agreement](https://git.frama-c.com/pub/frama-c/-/blob/master/CLA.md)

Closes #<issue>.

## Problem

`Typed_float.parse_hexadecimal` (`src/lib/floating_point/typed_float.ml:424-437`) parsed
hexadecimal floating-point constants by calling `float_of_string_opt` (rounding to `double` first)
and then narrowing with `represents ~in_format:format`. For single-precision (`f`/`f32`) literals
with more than 53 significand bits — such as `0x1.0000010000000001p0f`,
`0x1.0000000000000001p-150f`, and `0x1.fffffeffffffffffffp127f` — this caused double rounding,
yielding the wrong float value in violation of ISO C11 6.4.4.2p3 and IEC 60559.

## Change

`src/lib/floating_point/typed_float.ml`:

- Replace `is_hexadecimal` / `parse_hexadecimal` with `normalize_hexadecimal`, parsing the hex
  significand with `Z.of_string_base 16` and the binary exponent with `Z.of_string` to compute
  `lower`, `nearest`, and `upper` directly in the target format (`Single`, `Float32`, `Double`,
  `Float64`) with a single exact IEEE 754 rounding (`Z.log2`, `Z.trailing_zeros`, `Z.testbit`,
  handling normals, subnormals, ties-to-even, overflow, underflow, and zero).
- Add anchored hexadecimal regexps (`hex_dot_frac_exp` and `hex_exp`, including optional sign) in
  `Regexp` and dispatch them in `parse` through `apply_sign`.

New regression test `tests/misc/hex_float_rounding.c` (+ oracles) covering normal, signed,
`_Float32`, subnormal, tie-to-even, `FLT_MAX` overflow boundary, `double`, and exact hex float
literals. No existing oracle changes.

## Testing

All on Debian 13 (OCaml 5.5, gcc 14.2.0), upstream `master` at `189053d4a2`:

- **Standalone reproducer (`5` Eva checks):**
  - Before (`master` `189053d4a2` and `34.0~beta`): `Assertions 2 valid 0 unknown 3 invalid 5 total`
    (`RESULT: bug present`, exit 1).
  - After (installed patched `master`): `Assertions 5 valid 0 unknown 0 invalid 5 total`
    (`RESULT: fixed`, exit 0).
- **New test on unpatched `master`:** `tests/misc/hex_float_rounding.c` fails (exit 1); passes with
  the patch (12/12 assertions valid).
- **ptests, default configuration:** `./dev/test.sh -p tests/misc -- -j 2` passes with zero diffs
  on any existing oracle.
- **`./dev/check-files.sh -p HEAD~1`:** passes (`Lint 4 file(s)`).
- **Not run:** suites outside `tests/misc` (the change is local to `Typed_float.parse` hexadecimal
  parsing).

The analysis and fix were prepared with LLM assistance; I reviewed them and ran the reproducer and
tests described above.
