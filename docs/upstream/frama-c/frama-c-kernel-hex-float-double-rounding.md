# Kernel: hexadecimal floating-point literals with `f`/`f32` suffix suffer double rounding through `double`

Draft for the Frama-C issue tracker (https://git.frama-c.com/pub/frama-c/-/issues).
**Not filed.** Issue 80 of this folder, drafted on 2026-11-23. Filing remains paused pending the
maintainers' reply on [#2832](https://git.frama-c.com/pub/frama-c/-/work_items/2832).

**Package:**
[issue text](./filing/80-kernel-hex-float-double-rounding-issue.md),
[MR text](./filing/80-kernel-hex-float-double-rounding-mr.md),
[reproducer](./repro/80-kernel-hex-float-double-rounding.sh) with its
[C file](./repro/80-kernel-hex-float-double-rounding.c), and
[patch](./patches/80-kernel-hex-float-double-rounding.patch) (validated on `master` `189053d4a2`).

## Summary

`Typed_float.parse_hexadecimal` (`src/lib/floating_point/typed_float.ml:424-437`) parses
hexadecimal floating-point literals by converting them to an OCaml 64-bit `float` (`double`) via
`float_of_string_opt` and then narrowing that intermediate `double` to `format` (`Single` or
`Float32`). Any single-precision hex float literal with bits beyond bit 53 of the significand
(for example `0x1.0000010000000001p0f`, `0x1.0000000000000001p-150f`, or
`0x1.fffffeffffffffffffp127f`) suffers double rounding in violation of ISO C11 6.4.4.2p3 and IEC
60559.

## Versions

| | Result |
| :-- | :-- |
| `34.0~beta (Selenium)`, opam build (`framac-analysis:latest`, 2026-11-23) | **bug present** (`Assertions 2 valid 0 unknown 3 invalid 5 total`, `RESULT: bug present`) |
| `35.0~~dev (Bromine)`, `master` `189053d4a2` (`framac-master-audit:189053d`, 2026-11-23) | **bug present**, identical output (`RESULT: bug present`) |
| `master` `189053d4a2` + [`./patches/80-kernel-hex-float-double-rounding.patch`](./patches/80-kernel-hex-float-double-rounding.patch) | **fixed** (`Assertions 5 valid 0 unknown 0 invalid 5 total`, `RESULT: fixed`) |

Debian 13 (trixie; glibc 2.41, gcc 14.2.0), OCaml 5.5.

## Root cause

In `src/lib/floating_point/typed_float.ml`, `parse_hexadecimal` (lines 424-437) calls
`float_of_string_opt s` under `Nearest_even`, `Downward`, and `Upward` rounding modes, producing
`binary64` values, and then narrows each via `represents ~float:... ~in_format:format`. For
`0x1.0000010000000001p0f`, the `2^-64` bit is discarded when rounding to `binary64`, leaving the
exact `binary32` midpoint `0x1.000001p0`, which round-to-nearest-even then rounds down to `1.0f`
instead of up to `0x1.000002p0f`. The same double rounding affects subnormals
(`0x1.0000000000000001p-150f` -> `0.0f` instead of `0x1p-149f`) and the `FLT_MAX` boundary
(`0x1.fffffeffffffffffffp127f` -> `+inf` instead of `0x1.fffffep127f`). In addition,
`is_hexadecimal` (line 421) did not accept a leading sign (`+`/`-`).

## Fix and validation

Patch [`./patches/80-kernel-hex-float-double-rounding.patch`](./patches/80-kernel-hex-float-double-rounding.patch):
one commit (`c3b2e96116`) on `master` `189053d4a2`, 4 files (`src/lib/floating_point/typed_float.ml`
plus regression test `tests/misc/hex_float_rounding.c` and its 2 oracles).

- Replaces `is_hexadecimal` / `parse_hexadecimal` with `normalize_hexadecimal` using `Z.of_string_base 16`
  and exact `Z` bit operations (`Z.log2`, `Z.trailing_zeros`, `Z.testbit`) for single-step rounding
  in `Single`, `Float32`, `Double`, and `Float64`.
- Adds anchored regexps `hex_dot_frac_exp` and `hex_exp` (with optional sign) and applies `apply_sign`.
- Validated on 2026-11-23 in `framac-master-audit:189053d`:
  - New test `tests/misc/hex_float_rounding.c` fails on unpatched `master`, passes with patch (12/12
    Eva checks valid).
  - Full `./dev/test.sh -p tests/misc -- -j 2` passes with zero diffs on existing oracles.
  - `./dev/check-files.sh -p HEAD~1` passes (`Lint 4 file(s)`).
  - Standalone reproducer flips from `RESULT: bug present` (exit 1) to `RESULT: fixed` (exit 0).
- Local `opam/` queue recommendation: **YES** (soundness defect affecting float literal parsing for
  Eva/WP/E-ACSL).
