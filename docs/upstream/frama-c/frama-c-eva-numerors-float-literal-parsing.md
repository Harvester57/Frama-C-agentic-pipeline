# Eva `numerors` domain: decimal-only literal parser drops a sure alarm on `DBL_MAX` and crashes on `FLT_MAX`, `INFINITY`, `0x1.ep0`, and `1.5d`

Draft for the Frama-C issue tracker (https://git.frama-c.com/pub/frama-c/-/issues).
**Not filed.** Issue 55 of this folder, drafted on 2026-11-22. Filing remains paused pending the
maintainers' reply on [#2832](https://git.frama-c.com/pub/frama-c/-/work_items/2832).

**Package:**
[issue text](./filing/55-eva-numerors-float-literal-parsing-issue.md),
[MR text](./filing/55-eva-numerors-float-literal-parsing-mr.md),
[reproducer](./repro/55-eva-numerors-float-literal-parsing.sh) with its
[C file](./repro/55-eva-numerors-float-literal-parsing.c), and
[patch](./patches/55-eva-numerors-float-literal-parsing.patch) (validated on `master` `189053d4a2`).

## Summary

Under `-eva -eva-domains numerors`, `IEEE754.Make.constant` parses C floating-point constant source
text via `Rational.of_string` (`src/lib/arithmetic/rational.ml`), which only splits decimal literals
on `'e'` and `'.'` and only strips `f`/`l`/`f32`/`f64` suffixes. In addition, non-finite `CReal`
constants (`INFINITY`, `NAN`, `HUGE_VAL`) are passed directly to `Scalar.of_string`. This causes:

1. **Unsoundness (lost sure alarm):** `<float.h>` `DBL_MAX` (`0x1.fffffffffffffp+1023`) is misparsed
   as `8.096e+304`, causing `if (x < DBL_MAX)` to be treated as false for `x` in `[1e305 .. 1e306]`
   and dropping the sure out-of-bounds alarm on `t[2] = 1`.
2. **Wrong real bounds:** hexadecimal floating-point literals without hex digit `'e'` (such as
   `0x1.8p1`) are misparsed (`0x1.8p1` becomes `0.048`, giving `Real : [0.048 .. 0.096]` instead of
   `[3. .. 6.]`).
3. **Uncaught OCaml exceptions (exit 125):** `<float.h>` `FLT_MAX` and `0x1.ep0` crash with
   `Failure("int_of_string")`; GCC `d`-suffixed literals (`1.5d`) and `<math.h>` `INFINITY`, `NAN`,
   and `HUGE_VAL` crash with `Invalid_argument("Z.of_substring_base: invalid digit")`.

## Versions

| | Result |
| :-- | :-- |
| `34.0~beta (Selenium)`, opam build (`framac-analysis:latest`, 2026-11-22) | **unsound / crashes** (sure alarm lost on `DBL_MAX`, `0x1.8p1` misparsed, exit 125 on `0x1.ep0`/`FLT_MAX`/`1.5d`/`INFINITY`) |
| `35.0~~dev (Bromine)`, `master` `189053d4a2` (`framac-master-audit:189053d`, 2026-11-22) | **unsound / crashes**, identical messages (`RESULT: bug present (6 of 6 cases fail)`) |
| `master` `189053d4a2` + [`./patches/55-eva-numerors-float-literal-parsing.patch`](./patches/55-eva-numerors-float-literal-parsing.patch) | **fixed** (`RESULT: fixed`, 6/6 cases pass: sure alarm restored, exact intervals, zero crashes) |

Debian 13 (trixie), OCaml 5.5, gcc 14.2.0.

## Root cause

1. `Rational.of_string` (`src/lib/arithmetic/rational.ml:33-62`):
   - `split_significant_exponent` splits on `'e'` and calls `int_of_string` on the suffix, crashing
     on any hex float containing hex digit `'e'` (`0x1.ep0`, `FLT_MAX = 0x1.fffffep+127f`).
   - `significant_of_string` splits on `'.'` and divides `integer ^ fractional` by
     `10^(String.length fractional)`, silently misparsing hex floats without `'e'` (`0x1.8p1` ->
     `0x18p1 / 1000 = 0.048`, `DBL_MAX` -> `8.096e+304`) because `Q.of_string` interprets the
     concatenated hex float as a scaled binary float which is then divided by a power of 10.
   - `remove_float_suffix` does not strip GCC `'d'`/`'D'`.
2. `IEEE754.Make.constant` (`plugins/eva/src/values/non_integer_arithmetic/IEEE754.ml:567-583`)
   matches `CReal (_, fkind, Some str)` without checking `Float.is_finite f`, sending `"INFINITY"`,
   `"NAN"`, or `"HUGE_VAL"` to `Scalar.of_string` -> `Rational.of_string` -> `Q.of_string`.

## Subtlety notes

- **Suffix stripping safety:** `remove_float_suffix` only strips `f`/`d`/`l`/`f32`/`f64` when the
  character preceding the suffix is `[0-9.]` and, for `0x`/`+0x`/`-0x` strings, only when `'p'` is
  present. This avoids stripping hex digits `f` or `d` from hexadecimal integer strings (`0x1f`,
  `0x1d`) or corrupting non-numeric inputs.
- **Zarith `Q.of_string`:** natively supports decimal, scientific (`1e-5`), hexadecimal float
  (`0x1.8p1`, `0x1.fffffffffffffp+1023`), and rational (`1/3`) strings.
- **Relationship to `#2831`:** same literal-parsing family as WP issue `#2831`, but in a separate
  module (`src/lib/arithmetic/rational.ml` and `plugins/eva/src/values/non_integer_arithmetic/IEEE754.ml`).

## Fix and validation

Patch [`./patches/55-eva-numerors-float-literal-parsing.patch`](./patches/55-eva-numerors-float-literal-parsing.patch):
one commit (`2f087defd5`) on `master` `189053d4a2`, 4 files (181 insertions, 28 deletions:
`src/lib/arithmetic/rational.ml`, `plugins/eva/src/values/non_integer_arithmetic/IEEE754.ml`, and
new regression test `plugins/eva/tests/numerors/float_literals.c` with its oracle).

Validated on 2026-11-22 in `framac-master-audit:189053d` (`master`
`189053d4a2bd460c5c557dba8569474ff0419e73`):

- **Patch hygiene:** `git format-patch` produces zero file-mode changes and no executable files.
- **New test against unpatched `master`:** `float_literals.c` FAILS with exit 125
  (`Failure("int_of_string")`).
- **New test against patched sources:** `float_literals.c` PASSES.
- **Numerors suite, default configuration:** `./dev/test.sh -p plugins/eva/tests/numerors` PASSES
  (exit 0, zero diffs on existing oracles).
- **`./dev/check-files.sh -p HEAD~1`:** PASSES (`Lint 4 file(s)`).
- **Installed patched tree + reproducer:** `RESULT: fixed` (6/6 cases pass, exit 0; before patch:
  `RESULT: bug present (6 of 6 cases fail)`).

Not run: 32-bit targets and `make default-tests` outside `plugins/eva/tests/numerors`.

## Duplicates

Searched live on 2026-11-22 via read-only GitLab API (`pub/frama-c`, issues and merge requests, all
states) for `numerors`, `Rational.of_string`, `split_significant_exponent`, `DBL_MAX`, `FLT_MAX`,
and `IEEE754`. Zero duplicates in `pub/frama-c` issues/MRs, the CSV snapshot, or packages `01`-`50`.

## For the pipeline

Do **not** add to the local `opam/` patch queue: `numerors` is an experimental opt-in Eva domain
not used by the Frama-C verification pipeline.
