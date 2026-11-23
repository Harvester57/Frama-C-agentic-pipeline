# WP double-rounds rational and integer constants when converting to `float`

- **Parent index:** [`./README.md`](./README.md)
- **Package:** `67` (`H2` from [`./frama-c-hunt-2026-11-18-candidates.md`](./frama-c-hunt-2026-11-18-candidates.md))
- **Issue text:** [`./filing/67-wp-float-constant-double-rounding-issue.md`](./filing/67-wp-float-constant-double-rounding-issue.md)
- **Merge request text:** [`./filing/67-wp-float-constant-double-rounding-mr.md`](./filing/67-wp-float-constant-double-rounding-mr.md)
- **Reproducer:** [`./repro/67-wp-float-constant-double-rounding.sh`](./repro/67-wp-float-constant-double-rounding.sh) + [`./repro/67-wp-float-constant-double-rounding.c`](./repro/67-wp-float-constant-double-rounding.c)
- **Patch:** [`./patches/67-wp-float-constant-double-rounding.patch`](./patches/67-wp-float-constant-double-rounding.patch)
- **Local `opam/` patch queue recommendation:** **NO (low reach)** — triggers only when a constant lies within ~2^-29 (relative) of a binary32 midpoint; cleanly fixable upstream.

## Summary

`Cfloat.qmake` (`plugins/wp/src/Cfloat.ml:131`) implements `qmake ulp q = fmake ulp (Q.to_float q)`, rounding an arbitrary-precision rational `Q.t` to IEEE 754 binary64 first and then rounding a second time to binary32 via `Floating_point.round_to_single_precision`.

As a result, Qed proves false equalities such as `(float)1.0000000596046447753906250000000000000001 == 1.0` and `(float)1152921573326323713LL == 1152921504606846976.0` (`gcc`: `1152921642045800448.0`), and refutes true lemmas at the `FLT_MAX` overflow threshold (`(float)340282356779733661637539395458142568447.0 == 340282346638528859811704183484516925440.0`) and subnormal midpoints.

## Standards and ground truth

- ACSL Reference Manual: `(float)` on a real denotes direct round-to-nearest-even to binary32.
- IEC 60559 (IEEE 754, claimed by WP's `Float` model and implemented by `gcc 14.2.0`): single rounding to binary32. (ISO C17 6.3.1.4p2 alone allows either neighbor for integer-to-float, but IEC 60559 and ACSL do not.)

## Duplicate search

Live read-only `glab api` search across `pub/frama-c` (project `780`, issues and MRs, all states) for `double rounding`, `qmake`, `round_to_single`, `Cfloat`, plus [`./pub-frama-c_work_items_2026-11-09.csv`](./pub-frama-c_work_items_2026-11-09.csv) and packages `01`-`50`: **0 duplicates** (`!59`/`#2831` parses literals in `parse_literal`, distinct; `#2832` overview).

## Interaction with existing patches

Touches `plugins/wp/src/Cfloat.ml:131`, adjacent to [`./patches/42-wp-hexadecimal-float-literals.patch`](./patches/42-wp-hexadecimal-float-literals.patch) (`#2831` / `!59`) and [`./patches/68-wp-non-finite-float-constant.patch`](./patches/68-wp-non-finite-float-constant.patch). Stacking with `42` and `68` is verified in the audit container.

## Fix and validation

- **Source change (`plugins/wp/src/Cfloat.ml`):** add exact single-rounding `q_to_float32` (using Zarith `Z.numbits`, `Z.ediv_rem`, round-to-nearest-even, normals/subnormals/overflow) and call it from `qmake Float32`.
- **Regression test:** `plugins/wp/tests/wp_acsl/float_double_rounding.i`. Fails on unpatched `master` `189053d4a2`, passes patched.
- **Full WP suite:** `./dev/test.sh -p plugins/wp` passes with zero existing oracle changes.
- **Lint/headers:** `./dev/check-files.sh -p HEAD~1` passes; zero mode changes.
- **Reproducer:** exits `1` on stock `master` `189053d4a2` and stock `34.0~beta`, exits `0` (`RESULT: fixed`) after applying the patch.
