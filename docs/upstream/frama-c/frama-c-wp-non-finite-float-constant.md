# WP turns overflowed and non-finite float constants into infinite `Kreal` constants and crashes Why3 export (`Wp.Cfloat.const_float`)

- **Parent index:** [`./README.md`](./README.md)
- **Package:** `68` (`N3` from [`./frama-c-hunt-2026-11-18-candidates.md`](./frama-c-hunt-2026-11-18-candidates.md))
- **Issue text:** [`./filing/68-wp-non-finite-float-constant-issue.md`](./filing/68-wp-non-finite-float-constant-issue.md)
- **Merge request text:** [`./filing/68-wp-non-finite-float-constant-mr.md`](./filing/68-wp-non-finite-float-constant-mr.md)
- **Reproducer:** [`./repro/68-wp-non-finite-float-constant.sh`](./repro/68-wp-non-finite-float-constant.sh) + [`./repro/68-wp-non-finite-float-constant.c`](./repro/68-wp-non-finite-float-constant.c)
- **Patch:** [`./patches/68-wp-non-finite-float-constant.patch`](./patches/68-wp-non-finite-float-constant.patch)
- **Local `opam/` patch queue recommendation:** **YES (crash + soundness)** — prevents `Invalid_argument("Wp.Cfloat.const_float")` prover failures on RTE float-overflow guards and prevents Qed from proving `y + 1.0 == z` after overflow.

## Summary

`Cfloat.fmake` (`plugins/wp/src/Cfloat.ml:127-130`), `Cfloat.parse_literal` (`:140`), and `Cfloat.code_lit` (`:181-186`) pass non-finite OCaml `float` values (`+inf`, `-inf`, `nan`) directly to `F.e_float` and `Q.of_float`, producing non-finite `Kreal` terms (`Q.inf`, `Q.minus_inf`, `Q.undef`) inside Qed's real arithmetic.

- Qed proves impossible real equalities (`1e308 * 10.0 + 1.0 == 1e308 * 20.0`, `(float)1e39 + 1.0 == (float)1e39`, `1e40f + 1.0 == 1e40f`) and refutes true identities (`(float)1e39 - (float)1e39 == 0.0`).
- Any remaining goal exported to Why3 — including the RTE `is_nan_or_infinite` guard on `1e308 * 10.0`, `float f = 1e40f;`, or `-constfold` `1.0 / 0.0` — fails with `[Why3 Error] anomaly: Invalid_argument("Wp.Cfloat.const_float")`.

## Duplicate search

Live read-only `glab api` search across `pub/frama-c` (project `780`, issues and MRs, all states) for `const_float`, `infinite`, `e_float`, `Cfloat overflow`, plus [`./pub-frama-c_work_items_2026-11-09.csv`](./pub-frama-c_work_items_2026-11-09.csv) and packages `01`-`50`: **0 duplicates** (`#2698`, `#2608`, `#550`, `!59` all distinct; `#2832` overview).

## Interaction with existing patches

Touches `plugins/wp/src/Cfloat.ml:127-140, 181-186`, overlapping the context window of [`./patches/42-wp-hexadecimal-float-literals.patch`](./patches/42-wp-hexadecimal-float-literals.patch) (`#2831` / `!59`, which also calls `Q.of_float v` on suffixed literals) and [`./patches/67-wp-float-constant-double-rounding.patch`](./patches/67-wp-float-constant-double-rounding.patch). Stacking with `42` and `67` is documented and tested.

## Fix and validation

- **Source change (`plugins/wp/src/Cfloat.ml`):**
  - `fmake`: check `Float.is_finite v` after rounding, raising `Not_found` when non-finite (letting Why3 handle overflow symbolically, matching the existing `DIV` guard at line 330-331).
  - `acsl_lit`: check `Q.is_real q` before calling `F.e_real q` (emitting `Warning.error` otherwise), keeping the patch conflict-free with `42` (`!59`).
  - `code_lit`: guard `F.e_float value` on `Float.is_finite value`, emitting `Warning.error "Non-finite floating-point constant"` otherwise.
- **Regression test:** `plugins/wp/tests/wp_acsl/float_non_finite.i`. Fails on unpatched `master` `189053d4a2`, passes patched.
- **Full WP suite:** `./dev/test.sh -p plugins/wp` passes with zero existing oracle changes.
- **Lint/headers:** `./dev/check-files.sh -p HEAD~1` passes; zero mode changes.
- **Reproducer:** exits `1` on stock `master` `189053d4a2` and stock `34.0~beta`, exits `0` (`RESULT: fixed`) after applying the patch.
