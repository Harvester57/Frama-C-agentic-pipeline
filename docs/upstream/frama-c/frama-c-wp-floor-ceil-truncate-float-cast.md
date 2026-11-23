# WP `\floor`, `\ceil`, `\truncate`, and float-to-integer casts of constants prove false facts

- **Parent index:** [`./README.md`](./README.md)
- **Package:** `65` (`H1` from [`./frama-c-hunt-2026-11-18-candidates.md`](./frama-c-hunt-2026-11-18-candidates.md))
- **Issue text:** [`./filing/65-wp-floor-ceil-truncate-float-cast-issue.md`](./filing/65-wp-floor-ceil-truncate-float-cast-issue.md)
- **Merge request text:** [`./filing/65-wp-floor-ceil-truncate-float-cast-mr.md`](./filing/65-wp-floor-ceil-truncate-float-cast-mr.md)
- **Reproducer:** [`./repro/65-wp-floor-ceil-truncate-float-cast.sh`](./repro/65-wp-floor-ceil-truncate-float-cast.sh) + [`./repro/65-wp-floor-ceil-truncate-float-cast.c`](./repro/65-wp-floor-ceil-truncate-float-cast.c)
- **Patch:** [`./patches/65-wp-floor-ceil-truncate-float-cast.patch`](./patches/65-wp-floor-ceil-truncate-float-cast.patch)
- **Local `opam/` patch queue recommendation:** **YES (soundness)** — Qed proves false lemmas and false C postconditions on valid `long long` / `unsigned long long` casts of `double` / `float` values.

## Summary

`Cmath.builtin_truncate` (`plugins/wp/src/Cmath.ml:42-61`) evaluates `\floor`, `\ceil`, `\truncate`, `(integer)` casts, and C float-to-integer casts (`Cint.of_real` at `plugins/wp/src/Cint.ml:379`) on rational constants `Kreal r` via `int_of_float (Q.to_float r)`.

- Rounding `Q.t` through IEEE 754 `double` loses precision near integers: Qed proves `\floor(0.99999999999999999999) == 1`, `\ceil(0.99999999999999999999) == 2`, `\truncate(-0.99999999999999999999) == -1`, `(integer)0.99999999999999999999 == 1`, and `\floor(9007199254740993.5) == 9007199254740994` (where the floor exceeds its argument).
- Converting through OCaml's 63-bit `int` wraps silently in `[2^62, 2^63)` and yields unspecified results (0 on x86-64) at or above `2^63` without raising: Qed proves `\floor(1e30) == 0`, `(long long)5e18 == -4223372036854775808` (`gcc`: `5000000000000000000`), and `(unsigned long long)4611686018427387904.0f == 13835058055282163712ULL` (`gcc`: `4611686018427387904`).

## Standards and ground truth

- WP manual (`plugins/wp/doc/manual/wp_builtins.tex:76-77`): "Constants (rationals) are truncated towards the expected direction." No limitation is documented.
- ISO C11 6.3.1.4p1: converting a finite floating-point value to an integer type truncates toward zero when representable (`gcc 14.2.0` confirms `5000000000000000000` and `4611686018427387904`).

## Duplicate search

Live read-only `glab api` search across `pub/frama-c` (project `780`, issues and MRs, all states) for `builtin_truncate`, `floor`, `ceil`, `truncate`, `int_of_float`, plus [`./pub-frama-c_work_items_2026-11-09.csv`](./pub-frama-c_work_items_2026-11-09.csv) and packages `01`-`50`: **0 duplicates** (`#959` closed crash on `\floor` and `#2792` closed shift rules are distinct; `#2832` overview).

## Fix and validation

- **Source change (`plugins/wp/src/Cmath.ml:47-59`):** guard on `Q.is_real r` and compute exact `Z.t` via `Z.fdiv r.Q.num r.Q.den` (`f_floor`), `Z.cdiv r.Q.num r.Q.den` (`f_ceil`), and `Q.to_bigint r` (`f_truncate`), returning `F.e_zint z`.
- **Regression test:** `plugins/wp/tests/wp_acsl/truncate_const.i`. Fails on unpatched `master` `189053d4a2`, passes patched.
- **Full WP suite:** `./dev/test.sh -p plugins/wp` passes with zero existing oracle changes.
- **Lint/headers:** `./dev/check-files.sh -p HEAD~1` passes; zero mode changes.
- **Reproducer:** exits `1` on stock `master` `189053d4a2` and stock `34.0~beta`, exits `0` (`RESULT: fixed`) after applying the patch.
