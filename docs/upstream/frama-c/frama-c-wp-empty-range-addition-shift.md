# WP empty-range addition, subtraction, and pointer shifts prove false properties

- **Parent index:** [`./README.md`](./README.md)
- **Package:** `66` (`H3 + N2` from [`./frama-c-hunt-2026-11-18-candidates.md`](./frama-c-hunt-2026-11-18-candidates.md))
- **Issue text:** [`./filing/66-wp-empty-range-addition-shift-issue.md`](./filing/66-wp-empty-range-addition-shift-issue.md)
- **Merge request text:** [`./filing/66-wp-empty-range-addition-shift-mr.md`](./filing/66-wp-empty-range-addition-shift-mr.md)
- **Reproducer:** [`./repro/66-wp-empty-range-addition-shift.sh`](./repro/66-wp-empty-range-addition-shift.sh) + [`./repro/66-wp-empty-range-addition-shift.c`](./repro/66-wp-empty-range-addition-shift.c)
- **Patch:** [`./patches/66-wp-empty-range-addition-shift.patch`](./patches/66-wp-empty-range-addition-shift.patch)
- **Local `opam/` patch queue recommendation:** **YES (soundness)** — allows WP to prove `\valid(p)` and `assigns` clauses from empty `p + (0..n-1) + (0..1)` pointer ranges as well as false set memberships.

## Summary

Two sites in WP add or subtract integer ranges bound-by-bound using `Vset.bound_add` / `Vset.bound_sub` without checking whether either operand range can be empty (`a > b` or `c > d`):

1. **`plugins/wp/src/Vset.ml:362-363, 376-377` (`lift_add`, `lift_sub`):** proves `8 \in ((5..3) + (0..10))`, `-2 \in ((5..3) - (0..10))`, `0 \in ((..3) + (5..4))`, and `5 \in ((0..n-1) + (0..10))` under `n == 0`, while refuting `\subset((5..3) + (0..10), \empty)`.
2. **`plugins/wp/src/Cvalues.ml:804-808` (`shift_set`, sole external caller of `Vset.bound_add`):** under `n == 0`, reduces `\valid(p + (0..n-1) + (0..1))` to `valid_rw(Malloc_0, shift_sint32(p, 0), 1)` (proving `\valid(p)`) and proves `assigns *(p + (0..n-1) + (0..1))` for `*p = 1;` (while the singleton-shift control `*(p + (0..n-1) + 0)` gives `Prove: false.`).

## Standards and ground truth

ACSL Reference Manual: an integer range `t1..t2` with `t1 > t2` denotes `\empty`, and any operation lifted over `\empty` evaluates to `\empty`.

## Duplicate search

Live read-only `glab api` search across `pub/frama-c` (project `780`, issues and MRs, all states) for `Vset`, `lift_add`, `lift_sub`, `empty range`, `shift_set`, `Srange`, plus [`./pub-frama-c_work_items_2026-11-09.csv`](./pub-frama-c_work_items_2026-11-09.csv) and packages `01`-`50`: **0 duplicates** (`#2769`, `#2767`, `#2617` are closed and distinct; `#2832` overview).

## Fix and validation

- **Source changes (`plugins/wp/src/Vset.mli`, `Vset.ml`, `Cvalues.ml`):** expose `non_empty_range` and `is_non_empty_range` in `Vset`, fold two ranges directly to `Range`/`Srange` only when both are statically non-empty (`Yes`), return an empty range when either is statically empty (`No`), and otherwise emit a single-variable comprehension (`Descr`/`Sdescr`) guarded by `non_empty_range a b && non_empty_range c d`.
- **Regression test:** `plugins/wp/tests/wp_acsl/empty_range_add.i` (covering static empty ranges, open ranges, symbolic empty ranges, `shift_empty_valid`, `shift_empty_assigns`, and non-empty control `shift_nonempty_assigns`). Fails on unpatched `master` `189053d4a2`, passes patched.
- **Full WP suite:** `./dev/test.sh -p plugins/wp` passes with zero existing oracle changes.
- **Lint/headers:** `./dev/check-files.sh -p HEAD~1` passes; zero mode changes.
- **Reproducer:** exits `1` on stock `master` `189053d4a2` and stock `34.0~beta`, exits `0` (`RESULT: fixed`) after applying the patch.
