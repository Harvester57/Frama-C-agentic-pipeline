# [wp] preserve emptiness when adding or subtracting integer ranges

- Source branch: `fix/wp-empty-range-addition-shift` on the fork of `pub/frama-c`; target branch `master`.
- Based on: `189053d4a2`. Patch: [`../patches/66-wp-empty-range-addition-shift.patch`](../patches/66-wp-empty-range-addition-shift.patch)

<!-- Everything below this line is the merge request description. -->

Before submitting the merge request, please confirm (by adding a X in the [ ]):

- [ ] you contributed to Frama-C as prescribed in the [instructions](https://git.frama-c.com/pub/frama-c/-/blob/master/CONTRIBUTING.md).
- [ ] if the size of the PR requires it, you have signed the
  [Contributor Licensing Agreement](https://git.frama-c.com/pub/frama-c/-/blob/master/CLA.md)

Closes #<issue>.

## Problem

`Vset.lift_add` (`plugins/wp/src/Vset.ml:362-363`), `Vset.lift_sub` (`:376-377`), and `Cvalues.shift_set` (`plugins/wp/src/Cvalues.ml:804-808`, the sole external caller of `Vset.bound_add`) folded two integer ranges `(a..b)` and `(c..d)` bound-by-bound into `(a+c .. b+d)` (or `(a-d .. b-c)`) without checking whether either operand range could be empty (`a > b` or `c > d`). When one operand was empty (statically such as `5..3`, or symbolically such as `0 .. n-1` with `n == 0`), WP proved false set memberships (`8 \in ((5..3) + (0..10))`, `-2 \in ((5..3) - (0..10))`, `0 \in ((..3) + (5..4))`), refuted `\subset((5..3) + (0..10), \empty)`, derived `\valid(p)` from an empty `\valid(p + (0..n-1) + (0..1))` precondition, and proved an empty `assigns` clause for `*p = 1`.

## Change

`plugins/wp/src/Vset.mli`, `plugins/wp/src/Vset.ml`, and `plugins/wp/src/Cvalues.ml` (39 lines added, 3 lines removed):

- Add `Vset.non_empty_range` and `Vset.is_non_empty_range`.
- In `Vset.lift_add` and `Vset.lift_sub`, fold `Range(a,b)` and `Range(c,d)` to a single `Range` only when both ranges are statically non-empty (`Yes`); return an empty range when either is statically empty (`No`); otherwise emit a single-variable `Descr([k], k, ...)` guarded by `non_empty_range a b && non_empty_range c d`.
- In `Cvalues.shift_set`, fold `Srange` and `Vset.Range` to `srange` only when both ranges are statically non-empty, and otherwise emit a single-variable `Sdescr([k], M.shift l obj0 k, ...)` carrying the same non-emptiness guards.

New test `plugins/wp/tests/wp_acsl/empty_range_add.i` (1 oracle) covering static empty ranges, open ranges, symbolic empty range addition, pointer-shift `\valid` and `assigns` when empty, and a non-empty pointer-shift `assigns` control (still proved by Qed).

No existing oracle changes.

## Testing

All on Debian 13 (OCaml 5.5, Alt-Ergo 2.6.4), upstream `master` at `189053d4a2`:

- **Reproducer (8 checks covering `Vset` addition/subtraction, open ranges, `\subset(..., \empty)`, symbolic `n == 0`, and `Cvalues` pointer-shift `\valid` and `assigns`):**
  - Before (stock `master` `189053d4a2` and stock `34.0~beta`): 7 of 8 checks fail.
  - After (patched `master`): 8 of 8 checks pass (`RESULT: fixed`).
- **New test on unpatched `master`:** `plugins/wp/tests/wp_acsl/empty_range_add.i` fails on unpatched `master` and passes with the patch.
- **ptests, default configuration:** `./dev/test.sh -p plugins/wp` passes with zero existing oracle diffs.
- **`./dev/check-files.sh -p HEAD~1`:** passes (`Lint 5 file(s)`).
- **Not run:** `make default-tests` outside `plugins/wp` and the WP `qualif` configuration (offline cache).

The analysis and fix were prepared with LLM assistance; I reviewed them and ran the reproducer and tests described above.
