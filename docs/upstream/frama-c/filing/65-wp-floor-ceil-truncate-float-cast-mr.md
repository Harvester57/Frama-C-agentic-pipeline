# [wp] compute exact big-int floor/ceil/truncate on rational constants

- Source branch: `fix/wp-floor-ceil-truncate-float-cast` on the fork of `pub/frama-c`; target branch `master`.
- Based on: `189053d4a2`. Patch: [`../patches/65-wp-floor-ceil-truncate-float-cast.patch`](../patches/65-wp-floor-ceil-truncate-float-cast.patch)

<!-- Everything below this line is the merge request description. -->

Before submitting the merge request, please confirm (by adding a X in the [ ]):

- [ ] you contributed to Frama-C as prescribed in the [instructions](https://git.frama-c.com/pub/frama-c/-/blob/master/CONTRIBUTING.md).
- [ ] if the size of the PR requires it, you have signed the
  [Contributor Licensing Agreement](https://git.frama-c.com/pub/frama-c/-/blob/master/CLA.md)

Closes #<issue>.

## Problem

`Cmath.builtin_truncate` (`plugins/wp/src/Cmath.ml:42-61`) evaluated `\floor`, `\ceil`, `\truncate`, `(integer)` casts, and C float-to-integer casts (`Cint.of_real`) on constant rationals via `int_of_float (Q.to_float r)`. Rounding through IEEE 754 `double` lost precision near integers (proving `\floor(0.99999999999999999999) == 1` and `\floor(9007199254740993.5) == 9007199254740994`) and `int_of_float` wrapped silently or yielded unspecified values above `2^62` (proving `(long long)5e18 == -4223372036854775808`, `(unsigned long long)4611686018427387904.0f == 13835058055282163712ULL`, and `\floor(1e30) == 0`).

## Change

`plugins/wp/src/Cmath.ml` (7 lines added, 13 lines removed):

- Replace the `int_of_float (Q.to_float r)` path with exact arbitrary-precision Zarith operations guarded on `Q.is_real r`: `Z.fdiv r.Q.num r.Q.den` for `f_floor`, `Z.cdiv r.Q.num r.Q.den` for `f_ceil`, and `Q.to_bigint r` for `f_truncate`, returning `F.e_zint z`.

New test `plugins/wp/tests/wp_acsl/truncate_const.i` (1 oracle) covering near-integer rationals (positive and negative), large rationals above `2^53`, `1e30`, `(integer)` casts, and C `long long` / `unsigned long long` casts.

No existing oracle changes.

## Testing

All on Debian 13 (OCaml 5.5, Zarith 1.14, gcc 14.2.0), upstream `master` at `189053d4a2`:

- **Reproducer (16 goals: 8 false + 8 true across `\floor`, `\ceil`, `\truncate`, `(integer)`, `(long long)`, `(unsigned long long)`):**
  - Before (stock `master` `189053d4a2` and stock `34.0~beta`): 16 of 16 goals fail.
  - After (patched `master`): 16 of 16 goals pass (`RESULT: fixed`).
- **New test on unpatched `master`:** `plugins/wp/tests/wp_acsl/truncate_const.i` fails on unpatched `master` and passes with the patch.
- **ptests, default configuration:** `./dev/test.sh -p plugins/wp` passes with zero existing oracle diffs.
- **`./dev/check-files.sh -p HEAD~1`:** passes (`Lint 3 file(s)`).
- **Not run:** `make default-tests` outside `plugins/wp` and the WP `qualif` configuration (the change is local to `Cmath.builtin_truncate`).

The analysis and fix were prepared with LLM assistance; I reviewed them and ran the reproducer and tests described above.
