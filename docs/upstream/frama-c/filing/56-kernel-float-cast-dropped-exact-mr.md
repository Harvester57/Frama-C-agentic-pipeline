# [kernel] check value preservation for target fkind in Cil.isExactFloat

- Source branch: `fix/kernel-float-cast-dropped-exact` on the fork of `pub/frama-c`; target branch `master`.
- Based on: `189053d4a2`. Patch: [`../patches/56-kernel-float-cast-dropped-exact.patch`](../patches/56-kernel-float-cast-dropped-exact.patch)

<!-- Everything below this line is the merge request description. -->

Before submitting the merge request, please confirm (by adding a X in the [ ]):

- [ ] you contributed to Frama-C as prescribed in the [instructions](https://git.frama-c.com/pub/frama-c/-/blob/master/CONTRIBUTING.md).
- [ ] if the size of the PR requires it, you have signed the
  [Contributor Licensing Agreement](https://git.frama-c.com/pub/frama-c/-/blob/master/CLA.md)

Closes #<issue>.

## Problem

`Cil.isExactFloat` (`src/kernel/services/ast_queries/cil.ml:2494-2495`) checked only
`r.r_upper = r.r_lower && isFiniteFloat fk r.r_nearest`. For `fk = FFloat` and a literal that is
exact as a `double` but not as a `float` (such as `16777217.0` or `1e11`), `isExactFloat` returned
`true`, causing `Logic_utils.numeric_coerce` (`logic_utils.ml:332-333`) to strip the `(float)`
cast. WP then proved false equalities such as `(float)16777217.0 == 16777217.0`, and Eva marked
true assertions invalid, stopping propagation and hiding downstream alarms.

## Change

- `src/kernel/services/ast_queries/cil.ml` (`isExactFloat`, 3 insertions, 1 deletion): round
  `r.r_nearest` with `Floating_point.round_if_single_precision fk` and require both
  `Floating_point.is_finite f` and `Float.equal f r.r_nearest`.
- New test `tests/spec/float_cast_exact.c` with 2 oracles (`-print` and `-eva`), verifying that
  exact `(float)16777216.0` is still simplified, inexact `(float)16777217.0`, `(float)2147483647.0`,
  and `(float)1e11` retain their casts, Eva validates all 4 assertions and reports the downstream
  division-by-zero alarm.
- Zero existing oracle changes.

## Testing

All on Debian GNU/Linux 13 (trixie; OCaml 5.5, glibc 2.41, gcc 14.2.0), upstream `master` at
`189053d4a2`:

- **New test on unpatched `master`:** `tests/spec/float_cast_exact.c` fails on both runs (`(float)`
  cast stripped in `-print`; true checks invalid and 0 alarms in `-eva`). With the patch, both runs
  pass.
- **ptests, default configuration:** `./dev/test.sh -p tests/spec tests/syntax tests/cil` passes
  with zero diffs on any existing oracle.
- **`./dev/check-files.sh -p HEAD~1`:** passes (`Lint 4 file(s)`).
- **Standalone reproducer:** flips from `RESULT: bug present (3 of 3 checks fail)` (on both
  `master` `189053d4a2` and `34.0~beta`) to `RESULT: fixed` with the patch installed.
- **Not run:** `make default-tests` outside `tests/spec`, `tests/syntax`, and `tests/cil` (the
  only other caller of `Cil.isExactFloat` is `plugins/aorai/src/aorai_utils.ml:393`, which expects
  exactness in `fk`).

The analysis and fix were prepared with LLM assistance; I reviewed them and ran the reproducer and
tests described above.
