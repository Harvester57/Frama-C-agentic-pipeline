# [wp] reject -wp-par values below 1 at option parsing time

- Source branch: `fix/wp-par-range-check` on the fork of `pub/frama-c`; target branch `master`.
- Based on: `189053d4a2`. Patch: [`../patches/71-wp-par-range-check.patch`](../patches/71-wp-par-range-check.patch)

<!-- Everything below this line is the merge request description. -->

Before submitting the merge request, please confirm (by adding a X in the [ ]):

- [ ] you contributed to Frama-C as prescribed in the [instructions](https://git.frama-c.com/pub/frama-c/-/blob/master/CONTRIBUTING.md).
- [ ] if the size of the PR requires it, you have signed the
  [Contributor Licensing Agreement](https://git.frama-c.com/pub/frama-c/-/blob/master/CLA.md)

Closes #<issue>.

## Problem

`Wp_parameters.Procs` (`-wp-par`, `plugins/wp/src/wp_parameters.ml:862-870`) had no range constraint, so `-wp-par 0` and negative values passed option parsing (and `wpApi.ml:139`) and crashed in Why3's `Prove_client.set_max_running_provers` with `Unexpected error (Invalid_argument("Prove_client.set_max_running_provers"))` (exit code 125).

## Change

`plugins/wp/src/wp_parameters.ml` (2 lines added):

- Add `let () = Procs.set_range ~min:1 ~max:max_int`.

New test `plugins/wp/tests/wp_acsl/par_range.i` (2 runs: `-wp-par 0` and `-wp-par -1`; 2 oracles, `EXIT: 1`).

No existing oracle changes.

## Testing

All on Debian 13 (OCaml 5.5, gcc 14.2.0, Alt-Ergo 2.6.4), upstream `master` at `189053d4a2`:

- **Reproducer (`-wp-par 0`, `-wp-par -1`, and valid control `-wp-par 1`):**
  - Before (stock `master` `189053d4a2` and stock `34.0~beta`): `0` and `-1` crash with exit 125 (2 of 3 cases fail).
  - After (patched `master`): `0` and `-1` exit 1 with `[wp] User Error: argument of -wp-par must be at least 1.` and `1` exits 0 (`RESULT: fixed`).
- **New test on unpatched `master`:** `plugins/wp/tests/wp_acsl/par_range.i` fails on unpatched `master` (exit 125) and passes with the patch (exit 1).
- **ptests, default configuration:** `./dev/test.sh -p plugins/wp` passes with zero existing oracle diffs.
- **Stacking with `-wp-time-margin` validation in `wp_parameters.ml`:** verified clean `git am --3way --keep-non-patch` in both orders with both tests passing.
- **`./dev/check-files.sh -p HEAD~1`:** passes (`Lint 4 file(s)`).
- **Not run:** `make default-tests` outside `plugins/wp`.

The analysis and fix were prepared with LLM assistance; I reviewed them and ran the reproducer and tests described above.
