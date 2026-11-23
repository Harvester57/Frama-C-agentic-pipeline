# [wp] catch Failure when parsing strategy prover timeouts

- Source branch: `fix/wp-strategy-timeout-exception` on the fork of `pub/frama-c`; target branch `master`.
- Based on: `189053d4a2`. Patch: [`../patches/69-wp-strategy-timeout-exception.patch`](../patches/69-wp-strategy-timeout-exception.patch)

<!-- Everything below this line is the merge request description. -->

Before submitting the merge request, please confirm (by adding a X in the [ ]):

- [ ] you contributed to Frama-C as prescribed in the [instructions](https://git.frama-c.com/pub/frama-c/-/blob/master/CONTRIBUTING.md).
- [ ] if the size of the PR requires it, you have signed the
  [Contributor Licensing Agreement](https://git.frama-c.com/pub/frama-c/-/blob/master/CLA.md)

Closes #<issue>.

## Problem

In `plugins/wp/src/ProofStrategy.ml` (`parse_provers`, lines 158-169), both `int_of_string` and `float_of_string` were wrapped with `with Invalid_argument _` to emit `"Invalid timeout"`. Because OCaml's `int_of_string` and `float_of_string` raise `Failure _`, any `strategy` prover timeout with a suffix (`2u`, `2.5f`) or overflowing integer (`99999999999999999999`) aborted Frama-C with an internal error (exit 4) instead of a clean annotation error (exit 1).

## Change

`plugins/wp/src/ProofStrategy.ml` (4 lines changed):

- Catch `Failure _` instead of `Invalid_argument _` around `int_of_string` and `float_of_string`.
- Reject non-finite float timeouts (`not (Float.is_finite time) || time < 0.0`).

New test `plugins/wp/tests/wp_acsl/strategy_timeout.c` (3 runs: `2u`, `2.5f`, `99999999999999999999`; 3 oracles, `EXIT: 1`).

No existing oracle changes.

## Testing

All on Debian 13 (OCaml 5.5, gcc 14.2.0), upstream `master` at `189053d4a2`:

- **Reproducer (3 cases: `2u`, `2.5f`, `99999999999999999999`):**
  - Before (stock `master` `189053d4a2` and stock `34.0~beta`): 3 of 3 cases abort with exit 4 internal error.
  - After (patched `master`): 3 of 3 cases exit 1 with `Invalid timeout` (`RESULT: fixed`).
- **New test on unpatched `master`:** `plugins/wp/tests/wp_acsl/strategy_timeout.c` fails on unpatched `master` (exit 4) and passes with the patch (exit 1).
- **ptests, default configuration:** `./dev/test.sh -p plugins/wp` passes with zero existing oracle diffs.
- **`./dev/check-files.sh -p HEAD~1`:** passes (`Lint 5 file(s)`).
- **Not run:** `make default-tests` outside `plugins/wp`.

The analysis and fix were prepared with LLM assistance; I reviewed them and ran the reproducer and tests described above.
