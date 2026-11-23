# [wp] validate -wp-time-margin as a finite non-negative float and fix manual default

- Source branch: `fix/wp-time-margin-validation` on the fork of `pub/frama-c`; target branch `master`.
- Based on: `189053d4a2`. Patch: [`../patches/70-wp-time-margin-validation.patch`](../patches/70-wp-time-margin-validation.patch)

<!-- Everything below this line is the merge request description. -->

Before submitting the merge request, please confirm (by adding a X in the [ ]):

- [ ] you contributed to Frama-C as prescribed in the [instructions](https://git.frama-c.com/pub/frama-c/-/blob/master/CONTRIBUTING.md).
- [ ] if the size of the PR requires it, you have signed the
  [Contributor Licensing Agreement](https://git.frama-c.com/pub/frama-c/-/blob/master/CLA.md)

Closes #<issue>.

## Problem

`Wp_parameters.TimeMargin` (`-wp-time-margin`) was declared as a `String` parameter (`plugins/wp/src/wp_parameters.ml:846-857`, `.mli:116`) and parsed lazily via unguarded `float_of_string` in `VCS.ml:132` and `ProofEngine.ml:598`. Passing `-wp-time-margin 1s` (invited by `plugins/wp/doc/manual/wp_plugin.tex:1441`, which stated `Default is 5s.` while the code defaulted to `"0.5"`) crashed after provers ran with `Unexpected error (Failure("float_of_string"))` (exit 125), while `nan`, `inf`, and `-1` were accepted silently.

## Change

- `plugins/wp/src/wp_parameters.ml` and `wp_parameters.mli`: change `TimeMargin` from `String` to `Float` (`default = 0.5`), set `TimeMargin.set_range ~min:0.0 ~max:infinity`, and add a set-hook rejecting non-finite floats (`not (Stdlib.Float.is_finite f)`).
- `plugins/wp/src/VCS.ml:132` and `plugins/wp/src/ProofEngine.ml:598`: read `Wp_parameters.TimeMargin.get ()` directly without `float_of_string`.
- `plugins/wp/doc/manual/wp_plugin.tex:1441`: update `Default is \verb+5s+.` to `Default is \verb+0.5+ seconds.`.
- `tests/misc/oracle/help-messages.32.res.oracle`: remove the string-option `(preferably use -wp-time-margin="n")` hint from `-wp-help`.
- New test `plugins/wp/tests/wp_acsl/time_margin.i` (4 runs: `1s`, `nan`, `inf`, `-1`; 4 oracles, `EXIT: 1`).

No other existing oracle changes.

## Testing

All on Debian 13 (OCaml 5.5, gcc 14.2.0, Alt-Ergo 2.6.4), upstream `master` at `189053d4a2`:

- **Reproducer (`1s`, `nan`, `inf`, `-1`, plus valid control `0.25`):**
  - Before (stock `master` `189053d4a2` and stock `34.0~beta`): `1s` crashes with exit 125, `nan` and `inf` silently exit 0 (3 of 5 cases fail).
  - After (patched `master`): all 4 invalid values exit 1 with a clean `User Error` and `0.25` exits 0 (`RESULT: fixed`).
- **New test on unpatched `master`:** `plugins/wp/tests/wp_acsl/time_margin.i` fails on unpatched `master` and passes with the patch.
- **ptests, default configuration:** `plugins/wp/tests/wp_acsl/time_margin.i` and `tests/misc/help-messages.i` pass with the updated oracle.
- **`./dev/check-files.sh -p HEAD~1`:** passes (`Lint 11 file(s)`).
- **Not run:** LaTeX manual build (no LaTeX in container) and `make default-tests` outside `plugins/wp` and `tests/misc/help-messages.i`.

The analysis and fix were prepared with LLM assistance; I reviewed them and ran the reproducer and tests described above.
