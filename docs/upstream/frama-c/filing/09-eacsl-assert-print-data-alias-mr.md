# [e-acsl] fix the target of deprecated alias -e-acsl-assert-print-data

- Source branch: `fix/eacsl-assert-print-data-alias` on the fork of `pub/frama-c`; target branch `master`.
- Based on: `3dff90fc70`. Patch: [`../patches/09-eacsl-assert-print-data-alias.patch`](../patches/09-eacsl-assert-print-data-alias.patch)

<!-- Everything below this line is the merge request description. -->

Before submitting the merge request, please confirm (by adding a X in the [ ]):

- [ ] you contributed to Frama-C as prescribed in the [instructions](https://git.frama-c.com/pub/frama-c/-/blob/master/CONTRIBUTING.md).
- [ ] if the size of the PR requires it, you have signed the
  [Contributor Licensing Agreement](https://git.frama-c.com/pub/frama-c/-/blob/master/CLA.md)

Closes #2808.

## Problem

The deprecated option `-e-acsl-assert-print-data` is registered as an alias of `Verify_valid`
(`-e-acsl-O-valid`) instead of `Print_values` (`-e-acsl-O-print-values`), at
`plugins/e-acsl/src/options.ml:212`. A command line that still uses the old option re-instruments
annotations that other analyses already proved, `-e-acsl-no-assert-print-data` does not turn value
printing off, and the deprecation warning points users to the wrong option.

## Change

- `plugins/e-acsl/src/options.ml`: `Print_values.add_aliases` instead of `Verify_valid.add_aliases`
  for `-e-acsl-assert-print-data`. This is what the old option did, and what
  `e-acsl-gcc --assert-print-data` already maps to.
- `plugins/e-acsl/tests/special/e-acsl-no-assert-print-data.c`: a second default-configuration run
  with the deprecated `-e-acsl-no-assert-print-data`. Its new oracle `gen_*.1.c` is identical to
  the `gen_*.0.c` of the `-e-acsl-O-no-print-values` run; before the fix it had two more lines
  (`__e_acsl_assert_register_int` and `__e_acsl_assert_clean`). The `.1.res.oracle` records the
  corrected deprecation warning. The run header keeps its line count, so the existing `.0` oracles
  do not change.
- `plugins/e-acsl/doc/Changelog`: one entry.

## Testing

On master `3dff90fc70` (Debian 13, OCaml 5.5 switch), built with the patch and installed:

| Check | master | with the patch |
|---|---|---|
| warning for `-e-acsl-assert-print-data` | `alias for option -e-acsl-O-valid` | `alias for option -e-acsl-O-print-values` |
| warning for `-e-acsl-no-assert-print-data` | `alias for option -e-acsl-O-no-valid` | `alias for option -e-acsl-O-no-print-values` |
| `__e_acsl_assert_register_*` calls: default / `-e-acsl-O-no-print-values` / `-e-acsl-no-assert-print-data` | 2 / 0 / 2 | 2 / 0 / 0 |
| `__e_acsl_assert(` calls after WP: default / `-e-acsl-O-valid` / `-e-acsl-assert-print-data` | 0 / 2 / 2 | 0 / 2 / 0 |
| new `special/e-acsl-no-assert-print-data.1` run | `gen_*.1.c` differs from `gen_*.0.c` | identical |
| ptests `plugins/e-acsl/tests`, default configuration (`@plugins/e-acsl/tests/ptests_config`, 198 results) | | pass, no oracle change besides the two new ones |

- `git diff --check`: clean, except for the two generated oracles (trailing space after `Warning:`
  and the final empty line, as in every existing oracle).
- New and changed test files pass `clang-format-19 --dry-run` with `plugins/e-acsl/.clang-format`.
- `./dev/check-files.sh -p` (that is, `make check-lint` and `make check-headers` on the changed
  files) with ocp-indent 1.10.0 and clang-format 19.1.7: clean.

The analysis and fix were prepared with LLM assistance (Claude Code); I reviewed them and ran the
reproducer and tests described above.
