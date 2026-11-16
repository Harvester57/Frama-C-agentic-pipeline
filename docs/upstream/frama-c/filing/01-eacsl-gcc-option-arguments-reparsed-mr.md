# [e-acsl] e-acsl-gcc: do not read the words of option arguments as options

- Source branch: `fix/eacsl-gcc-option-arguments` on the fork of `pub/frama-c`; target branch `master`.
- Based on: `3dff90fc70`. Patch: [`../patches/01-eacsl-gcc-option-arguments-reparsed.patch`](../patches/01-eacsl-gcc-option-arguments-reparsed.patch)

<!-- Everything below this line is the merge request description. -->

Before submitting the merge request, please confirm (by adding a X in the [ ]):

- [ ] you contributed to Frama-C as prescribed in the [instructions](https://git.frama-c.com/pub/frama-c/-/blob/master/CONTRIBUTING.md).
- [ ] if the size of the PR requires it, you have signed the
  [Contributor Licensing Agreement](https://git.frama-c.com/pub/frama-c/-/blob/master/CLA.md)

Closes #2807.

## Problem

After getopt, `e-acsl-gcc` walks its options with an unquoted `for i in $@` (lines 442-444 of
`plugins/e-acsl/scripts/e-acsl-gcc`), while each `case` branch shifts the real positional
parameters. The words of an option argument are therefore matched against the option patterns
again: `-e "-g -O1"` turns on `-e-acsl-O-gmp-only` and drops an input file (or aborts),
`-E "-I inc"` and `-l "-L /usr/lib -lm"` fail with `no input files`.

## Change

- `plugins/e-acsl/scripts/e-acsl-gcc`: `while [ $# -gt 0 ]` with `case "$1"` instead of
  `for i in $@` with `case "$i"`. Every branch already shifts its option and its argument (I
  checked the 56 option branches, which cover every option of `SHORTOPTIONS` and `LONGOPTIONS`). A `--)` branch ends
  the loop and replaces the trailing `shift`. A `*)` branch reports an error: getopt puts every
  non-option after `--`, so it cannot be reached today, but it keeps the `while` loop from spinning
  if a future branch forgets to shift.
- New test `plugins/e-acsl/tests/special/e-acsl-gcc-option-arguments.c`: its `dev` run passes
  `-e -g` to `e-acsl-gcc` (`ROOT_EACSL_GCC_OPTS_EXT`). Before the fix it fails with
  `e-acsl-gcc: fatal error: no input files`. The default-configuration oracles are the usual
  `gen_*.0.c` and `.0.res.oracle` of an empty `main`.
- `plugins/e-acsl/doc/Changelog`: one entry.

## Testing

On master `3dff90fc70` (Debian 13, bash 5.2, util-linux getopt), built with the patch and
installed:

| Invocation | master | with the patch |
|---|---|---|
| `-n -E -Iinc -e "-g -O1" -o a.c main.c helper.c` | Frama-C gets `helper.c ... -e-acsl-O-gmp-only ... -ocode --`, aborts | Frama-C gets `main.c helper.c`, no GMP, `-ocode a.c` |
| `-n -o a.c -e "-g -O1" helper.c main.c` | exit 0, but Frama-C gets `main.c` only, with `-e-acsl-O-gmp-only` | exit 0, Frama-C gets `helper.c main.c`, no GMP |
| `-n -E "-I inc" -o b.c main.c` | `no input files` | builds |
| `-E -Iinc -e -Iinc -l "-L /usr/lib -lm" -o c.c -O c main.c` | `no input files` | builds and links; `c.e-acsl` exits 0 |

- ptests, E-ACSL `dev` configuration (`@plugins/e-acsl/tests/ptests_config_dev`, which runs
  `e-acsl-gcc` on every test, 196 tests with the new one): all pass. The new test failed before the
  fix (`no input files`).
- ptests, `special` directory, default configuration: pass (only the new test's oracles added).
- `git diff --check`: clean, except for the final empty line of the generated `gen_*.0.c` oracle,
  as in every existing oracle.
- The new test passes `clang-format-19 --dry-run` with `plugins/e-acsl/.clang-format`.
- `./dev/check-files.sh -p` (that is, `make check-lint` and `make check-headers` on the changed
  files) with ocp-indent 1.10.0 and clang-format 19.1.7: clean.

The analysis and fix were prepared with LLM assistance (Claude Code); I reviewed them and ran the
reproducer and tests described above.
