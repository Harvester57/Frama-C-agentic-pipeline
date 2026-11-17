# [e-acsl] monitor the arguments of format functions

- Source branch: `fix/eacsl-format-mtracking` on the fork of `pub/frama-c`; target branch `master`.
- Based on: `95408044f7`. Patch: [`../patches/33-eacsl-format-literal-without-full-mtracking.patch`](../patches/33-eacsl-format-literal-without-full-mtracking.patch)

<!-- Everything below this line is the merge request description. -->

Before submitting the merge request, please confirm (by adding a X in the [ ]):

- [ ] you contributed to Frama-C as prescribed in the [instructions](https://git.frama-c.com/pub/frama-c/-/blob/master/CONTRIBUTING.md).
- [ ] if the size of the PR requires it, you have signed the
  [Contributor Licensing Agreement](https://git.frama-c.com/pub/frama-c/-/blob/master/CLA.md)

Closes #<issue>.

## Problem

With `-e-acsl-validate-format-strings` and without `-e-acsl-full-mtracking`, every call to a
format function aborts with `invalid format string (unallocated or unterminated)`: the memory
tracking analysis does not monitor the format string, nor the strings and pointers passed for
`"%s"`, `"%p"` and `"%n"`, all of which the RTL replacement checks. The example of the user manual
is affected. The `format/` and `builtin/` `dev` configurations work around it with
`--full-mtracking` ("Remove --full-mtracking once e-acsl#118 is fixed").

## Change

`plugins/e-acsl/src/analyses/memory_tracking.ml`, `do_call`: when
`Options.Validate_format_strings.get ()` holds and the callee is a format function
(`Functions.Libc.is_printf_name`), the base variable of every pointer or array argument is added to
the monitored set (`Varinfos.add`, which also demotes string literals). This is the rule the
analysis already applies to the actuals of a function whose formals are monitored, and it
propagates backwards: a pointer or a formal passed for `"%s"` makes the array behind it monitored.

Nothing changes without `-e-acsl-validate-format-strings`, nor with `-e-acsl-full-mtracking` (the
analysis is not consulted then; the code that `e-acsl-gcc -M --validate-format-strings` generates
for `printf.c`, `fprintf.c` and `sprintf.c` is byte-identical before and after).

Oracles: `format/test_config` (default configuration) does not use `-e-acsl-full-mtracking`, so
`oracle/gen_printf.0.c`, `gen_fprintf.0.c` and `gen_sprintf.0.c` now monitor the literals and
locals passed to the format functions (`__e_acsl_store_block`, `__e_acsl_full_init`,
`__e_acsl_mark_readonly`, `__e_acsl_delete_block`). Their `.res.oracle` files and the `dev` oracles
do not change.

New test `format/printf_mtracking.c`, run without `--full-mtracking` in the `dev` configuration too
(it overrides `ROOT_EACSL_GCC_OPTS_EXT`): literal formats and arguments, a local array passed
directly, through a pointer, a struct field and a formal, `"%n"` and `"%p"`, which pass; the
manual's type error and three unterminated arrays (directly, through a pointer, through a formal),
which abort. I left `--full-mtracking` in `format/test_config_dev`; removing it would run the whole
directory without it, which I have not tried.

The generated-code oracles of new `format/` tests made without this change gain the same monitoring
code: if the merge requests for #ISSUE-30, #ISSUE-31 or #ISSUE-32 land first, their
`gen_printf_promoted.0.c`, `gen_printf_fp_args.0.c` and `gen_printf_star.0.c` need regenerating,
or theirs after this one. The patches apply together in any order (`git am --3way`).

## Testing

All on Debian 13 (gcc 14.2.0, x86_64), `master` at `95408044f7` built with dune, then the same tree
with this patch:

- Reproducer from #<issue> (`ip.c`, `e-acsl-gcc -q -c -G gcc --validate-format-strings`) and its
  cases. Before: every case aborts with `invalid format string (unallocated or unterminated)`.
  After: `ip.c` prints `192.168.1.200`; a local array, a pointer to it, a formal and `"%n"` run;
  the manual's example aborts with
  `directive 1 ('%d') expects argument of type 'int' but the corresponding argument has type 'char*'`;
  unterminated arrays abort with `unterminated string in directive 1 ('%s')`. Same results as with
  `-M`, before and after.
- The new test fails on unpatched `master` in both configurations: the default one differs from
  `gen_printf_mtracking.0.c`, and the `dev` one aborts before its first report (the harness's own
  `fprintf` fails too: `fprintf: invalid format string (unallocated or unterminated)`). With the
  patch both pass (12 sub-tests, 4 of them expected aborts).
- `frama-c-ptests -create-missing-oracles plugins/e-acsl/tests`, then
  `dune build --release -j 6 @plugins/e-acsl/tests/format/ptests_config`: all 4 tests of `format/`
  pass with the regenerated oracles. In the `dev` configuration I ran `printf_mtracking.c` and
  `fprintf.c`: both match. Not run: the `dev` configuration of `printf.c` and `sprintf.c` (their
  instrumented code with `-M` is identical, see above), and the other directories (only `format/`
  uses `--validate-format-strings`).
- `./dev/check-files.sh -p HEAD~1` (ocp-indent 1.10.0, clang-format 19.1.7, headache) passes.
- With the patches for #ISSUE-30, #ISSUE-31 and #ISSUE-32 applied too: the `dev` configuration of
  the four new tests and `fprintf.c` pass; the default configuration fails only on the three
  generated-code oracles named above.

The analysis and fix were prepared with LLM assistance (Claude Code); I reviewed them and ran the
reproducer and tests described above.
