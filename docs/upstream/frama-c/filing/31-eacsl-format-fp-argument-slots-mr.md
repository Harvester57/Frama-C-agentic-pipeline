# [e-acsl] read each format argument with its own type

- Source branch: `fix/eacsl-format-fp-args` on the fork of `pub/frama-c`; target branch `master`.
- Based on: `3dff90fc70`; re-validated on `95408044f7` (2026-11-17), the base to branch from. Patch: [`../patches/31-eacsl-format-fp-argument-slots.patch`](../patches/31-eacsl-format-fp-argument-slots.patch)

<!-- Everything below this line is the merge request description. -->

Before submitting the merge request, please confirm (by adding a X in the [ ]):

- [ ] you contributed to Frama-C as prescribed in the [instructions](https://git.frama-c.com/pub/frama-c/-/blob/master/CONTRIBUTING.md).
- [ ] if the size of the PR requires it, you have signed the
  [Contributor Licensing Agreement](https://git.frama-c.com/pub/frama-c/-/blob/master/CLA.md)

Closes #2820.

## Problem

With `--validate-format-strings`, `validate_format`
(`plugins/e-acsl/share/e-acsl/libc_replacements/e_acsl_stdio.c`) reads every variadic argument with
`va_arg(ap, void *)`. On x86_64 a `double` is passed in an SSE register and a `long double` in
memory, so the read meant for such an argument takes the next pointer, and every later `"%s"`,
`"%p"` or `"%n"` is checked against the argument after its own:

- `snprintf(t, sizeof t, "%f %s", 1.5, "abc")` aborts with
  `attempt to access unallocated memory via directive 2 ('%s')`;
- an unterminated string for `"%s"` after a `double` is reported on the wrong directive, or not at
  all when a valid string follows it.

On a 32-bit target (`--mbits 32`), a `double` or a `long long` would shift the arguments the same way.

## Change

`validate_format` reads each argument with the type given by the format description that the
instrumentation passes (`fmtdesc`): the pointer letters as `void *` (the only values it keeps),
`e`/`f` as `double`, `E` as `long double`, `l`/`L` as `long`, `r`/`R` as `long long`, and every other
letter as `int` (`int`, `unsigned int` and the types promoted to `int`). The instrumentation is not
changed.

New test `format/printf_fp_args.c`: `"%s"`, `"%p"` and `"%n"` after a `double` or a `long double`,
mixed with `int`, `long` and `long long` arguments, nine `double`s (so that the last one is passed on
the stack), and two invalid strings after a `double` that must be reported on their own directive
(`unterminated string in directive 2 ('%s')`), one of them followed by a valid string.

The new test includes `utils/signalled.h`, whose `signal_eval` has formals: if !28 (#2797, formals
marked initialized) lands first, `oracle/gen_printf_fp_args.0.c` needs regenerating (it gains
`__e_acsl_full_init((void *)(& status));`, as `gen_printf.0.c` does in !28).

This merge request and the one for #2819 (promoted `unsigned char` for `"%u"`) both change
`e_acsl_stdio.c`, in different functions, and add different test files: each applies alone on
`3dff90fc70`, and the two apply together in either order (`git am --3way`).

## Testing

All on Debian 13 (gcc 14.2.0, x86_64), `master` at `3dff90fc70` built with dune, then the same tree
with this patch:

- Reproducer from #2820 (`dbl.c`, `e-acsl-gcc -c -M -G gcc --validate-format-strings`) and the
  issue's other cases. Before: `dbl.c`, `"%Lf %s"` and `"%f%n"` abort on a valid argument,
  `"%f %s %s"` with an unterminated first string aborts on directive 3, and `"%f %s"` with the
  unterminated string and a spare valid one runs. After: the first three run (`dbl.c` prints
  `1.500000 abc`), and both unterminated-string cases abort with
  `unterminated string in directive 2 ('%s')`.
- The new test `format/printf_fp_args.c` fails on unpatched `master` in the `dev` configuration
  (`TEST 1: FAIL: Unexpected signal at printf_fp_args.c:24`) and passes with the patch (9
  sub-tests, 2 of them expected aborts). Its default-configuration oracles are the same before and
  after, since the instrumentation is not changed.
- `frama-c-ptests -create-missing-oracles plugins/e-acsl/tests`, then
  `dune build --release -j 8 @plugins/e-acsl/tests/format/ptests_config`: all 4 tests of `format/`
  pass. In the `dev` configuration I ran `printf_fp_args.c`, `printf.c` and `fprintf.c` one by one
  (core dumps disabled by `ulimit -c 1`; `printf.c` takes 12 minutes on my host): all match their
oracles, so no existing oracle changes. Not run: the `dev` configuration of
  `sprintf.c`, and the other E-ACSL test directories (the runtime function changed is only compiled
  with `--validate-format-strings`).
- Not tested on a 32-bit target (no 32-bit libc on my host).
- With the patch for #2819 applied too: the default configuration of `format/`, and the `dev`
  configuration of both new tests and `fprintf.c`, pass; a mixed call
  `snprintf(t, n, "%f %u %s %Lf %x %s", 1.5, uc, s, 2.5L, us, s)` prints
  `1.500000 200 abc 2.500000 ea60 abc`.
- `./dev/check-files.sh -p HEAD~1` (`make check-lint` and `make check-headers` on the changed files,
  with ocp-indent 1.10.0, headache 1.08 and clang-format 19.1.7) passes on a clone holding this
  commit; the new test is clang-formatted.
- The patch applies with `git am` on `3dff90fc70` alone, before or after the patch for #2819,
  and on top of the patches of my other reports applied in sequence (!25 to !45, and the one
  proposed in #2816), with `git am --3way`.
- Rerun on current `master` (`95408044f7`): the patch applies with `git am`; the reproducer gives the
  same results before and after; the new test fails on the unpatched sources in the `dev`
  configuration and passes with the patch; the default configuration of the whole E-ACSL suite (198
  results) and `./dev/check-files.sh -p HEAD~1` pass. With the patch for #2819 applied too, the
  `dev` configuration of all of `format/` (`fprintf.c`, `printf.c`, `sprintf.c` and the two new
  tests) and the default configuration of the whole E-ACSL suite pass, which covers the runs listed
  as not run above (32-bit targets excepted).

The analysis and fix were prepared with LLM assistance (Claude Code); I reviewed them and ran the
reproducer and tests described above.
