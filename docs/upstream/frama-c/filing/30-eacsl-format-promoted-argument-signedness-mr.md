# [e-acsl] accept a promoted unsigned char or short for %u and %x

- Source branch: `fix/eacsl-format-promoted` on the fork of `pub/frama-c`; target branch `master`.
- Based on: `3dff90fc70`. Patch: [`../patches/30-eacsl-format-promoted-argument-signedness.patch`](../patches/30-eacsl-format-promoted-argument-signedness.patch)

<!-- Everything below this line is the merge request description. -->

Before submitting the merge request, please confirm (by adding a X in the [ ]):

- [ ] you contributed to Frama-C as prescribed in the [instructions](https://git.frama-c.com/pub/frama-c/-/blob/master/CONTRIBUTING.md).
- [ ] if the size of the PR requires it, you have signed the
  [Contributor Licensing Agreement](https://git.frama-c.com/pub/frama-c/-/blob/master/CLA.md)

Closes #<issue>.

This is option 1 of the issue (static). It keeps the strict reading of `format/printf.c` for `int`
against `unsigned int`; the issue asks whether you want that case relaxed too (option 2).

## Problem

With `--validate-format-strings`, `Functions.Libc.get_printf_argument_str` describes each variadic
argument by one letter of its type, and the runtime (`validate_format_type`,
`plugins/e-acsl/share/e-acsl/libc_replacements/e_acsl_stdio.c`) requires that letter to equal the
type the directive expects. An `unsigned char`, `unsigned short` or `_Bool` argument reaches the
instrumentation promoted to `int`, so it is described as `int`, and `"%u"`, `"%o"`, `"%x"` and `"%X"`
reject it:

```text
snprintf: directive 1 ('%u') expects argument of type 'unsigned int' but the corresponding argument has type 'int'
```

Every value of these types is representable in both `int` and `unsigned int` (C11 7.16.1.1p2), and
the runtime already accepts the same argument for `"%hhu"`.

## Change

- `plugins/e-acsl/src/libraries/functions.ml`, `get_printf_argument_str`: an argument that is a cast
  to `int` of an expression of type `unsigned char`, `unsigned short` or `_Bool` (or `char` where
  `Machine.char_is_unsigned ()`) is described by that type: `C` (`unsigned char`, also used for
  `_Bool` and an unsigned `char`) or `H` (`unsigned short`). Both letters were already defined in the
  runtime's table of abbreviated types but never generated. Signed types smaller than `int` keep `d`.
- `e_acsl_stdio.c`: new function `compatible_abbr`, used by `validate_format_type`: `C` and `H` are
  accepted where `int` or `unsigned int` is expected
  (`[di]` and `[ouxX]` without a length modifier, `%c`, `%hh*`, `%h*`, and `%lc` with a 32-bit
  `wint_t`). Anywhere else they are rejected as before, and the message names the argument's own
  type: `expects argument of type 'unsigned long' but the corresponding argument has type 'unsigned char'`.

The rule, stated once: an argument whose type before promotion is unsigned and smaller than `int`
matches both `int` and `unsigned int`; a signed one matches `int` only (a negative value is not
representable in `unsigned int`), as today; `int` and `unsigned int` stay distinct. This is the rule
gcc applies with `-Wformat-signedness`.

Consequences to know about:

- `_Bool` reuses `C` rather than a new letter: a new entry in the table at the top of
  `e_acsl_stdio.c` would shift the `e_acsl_stdio.c:549` line number printed in 85 lines of
  `oracle_dev/printf.0.e-acsl.err.log`. So a rejected `_Bool` is named `'unsigned char'`
  (`printf("%lu\n", b)`: `expects argument of type 'unsigned long' but the corresponding argument has type 'unsigned char'`).
  A new letter is easy to add if you prefer.
- The plain `char` branch (`Machine.char_is_unsigned ()`) is not exercised: on the machdeps where
  E-ACSL instruments (`x86_64`, `macos_arm`), `char` is signed and keeps `d`; with `ppc_32` or
  `x86_16`, E-ACSL's own `e_acsl.h` does not parse ("Array length is too large").
- CIL does not distinguish the implicit promotion from a cast written by the user, so
  `printf("%u", (int)uc)` is accepted too. Its value is still in `0..255`, so this is sound.
- A bit-field `unsigned b : 3` is typed `unsigned int` by the kernel (`(unsigned int)v.b`), so it is
  described as `D`, as before: `"%u"` accepts it and `"%d"` rejects it. Not changed here.

New test `format/printf_promoted.c`: `unsigned char`, `unsigned short` and `_Bool` with `[ouxX]`,
`[di]`, `%c`, `%hh*` and `%h*`, the `"%u.%u.%u.%u"` call from the issue, and an explicit cast to
`unsigned char`, which pass; a negative `signed char` and `short` with `"%u"`/`"%x"`, `"%u"` with an
`int`, `"%d"` with an `unsigned int`, and a promoted byte with `"%lu"` and `"%llx"`, which still abort.

No existing oracle changes: `format/printf.c` only passes signed `char` and `short` (`chr`, `shrt`),
which keep `d`, so `oracle/gen_printf.0.c` is byte-identical.

The new test includes `utils/signalled.h`, whose `signal_eval` has formals: if !28 (#2797, formals
marked initialized) lands first, `oracle/gen_printf_promoted.0.c` needs regenerating (it gains
`__e_acsl_full_init((void *)(& status));`, as `gen_printf.0.c` does in !28).

This merge request and the one for #ISSUE-31 (`%s` after a `double`) both change `e_acsl_stdio.c`,
in different functions, and add different test files: each applies alone on `3dff90fc70`, and the two
apply together in either order (`git am --3way`).

## Testing

All on Debian 13 (gcc 14.2.0), `master` at `3dff90fc70` built with dune, then the same tree with this
patch:

- Reproducer from #<issue> (`ntop.c`, `e-acsl-gcc -c -M -G gcc --validate-format-strings`) and the
  issue's other cases. Before: every case aborts except `"%hhu"`. After: `ntop.c` prints
  `192.168.1.200` (exit 0), `"%x"` with an `unsigned char` and `"%u"` with an `unsigned short` print
  their value; `"%u"` with `signed char -1`, `"%u"` with an `int` and `"%d"` with an `unsigned int`
  still abort with the same message. The format description strings in the generated code go from
  `"d"` to `"C"` / `"H"` for the unsigned small types only.
- The new test `format/printf_promoted.c` fails on unpatched `master` in both configurations: the
  default one differs from the new `gen_printf_promoted.0.c` (`"dddd"` instead of `"CCCC"`, etc.),
  and the `dev` one stops at `TEST 1: FAIL: Unexpected signal at printf_promoted.c:26`. With the
  patch it passes in both (14 sub-tests, 6 of them expected aborts).
- `frama-c-ptests -create-missing-oracles plugins/e-acsl/tests`, then
  `dune build --release -j 8 @plugins/e-acsl/tests/format/ptests_config`: all 4 tests of `format/`
  pass, so `oracle/gen_printf.0.c` is unchanged. In the `dev` configuration I ran `printf.c`,
  `fprintf.c` and `printf_promoted.c` one by one (`printf.c` takes 14 minutes on my host with core
  dumps disabled by `ulimit -c 1`): all match their oracles, so `oracle_dev/printf.0.e-acsl.err.log`
  is unchanged too. Not run: the `dev` configuration of `sprintf.c`, and the other E-ACSL test
  directories (the change only affects programs built with `--validate-format-strings`, which only
  `format/` uses).
- With the patch for #ISSUE-31 applied on top: the default configuration of `format/`, and the `dev`
  configuration of both new tests and `fprintf.c`, pass; a mixed call
  `snprintf(t, n, "%f %u %s %Lf %x %s", 1.5, uc, s, 2.5L, us, s)` prints
  `1.500000 200 abc 2.500000 ea60 abc`.
- `./dev/check-files.sh -p HEAD~1` (`make check-lint` and `make check-headers` on the changed files,
  with ocp-indent 1.10.0, headache 1.08 and clang-format 19.1.7) passes on a clone holding this
  commit; the new test is clang-formatted.
- The patch applies with `git am` on `3dff90fc70` alone, before or after the patch for #ISSUE-31,
  and on top of the patches of my other reports applied in sequence (!25 to !45, and the one
  proposed in #2816), with `git am --3way`.

The analysis and fix were prepared with LLM assistance (Claude Code); I reviewed them and ran the
reproducer and tests described above.
