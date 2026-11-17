# [kernel] lexer: accept the GNU spelling __restrict__ of restrict

- Source branch: `fix/restrict-gnu-spelling` on the fork of `pub/frama-c`; target branch `master`.
- Based on: `95408044f7`. Patch: [`../patches/35-kernel-restrict-gnu-spelling.patch`](../patches/35-kernel-restrict-gnu-spelling.patch)

<!-- Everything below this line is the merge request description. -->

Before submitting the merge request, please confirm (by adding a X in the [ ]):

- [ ] you contributed to Frama-C as prescribed in the [instructions](https://git.frama-c.com/pub/frama-c/-/blob/master/CONTRIBUTING.md).
- [ ] if the size of the PR requires it, you have signed the
  [Contributor Licensing Agreement](https://git.frama-c.com/pub/frama-c/-/blob/master/CLA.md)

Closes #<issue>.

## Problem

GCC and Clang accept `restrict`, `__restrict` and `__restrict__` as the same type qualifier. The
lexer registers only `restrict` and `__restrict`, so `__restrict__` is an identifier: a declaration
that uses it is a syntax error, and an unnamed parameter `int *__restrict__` becomes a parameter
named `__restrict__`. `share/libc/features.h` defines `__restrict__` as `__restrict`, which hides
the problem whenever a Frama-C libc header is included, but not in files that include none, nor
with `-no-frama-c-stdlib`.

## Change

`src/kernel/internals/parsing/clexer.mll`: register `__restrict__` as `RESTRICT`, with `valid`,
next to `__restrict` and `restrict`, like the other GNU spellings (`__const__`, `__signed__`,
`__inline__`, `__volatile__`). The `features.h` define is left in place; it is now redundant but
harmless, and removing it can be a separate cleanup if you prefer.

New test `tests/syntax/restrict_gnu_spelling.i` (a `.i`, so it is not preprocessed and no libc
macro can rewrite the spelling; default configuration of the directory): the three spellings at
file scope, in struct members, named and unnamed prototype parameters, definition parameters,
block-scope locals with `const` and `volatile`, a pointer to a restrict pointer, and a cast. All
are printed as `restrict`.

## Testing

On a build of `95408044f7` with the patch (Debian 13, OCaml 5.5 switch, gcc 14.2, clang 19.1.7):

- Reproducer from the issue: before, a syntax error in each of 6 positions (file scope, member,
  prototype, definition, block scope, cast), with the default machdep and with
  `-machdep gcc_x86_64 -no-frama-c-stdlib`, and the unnamed-parameter body accepted; after, all 6
  positions are accepted in both configurations and the unnamed-parameter body is rejected, as by
  gcc.
- The new test fails on `95408044f7` (`syntax error ... before or at token: g3`) and passes with
  the patch. Its printed code (the oracle) compiles with `gcc -std=c99 -pedantic -Wall` and
  `clang -std=c99 -pedantic -Wall`.
- ptests, default configuration: `dune build @tests/ptests_config` (all of `tests/`, 1217
  results), `@plugins/rte/tests/ptests_config` (87), `@plugins/eva/tests/ptests_config` (794) and
  `@plugins/aorai/tests/ptests_config` (39; aorai is the other user of `Clexer.is_c_keyword`) pass;
  the only new or changed oracle is the new test's. `dune build
  @src/kernel/internals/parsing/tests/runtest` passes. The other plug-in suites (WP, E-ACSL, ...)
  were not run.
- `./dev/check-files.sh -p HEAD~1` (lint and headers on the changed files) with ocp-indent 1.10.0
  and clang-format 19.1.7: clean.
- `git diff --check`: only the final blank line of the new oracle (Frama-C output).

The analysis and fix were prepared with LLM assistance (Claude Code); I reviewed them and ran the
reproducer and tests described above.
