# [kernel] type multi-character constants as int in Cil.interpret_character_constant

- Source branch: `fix/kernel-multichar-const-type` on the fork of `pub/frama-c`; target branch `master`.
- Based on: `189053d4a2`. Patch: [`../patches/62-kernel-multichar-const-type.patch`](../patches/62-kernel-multichar-const-type.patch)

<!-- Everything below this line is the merge request description. -->

Before submitting the merge request, please confirm (by adding a X in the [ ]):

- [ ] you contributed to Frama-C as prescribed in the [instructions](https://git.frama-c.com/pub/frama-c/-/blob/master/CONTRIBUTING.md).
- [ ] if the size of the PR requires it, you have signed the
  [Contributor Licensing Agreement](https://git.frama-c.com/pub/frama-c/-/blob/master/CLA.md)

Closes #<issue>.

## Problem

`Cil.interpret_character_constant` (`src/kernel/services/ast_queries/cil.ml:4150-4161`) typed
multi-character integer constants as `unsigned long` (`'ab'` -> `24930UL`) or `unsigned long long`
(`'\377\377\377\377'` -> `4294967295ULL`), violating ISO C11 6.4.4.4p10 ("An integer character
constant has type `int`"). It also treated multi-character constants with value `< 256` (such as
`'\0\200'`) as single-character `CChr`.

## Change

- `src/kernel/services/ast_queries/cil.ml` (`interpret_character_constant`): emit `CChr` only for
  single-element lists `[ _ ]` with `0 <= value < 256`; for multi-character constants, wrap
  `value` with `truncateInteger64 IInt (Z.of_int64 value)` and return
  `CInt64 (v, IInt, None), Cil_const.intType`.
- New test `tests/syntax/multichar_const_type.c` with its `-print -eva` oracle, covering signed
  arithmetic, `sizeof`, 4-byte sign wrap, `_Generic`, and `'\0\200'`.
- Existing oracle update: 1 line in `tests/syntax/oracle/define_string_logic_pp_bts2101.0.res.oracle`
  (`(char)7815260946135808373` -> `(char)1768454517`, reflecting 32-bit `int` truncation of the
  multi-character literal instead of 64-bit `unsigned long long`).

## Testing

All on Debian GNU/Linux 13 (trixie; OCaml 5.5, glibc 2.41, gcc 14.2.0), upstream `master` at
`189053d4a2`:

- **New test on unpatched `master`:** `tests/syntax/multichar_const_type.c` fails on unpatched
  `master` and passes with the patch.
- **ptests, default configuration:** `./dev/test.sh -p tests/spec tests/syntax tests/cil` passes
  (with only the 1 expected oracle line updated above).
- **`./dev/check-files.sh -p HEAD~1`:** passes (`Lint 4 file(s)`).
- **Standalone reproducer:** flips from `RESULT: bug present (2 of 2 checks fail)` (on both
  `master` `189053d4a2` and `34.0~beta`) to `RESULT: fixed` with the patch.
- **Stacking:** applies cleanly with `git am --3way --keep-non-patch` alongside sibling `cil.ml`
  fixes (`Cil.isExactFloat`, `Cil.fitsInInt`/`truncateInteger64`, `Cil.charConstToInt`).

The analysis and fix were prepared with LLM assistance; I reviewed them and ran the reproducer and
tests described above.
