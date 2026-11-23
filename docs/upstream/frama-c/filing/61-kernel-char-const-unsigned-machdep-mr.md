# [kernel] respect Machine.char_is_unsigned in Cil.charConstToInt

- Source branch: `fix/kernel-char-const-unsigned-machdep` on the fork of `pub/frama-c`; target branch `master`.
- Based on: `189053d4a2`. Patch: [`../patches/61-kernel-char-const-unsigned-machdep.patch`](../patches/61-kernel-char-const-unsigned-machdep.patch)

<!-- Everything below this line is the merge request description. -->

Before submitting the merge request, please confirm (by adding a X in the [ ]):

- [ ] you contributed to Frama-C as prescribed in the [instructions](https://git.frama-c.com/pub/frama-c/-/blob/master/CONTRIBUTING.md).
- [ ] if the size of the PR requires it, you have signed the
  [Contributor Licensing Agreement](https://git.frama-c.com/pub/frama-c/-/blob/master/CLA.md)

Closes #<issue>.

## Problem

`Cil.charConstToInt` (`src/kernel/services/ast_queries/cil.ml:2547-2551`) always sign-extended
character constants `>= 128`, even on machdeps where `char` is unsigned (such as `ppc_32`). On
such machdeps, `'\377'` evaluated to `-1` while `(char)255` and `"\377"[0]` evaluated to `255`,
contradicting ISO C11 6.4.4.4p10 and `gcc -funsigned-char`.

## Change

- `src/kernel/services/ast_queries/cil.ml` (`charConstToInt`): return `Z.of_int c'` when
  `Machine.char_is_unsigned () || c' < 128`, and sign-extend `c' - 256` otherwise.
- New test `tests/syntax/char_const_unsigned.c` with 2 oracles (`-machdep ppc_32 -print -eva` and
  `-machdep x86_64 -eva` control).
- Zero existing oracle changes.

## Testing

All on Debian GNU/Linux 13 (trixie; OCaml 5.5, glibc 2.41, gcc 14.2.0), upstream `master` at
`189053d4a2`:

- **New test on unpatched `master`:** `tests/syntax/char_const_unsigned.c` fails on unpatched
  `master` under `-machdep ppc_32` and passes with the patch.
- **ptests, default configuration:** `./dev/test.sh -p tests/spec tests/syntax tests/cil` passes
  with zero diffs on any existing oracle.
- **`./dev/check-files.sh -p HEAD~1`:** passes (`Lint 4 file(s)`).
- **Standalone reproducer:** flips from `RESULT: bug present (2 of 2 checks fail)` (on both
  `master` `189053d4a2` and `34.0~beta`) to `RESULT: fixed` with the patch.
- **Stacking:** applies cleanly with `git am --3way --keep-non-patch` alongside sibling `cil.ml`
  fixes (`Cil.isExactFloat`, `Cil.fitsInInt`/`truncateInteger64`, `Cil.interpret_character_constant`).

The analysis and fix were prepared with LLM assistance; I reviewed them and ran the reproducer and
tests described above.
