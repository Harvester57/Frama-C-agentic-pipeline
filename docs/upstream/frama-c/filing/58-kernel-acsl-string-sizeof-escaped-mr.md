# [kernel] type ACSL string literals from their unescaped contents

- Source branch: `fix/kernel-acsl-string-sizeof-escaped` on the fork of `pub/frama-c`; target branch `master`.
- Based on: `189053d4a2`. Patch: [`../patches/58-kernel-acsl-string-sizeof-escaped.patch`](../patches/58-kernel-acsl-string-sizeof-escaped.patch)

<!-- Everything below this line is the merge request description. -->

Before submitting the merge request, please confirm (by adding a X in the [ ]):

- [ ] you contributed to Frama-C as prescribed in the [instructions](https://git.frama-c.com/pub/frama-c/-/blob/master/CONTRIBUTING.md).
- [ ] if the size of the PR requires it, you have signed the
  [Contributor Licensing Agreement](https://git.frama-c.com/pub/frama-c/-/blob/master/CLA.md)

Closes #<issue>.

## Problem

In `src/kernel/services/ast_queries/logic_typing.ml:2684-2685`, `PLconstant (StringConstant s)`
typed the string literal from its raw escaped source string `s` instead of `unescape s`. As a
result, `sizeof("\n")` evaluated to `3` instead of `2`, and `sizeof(GREETING)` on
`#define GREETING "hello\n"` evaluated to `8` instead of `7`, causing WP to refute true contracts
and Eva to mark valid `\valid` preconditions invalid.

## Change

- `src/kernel/services/ast_queries/logic_typing.ml` (lines 2684-2685, 2 insertions, 1 deletion):
  bind `let s = unescape s in` and pass the unescaped string `s` to both `LStr s` and
  `typeOf_string_literal loc s`.
- New test `tests/spec/string_sizeof_escape.c` with its Eva oracle, verifying `sizeof` on `"\n"`,
  `"a\0b"`, `"\x41"`, `"\\"`, and `#define GREETING "hello\n"` (including a `\valid` precondition
  and postcondition).
- Zero existing oracle changes.

## Testing

All on Debian GNU/Linux 13 (trixie; OCaml 5.5, glibc 2.41, gcc 14.2.0), upstream `master` at
`189053d4a2`:

- **New test on unpatched `master`:** `tests/spec/string_sizeof_escape.c` fails on unpatched
  `master` and passes with the patch.
- **ptests, default configuration:** `./dev/test.sh -p tests/spec tests/syntax tests/cil` passes
  with zero diffs on any existing oracle.
- **`./dev/check-files.sh -p HEAD~1`:** passes (`Lint 3 file(s)`).
- **Standalone reproducer:** flips from `RESULT: bug present (2 of 2 checks fail)` (on both
  `master` `189053d4a2` and `34.0~beta`) to `RESULT: fixed` with the patch.
- **Stacking:** applies cleanly with `git am --3way --keep-non-patch` alongside sibling
  `logic_typing.ml` fixes (ACSL hex/octal escapes and ACSL wide-string octal escapes).

The analysis and fix were prepared with LLM assistance; I reviewed them and ran the reproducer and
tests described above.
