# [kernel] restrict ACSL wide-string octal escapes to 0-7 and support \v

- Source branch: `fix/kernel-acsl-wstring-octal-escapes` on the fork of `pub/frama-c`; target branch `master`.
- Based on: `189053d4a2`. Patch: [`../patches/60-kernel-acsl-wstring-octal-escapes.patch`](../patches/60-kernel-acsl-wstring-octal-escapes.patch)

<!-- Everything below this line is the merge request description. -->

Before submitting the merge request, please confirm (by adding a X in the [ ]):

- [ ] you contributed to Frama-C as prescribed in the [instructions](https://git.frama-c.com/pub/frama-c/-/blob/master/CONTRIBUTING.md).
- [ ] if the size of the PR requires it, you have signed the
  [Contributor Licensing Agreement](https://git.frama-c.com/pub/frama-c/-/blob/master/CLA.md)

Closes #<issue>.

## Problem

`Logic_typing.wcharlist_of_string` (`src/kernel/services/ast_queries/logic_typing.ml:23-87`)
accepted `'8'` and `'9'` as octal digits in ACSL wide string literals (turning `L"\18"` into
`[16]` instead of `[1, '8']`) and omitted the standard C escape `\v` (warning
`Ill-formed escape sequence in wide string` and storing `'v'`).

## Change

- `src/kernel/services/ast_queries/logic_typing.ml` (`wcharlist_of_string`, 3 insertions, 2
  deletions): restrict octal digit matching at lines 30 and 62 from `'0'..'9'` to `'0'..'7'`, and
  add `| 'v' -> incr i; res:= Int64.of_int 11 :: !res`.
- New test `tests/spec/wstring_escapes.c` with its oracle, verifying `L"\18"`, `L"\79"`, `L"\123"`,
  and `L"\v"`.
- Zero existing oracle changes.

## Testing

All on Debian GNU/Linux 13 (trixie; OCaml 5.5, glibc 2.41, gcc 14.2.0), upstream `master` at
`189053d4a2`:

- **New test on unpatched `master`:** `tests/spec/wstring_escapes.c` fails on unpatched `master`
  and passes with the patch.
- **ptests, default configuration:** `./dev/test.sh -p tests/spec tests/syntax tests/cil` passes
  with zero diffs on any existing oracle.
- **`./dev/check-files.sh -p HEAD~1`:** passes (`Lint 3 file(s)`).
- **Standalone reproducer:** flips from `RESULT: bug present (3 of 3 checks fail)` (on both
  `master` `189053d4a2` and `34.0~beta`) to `RESULT: fixed` with the patch.
- **Stacking:** applies cleanly with `git am --3way --keep-non-patch` alongside sibling
  `logic_typing.ml` fixes (ACSL string `sizeof` and ACSL hex/octal escapes).

The analysis and fix were prepared with LLM assistance; I reviewed them and ran the reproducer and
tests described above.
