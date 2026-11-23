# [kernel] reject out-of-range escapes in narrow character constants

- Source branch: `fix/kernel-narrow-char-escape-range` on the fork of `pub/frama-c`; target branch `master`.
- Based on: `189053d4a2`. Patch: [`../patches/86-kernel-narrow-char-escape-range.patch`](../patches/86-kernel-narrow-char-escape-range.patch)

<!-- Everything below this line is the merge request description. -->

Before submitting the merge request, please confirm (by adding a X in the [ ]):

- [ ] you contributed to Frama-C as prescribed in the [instructions](https://git.frama-c.com/pub/frama-c/-/blob/master/CONTRIBUTING.md).
- [ ] if the size of the PR requires it, you have signed the
  [Contributor Licensing Agreement](https://git.frama-c.com/pub/frama-c/-/blob/master/CLA.md)

Closes #<issue>.

## Problem

In `src/kernel/internals/parsing/cparser.mly`, `string_constant` validates that every element of a
narrow string literal lies in `0..255` via `int64_to_char`, rejecting `"\777"` and `"\x1ff"` with
`integral literal 0x1ff too big`. The `CST_CHAR` rule at line 742 skipped that check, so narrow
character constants with out-of-range octal/hex escapes (`'\777'`, `'\x1ff'`, `'a\x100'`) were
silently accepted as `511` (`511UL`) or `25088`, violating ISO C11 6.4.4.4p9.

## Change

`src/kernel/internals/parsing/cparser.mly` (line 742):

- Validate each element of `fst $1` in the `CST_CHAR` production with `int64_to_char ~loc`, matching
  `string_constant` and leaving `CST_WCHAR` unchanged.

New regression test `tests/syntax/char_escape_range.c` (+ oracles) verifying valid narrow and wide
constants (`'\377'`, `'\xff'`, `'ab'`, `L'\777'`, `L'\x1ff'`) are accepted while `'\777'`, `'\x1ff'`,
and `'a\x100'` are rejected with exit 1. No existing oracle changes.

## Testing

All on Debian 13 (OCaml 5.5, gcc 14.2.0), upstream `master` at `189053d4a2`:

- **Standalone reproducer (`oct`, `hex`, `multi`, `valid`):**
  - Before (`master` `189053d4a2` and `34.0~beta`): `oct`, `hex`, and `multi` silently exit 0 as
    `511`, `511`, `25088` (`RESULT: bug present (3 of 4 cases fail)`).
  - After (installed patched `master`): `oct`, `hex`, `multi` exit 1 (`integral literal 0x... too
    big`), `valid` exits 0 (`RESULT: fixed`).
- **New test on unpatched `master`:** `tests/syntax/char_escape_range.c` fails (cases 1-3 exit 0
  instead of 1); passes with the patch.
- **ptests, default configuration:** `./dev/test.sh -p tests/syntax -- -j 2` passes with zero diffs
  on any existing oracle.
- **`./dev/check-files.sh -p HEAD~1`:** passes (`Lint 10 file(s)`).
- **Not run:** suites outside `tests/syntax` (the change is local to the `CST_CHAR` rule in
  `cparser.mly`).

The analysis and fix were prepared with LLM assistance; I reviewed them and ran the reproducer and
tests described above.
