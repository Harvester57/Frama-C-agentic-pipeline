# [kernel] preserve escape boundaries when concatenating ACSL string literals

- Source branch: `fix/kernel-acsl-adjacent-string-concat` on the fork of `pub/frama-c`; target branch `master`.
- Based on: `189053d4a2`. Patch: [`../patches/81-kernel-acsl-adjacent-string-concat.patch`](../patches/81-kernel-acsl-adjacent-string-concat.patch)

<!-- Everything below this line is the merge request description. -->

Before submitting the merge request, please confirm (by adding a X in the [ ]):

- [ ] you contributed to Frama-C as prescribed in the [instructions](https://git.frama-c.com/pub/frama-c/-/blob/master/CONTRIBUTING.md).
- [ ] if the size of the PR requires it, you have signed the
  [Contributor Licensing Agreement](https://git.frama-c.com/pub/frama-c/-/blob/master/CLA.md)

Closes #<issue>.

## Problem

In `src/kernel/internals/parsing/logic_parser.mly:679-683`, adjacent ACSL string literals were
concatenated as raw escaped strings (`prefix ^ suffix`) before `Logic_typing` unescaped them. A
trailing hexadecimal escape (`\x4`) or 1-/2-digit octal escape (`\01`, `\7`) in `prefix` therefore
absorbed leading digits from `suffix`, turning `"\x4" "1"` into `"\x41"` (`"A"`) and `"\01" "2"`
into `"\012"` (`"\n"`), violating ISO C11 5.1.1.2p1 phase 6 and disagreeing with the C parser.

## Change

`src/kernel/internals/parsing/logic_parser.mly`:

- Add `concat_string_literal` and call it in the `string STRING_LITERAL` production instead of raw
  `prefix ^ suffix`.
- When `prefix` ends with a hex escape (`\xH+`, value `<= 0xff`) and `suffix` starts with a hex
  digit, rewrite the trailing escape as a 3-digit octal escape (`\NNN`) so subsequent digits cannot
  merge into it.
- When `prefix` ends with a 1- or 2-digit octal escape and `suffix` starts with a digit `0`..`9`,
  zero-pad the trailing octal escape to 3 digits before concatenation.
- Touch only `logic_parser.mly` (keeping `Logic_ptree.StringConstant` / `WStringConstant` unchanged
  and fully disjoint from `logic_typing.ml` and `logic_lexer.mll`).

New regression test `tests/spec/string_concat_escape.c` (+ oracles) covering narrow and wide
hex/octal adjacent concatenations, escaped-backslash boundaries (`"\\" "x41"`), and 3-part
concatenation (`"\x4" "1" "2"`). No existing oracle changes.

Interaction with related merge requests:

- Stacks cleanly via `git am --3way --keep-non-patch` in both orders with the sibling ACSL string
  `sizeof` fix (`logic_typing.ml`), with zero conflicts and both regression tests passing.

## Testing

All on Debian 13 (OCaml 5.5, gcc 14.2.0), upstream `master` at `189053d4a2`:

- **Standalone reproducer (`5` narrow/wide cases):**
  - Before (`master` `189053d4a2` and `34.0~beta`): 4 of 5 cases fail (`"\x4" "1"` -> `"A"`,
    `"\01" "2"` -> `"\n"`, `L"\x4" "1"` -> `L"A"`, `L"\01" "2"` -> `L"\\n"`, `RESULT: bug present`).
  - After (installed patched `master`): 5 of 5 cases pass (`RESULT: fixed`).
- **New test on unpatched `master`:** `tests/spec/string_concat_escape.c` fails; passes with the
  patch.
- **ptests, default configuration:** `./dev/test.sh -p tests/spec -- -j 2` passes with zero diffs
  on any existing oracle.
- **Stacked with the sibling ACSL string `sizeof` fix (`logic_typing.ml`):** both merge orders apply
  cleanly with `git am --3way --keep-non-patch`, build, and pass both `string_sizeof_escape.c` and
  `string_concat_escape.c`.
- **`./dev/check-files.sh -p HEAD~1`:** passes (`Lint 4 file(s)`).
- **Not run:** suites outside `tests/spec` (the change is local to the ACSL `string` rule in
  `logic_parser.mly`).

The analysis and fix were prepared with LLM assistance; I reviewed them and ran the reproducer and
tests described above.
