# [kernel] decode ACSL hex/octal character and string escapes without byte splitting or Char.chr crash

- Source branch: `fix/kernel-acsl-hex-octal-escapes` on the fork of `pub/frama-c`; target branch `master`.
- Based on: `189053d4a2`. Patch: [`../patches/59-kernel-acsl-hex-octal-escapes.patch`](../patches/59-kernel-acsl-hex-octal-escapes.patch)

<!-- Everything below this line is the merge request description. -->

Before submitting the merge request, please confirm (by adding a X in the [ ]):

- [ ] you contributed to Frama-C as prescribed in the [instructions](https://git.frama-c.com/pub/frama-c/-/blob/master/CONTRIBUTING.md).
- [ ] if the size of the PR requires it, you have signed the
  [Contributor Licensing Agreement](https://git.frama-c.com/pub/frama-c/-/blob/master/CLA.md)

Closes #<issue>.

## Problem

`Logic_lexer.chr` (`src/kernel/internals/parsing/logic_lexer.mll:525-552`) decoded escapes into an
8-bit `Buffer`, splitting hexadecimal escapes into pairs of digits (`'\x041'` -> `1025`,
`L'\x20AC'` -> `137438953644`, `"\x041"` -> `"\004\001"`) and passing octal values up to `511`
directly to `Char.chr` (crashing with `Invalid_argument("Char.chr")` on valid ISO C `L'\777'` as
well as narrow `'\777'` and `"\777"`). In addition, `Logic_typing.parseInt`
(`logic_typing.ml:1161-1167`) did not truncate `L'...'` constants to `Machine.wchar_kind ()`, so
`L'ab'` evaluated to `416611827810` instead of `98`.

## Change

- `src/kernel/internals/parsing/logic_lexer.mli` and `logic_lexer.mll`:
  - Keep raw char/wchar literal text in `INT_CONSTANT` so wide character escapes are not forced
    through an 8-bit `Buffer`.
  - Fix `chr` (used for narrow strings) to decode full `hex_escape` and `oct_escape` values and
    raise `lex_error` when `> 255`.
  - Add `chr_codes : Lexing.lexbuf -> int64 list` decoding each escape sequence to one code unit
    (matching `clexer.mll`).
- `src/kernel/services/ast_queries/logic_typing.ml`:
  - Decode `'...'` and `L'...'` in `parseInt` via `Logic_lexer.chr_codes`, range-checking narrow
    `'...'` units against `0..255` and truncating `L'...'` via
    `Cil.truncateInteger64 (Machine.wchar_kind ())`.
  - Catch `Logic_lexer.Error` in `term` and report it via `C.error`.
- New tests `tests/spec/char_hex_oct_escapes.c` (2 oracles: `-print`, `-eva`) and
  `tests/spec/char_hex_oct_escapes_err.c` (3 oracles: out-of-range `'\777'`, `"\777"`, `"\x1ff"`).
- Zero existing oracle changes.

## Testing

All on Debian GNU/Linux 13 (trixie; OCaml 5.5, glibc 2.41, gcc 14.2.0), upstream `master` at
`189053d4a2`:

- **New tests on unpatched `master`:** both `tests/spec/char_hex_oct_escapes.c` and
  `tests/spec/char_hex_oct_escapes_err.c` fail on unpatched `master` and pass with the patch.
- **ptests, default configuration:** `./dev/test.sh -p tests/spec tests/syntax tests/cil` passes
  with zero diffs on any existing oracle.
- **`./dev/check-files.sh -p HEAD~1`:** passes (`Lint 10 file(s)`).
- **Standalone reproducer:** flips from `RESULT: bug present (4 of 4 checks fail)` (on both
  `master` `189053d4a2` and `34.0~beta`) to `RESULT: fixed` with the patch.
- **Stacking:** applies cleanly with `git am --3way --keep-non-patch` alongside sibling
  `logic_typing.ml` fixes (ACSL string `sizeof` and ACSL wide-string octal escapes).

The analysis and fix were prepared with LLM assistance; I reviewed them and ran the reproducer and
tests described above.
