# [kernel] handle \e/\E and reject unknown escapes in ACSL lexer

- Source branch: `fix/kernel-acsl-unknown-escape-char` on the fork of `pub/frama-c`; target branch `master`.
- Based on: `189053d4a2`. Patch: [`../patches/82-kernel-acsl-unknown-escape-char.patch`](../patches/82-kernel-acsl-unknown-escape-char.patch)

<!-- Everything below this line is the merge request description. -->

Before submitting the merge request, please confirm (by adding a X in the [ ]):

- [ ] you contributed to Frama-C as prescribed in the [instructions](https://git.frama-c.com/pub/frama-c/-/blob/master/CONTRIBUTING.md).
- [ ] if the size of the PR requires it, you have signed the
  [Contributor Licensing Agreement](https://git.frama-c.com/pub/frama-c/-/blob/master/CLA.md)

Closes #<issue>.

## Problem

In `src/kernel/internals/parsing/logic_lexer.mll`, `escape` (lines 386-388) and `chr` (lines
553-570) did not support `\e`/`\E` (GCC extension supported by `clexer.mll:277`) and had a catch-all
`| _` that silently kept any unrecognized `\c` escape as two raw characters (`'\\'` and `c`). Thus
`'\e'` evaluated to `23653` instead of `27` (disagreeing with C) and `'\z'` / `"\z"` were silently
accepted (`'\z'` became `23674`).

## Change

`src/kernel/internals/parsing/logic_lexer.mll`:

- Add `'e' | 'E'` to `escape` and map `'e' | 'E' -> '\027'` in `chr`.
- Add `| '\\' _ { lex_error lexbuf ("unrecognized escape sequence: " ^ lexeme lexbuf) }` before
  `| eof` / `| _` in `chr`.
- Validate narrow `STRING_LITERAL` tokens through `chr` during lexing so unknown escapes in ACSL
  strings are caught cleanly by `parse_from_position` (`annot-error`).

New regression test `tests/spec/acsl_escape_char.c` (+ oracles) verifying `'\e'`/`'\E'`/`"\e"` decode
to `'\033'` (`27`, matching C in Eva) and `'\z'`/`"\z"` are rejected with `lexical error,
unrecognized escape sequence: \z`. No existing oracle changes.

Interaction with related merge requests:

- **Sibling ACSL hex/octal escapes MR (`logic_lexer.mll`):** applies cleanly with `git am --3way
  --keep-non-patch` and builds cleanly in both orders (all hunks in `logic_lexer.mll` are
  disjoint). Two semantic interactions to note if both merge:
  1. Because the sibling hex/octal escapes MR moves ACSL character literal decoding into a new
     `chr_codes` lexer rule, if it lands first, `chr_codes` should also receive the same
     `'e' | 'E' -> '\027'` and `'\\' _ -> lex_error` arms added here to `chr`.
  2. Because this commit validates narrow `STRING_LITERAL` via `chr` during lexing, out-of-range
     narrow string escapes tested in the sibling MR's `char_hex_oct_escapes_err.{1,2}` are caught at
     lexing time (`There were parsing errors`) rather than during typing (`stopping on file ... that
     has errors`), still exiting 1 with the exact same `lexical error` message.

## Testing

All on Debian 13 (OCaml 5.5, gcc 14.2.0), upstream `master` at `189053d4a2`:

- **Standalone reproducer (`esc`, `unknown`, `unknown_str`):**
  - Before (`master` `189053d4a2` and `34.0~beta`): `esc` fails 3/3 Eva checks, `unknown` and
    `unknown_str` exit 0 silently (`RESULT: bug present (3 of 3 cases fail)`).
  - After (installed patched `master`): `esc` proves 3/3 Eva checks valid, `unknown` and
    `unknown_str` exit 1 with `lexical error, unrecognized escape sequence: \z` (`RESULT: fixed`).
- **New test on unpatched `master`:** `tests/spec/acsl_escape_char.c` fails; passes with the patch.
- **ptests, default configuration:** `./dev/test.sh -p tests/spec -- -j 2` passes with zero diffs
  on any existing oracle.
- **Stacked with the sibling ACSL hex/octal escapes MR (`logic_lexer.mll`):** `git am --3way
  --keep-non-patch` applies with zero conflicts and builds cleanly in both merge orders;
  `char_hex_oct_escapes.c` passes (with the expected lexing-vs-typing diagnostic timing note on
  `char_hex_oct_escapes_err.{1,2}` documented above).
- **`./dev/check-files.sh -p HEAD~1`:** passes (`Lint 8 file(s)`).
- **Not run:** suites outside `tests/spec` (the change is local to `logic_lexer.mll`).

The analysis and fix were prepared with LLM assistance; I reviewed them and ran the reproducer and
tests described above.
