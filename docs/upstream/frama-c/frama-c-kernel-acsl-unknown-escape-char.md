# Kernel: ACSL lexer silently keeps unknown escape sequences and `\e`/`\E` as two raw characters

Draft for the Frama-C issue tracker (https://git.frama-c.com/pub/frama-c/-/issues).
**Not filed.** Issue 82 of this folder, drafted on 2026-11-23. Filing remains paused pending the
maintainers' reply on [#2832](https://git.frama-c.com/pub/frama-c/-/work_items/2832).

**Package:**
[issue text](./filing/82-kernel-acsl-unknown-escape-char-issue.md),
[MR text](./filing/82-kernel-acsl-unknown-escape-char-mr.md),
[reproducer](./repro/82-kernel-acsl-unknown-escape-char.sh) with its
[C file](./repro/82-kernel-acsl-unknown-escape-char.c), and
[patch](./patches/82-kernel-acsl-unknown-escape-char.patch) (validated on `master` `189053d4a2`).

## Summary

`src/kernel/internals/parsing/logic_lexer.mll` omits `\e`/`\E` (supported in `clexer.mll:277`) and
falls through to a catch-all `| _` in `chr` (line 570) for any unknown escape, silently keeping
`'\e'` as `23653` (`'\\' * 256 + 'e'`) instead of `27` and `'\z'` as `23674` instead of raising a
lexical error.

## Versions

| | Result |
| :-- | :-- |
| `34.0~beta (Selenium)`, opam build (`framac-analysis:latest`, 2026-11-23) | **bug present** (`esc` 0/3 valid; `unknown` and `unknown_str` silently exit 0; `RESULT: bug present (3 of 3 cases fail)`) |
| `35.0~~dev (Bromine)`, `master` `189053d4a2` (`framac-master-audit:189053d`, 2026-11-23) | **bug present**, identical output (`RESULT: bug present (3 of 3 cases fail)`) |
| `master` `189053d4a2` + [`./patches/82-kernel-acsl-unknown-escape-char.patch`](./patches/82-kernel-acsl-unknown-escape-char.patch) | **fixed** (`esc` 3/3 valid; `unknown` and `unknown_str` rejected with exit 1; `RESULT: fixed`) |

Debian 13 (trixie; glibc 2.41, gcc 14.2.0), OCaml 5.5.

## Root cause

In `src/kernel/internals/parsing/logic_lexer.mll`, `let escape` (lines 386-388) and `chr` (lines
553-570) omit `'e'`/`'E'` and fall into `| _ { Buffer.add_string buffer (lexeme lexbuf); chr buffer
lexbuf }` on any unrecognized `\c` escape.

## Fix and validation

Patch [`./patches/82-kernel-acsl-unknown-escape-char.patch`](./patches/82-kernel-acsl-unknown-escape-char.patch):
one commit (`7a0614dc13`) on `master` `189053d4a2`, 8 files (`src/kernel/internals/parsing/logic_lexer.mll`
plus regression test `tests/spec/acsl_escape_char.c` and its 6 oracles).

- Adds `'e' | 'E'` to `escape` and `chr` (`'\027'`), adds `| '\\' _ -> lex_error ...` before `| eof`
  / `| _`, and validates narrow `STRING_LITERAL` tokens through `chr` during lexing so unknown
  escapes are caught cleanly by `parse_from_position`.
- Stacking with [`./patches/59-kernel-acsl-hex-octal-escapes.patch`](./patches/59-kernel-acsl-hex-octal-escapes.patch)
  (`logic_lexer.mll`): `git am --3way --keep-non-patch` applies with zero conflicts and builds in
  both orders (`59` then `82`, `82` then `59`); documented the two semantic interactions (`59`'s new
  `chr_codes` rule needs the same `'e'|'E'` + `'\\' _` arms if `59` lands first, and `59`'s
  `char_hex_oct_escapes_err.{1,2}` errors are caught earlier at lexing time).
- Validated on 2026-11-23 in `framac-master-audit:189053d`:
  - `tests/spec/acsl_escape_char.c` fails on unpatched `master`, passes with patch.
  - Full `./dev/test.sh -p tests/spec -- -j 2` passes with zero diffs on existing oracles.
  - `./dev/check-files.sh -p HEAD~1` passes (`Lint 8 file(s)`).
  - Standalone reproducer flips from `RESULT: bug present (3 of 3 cases fail)` (exit 1) to
    `RESULT: fixed` (exit 0).
- Local `opam/` queue recommendation: **NO** (triggered only by `\e`/`\E` or invalid escape
  sequences inside ACSL annotations).
