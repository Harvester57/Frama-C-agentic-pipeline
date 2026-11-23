# Kernel: ACSL lexer splits hexadecimal escapes into byte pairs, crashes with `Char.chr` on octal escapes above `\377`, and does not truncate `L'...'` to `wchar_t`

Draft for the Frama-C issue tracker (https://git.frama-c.com/pub/frama-c/-/issues).
**Not filed.** Issue 59 of this folder, drafted on 2026-11-23 (merged hunt candidates `H6 + H18`).
Filing remains paused pending the maintainers' reply on
[#2832](https://git.frama-c.com/pub/frama-c/-/work_items/2832).

**Package:**
[issue text](./filing/59-kernel-acsl-hex-octal-escapes-issue.md),
[MR text](./filing/59-kernel-acsl-hex-octal-escapes-mr.md),
[reproducer](./repro/59-kernel-acsl-hex-octal-escapes.sh) with its
[C file](./repro/59-kernel-acsl-hex-octal-escapes.c), and
[patch](./patches/59-kernel-acsl-hex-octal-escapes.patch) (validated on `master` `189053d4a2`).

## Summary

Three coupled bugs in ACSL character and narrow-string escape handling share the same root cause
(`Logic_lexer.chr` encoding escapes into an 8-bit `Buffer`):

1. `hex_escape` (`logic_lexer.mll:526-542`) splits hex digits into 2-digit bytes, turning `'\x041'`
   into `1025`, `L'\x20AC'` into `137438953644` (`0x20000000AC`), and `"\x041"` into `"\004\001"`.
2. `oct_escape` (`logic_lexer.mll:543-552`) calls `Char.chr` on values `0..511` without a range
   check, crashing with `Invalid_argument("Char.chr")` on valid ISO C `L'\777'` (exit 4), `'\777'`
   (exit 4), and `"\777"` (exit 125).
3. `Logic_typing.parseInt` (`logic_typing.ml:1161-1167`) never truncates `L'...'` to
   `Machine.wchar_kind ()`, turning `L'ab'` into `416611827810` instead of `98`.

## Versions

| | Result |
| :-- | :-- |
| `34.0~beta (Selenium)`, opam build (`framac-analysis:latest`, 2026-11-23) | **reproduces** (`RESULT: bug present (4 of 4 checks fail)`) |
| `35.0~~dev (Bromine)`, `master` `189053d4a2` (`framac-master-audit:189053d`, 2026-11-23) | **reproduces**, identical output (`RESULT: bug present (4 of 4 checks fail)`) |
| `master` `189053d4a2` + [`./patches/59-kernel-acsl-hex-octal-escapes.patch`](./patches/59-kernel-acsl-hex-octal-escapes.patch) | **fixed** (`RESULT: fixed`) |

Debian GNU/Linux 13 (trixie; OCaml 5.5, glibc 2.41, gcc 14.2.0).

## Root cause and fix

- `src/kernel/internals/parsing/logic_lexer.mll` + `.mli`: keep raw char/wchar literal in
  `INT_CONSTANT`; fix `chr` (narrow strings) to parse full `hex_escape`/`oct_escape` values with
  `<= 255` range checks raising `lex_error`; add `chr_codes : Lexing.lexbuf -> int64 list` decoding
  each escape to one code unit (matching `clexer.mll`).
- `src/kernel/services/ast_queries/logic_typing.ml`: use `Logic_lexer.chr_codes` in `parseInt`,
  truncate `L'...'` with `Cil.truncateInteger64 (Machine.wchar_kind ())`, range-check narrow
  `'...'` units against `0..255`, and catch `Logic_lexer.Error` in `term` (disjoint from `58` at
  line 2685 and `60` at lines 30/62/71) to emit clean `C.error` annotation diagnostics.

Stacks cleanly via `git am --3way --keep-non-patch` with sibling `logic_typing.ml` packages `58`
and `60` (and leaves `logic_lexer.mll:553-570` untouched for Wave 2 `82`/`N10`).

## Duplicate search

Live read-only `glab api` search on `pub/frama-c` (project 780, issues and MRs, all states,
2026-11-23), `pub-frama-c_work_items_2026-11-09.csv`, and packages `01`–`50` for `hex_escape`,
`oct_escape`, `Char.chr`, `wide character`, `escape sequence`: zero duplicates (`#154` closed was
`\v` crash; `#2672` open is wide-string `sizeof`; `#2832` is overview).

## Local `opam/` patch queue recommendation

**YES** (fixes wrong ACSL values for wide character constants and narrow hex escapes, plus two
`Char.chr` crashes).
