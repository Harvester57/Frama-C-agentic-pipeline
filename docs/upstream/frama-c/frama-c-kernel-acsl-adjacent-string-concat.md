# Kernel: adjacent string literals in ACSL annotations concatenated as raw text before unescaping

Draft for the Frama-C issue tracker (https://git.frama-c.com/pub/frama-c/-/issues).
**Not filed.** Issue 81 of this folder, drafted on 2026-11-23. Filing remains paused pending the
maintainers' reply on [#2832](https://git.frama-c.com/pub/frama-c/-/work_items/2832).

**Package:**
[issue text](./filing/81-kernel-acsl-adjacent-string-concat-issue.md),
[MR text](./filing/81-kernel-acsl-adjacent-string-concat-mr.md),
[reproducer](./repro/81-kernel-acsl-adjacent-string-concat.sh) with its
[C file](./repro/81-kernel-acsl-adjacent-string-concat.c), and
[patch](./patches/81-kernel-acsl-adjacent-string-concat.patch) (validated on `master` `189053d4a2`).

## Summary

`src/kernel/internals/parsing/logic_parser.mly:679-683` concatenates adjacent ACSL string literals
as raw text (`prefix ^ suffix`) before escape sequences are decoded in `Logic_typing`, turning
`"\x4" "1"` into `"A"` (`0x41`) and `"\01" "2"` into `"\n"` (`\012`), violating ISO C11 5.1.1.2p1
phase 6 and disagreeing with Frama-C's C parser (`"\0041"` and `"\0012"`).

## Versions

| | Result |
| :-- | :-- |
| `34.0~beta (Selenium)`, opam build (`framac-analysis:latest`, 2026-11-23) | **bug present** (`"\x4" "1"` -> `"A"`, `"\01" "2"` -> `"\n"`, `RESULT: bug present (4 of 5 cases fail)`) |
| `35.0~~dev (Bromine)`, `master` `189053d4a2` (`framac-master-audit:189053d`, 2026-11-23) | **bug present**, identical output (`RESULT: bug present (4 of 5 cases fail)`) |
| `master` `189053d4a2` + [`./patches/81-kernel-acsl-adjacent-string-concat.patch`](./patches/81-kernel-acsl-adjacent-string-concat.patch) | **fixed** (`"\0041"`, `"\0012"`, `L"\\004" "1"`, `L"\\001" "2"`, `RESULT: fixed`) |

Debian 13 (trixie; glibc 2.41, gcc 14.2.0), OCaml 5.5.

## Root cause

`Logic_lexer` returns raw (un-unescaped) string contents in `STRING_LITERAL`, and
`logic_parser.mly:679-683` concatenates adjacent tokens with `prefix ^ suffix` before
`Logic_typing.unescape` / `wcharlist_of_string` decode escapes.

## Fix and validation

Patch [`./patches/81-kernel-acsl-adjacent-string-concat.patch`](./patches/81-kernel-acsl-adjacent-string-concat.patch):
one commit (`180dfc11f3`) on `master` `189053d4a2`, 4 files (`src/kernel/internals/parsing/logic_parser.mly`
plus regression test `tests/spec/string_concat_escape.c` and its 2 oracles).

- Adds `concat_string_literal` normalizing trailing hex (`\xH+`, `<= 0xff`) and short octal
  (`\d`, `\dd`) escapes to 3-digit octal (`\NNN`) when the next token begins with a digit that would
  otherwise be absorbed.
- Touches only `logic_parser.mly` (zero file overlap with [`./patches/58-kernel-acsl-string-sizeof-escaped.patch`](./patches/58-kernel-acsl-string-sizeof-escaped.patch),
  [`./patches/59-kernel-acsl-hex-octal-escapes.patch`](./patches/59-kernel-acsl-hex-octal-escapes.patch), or
  [`./patches/60-kernel-acsl-wstring-octal-escapes.patch`](./patches/60-kernel-acsl-wstring-octal-escapes.patch)).
- Validated on 2026-11-23 in `framac-master-audit:189053d`:
  - `tests/spec/string_concat_escape.c` fails on unpatched `master`, passes with patch.
  - Full `./dev/test.sh -p tests/spec -- -j 2` passes with zero diffs on existing oracles.
  - `./dev/check-files.sh -p HEAD~1` passes (`Lint 4 file(s)`).
  - Stacking check `58 + 81` and `81 + 58` both apply cleanly (`git am --3way --keep-non-patch`),
    build, and pass both `string_sizeof_escape.c` and `string_concat_escape.c`.
  - Standalone reproducer flips from `RESULT: bug present (4 of 5 cases fail)` (exit 1) to
    `RESULT: fixed` (exit 0).
- Local `opam/` queue recommendation: **NO** (rare pattern in synthesized ACSL contracts; silent
  only when adjacent ACSL string literals split across a hex/short-octal escape boundary).
