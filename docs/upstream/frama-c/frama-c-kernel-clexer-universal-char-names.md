# Kernel: C lexer rejects ISO C99/C11 universal character names (`\uXXXX` / `\UXXXXXXXX`) in literals

Draft for the Frama-C issue tracker (https://git.frama-c.com/pub/frama-c/-/issues).
**Not filed.** Issue 83 of this folder, drafted on 2026-11-23. Filing remains paused pending the
maintainers' reply on [#2832](https://git.frama-c.com/pub/frama-c/-/work_items/2832).

**Package:**
[issue text](./filing/83-kernel-clexer-universal-char-names-issue.md),
[MR text](./filing/83-kernel-clexer-universal-char-names-mr.md),
[reproducer](./repro/83-kernel-clexer-universal-char-names.sh) with its
[C file](./repro/83-kernel-clexer-universal-char-names.c), and
[patch](./patches/83-kernel-clexer-universal-char-names.patch) (validated on `master` `189053d4a2`).

## Summary

Frama-C's C lexer (`src/kernel/internals/parsing/clexer.mll`) rejects ISO C99/C11 universal
character names (`\uXXXX` and `\UXXXXXXXX`, ISO C11 6.4.3) inside narrow and wide character/string
literals with `User Error: Unrecognized escape sequence: \u`.

## Versions

| | Result |
| :-- | :-- |
| `34.0~beta (Selenium)`, opam build (`framac-analysis:latest`, 2026-11-23) | **bug present** (`Unrecognized escape sequence: \u`, `RESULT: bug present (4 of 4 cases fail)`) |
| `35.0~~dev (Bromine)`, `master` `189053d4a2` (`framac-master-audit:189053d`, 2026-11-23) | **bug present**, identical output (`RESULT: bug present (4 of 4 cases fail)`) |
| `master` `189053d4a2` + [`./patches/83-kernel-clexer-universal-char-names.patch`](./patches/83-kernel-clexer-universal-char-names.patch) | **fixed** (`valid` 4/4 Eva checks valid; `surrogate`, `low`, `high` rejected with `Invalid universal character name`; `RESULT: fixed`) |

Debian 13 (trixie; glibc 2.41, gcc 14.2.0), OCaml 5.5.

## Root cause

In `src/kernel/internals/parsing/clexer.mll`, `str` (lines 800-807) and `chr` (lines 810-816) only
match `hex_escape`, `oct_escape`, and single-character `escape`, so `\u` and `\U` fall into
`scan_escape` (line 286) and abort with `Unrecognized escape sequence`.

## Fix and validation

Patch [`./patches/83-kernel-clexer-universal-char-names.patch`](./patches/83-kernel-clexer-universal-char-names.patch):
one commit (`b3717852ae`) on `master` `189053d4a2`, 12 files (`src/kernel/internals/parsing/clexer.mll`
plus regression test `tests/syntax/ucn_literals.c` and its 10 oracles).

- Adds `ucn4`, `ucn8`, `bad_ucn`, and `scan_ucn ~wide` enforcing ISO C11 6.4.3p2 (rejecting
  `< 0x00A0` except `0x0024`/`0x0040`/`0x0060`, surrogates `0xD800..0xDFFF`, and `> 0x10FFFF`),
  emitting `[cp]` for wide literals and UTF-8 bytes for narrow literals.
- Complementary to [`./frama-c-kernel-wstring-escape-trigraph.md`](./frama-c-kernel-wstring-escape-trigraph.md)
  (package `77`, `escape.ml`); zero file overlap.
- Validated on 2026-11-23 in `framac-master-audit:189053d`:
  - `tests/syntax/ucn_literals.c` fails on unpatched `master`, passes with patch (5/5 Eva checks
    valid, 4/4 invalid UCNs rejected).
  - Full `./dev/test.sh -p tests/syntax -- -j 2` passes with zero diffs on existing oracles.
  - `./dev/check-files.sh -p HEAD~1` passes (`Lint 12 file(s)`).
  - Standalone reproducer flips from `RESULT: bug present (4 of 4 cases fail)` (exit 1) to
    `RESULT: fixed` (exit 0).
- Local `opam/` queue recommendation: **NO** (missing C99/C11 lexer feature, not a silent soundness
  bug).
