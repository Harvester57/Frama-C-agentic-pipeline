# Kernel (`Escape`): Wide-String Printer Emits Invalid `\u` Escapes, Crashes Above 2^32, and Resets Trigraph State

- **Parent index:** [`./README.md`](./README.md)
- **Filing issue:** [`./filing/77-kernel-wstring-escape-trigraph-issue.md`](./filing/77-kernel-wstring-escape-trigraph-issue.md)
- **Filing MR:** [`./filing/77-kernel-wstring-escape-trigraph-mr.md`](./filing/77-kernel-wstring-escape-trigraph-mr.md)
- **Standalone reproducer:** [`./repro/77-kernel-wstring-escape-trigraph.sh`](./repro/77-kernel-wstring-escape-trigraph.sh) + [`./repro/77-kernel-wstring-escape-trigraph.c`](./repro/77-kernel-wstring-escape-trigraph.c)
- **Patch:** [`./patches/77-kernel-wstring-escape-trigraph.patch`](./patches/77-kernel-wstring-escape-trigraph.patch)
- **Hunt origin:** Candidates `H12` + `N14` in [`./frama-c-hunt-2026-11-18-candidates.md`](./frama-c-hunt-2026-11-18-candidates.md)

## 1. Summary

`Escape.escape_wchar` and `Escape.escape_wstring` (`src/lib/utils/escape.ml:54-82`) have five
defects when printing C wide string literals (`L"..."`), all residing in the same 29-line block:

1. `0o1000 <= c < 0x10000` (`L"\x20AC"`): prints `\u20ac`, which Frama-C's own C lexer rejects
   (`Unrecognized escape sequence: \u`, see separate package `83` for `clexer.mll` UCN parsing).
2. UTF-16 surrogates `0xD800..0xDFFF` (`L"\xD800"`): prints `\ud800`, rejected by GCC and Clang
   under C11 6.4.3p2 (`not a valid universal character`).
3. `0x10000 <= c < 0x100000000` (`L"\x1F600"`, `L"\x1F600""A"`, `L"\x110000"`): line 69 uses
   `"\\u%04Lx"` (lowercase `\u` with 5 to 8 hex digits instead of `\UXXXXXXXX`, and invalid above
   `0x10FFFF`). GCC and Clang silently consume 4 hex digits and treat the rest as literal text
   (`b=1f60`, `c=1f60,30`, `e=1100` instead of `b=1f600`, `c=1f600,41`, `e=110000`).
4. `c >= 0x100000000` (`L"\x100000000"`): line 71 raises uncaught
   `Invalid_argument("Cprint.escape_string_intlist")` (exit 125). In addition, `limit` (line 56)
   uses `Int64.to_float` subtraction, mishandling negative `int64`.
5. Trigraph state reset (`N14`, line 63): `escape_wchar` calls `escape_char` (fresh `ref false`
   per character) instead of threading `maybe_trigraph` across the wide string like `escape_string`.
   `L"a?\?!b"` prints as `L"a??!b"`, which `gcc -std=c99` and `e-acsl-gcc` silently convert into
   `L"a|b"`.

## 2. Duplicate Check

Live read-only `glab api` search against `pub/frama-c` (project 780, issues and MRs, all states,
2026-11-22) for `escape_wstring`, `escape_string_intlist`, `universal character`, `trigraph`,
`wide string`, plus [`./pub-frama-c_work_items_2026-11-09.csv`](./pub-frama-c_work_items_2026-11-09.csv)
and packages `01`-`50`: **0 duplicates** (open `#2672` `sizeof(L"AA")` and `#2347` `uint16` init
are distinct; `#2832` overview).

## 3. Fix & Validation

In `src/lib/utils/escape.ml`:

- Add `escape_wchar_internal maybe_trigraph charcode` threading `maybe_trigraph` through
  `escape_wstring` (using `escape_char_internal` for `0 <= c < 0x100`, resetting `maybe_trigraph`
  for `>= 0x100`).
- Emit `\%03Lo` for `0x100 <= c < 0o1000` and `\x%Lx` for all other values (`>= 0o1000` or
  negative `int64`, eliminating the `>= 2^32` crash and C11 6.4.3p2 UCN restrictions).
- In `escape_wstring`, when a `\x` escape is immediately followed by a hexadecimal digit
  (`0-9`, `a-f`, `A-F`), emit `" L"` to split adjacent wide string literals so the following digit
  is not consumed by `\x`.
- Update the single affected existing oracle line in `tests/spec/oracle/string.0.res.oracle:9`
  (`L"\uabcdt5ab"` -> `L"\xabcdt5ab"`) and add `tests/pretty_printing/wstring_escape.c`.

### Validation Log

- **Before (`master` `189053d4a2` and `34.0~beta`, stock images):** Reproducer `77` fails 6 of 6
  cases identically on both versions.
- **After (`master` `189053d4a2` + patch `77`, commit `6eda9d94a0`):**
  - Reproducer `77`: `RESULT: fixed` (6/6 cases pass: `wstring_gcc_c99`, `wstring_clang_c99`,
    `wstring_eacsl`, `surrogate_gcc`, `wstring_reparse`, `huge_no_crash`).
  - Regression test `tests/pretty_printing/wstring_escape.c` fails on unpatched `master` (`exit
    125`, `Invalid_argument("Cprint.escape_string_intlist")`) and passes patched.
  - Default test suites: `tests/pretty_printing`, `tests/spec` (1 expected line updated in
    `tests/spec/oracle/string.0.res.oracle`), `tests/syntax`, and `plugins/e-acsl` all pass.
  - `./dev/check-files.sh -p HEAD~1`: passes (`Lint 4 file(s)`), 0 file-mode changes.
- **Pipeline / `opam/` recommendation:** Low priority (only triggers on wide string literals with
  non-ASCII code points `>= 0x200` or trigraphs).
