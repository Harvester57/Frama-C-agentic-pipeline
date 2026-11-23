# [kernel] print wide-string escapes with \x and preserve trigraph state

- Source branch: `fix/kernel-wstring-escape-trigraph` on the fork of `pub/frama-c`; target branch `master`.
- Based on: `189053d4a2`. Patch: [`../patches/77-kernel-wstring-escape-trigraph.patch`](../patches/77-kernel-wstring-escape-trigraph.patch)

<!-- Everything below this line is the merge request description. -->

Before submitting the merge request, please confirm (by adding a X in the [ ]):

- [ ] you contributed to Frama-C as prescribed in the [instructions](https://git.frama-c.com/pub/frama-c/-/blob/master/CONTRIBUTING.md).
- [ ] if the size of the PR requires it, you have signed the
  [Contributor Licensing Agreement](https://git.frama-c.com/pub/frama-c/-/blob/master/CLA.md)

Closes #<issue>.

## Problem

`Escape.escape_wchar` and `Escape.escape_wstring` (`src/lib/utils/escape.ml`, lines 54-82) had five
defects when printing C wide string literals:

- Code points in `0o1000..0xFFFF` were printed as `\uXXXX`, rejected by Frama-C's C lexer on
  re-parse (`Unrecognized escape sequence: \u`) and rejected by GCC/Clang for UTF-16 surrogates
  (`0xD800..0xDFFF`, C11 6.4.3p2).
- Code points in `0x10000..0xFFFFFFFF` were printed with lowercase `\u` and 5 to 8 hex digits
  instead of `\UXXXXXXXX` (violating C11 6.4.3 and causing GCC/Clang to silently consume 4 digits
  plus trailing literal characters, and invalid above `0x10FFFF`).
- Code points `>= 2^32` (such as `L"\x100000000"`) crashed Frama-C with uncaught
  `Invalid_argument("Cprint.escape_string_intlist")` (exit 125).
- `limit` used `Int64.to_float` subtraction, mishandling negative `int64`.
- `escape_wchar` called `escape_char` (fresh `maybe_trigraph = ref false` per character), so
  `L"a?\?!b"` printed as `L"a??!b"` and was silently corrupted under `-std=c99` (including
  `e-acsl-gcc`).

## Change

`src/lib/utils/escape.ml` (36 lines added, 23 lines removed):

- Add `is_hex_digit` and `escape_wchar_internal maybe_trigraph charcode` threading trigraph state
  across `escape_wstring` (matching `escape_string`).
- Emit `\%03Lo` for `0x100 <= c < 0o1000` and `\x%Lx` for all other values (`>= 0o1000` or
  negative `int64`).
- In `escape_wstring`, emit `" L"` after a `\x` escape whenever the next character is a hexadecimal
  digit (`0-9`, `a-f`, `A-F`), preventing greedy hex consumption.

Update the single affected oracle line in `tests/spec/oracle/string.0.res.oracle` (`L"\uabcdt5ab"`
-> `L"\xabcdt5ab"`) and add regression test `tests/pretty_printing/wstring_escape.c` with its
oracle.

## Testing

All on Debian 13 (OCaml 5.5, gcc 14.2.0, clang 19.1.7), upstream `master` at `189053d4a2`:

- **Reproducer (6 cases: `gcc -std=c99`, `clang -std=c99`, `e-acsl-gcc`, surrogate `L"\xD800"`
  with `gcc`, Frama-C re-parse, and `L"\x100000000"` no-crash):**
  - Before (`master` `189053d4a2` and `34.0~beta`): 6 of 6 cases fail.
  - After (installed patched `master`): 6 of 6 cases pass (`RESULT: fixed`).
- **New test on unpatched `master`:** `tests/pretty_printing/wstring_escape.c` fails (`exit 125`,
  `Invalid_argument("Cprint.escape_string_intlist")`). With the patch, it passes and re-parsing is
  idempotent.
- **ptests, default configuration:** `./dev/test.sh -p tests/pretty_printing`,
  `./dev/test.sh -p tests/spec`, `./dev/test.sh -p tests/syntax`, and
  `./dev/test.sh -p plugins/e-acsl` all pass (with only the expected 1-line oracle update in
  `tests/spec/oracle/string.0.res.oracle`).
- **`./dev/check-files.sh -p HEAD~1`:** passes (`Lint 4 file(s)`).
- **Not run:** 32-bit targets and `make default-tests` outside the suites listed above.

The analysis and fix were prepared with LLM assistance; I reviewed them and ran the reproducer and
tests described above.
