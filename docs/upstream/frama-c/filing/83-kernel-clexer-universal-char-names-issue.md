# [Kernel] C lexer rejects ISO C99/C11 universal character names (\uXXXX and \UXXXXXXXX) in character and string literals

<!-- Everything below this line is the issue description. -->

### Summary

Frama-C's C lexer (`src/kernel/internals/parsing/clexer.mll`) does not recognize ISO C99/C11
universal character names (`\uXXXX` and `\UXXXXXXXX`, ISO C11 6.4.3) inside character and string
literals. Valid C99/C11 literals such as `L"\u20AC"`, `L"\U0001F600"`, `L'\u20AC'`, and `"\u20AC"`
are rejected with `User Error: Unrecognized escape sequence: \u`, even though Frama-C's ACSL lexer
already supports UCNs and Frama-C's own wide-string printer emits `\u` escapes.

### Steps to reproduce the issue

`ucn.c`:

```c
#include <stddef.h>

const wchar_t *ws1 = L"\u20AC";
const wchar_t *ws2 = L"\U0001F600";
wchar_t wc = L'\u20AC';
const char *s = "\u20AC";

void main(void) {
  /*@ check ws1[0] == 0x20AC && ws1[1] == 0; */
  /*@ check ws2[0] == 0x1F600 && ws2[1] == 0; */
  /*@ check wc == 0x20AC; */
  /*@ check (unsigned char)s[0] == 0xE2 && (unsigned char)s[1] == 0x82 && (unsigned char)s[2] == 0xAC && s[3] == 0; */
}
```

```sh
frama-c -eva ucn.c
```

### Expected behaviour

Matching ISO C11 6.4.3 and `gcc -std=c11` (which prints `ws1[0]=0x20ac`, `ws2[0]=0x1f600`,
`wc=0x20ac`, and UTF-8 bytes `e2 82 ac` for `s`):

- Wide literals (`L"\u20AC"`, `L"\U0001F600"`, `L'\u20AC'`) should decode to the Unicode scalar
  values `0x20AC` and `0x1F600`.
- Narrow literals (`"\u20AC"`, `"\u0024"`) should decode to their UTF-8 byte sequences (`0xE2 0x82
  0xAC`, `0x24`).
- Invalid UCNs per ISO C11 6.4.3p2 (code points `< 0x00A0` other than `0x0024`/`0x0040`/`0x0060`,
  UTF-16 surrogates `0xD800..0xDFFF`, values `> 0x10FFFF`, and incomplete `\u`/`\U` escapes) should
  be rejected with a descriptive parse error.

All 4 Eva checks in `ucn.c` should be proven valid (`Assertions 4 valid 0 unknown 0 invalid 4 total`).

### Actual behaviour

Frama-C aborts on line 3 with exit code 1:

```text
[kernel] Parsing ucn.c (with preprocessing)
[kernel] ucn.c:3: User Error:
  Unrecognized escape sequence: \u:
  Location: "ucn.c", line 3,
            before or at token: \u
  1     #include <stddef.h>
  2     
  3     const wchar_t *ws1 = L"\u20AC";
                               ^^
  4     const wchar_t *ws2 = L"\U0001F600";
  5     wchar_t wc = L'\u20AC';
[kernel] Frama-C aborted: invalid user input.
```

The same error occurs on both `35.0~~dev` (`189053d4a2`) and `34.0~beta` (Selenium).

### Contextual information

- Frama-C installation mode: from source (`master`) and opam (Docker image based on `framac/frama-c:dev`)
- Frama-C version: 35.0~~dev (Bromine), `master` at `189053d4a2`; also `34.0~beta` (Selenium)
- Plug-in used: kernel (C lexer, `clexer.mll`)
- OS name: Debian GNU/Linux
- OS version: 13 (trixie; glibc 2.41, gcc 14.2.0)

### Additional information (optional)

**Cause.** In `src/kernel/internals/parsing/clexer.mll`, `str` (lines 800-807) and `chr` (lines
810-816) only match `hex_escape`, `oct_escape`, and single-character `escape`. Any `\u` or `\U`
falls into `scan_escape` (lines 269-286), which rejects it with `Unrecognized escape sequence: \u`
(or `\U`).

**Fix.** Add `ucn4` (`\uXXXX`), `ucn8` (`\UXXXXXXXX`), `bad_ucn` (`\u`/`\U` with too few hex
digits), and `scan_ucn ~wide` in `clexer.mll`, threading `~wide` into `str` and `chr`:

- Enforce ISO C11 6.4.3p2 (`< 0x00A0` except `$`/`@`/`` ` ``, surrogates `0xD800..0xDFFF`, and
  `> 0x10FFFF` are rejected with `Invalid universal character name`).
- For wide literals (`L"..."`, `L'...'`), emit `[cp]`.
- For narrow literals (`"..."`, `'...'`), UTF-8 encode `cp` via `Buffer.add_utf_8_uchar` into
  `int64` bytes.

(Universal character names in C identifiers are left out of scope of this patch.) A merge request
with this fix and a regression test (`tests/syntax/ucn_literals.c`) is ready.

The analysis and fix were prepared with LLM assistance; I reviewed them and ran the reproducer and
tests described above.
