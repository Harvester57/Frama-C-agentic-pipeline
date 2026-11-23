# [Kernel] Pretty-printer double-escapes ACSL wide strings (`LWStr`) and prints empty `L""` as bare `L`

<!-- Everything below this line is the issue description. -->

### Summary

In `Cil_printer.logic_constant` (`src/kernel/services/ast_printing/cil_printer.ml`, lines
2399-2413), the `LWStr` printer has two bugs that break pretty-printing and re-parsing of ACSL
wide string literals:

1. **Double-escaping:** For every wide character in `0..255`, the printer calls
   `fprintf fmt "%S" (Escape.escape_char (Char.chr (Int64.to_int elt)))`. Because
   `Escape.escape_char` already escapes control characters, quotes, backslashes, and non-ASCII
   bytes, formatting its result with OCaml's `%S` escapes every backslash and quote a second time
   (for example `L"\n\t"` becomes `L"\\n" "\\t" ` and `L"a\"b"` becomes `L"a" "\\\"" "b" `).
   Re-parsing the printed file changes both the contents and `sizeof` of the literal, turning valid
   assertions into invalid ones.
2. **Invalid syntax for empty wide string `L""`:** When `s = []`, `fprintf fmt "L"` followed by
   `List.iter ... []` emits bare `L` without quotes (`sizeof(L)`), which fails re-parsing with
   `unbound logic variable L`.

### Steps to reproduce the issue

#### 1. Double-escaped ACSL wide string

`acsl_wstr.c`:

```c
#include <stddef.h>
int main(void) {
  //@ check s1: sizeof(L"\n\t") == 3 * sizeof(wchar_t);
  //@ check s2: sizeof(L"a\"b") == 4 * sizeof(wchar_t);
  //@ check s3: sizeof(L"a\\b") == 4 * sizeof(wchar_t);
  //@ check s4: sizeof(L"\351") == 2 * sizeof(wchar_t);
  return 0;
}
```

```sh
frama-c -eva acsl_wstr.c
frama-c acsl_wstr.c -print -ocode acsl_wstr_out.c
frama-c -eva acsl_wstr_out.c
frama-c -wp -wp-prover none -wp-print acsl_wstr_out.c
```

#### 2. Empty ACSL wide string `L""`

`acsl_wstr_empty.c`:

```c
#include <stddef.h>
int main(void) {
  //@ check e1: sizeof(L"") == 1 * sizeof(wchar_t);
  return 0;
}
```

```sh
frama-c acsl_wstr_empty.c -print -ocode acsl_wstr_empty_out.c
frama-c acsl_wstr_empty_out.c
```

### Expected behaviour

1. `acsl_wstr_out.c` prints `L"\n" "\t"`, `L"a" "\"" "b"`, `L"a" "\\" "b"`, and `L"\351"`. All
   four checks remain valid under Eva and `Prove: true.` under WP after re-parsing.
2. `acsl_wstr_empty_out.c` prints `sizeof(L"") == 1 * sizeof(wchar_t)`, re-parses cleanly, and the
   check remains valid.

### Actual behaviour

#### 1. `acsl_wstr.c`

On the original `acsl_wstr.c`, Eva validates all four checks (0 invalid).

`acsl_wstr_out.c` contains double-escaped literals:

```c
  /*@ check s1: sizeof(L"\\n" "\\t" ) ≡ 3 * sizeof(wchar_t); */ ;
  /*@ check s2: sizeof(L"a" "\\\"" "b" ) ≡ 4 * sizeof(wchar_t); */ ;
  /*@ check s3: sizeof(L"a" "\\\\" "b" ) ≡ 4 * sizeof(wchar_t); */ ;
  /*@ check s4: sizeof(L"\\351" ) ≡ 2 * sizeof(wchar_t); */ ;
```

Re-parsing `acsl_wstr_out.c` makes all four checks invalid under Eva and refuted (`Prove: false.`)
under WP:

```text
[eva:alarm] acsl_wstr_out.c:6: Warning: check 's1' got status invalid.
[eva:alarm] acsl_wstr_out.c:7: Warning: check 's2' got status invalid.
[eva:alarm] acsl_wstr_out.c:8: Warning: check 's3' got status invalid.
[eva:alarm] acsl_wstr_out.c:9: Warning: check 's4' got status invalid.
```

#### 2. `acsl_wstr_empty.c`

`acsl_wstr_empty_out.c` prints bare `L`:

```c
  /*@ check e1: sizeof(L) ≡ 1 * sizeof(wchar_t); */ ;
```

Re-parsing `acsl_wstr_empty_out.c` aborts (exit 1):

```text
[kernel:annot-error] acsl_wstr_empty_out.c:6: Failure: 
  unbound logic variable L. Ignoring code annotation
[kernel] User Error: warning annot-error treated as fatal error.
[kernel] Frama-C aborted: invalid user input.
```

### Contextual information

- Frama-C installation mode: from source (`master`) and opam (Docker image based on `framac/frama-c:dev`)
- Frama-C version: 35.0~~dev (Bromine), `master` at 189053d4a2; also 34.0~beta (Selenium), identical output
- Plug-in used: kernel (`Cil_printer`)
- OS name: Debian GNU/Linux
- OS version: 13 (trixie; glibc 2.41, gcc 14.2.0)

### Additional information (optional)

**Cause.** In `src/kernel/services/ast_printing/cil_printer.ml` (lines 2399-2411):

```ocaml
    | LWStr(s) ->
      fprintf fmt "L";
      List.iter
        (fun elt ->
           if (elt >= Int64.zero &&
               elt <= (Int64.of_int 255)) then
             fprintf fmt "%S"
               (Escape.escape_char (Char.chr (Int64.to_int elt)))
           else
             fprintf fmt "\"\\x%LX\"" elt;
           fprintf fmt "@ ")
        s;
```

- `Escape.escape_char` already returns the escaped content for inside quotes (just as `LStr` at
  line 2398 uses `fprintf fmt "\"%s\"" (Escape.escape_string s)`), so `%S` escapes it a second
  time.
- When `s = []`, `List.iter` prints nothing after `L`.

**Fix.** Add `| LWStr [] -> fprintf fmt "L\"\""` and change `"%S"` to `"\"%s\""` at line 2406.
A merge request with this fix and regression test `tests/pretty_printing/acsl_wstring.c` is ready.

The analysis and fix were prepared with LLM assistance; I reviewed them and ran the reproducer and
tests described above.
