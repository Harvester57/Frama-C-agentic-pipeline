# [Kernel] `sizeof` of an ACSL string literal counts raw escaped characters instead of unescaped bytes

<!-- Everything below this line is the issue description. -->

### Summary

In ACSL annotations, `sizeof` applied to a string literal containing escape sequences (such as
`"\n"`, `"a\0b"`, `"\x41"`, `"\\"`, or a `#define`d message macro like `#define GREETING "hello\n"`)
evaluates to the length of the raw escaped source text plus 1 instead of the unescaped byte length
plus 1. For example, `sizeof("\n")` evaluates to `3` instead of `2`, and `sizeof(GREETING)`
evaluates to `8` instead of `7`. On ordinary code that shares a string macro between C and ACSL
contracts, WP refutes true postconditions and Eva marks valid preconditions invalid and halts
analysis (`NON TERMINATING FUNCTION`).

### Steps to reproduce the issue

`string_sizeof_escape.c`:

```c
#define GREETING "hello\n"
char out[sizeof(GREETING)];

/*@ assigns \nothing;
    ensures len: \result == sizeof(GREETING); */
unsigned long greeting_size(void) { return sizeof(GREETING); }

/*@ requires room: \valid(buf + (0 .. sizeof(GREETING) - 1));
    assigns buf[0 .. sizeof(GREETING) - 1]; */
void greet(char *buf) { buf[0] = 'h'; }

int main(void) {
  //@ check c1: sizeof("\n") == 2;
  //@ check c2: sizeof("a\0b") == 4;
  //@ check c3: sizeof("\x41") == 2;
  //@ check c4: sizeof("\\") == 2;
  //@ check c5: sizeof(GREETING) == sizeof(out);
  greet(out);
  return 0;
}
```

```sh
frama-c -eva string_sizeof_escape.c
frama-c -wp -wp-prover none -wp-print string_sizeof_escape.c
```

### Expected behaviour

In C and ACSL, `sizeof("\n") == 2`, `sizeof("a\0b") == 4`, `sizeof("\x41") == 2`,
`sizeof("\\") == 2`, and `sizeof(GREETING) == sizeof(out) == 7`.

- `-eva` validates all five checks (`c1` through `c5`) and the precondition `room` of `greet`, and
  terminates normally.
- `-wp -wp-prover none -wp-print` proves `len`, `c1` through `c5`, and the `room` precondition
  (`Prove: true.`).

### Actual behaviour

`-eva` marks all five checks and `greet`'s precondition invalid and stops analysis at the call:

```text
[eva:alarm] string_sizeof_escape.c:13: Warning: check 'c1' got status invalid.
[eva:alarm] string_sizeof_escape.c:14: Warning: check 'c2' got status invalid.
[eva:alarm] string_sizeof_escape.c:15: Warning: check 'c3' got status invalid.
[eva:alarm] string_sizeof_escape.c:16: Warning: check 'c4' got status invalid.
[eva:alarm] string_sizeof_escape.c:17: Warning: check 'c5' got status invalid.
[eva:alarm] string_sizeof_escape.c:18: Warning:
  function greet: precondition 'room' got status invalid.
[eva:final-states] Values at end of function main:
  NON TERMINATING FUNCTION
```

`-wp -wp-prover none -wp-print` refutes every true property:

```text
Goal Post-condition 'len' in 'greeting_size':
Prove: false.
Goal Check 'c1' ("string_sizeof_escape.c", line 13):
Prove: false.
Goal Check 'c5' ("string_sizeof_escape.c", line 17):
Prove: false.
Goal Instance of 'Pre-condition 'room' in 'greet'' in 'main' at call 'greet' ("string_sizeof_escape.c", line 18)
Prove: false.
```

### Contextual information

- Frama-C installation mode: from source (`master`) and opam (Docker image based on `framac/frama-c:dev`)
- Frama-C version: 35.0~~dev (Bromine), `master` at 189053d4a2; also 34.0~beta (Selenium), same output
- Plug-in used: Kernel (ACSL typing, `logic_typing.ml`), observed in Eva and WP
- OS name: Debian GNU/Linux
- OS version: 13 (trixie; glibc 2.41, gcc 14.2.0)

### Additional information (optional)

**Cause.** In `src/kernel/services/ast_queries/logic_typing.ml` (lines 2684-2685, introduced by
commit `db4b010a04` on 2025-07-24):

```ocaml
    | PLconstant (StringConstant s) ->
      TConst (LStr (unescape s)), typeOf_string_literal loc s
```

The term node uses `unescape s`, whereas `typeOf_string_literal` receives the unescaped raw source
string `s`, so the array size includes every backslash and escape digit. (By contrast, wide string
literals on lines 2686-2688 bind `let l = wcharlist_of_string s` first and pass `l` to both
`LWStr` and `typeOf_wstring_literal`.)

**Fix.** Bind `let s = unescape s in` and pass the unescaped string `s` to both `LStr s` and
`typeOf_string_literal loc s`. A merge request with this fix and a regression test
(`tests/spec/string_sizeof_escape.c`) is ready.

The analysis and fix were prepared with LLM assistance; I reviewed them and ran the reproducer and
tests described above.
