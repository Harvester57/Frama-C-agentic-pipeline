# [Kernel] `Cil.charConstToInt` always sign-extends character constants >= 128 even on unsigned-`char` machdeps (`ppc_32`)

<!-- Everything below this line is the issue description. -->

### Summary

`Cil.charConstToInt` unconditionally sign-extends character constants with byte values `128..255`
to `-128..-1`, ignoring whether plain `char` is unsigned on the active machdep (such as the bundled
`ppc_32` machdep or custom ARM/PowerPC Linux machdeps). On such machdeps, `'\377'` evaluates to
`-1` while `(char)255` and `"\377"[0]` evaluate to `255`: Frama-C disagrees with ISO C11
6.4.4.4p10, `gcc -funsigned-char`, and its own `char` evaluation, causing comparisons like
`a[0] == '\377'` or `switch (c) { case '\377': ... }` to evaluate to false and silently turn live
code dead.

### Steps to reproduce the issue

`char_const_unsigned.c`:

```c
int main(void) {
  int h = '\377';
  char c = 255;
  char a[] = "\377";
  int eq = (a[0] == '\377');
  int sz = sizeof(char[('\377' > 0) ? 2 : 1]);
  //@ check h1: h == 255;
  //@ check h2: h == c;
  //@ check h3: '\377' == 255;
  //@ check h4: eq == 1;
  //@ check h5: sz == 2;
  return 0;
}
```

```sh
frama-c -machdep ppc_32 -print char_const_unsigned.c
frama-c -machdep ppc_32 -eva char_const_unsigned.c
```

### Expected behaviour

By ISO C11 6.4.4.4p10, an integer character constant containing a single character has the value of
that character converted to `int` via plain `char`. On `ppc_32` (`char_is_unsigned: true`, matching
`gcc -funsigned-char`), `'\377'` is `255`, `a[0] == '\377'` is `1`,
`sizeof(char[('\377' > 0) ? 2 : 1])` folds to `sizeof(char [2])`, and all five assertions (`h1`
through `h5`) are valid in Eva.

### Actual behaviour

`-print` folds `sizeof(char[('\377' > 0) ? 2 : 1])` to `sizeof(char [1])`, and Eva marks all five
assertions invalid:

```text
  int h = '\377';
  int eq = (int)a[0] == '\377';
  int sz = (int)sizeof(char [1]);
```

```text
[eva:alarm] char_const_unsigned.c:7: Warning: check 'h1' got status invalid.
[eva:alarm] char_const_unsigned.c:8: Warning: check 'h2' got status invalid.
[eva:alarm] char_const_unsigned.c:9: Warning: check 'h3' got status invalid.
[eva:alarm] char_const_unsigned.c:10: Warning: check 'h4' got status invalid.
[eva:alarm] char_const_unsigned.c:11: Warning: check 'h5' got status invalid.
    Assertions        0 valid     0 unknown     5 invalid      5 total
```

### Contextual information

- Frama-C installation mode: from source (`master`) and opam (Docker image based on `framac/frama-c:dev`)
- Frama-C version: 35.0~~dev (Bromine), `master` at 189053d4a2; also 34.0~beta (Selenium), same output
- Plug-in used: Kernel (`Cil.charConstToInt`), observed in Eva, WP, and E-ACSL
- OS name: Debian GNU/Linux
- OS version: 13 (trixie; glibc 2.41, gcc 14.2.0)

### Additional information (optional)

**Cause.** `Cil.charConstToInt` (`src/kernel/services/ast_queries/cil.ml:2547-2551`) always
sign-extends:

```ocaml
let charConstToInt c =
  let c' = Char.code c in
  if c' < 128
  then Z.of_int c'
  else Z.of_int (c' - 256)
```

Eva (`eva_ast_utils.ml`, `eval_terms.ml`, `main_values.ml`), WP (`ctypes.ml:232`), E-ACSL
(`interval.ml:353`), `cabs2cil.ml:5394`, and constant folding (`cil.ml:2558,3714,3798`) all go
through `Cil.charConstToInt`.

**Fix.** Consult `Machine.char_is_unsigned ()` in `Cil.charConstToInt`:

```ocaml
let charConstToInt c =
  let c' = Char.code c in
  if Machine.char_is_unsigned () || c' < 128
  then Z.of_int c'
  else Z.of_int (c' - 256)
```

A merge request with this fix and a regression test (`tests/syntax/char_const_unsigned.c`) is ready.

The analysis and fix were prepared with LLM assistance; I reviewed them and ran the reproducer and
tests described above.
