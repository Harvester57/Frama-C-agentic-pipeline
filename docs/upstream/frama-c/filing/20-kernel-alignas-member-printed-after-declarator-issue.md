# [Kernel] `_Alignas` printed after the declarator of struct members and after `*` in pointer declarators (invalid C)

<!-- Everything below this line is the issue description. -->

### Summary

The pretty-printer places `_Alignas` inside the declarator: after the name of a struct or union member (`uint64_t u64[2] _Alignas(16) ;`) and after the `*` of pointer declarators. GCC, Clang and Frama-C itself reject this, so the output of `-print` and `-ocode`, E-ACSL's included, does not compile.

### Steps to reproduce the issue

`t.c`:

```c
#include <stdint.h>

union blk {
  _Alignas(16) uint64_t u64[2]; /* nettle's union nettle_block16 */
  uint8_t b[16];
};

struct s {
  char c;
  _Alignas(8) char d;
  _Alignas(16) int *p;
};

_Alignas(16) int *gp;          /* global pointer */
_Alignas(16) int (*gfp)(int);  /* global function pointer */
_Alignas(8) char *gap[2];      /* global array of pointers */
_Alignas(16) uint64_t ga[2];   /* global array: already printed validly */

int main(void)
{
  _Alignas(16) int *lp = 0;    /* local pointer */
  union blk u = { .b = { 0 } };
  struct s v = { 0 };
  return (int)u.u64[0] + v.c + (lp == 0) + (gp == 0) + (gfp == 0)
    + (gap[0] == 0) + (int)ga[0];
}
```

```
$ frama-c -no-unicode t.c -print -ocode out.c
$ grep -n _Alignas out.c
$ gcc -std=gnu11 -fsyntax-only out.c
$ clang -std=gnu11 -fsyntax-only out.c
$ frama-c out.c
```

### Expected behaviour

`-print` / `-ocode` produce C code that compiles and that Frama-C itself can parse again, with the
same alignments. `_Alignas` is an alignment specifier, one of the declaration specifiers (C17
6.7.5), so it belongs before the declarator: `uint64_t _Alignas(16) u64[2];`,
`int _Alignas(16) *gp;`.

### Actual behaviour

The specifier is printed after the declarator of struct and union members, and after the `*` of any
pointer declarator (members, globals and locals):

```
4:   uint64_t u64[2] _Alignas(16) ;
9:   char d _Alignas(8) ;
10:   int *p _Alignas(16) ;
12:int *_Alignas(16) gp;
13:int (*_Alignas(16) gfp)(int );
14:char * _Alignas(8)gap[2];
15:uint64_t  _Alignas(16)ga[2];
19:  int *_Alignas(16) lp = (int *)0;
```

Only line 15 is valid C. GCC rejects the
others (`error: expected ':', ',', ';', '}' or '__attribute__' before '_Alignas'`, `error: expected
identifier or '(' before '_Alignas'`), Clang too (`error: expected ';' at end of declaration list`,
`error: expected identifier or '('`), and so does Frama-C when re-parsing its own output:

```
[kernel] out.c:4: User Error:
  syntax error:
  Location: "out.c", line 4, before or at token: _Alignas
```

The E-ACSL output inherits it: any program with an aligned member (for instance nettle's
`nettle-types.h`, `alignas(16) uint64_t u64[2];` in `union nettle_block16`) gives an instrumented
file that Clang cannot compile.

### Contextual information

- Frama-C installation mode: from source (`master`) and opam (Docker image based on `framac/frama-c:dev`)
- Frama-C version: 35.0~~dev (Bromine), `master` at 3dff90fc70; also 34.0~beta (Selenium), same output
- Plug-in used: kernel (`-print`, `-ocode`); E-ACSL inherits it
- OS name: Debian GNU/Linux
- OS version: 13 (trixie)

### Additional information (optional)

Cause, on `3dff90fc70`, `src/kernel/services/ast_printing/cil_printer.ml`:

- `fieldinfo` (lines 1895-1906) prints the member with `self#typ` and then appends
  `self#alignas ~space:true fi.falignas` after the name, giving `char d _Alignas(8) ;`. `vdecl`
  (line 728) passes the alignment to `self#typ ?alignas:v.valignas` instead.
- In `typ`, the `TPtr` case (lines 2069-2076) prints `palignas` inside the pointer declarator, right
  after the `*`, and the `TArray` case (lines 2112-2119) prints it in front of the name inside the
  array declarator. That is valid only when the array element is not itself a pointer (line 15
  above); otherwise it lands after a `*` (line 14).

Proposed fix: print the alignment with the base type only. `TPtr`, `TArray` and `TFun` pass
`?alignas` down to the recursive `self#typ` call and no longer print it in the declarator; the leaf
cases (`TInt`, `TNamed`, `TComp`, ...) already print it after the type name and its qualifiers.
`fieldinfo` passes `?alignas:fi.falignas` to `self#typ`, as `vdecl` does. Output with the fix:

```
4:   uint64_t _Alignas(16) u64[2] ;
9:   char _Alignas(8) d ;
10:   int _Alignas(16) *p ;
12:int _Alignas(16) *gp;
13:int _Alignas(16) (*gfp)(int );
14:char _Alignas(8) *gap[2];
15:uint64_t _Alignas(16) ga[2];
19:  int _Alignas(16) *lp = (int *)0;
```

GCC, Clang and Frama-C accept it, and `_Static_assert`s on `_Alignof(union blk) == 16`,
`_Alignof(struct s) == 16`, `__alignof__(gp) == 16` and `__alignof__(gap) == 8` hold on the
printed file. Declarations that were already valid only change spacing
(`uint64_t  _Alignas(16)ga[2]` becomes `uint64_t _Alignas(16) ga[2]`).

A merge request with a fix follows.

The analysis and fix were prepared with LLM assistance (Claude Code); I reviewed them and ran the
reproducer and tests described above.
