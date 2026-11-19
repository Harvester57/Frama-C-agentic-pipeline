# [Kernel] `_Alignas` printed after the declarator of struct members and after `*` in pointer declarators (invalid C)

<!-- Everything below this line is the issue description. -->

### Summary

The pretty-printer places `_Alignas` inside the declarator: after the name of a struct or union member (`uint64_t u64[2] _Alignas(16) ;`) and after the `*` of pointer declarators, and silently drops it on `__builtin_va_list` declarations (and, once `TPtr` forwards `?alignas`, on `__builtin_va_list *` under `-no-variadic-translation`). GCC, Clang and Frama-C itself reject the misplaced specifiers, so the output of `-print` and `-ocode`, E-ACSL's included, does not compile.

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
_Alignas(16) __builtin_va_list gva;
_Alignas(16) __builtin_va_list *gvap = &gva;

int main(void)
{
  _Alignas(16) int *lp = 0;    /* local pointer */
  union blk u = { .b = { 0 } };
  struct s v = { 0 };
  return (int)u.u64[0] + v.c + (lp == 0) + (gp == 0) + (gfp == 0)
    + (gap[0] == 0) + (int)ga[0] + (gvap == 0);
}
```

```
$ frama-c -no-unicode -no-variadic-translation t.c -print -ocode out.c
$ grep -n _Alignas out.c
$ gcc -std=gnu11 -fsyntax-only out.c
$ clang -std=gnu11 -fsyntax-only out.c
$ frama-c -no-variadic-translation out.c
```

### Expected behaviour

`-print` / `-ocode` produce C code that compiles and that Frama-C itself can parse again, with the
same alignments. `_Alignas` is an alignment specifier, one of the declaration specifiers (C17
6.7.5), so it belongs before the declarator: `uint64_t _Alignas(16) u64[2];`,
`int _Alignas(16) *gp;`, `__builtin_va_list _Alignas(16) gva;`,
`__builtin_va_list _Alignas(16) *gvap = & gva;`.

### Actual behaviour

The specifier is printed after the declarator of struct and union members, after the `*` of any
pointer declarator (members, globals and locals), and silently dropped on `gva`:

```
4:   uint64_t u64[2] _Alignas(16) ;
9:   char d _Alignas(8) ;
10:   int *p _Alignas(16) ;
12:int *_Alignas(16) gp;
13:int (*_Alignas(16) gfp)(int );
14:char * _Alignas(8)gap[2];
15:uint64_t  _Alignas(16)ga[2];
17:__builtin_va_list *_Alignas(16) gvap = & gva;
21:  int *_Alignas(16) lp = (int *)0;
```

Only line 15 is valid C, and `gva` on line 16 loses `_Alignas(16)`. GCC rejects the
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
- Frama-C version: 35.0~~dev (Bromine), `master` at `b80fcac74f` (first seen on `3dff90fc70`); also 34.0~beta (Selenium), same output
- Plug-in used: kernel (`-print`, `-ocode`); E-ACSL inherits it
- OS name: Debian GNU/Linux
- OS version: 13 (trixie)

### Additional information (optional)

Cause, on `b80fcac74f`, `src/kernel/services/ast_printing/cil_printer.ml`:

- `fieldinfo` prints the member with `self#typ` and then appends
  `self#alignas ~space:true fi.falignas` after the name, giving `char d _Alignas(8) ;`. `vdecl`
  passes the alignment to `self#typ ?alignas:v.valignas` instead.
- In `typ`, the `TPtr` case prints `palignas` inside the pointer declarator, right
  after the `*`, and the `TArray` case prints it in front of the name inside the
  array declarator. That is valid only when the array element is not itself a pointer (line 15
  above); otherwise it lands after a `*` (line 14).
- The `TBuiltin_va_list` case omits `palignas` entirely, silently dropping `_Alignas` on
  `__builtin_va_list` declarations and (once `TPtr` forwards `?alignas`) on pointers to
  `__builtin_va_list` under `-no-variadic-translation`, even though GCC and Clang accept both.

Proposed fix: print the alignment with the base type only. `TPtr`, `TArray` and `TFun` pass
`?alignas` down to the recursive `self#typ` call and no longer print it in the declarator;
`TBuiltin_va_list` prints `palignas true` like the other leaf cases (`TInt`, `TNamed`, `TComp`,
...). `fieldinfo` passes `?alignas:fi.falignas` to `self#typ`, as `vdecl` does. Output with the
fix:

```
4:   uint64_t _Alignas(16) u64[2] ;
9:   char _Alignas(8) d ;
10:   int _Alignas(16) *p ;
12:int _Alignas(16) *gp;
13:int _Alignas(16) (*gfp)(int );
14:char _Alignas(8) *gap[2];
15:uint64_t _Alignas(16) ga[2];
16:__builtin_va_list _Alignas(16) gva;
17:__builtin_va_list _Alignas(16) *gvap = & gva;
21:  int _Alignas(16) *lp = (int *)0;
```

GCC, Clang and Frama-C accept it, and `_Static_assert`s on `_Alignof(union blk) == 16`,
`_Alignof(struct s) == 16`, `__alignof__(gp) == 16`, `__alignof__(gap) == 8`,
`__alignof__(gva) == 16`, and `__alignof__(gvap) == 16` hold on the printed file. Declarations that
were already valid only change spacing (`uint64_t  _Alignas(16)ga[2]` becomes
`uint64_t _Alignas(16) ga[2]`).

A merge request with a fix follows.

The analysis and fix were prepared with LLM assistance (Claude Code); I reviewed them and ran the
reproducer and tests described above.
