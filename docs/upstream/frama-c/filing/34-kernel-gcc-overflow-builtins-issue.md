# [Libc] GCC's `__builtin_{add,sub,mul}_overflow`: wrong results for mixed operand types, parse error for small types, `_p` forms missing, and an uncompilable declaration when the header is not included

<!-- Everything below this line is the issue description. -->

### Summary

Frama-C models GCC's type-generic overflow builtins in `__fc_gcc_builtins.h` by `_Generic` macros that pick the typed form (`__builtin_sadd_overflow`, ...) from the type of the first operand. When the operand and result types differ, Eva computes a precise flag that the compiled program never returns; with `char` or `short` operands the parsing stops; the `_p` forms are not declared; and when the header is not included (non-GCC machdep, no libc header, `-no-frama-c-stdlib`) the builtin becomes an implicit K&R declaration whose printed prototype neither gcc nor clang can use. I did not write a patch; possible directions are listed below.

### Steps to reproduce the issue

`t.c`:

```c
#include <limits.h>

int test(void)
{
#if CASE == 1
  int a = 65536, b = 65536; long r;
  return __builtin_mul_overflow(a, b, &r);       /* gcc: 0 */
#elif CASE == 2
  int a = 1; long b = 0x17fffffffL, r;
  return __builtin_add_overflow(a, b, &r);       /* gcc: 0 */
#elif CASE == 3
  int a = -1, b = 0; unsigned r;
  return __builtin_add_overflow(a, b, &r);       /* gcc: 1 */
#elif CASE == 4
  unsigned char a = 200, b = 100, r;
  return __builtin_add_overflow(a, b, &r);       /* gcc: 1 */
#elif CASE == 5
  int a = INT_MAX;
  return __builtin_add_overflow_p(a, 1, (int)0); /* gcc: 1 */
#endif
}

int main(void)
{
  int o = test();
#ifdef __FRAMAC__
  Frama_C_show_each_overflow(o);
#endif
  return o;
}
```

```
$ frama-c -machdep gcc_x86_64 -cpp-extra-args=-DCASE=1 t.c -eva    # likewise CASE=2..5
```

`u.c` (no `#include`):

```c
int add_int(void)
{
  int a = 0x7fffffff, b = 1, r;
  return __builtin_add_overflow(a, b, &r);   /* 1 */
}

int add_long(void)
{
  long a = 0x7fffffff, b = 1, r;
  return __builtin_add_overflow(a, b, &r);   /* 0 */
}

int main(void) { return add_int() * 10 + add_long(); }   /* gcc: 10 */
```

```
$ frama-c u.c -print -ocode p.c     # same with -machdep gcc_x86_64, and with -no-frama-c-stdlib
$ gcc -o p p.c
$ clang -c p.c
$ e-acsl-gcc -c -O prog u.c
$ e-acsl-gcc -c -G clang -O prog u.c
```

### Expected behaviour

GCC's semantics: the operation is done in infinite precision on operands of any integer types, the
result is stored converted to the type of `*res`, and the flag says whether it fits. Eva's value of
the flag contains what gcc returns (0, 0, 1, 1, 1 for cases 1-5), and the printed code of `u.c`
compiles and returns 10.

### Actual behaviour

With `-machdep gcc_x86_64` and Frama-C's libc:

| Case | Types | gcc | Eva | Kernel message |
|---|---|---|---|---|
| 1 | `mul(int, int, long *)` | 0 | `{1}` | `[kernel:typing:incompatible-types-call] expected 'int *' but got argument of type 'long *': & r` |
| 2 | `add(int, long, long *)` | 0 | `{1}` | same (and `b` is converted to `int`) |
| 3 | `add(int, int, unsigned *)` | 1 | `{0}` | `expected 'int *' but got argument of type 'unsigned int *': & r` |
| 4 | `add(unsigned char, unsigned char, unsigned char *)` | 1 | parsing stops | `User Error: no compatible types and no default type in _Generic selection: controlling expression: 'a' (type: unsigned char); candidate types: unsigned long long, long long, unsigned long, long, unsigned int, int` |
| 5 | `add_overflow_p(int, int, int)` | 1 | `[-2147483648..2147483647]` | `[kernel:typing:implicit-function-declaration] Calling undeclared function __builtin_add_overflow_p. Old style K&R code?`, then `missing-spec` |

`u.c`, with the default machdep, with `-machdep gcc_x86_64`, and with `-no-frama-c-stdlib`:

```
[kernel:typing:implicit-function-declaration] u.c:4: Warning:
  Calling undeclared function __builtin_add_overflow. Old style K&R code?
[kernel:typing:incompatible-types-call] u.c:10: Warning:
  expected 'int *' but got argument of type 'long *': & r
```

The printed code declares the builtin from the first call and converts the second one:

```c
extern int ( /* missing proto */ __builtin_add_overflow)(int x_0, int x_1,
                                                         int *x_2);
...
  tmp = __builtin_add_overflow((int)a,(int)b,(int *)(& r));
```

The conversion changes the result of the second call (compiled by gcc, it returns 1 instead of 0).
gcc compiles `p.c` but the link fails with `undefined reference to '__builtin_add_overflow'`;
clang rejects it with `error: cannot redeclare builtin function '__builtin_add_overflow'`. E-ACSL
prints its instrumented file the same way, and `e-acsl-gcc` always parses with
`-machdep gcc_x86_64 -no-frama-c-stdlib`, so it fails on any program that uses these builtins:

```
a.out.frama.c:204:(.text+0x14): undefined reference to `__builtin_add_overflow'
...
e-acsl-gcc: fatal error: fail to compile/link instrumented code
```

and with `-G clang`:

```
a.out.frama.c:195:34: error: cannot redeclare builtin function '__builtin_add_overflow'
```

### Contextual information

- Frama-C installation mode: from source (`master`) and opam (Docker image based on `framac/frama-c:dev`)
- Frama-C version: 35.0~~dev (Bromine), `master` at 95408044f7; also 34.0~beta (Selenium), same output
- Plug-in used: kernel (libc), Eva, E-ACSL (`e-acsl-gcc`)
- OS name: Debian GNU/Linux
- OS version: 13 (trixie)

### Additional information (optional)

Where the model lives:

- `share/libc/__fc_gcc_builtins.h` declares the 18 typed forms with ACSL contracts and defines
  `__builtin_{add,sub,mul}_overflow` as `_Generic((a), int: ..., unsigned int: ..., long: ...,
  unsigned long: ..., long long: ..., unsigned long long: ...)(a,b,res)` (lines 87-95, 154-162,
  221-229). The comment above each macro says "technically, the types of a, b and *res could
  differ, but we assume that this is not the case". Cases 1-3 show what that assumption gives: a
  precise flag that differs from the program's, so an analysis can miss the path the program takes.
  Case 4 is a parse failure on valid GCC code.
- That header is included by the generated `__fc_machdep.h` only when `gccMode` holds (machdeps
  whose compiler is `gcc` or `clang`, `src/kernel/internals/runtime/machdep.ml:310` and
  `684-685`), and `__fc_machdep.h` is included by `features.h`. So a file that includes no Frama-C
  libc header pulling in `features.h`, a file parsed with `-no-frama-c-stdlib`, or any file on the
  default `x86_64` machdep never sees it. On the default machdep `__GNUC__` is not defined, so
  code that guards the builtins with it (MPack does) does not reach them; on `gcc_x86_64` it is,
  with or without `-no-frama-c-stdlib`, and `e-acsl-gcc` runs Frama-C with
  `-machdep gcc_x86_64 -no-frama-c-stdlib`.
- `share/machdeps/gcc_builtins.json` has no overflow entry, so the kernel knows none of these
  names by itself, and the `_p` forms are declared nowhere.

Possible directions; I would rather leave the choice to you:

1. **Dispatch on the result type** (`_Generic(*(res), ...)` over the typed forms). Small and keeps
   real builtin names in the printed code, but exact only when both operands fit the result type:
   it fixes cases 1 and 2, not case 3; and GCC has no typed forms for `char`/`short` results.
2. **Wide-operand helper functions** in the header: one spec-only function per result type taking
   `__int128` operands, with the existing contracts (whose `a + b` is mathematical). Exact for the
   analyses on all standard integer types, but the printed code (and E-ACSL's output) then calls
   functions that do not exist at link time, unless the printer maps them back.
3. **Kernel support**: type the three generic builtins and the `_p` forms in `cabs2cil`, as is done
   for `__builtin_offsetof` and `__builtin_types_compatible_p`, and keep the generic call in the
   AST, so that it prints as valid C; the semantics come from a declaration with a contract
   instantiated per call site (as the Variadic plug-in does for `printf`), or from Eva and WP
   built-ins. The header has the same TODO for the atomics ("add generic counterpart with some help
   from cabs2cil for typing").
4. **At least make the assumption visible**: a `default:` association selecting a form with a
   deliberately weak contract (flag in `{0, 1}`, `*res` unknown) or a warning when the types
   differ, and associations for the small integer types. Sound but imprecise.
5. Independently of the above, for the implicit-declaration path: do not invent a K&R prototype for
   an unknown `__builtin_` name (an error, or a dedicated warning), and do not print a declaration
   for it; and/or register the overflow builtins in a kernel table such as `gcc_builtins.json`, so
   that they exist on GCC machdeps without Frama-C's libc.

Related: #2776 (support for `__builtin_addc`/`__builtin_subc`), #2758 (atomics and their
`_Generic`-based library model), #2766 (`__builtin_clz` contracts in the same header).

The analysis was prepared with LLM assistance (Claude Code); I reviewed it and ran the reproducers
described above.
