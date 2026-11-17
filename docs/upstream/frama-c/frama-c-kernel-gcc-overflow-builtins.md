# Kernel/Libc: GCC's type-generic overflow builtins are modelled by first-operand `_Generic` macros (wrong result for mixed types, parse error for small types), the `_p` forms are missing, and without that header the call becomes an implicit declaration that gcc cannot link and clang rejects

Draft bug report for the Frama-C issue tracker (https://git.frama-c.com/pub/frama-c/-/issues).
Filed on 2026-11-18 as [#2823](https://git.frama-c.com/pub/frama-c/-/work_items/2823). Issue 34 of this folder. Issue only: no patch (see "Options").

**Filing package:** [issue](./filing/34-kernel-gcc-overflow-builtins-issue.md), [reproducer](./repro/34-kernel-gcc-overflow-builtins.sh)

## Summary

GCC (and Clang) provide `__builtin_add_overflow(a, b, res)`, `__builtin_sub_overflow` and
`__builtin_mul_overflow`: the operands and `*res` may have any integer types, the operation is done
in infinite precision, the result is stored converted to the type of `*res`, and the builtin returns
whether it fits. The `_p` forms (`__builtin_add_overflow_p(a, b, c)`) only test, using the type of
the third argument. Frama-C knows these builtins in one place only:
`share/libc/__fc_gcc_builtins.h`, which declares the typed forms (`__builtin_sadd_overflow` ...
`__builtin_umulll_overflow`) with ACSL contracts and defines the three generic forms as macros that
select a typed form by `_Generic` on the type of the **first operand**. That header is included by
the generated `__fc_machdep.h` only when `gccMode` holds, that is for machdeps whose compiler is
`gcc` or `clang` (`src/kernel/internals/runtime/machdep.ml:310` and `684-685`), and
`__fc_machdep.h` is included by `features.h` (`share/libc/features.h:150`); so the header is seen
only when the file includes a Frama-C libc header that pulls in `features.h`, on such a machdep. The kernel's builtin table
(`share/machdeps/gcc_builtins.json`) has no overflow entry.

Consequences, all reproduced on `master` `95408044f7` and 34.0~beta:

1. **Mixed types, Frama-C libc, `gcc_x86_64`: Eva computes a flag the program never returns.** The
   macro calls the typed form of the first operand's type and the kernel converts the other
   arguments, including `&r`, with only a `[kernel:typing:incompatible-types-call]` warning:
   - `int a = 65536, b = 65536; long r; __builtin_mul_overflow(a, b, &r)`: gcc 0, Eva `{1}`
     (`__builtin_smul_overflow` in `int`; Eva also leaves bits 32-63 of `r` uninitialized);
   - `int a = 1; long b = 0x17fffffff, r; __builtin_add_overflow(a, b, &r)`: gcc 0, Eva `{1}`
     (`b` truncated to `int`);
   - `int a = -1, b = 0; unsigned r; __builtin_add_overflow(a, b, &r)`: gcc 1 (-1 does not fit in
     `unsigned`), Eva `{0}`.
   The header says so (lines 84-85, 151-152, 218-219: "technically, the types of a, b and *res
   could differ, but we assume that this is not the case"), so it is a documented simplification,
   but its consequence is a precise wrong value, not an over-approximation: an analysis may miss the
   path the real program takes.
2. **Operands of type `char`, `short` (or `_Bool`, enums), Frama-C libc, `gcc_x86_64`: the parsing
   stops.** `_Generic` has no association for them and no `default`:
   `User Error: no compatible types and no default type in _Generic selection: controlling
   expression: 'a' (type: unsigned char); candidate types: unsigned long long, long long, unsigned
   long, long, unsigned int, int`. GCC accepts any integer type.
3. **The `_p` forms are not declared** even with the header:
   `Calling undeclared function __builtin_add_overflow_p. Old style K&R code?`, then
   `missing-spec`, and Eva returns `[-2147483648..2147483647]`.
4. **Without the header** (default `x86_64` machdep; a `gcc_*` machdep with no libc include; any
   machdep with `-no-frama-c-stdlib`, which is what stock `e-acsl-gcc` always runs:
   `-machdep gcc_x86_64 -no-frama-c-stdlib`): the call is an implicit K&R declaration. Its prototype is guessed from the first call, and later calls
   are converted to it: in the reproducer the second call becomes
   `__builtin_add_overflow((int)a,(int)b,(int *)(& r))`, which changes its result (gcc on the
   original: 0; that converted call, compiled by gcc: 1). Eva gets `missing-spec` and any value
   (WP was not run). The printed code declares
   `extern int ( /* missing proto */ __builtin_add_overflow)(int x_0, int x_1, int *x_2);`:
   gcc compiles it but the link fails (`undefined reference to '__builtin_add_overflow'`), and clang
   rejects it (`error: cannot redeclare builtin function '__builtin_add_overflow'`). E-ACSL prints
   its instrumented file the same way, so stock `e-acsl-gcc -c` fails on any program that uses these
   builtins (`e-acsl-gcc: fatal error: fail to compile/link instrumented code`; with `-G clang`,
   the clang error above). That is how the observation was made on mpack.

### Bug or feature request

Both. Points 1 and 2 are defects of the existing model (wrong analysis result, rejection of valid
GCC code); point 3 is a missing feature; point 4 is the general implicit-declaration path applied to
a compiler builtin, whose printed declaration is not valid for either compiler. The generic default
machdep (`x86_64`, `compiler: generic`) not knowing GCC builtins is by design, and Frama-C does not
define `__GNUC__` there (checked: `#ifdef __GNUC__` is false), so code that guards the builtins
with `__GNUC__`, as mpack does, does not reach them on that machdep. It does on `gcc_x86_64`
(`__GNUC__` is 14 in these images), including with `-no-frama-c-stdlib`, the E-ACSL configuration.

### Why no patch

I did not find a small change that is both sound and keeps the printed code compilable:

- dispatching on the result type `*(res)` and converting the operands to it is exact only when both
  operand values fit the result type (it fixes the first two calls above, not the
  `int -1` / `unsigned` one), and GCC has no typed forms for `char`/`short` results;
- Frama-C-only helper functions with wide operands (one per result type, `__int128` parameters, the
  same ACSL contract with mathematical `a + b`) are exact for all operand types up to 64 bits, but
  the printed and E-ACSL-instrumented code then calls names that do not exist at link time;
- typing the builtins in the kernel needs analyzer support (Eva, WP, E-ACSL), which is a design
  decision for the maintainers.

These are listed as options in the issue.

## Versions

| | Result |
|---|---|
| `35.0~~dev (Bromine)`, `master` at `95408044f7` (image `framac-master-audit:9540804`) | **present**: points 1-4 as above |
| `34.0~beta (Selenium)`, opam build (image `framac-analysis:latest`) | **present**, identical output |

## Reproduction

[`./repro/34-kernel-gcc-overflow-builtins.c`](./repro/34-kernel-gcc-overflow-builtins.c) (five
calls selected by `CASE`, Frama-C libc included) and
[`./repro/34-kernel-gcc-overflow-builtins-implicit.c`](./repro/34-kernel-gcc-overflow-builtins-implicit.c)
(no include; an `int` call, then a `long` call).
[`./repro/34-kernel-gcc-overflow-builtins.sh`](./repro/34-kernel-gcc-overflow-builtins.sh) compares
gcc's result with Eva's value of the flag, then prints the second file with each configuration and
compiles the printed code with gcc and clang:

```
--- Frama-C libc, -machdep gcc_x86_64, Eva value of the returned flag
case 1 mul(int, int, long *):          gcc 0, Eva {1}
  expected 'int *' but got argument of type 'long *': & r
case 2 add(int, long, long *):         gcc 0, Eva {1}
  expected 'int *' but got argument of type 'long *': & r
case 3 add(int, int, unsigned *):      gcc 1, Eva {0}
  expected 'int *' but got argument of type 'unsigned int *': & r
case 4 add(uchar, uchar, uchar *):     gcc 1, Eva (parsing aborted)
  no compatible types and no default type in _Generic selection:
case 5 add_overflow_p(int, int, int):  gcc 1, Eva [-2147483648..2147483647]
  Calling undeclared function __builtin_add_overflow_p. Old style K&R code?
--- no declaration in scope (x86_64; gcc_x86_64; gcc_x86_64 -no-frama-c-stdlib)
x86_64: frama-c -print:
  Calling undeclared function __builtin_add_overflow. Old style K&R code?
  expected 'int *' but got argument of type 'long *': & r
extern int ( /* missing proto */ __builtin_add_overflow)(int x_0, int x_1,
  tmp = __builtin_add_overflow((int)a,(int)b,(int *)(& r));
original, gcc: exit 10
printed, gcc: link FAILED: undefined reference to `__builtin_add_overflow'
printed, clang: FAILED: error: cannot redeclare builtin function '__builtin_add_overflow'
gcc_x86_64: (same output)
gcc_x86_64 -no-frama-c-stdlib: (same output)
--- stock e-acsl-gcc on the same file
e-acsl-gcc -c: exit 1, frama-c run with: -machdep gcc_x86_64 -no-frama-c-stdlib
undefined reference to `__builtin_add_overflow'
e-acsl-gcc: fatal error: fail to compile/link instrumented code
e-acsl-gcc -c -G clang: exit 1
error: cannot redeclare builtin function '__builtin_add_overflow'
RESULT: bug present
```

The script ran end to end on both images; on the master container the installed build was the one
with the item 35 lexer patch, which does not touch this path (the first two sections were also run
on the unpatched master build, with the same output).

## Options (in the issue)

1. **Result-type dispatch in the header**: `_Generic(*(res), ...)` over the typed forms. Small, keeps
   real GCC builtin names; exact only when both operands fit the result type; `char`/`short` results
   still need something else.
2. **Wide-operand helpers in the header**: per result type, a spec-only function taking `__int128`
   operands with the existing contract. Exact for Frama-C's analyses on all standard types; the
   printed code calls non-existent functions (E-ACSL output does not link) unless the printer maps
   them back to the generic builtin.
3. **Kernel support**: type the three generic builtins and the `_p` forms in `cabs2cil`, as is done
   for `__builtin_offsetof` and `__builtin_types_compatible_p`, and keep the generic call in the AST
   (it prints as valid C). Semantics then come from a per-call instantiated declaration with an ACSL
   contract (as the Variadic plug-in does for `printf`) or from Eva/WP built-ins. The header has the
   same TODO for the atomics ("add generic counterpart with some help from cabs2cil for typing").
4. **At least make the assumption visible**: a `default` association that selects a typed form with
   a deliberately weak contract (flag in `{0, 1}`, `*res` unknown), or a warning, when the three
   types differ, and an association for the small types; sound but imprecise.
5. **Independently, for point 4**: do not invent a K&R prototype for an unknown `__builtin_` name
   (warn more loudly, or error), and do not print a declaration for it; and/or move the overflow
   builtins to `gcc_builtins.json` or another kernel-side table so they exist on GCC machdeps without
   the libc.

## Workaround

The pipeline's [`../../../templates/fc_stubs/fc_compat_types.h`](../../../templates/fc_stubs/fc_compat_types.h)
(force-included on every Frama-C parse) defines the three `_p` forms, and under `__FRAMAC_EACSL__`
(the E-ACSL frontend on host headers) also the generic and typed forms, as GNU statement-expression
macros with GCC's semantics (fixed `a3ec02c`, merged as `f32ba49`; see the
"cannot redeclare builtin function" entry of
[`../../troubleshooting/eacsl-and-fuzzing.md`](../../troubleshooting/eacsl-and-fuzzing.md)). With
Frama-C's libc on `gcc_x86_64` the pipeline keeps Frama-C's first-operand model, so point 1 still
applies to Eva and WP results there. Before that fix the run used `-DMPACK_HAS_OVERFLOW_BUILTINS=0`
(the target's portable fallback).

## Tracker

Not filed at the time of writing. A live search on 2026-11-17 (`__builtin_add_overflow`,
`__builtin_mul_overflow`, `add_overflow`, `mul_overflow`, `sadd`, `_overflow_p`, `gcc_builtins`,
`gcc builtin`, `_Generic`, `missing proto`, `implicit-function-declaration`, `Old style K&R`,
`cannot redeclare builtin`; issues and merge requests, all states) found no duplicate. Related:
#2776 (open, `__builtin_addc`/`__builtin_subc` support, user-side contracts), #2758 (open, atomics
do not accept all permitted types; the reporter argues for kernel support rather than `_Generic`
libraries, and a maintainer answers that proper support needs significant work), #2766 (open, more precise `__builtin_clz` contracts in the same header).
