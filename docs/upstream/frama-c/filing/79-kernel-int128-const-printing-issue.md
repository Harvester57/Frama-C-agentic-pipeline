# [Kernel] `__int128` constants are printed with `LL`/`ULL` suffixes, silently truncated by GCC/Clang and rejected on re-parse

<!-- Everything below this line is the issue description. -->

### Summary

`Cil_printer.constant` (`src/kernel/services/ast_printing/cil_printer.ml`, lines 627-628) prints
`IInt128` and `IUInt128` constants with `LL` and `ULL` suffixes. Neither ISO C nor GCC/Clang has
a 128-bit integer literal suffix. Whenever a 128-bit constant outside the 64-bit `long long` /
`unsigned long long` range is synthesized (for example by `-constfold`, which `e-acsl-gcc` enables
by default), Frama-C emits out-of-range `LL`/`ULL` literals that GCC and Clang silently truncate
to 64 bits (with only a warning) and that Frama-C itself rejects on re-parse.

### Steps to reproduce the issue

`i128.c`:

```c
#include <stdio.h>

int main(void) {
  __int128 v = ((__int128)1 << 100) + 5;
  unsigned __int128 u = ~(unsigned __int128)0;
  __int128 m = -((__int128)1 << 126) - ((__int128)1 << 126);
  printf("%llx %llx | %llx %llx | %llx %llx\n",
         (unsigned long long)((unsigned __int128)v >> 64), (unsigned long long)v,
         (unsigned long long)(u >> 64), (unsigned long long)u,
         (unsigned long long)((unsigned __int128)m >> 64), (unsigned long long)m);
  return 0;
}
```

```sh
gcc i128.c -o i128_gcc && ./i128_gcc
frama-c -machdep gcc_x86_64 -no-frama-c-stdlib -constfold i128.c -print -ocode i128_out.c
gcc i128_out.c -o i128_out && ./i128_out
frama-c -machdep gcc_x86_64 -no-frama-c-stdlib i128_out.c
e-acsl-gcc -c -F "-machdep gcc_x86_64" i128.c -o i128.gen.c -O i128_e && ./i128_e.e-acsl
```

Host headers are used with `e-acsl-gcc` / `-no-frama-c-stdlib` on Debian 13 (trixie; glibc 2.41,
gcc 14.2.0, clang 19.1.7).

### Expected behaviour

`i128_out.c` represents 128-bit constants as valid C integer constant expressions (for example
splitting high and low 64-bit halves with `<< 64` and `|`), compiles cleanly under GCC and Clang
without warnings, re-parses cleanly in Frama-C, and both `i128_out` and `i128_e.e-acsl` print the
exact same values as `i128_gcc`:

```text
1000000000 5 | ffffffffffffffff ffffffffffffffff | 8000000000000000 0
```

### Actual behaviour

Original `gcc` output:

```text
1000000000 5 | ffffffffffffffff ffffffffffffffff | 8000000000000000 0
```

`frama-c -machdep gcc_x86_64 -constfold -print` emits:

```c
  __int128 v = 1267650600228229401496703205381LL;
  unsigned __int128 u = 340282366920938463463374607431768211455ULL;
  __int128 m = (-170141183460469231731687303715884105727LL-1LL);
```

Compiling `i128_out.c` with `gcc` emits only warnings (`integer constant is too large for its type`),
and both `i128_out` and `i128_e.e-acsl` print truncated 64-bit values:

```text
0 5 | 0 ffffffffffffffff | ffffffffffffffff 0
```

Re-parsing `i128_out.c` with Frama-C aborts (exit 1):

```text
[kernel] i128_out.c:5: User Error: 
  Cannot represent the integer 1267650600228229401496703205381LL
[kernel] i128_out.c:6: User Error: 
  Cannot represent the integer 340282366920938463463374607431768211455ULL
[kernel] i128_out.c:7: User Error: 
  Cannot represent the integer 170141183460469231731687303715884105727LL
```

### Contextual information

- Frama-C installation mode: from source (`master`) and opam (Docker image based on `framac/frama-c:dev`)
- Frama-C version: 35.0~~dev (Bromine), `master` at 189053d4a2; also 34.0~beta (Selenium), identical output
- Plug-in used: kernel (`Cil_printer`, `-constfold`), also surfaced via E-ACSL (`e-acsl-gcc`)
- OS name: Debian GNU/Linux
- OS version: 13 (trixie; glibc 2.41, gcc 14.2.0, clang 19.1.7)

### Additional information (optional)

**Cause.** In `src/kernel/services/ast_printing/cil_printer.ml` (lines 627-628), `IInt128` is
grouped with `ILongLong` (`LL`) and `IUInt128` with `IULongLong` (`ULL`). As documented in the GCC
manual ("128-bit Integers"), there is no C literal syntax for `__int128` constants on targets where
`long long` is 64 bits.

**Fix.** In `Cil_printer.constant`:

- When an `IInt128` or `IUInt128` constant fits in 64-bit `long long` / `unsigned long long`, emit
  an explicit `(__int128)` or `(unsigned __int128)` cast around the 64-bit literal.
- When it exceeds 64-bit range (including `INT128_MIN = -2^127`), split its two's-complement bit
  pattern into 64-bit unsigned high and low halves and emit
  `(((unsigned __int128)0x<hi>ULL << 64) | 0x<lo>ULL)` (omitting `| 0x0ULL` when the low half is
  zero), wrapped in `((__int128)...)` for signed `IInt128`. This is a valid C integer constant
  expression with zero UB and zero warnings under GCC and Clang, and re-parses cleanly in Frama-C.

A merge request with this fix and regression test `tests/pretty_printing/int128_const.c` is ready.

**Workaround.** For `e-acsl-gcc`, pass `--no-constfold` when 128-bit expressions do not need
constant folding.

The analysis and fix were prepared with LLM assistance; I reviewed them and ran the reproducer and
tests described above.
