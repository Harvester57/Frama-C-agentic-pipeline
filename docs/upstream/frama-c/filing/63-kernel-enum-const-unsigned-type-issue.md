# [Kernel] Enumeration constants of non-negative enums are typed unsigned (`enum.ekind`) instead of `int`, causing unsound WP proofs, wrong Eva verdicts, and altered E-ACSL branches

<!-- Everything below this line is the issue description. -->

### Summary

Since commit `2da90c219f` (merged in `7e9af986e2`, 2026-04-10, `#@1682`), Frama-C retypes every
enumeration constant to `enum.ekind` under the default GCC-like enum representation. For any enum
whose constants are all non-negative and fit in `int` (for example `enum { N = 4 };`), `enum.ekind`
is `unsigned int`, so the constant `N` itself receives type `unsigned int` instead of `int`.

This violates ISO C11/C17 6.7.2.2p3, ISO C23 6.7.2.2p12, and GCC's actual behaviour: in GCC, the
enumerated type `enum E` is `unsigned int`, while every enumeration constant has type `int`
whenever all constants of the enum fit in `int`. Because `N` is typed `unsigned int`, signed
comparisons such as `int i = -1; i < N` undergo usual arithmetic conversion to `(unsigned int)i < N`
and evaluate to `0` instead of `1`. On ordinary C code under `-machdep gcc_x86_64`, WP proves an
out-of-bounds read `a[-1]` safe, Eva computes the wrong return value and drops loops, and E-ACSL
generates an instrumented binary that takes the opposite branch.

No command-line option restores GCC/ISO C semantics: `-enums int` fixes `i < N` but changes the
enumerated type itself to signed `int`, breaking comparisons on enum-typed objects such as
`enum E e = (enum E)-1; e < B`.

### Steps to reproduce the issue

`enum_const_type.c`:

```c
enum { N = 4 };
int a[N];

int get(int i) {
  if (i < N)
    return a[i]; /* out of bounds for every negative i */
  return -1;
}

enum { MAX = 10 };

/*@ ensures wrong: \result == 0; */
int lt(int i) {
  i = -1;
  return i < MAX; /* C: 1 */
}

enum Small { S0 = 0, S1 = 1 };

int main(void) {
  int i = -1;
  enum Small sv = (enum Small)-1;
  int c_int = (i < N);
  int c_enum = (sv < S1);
  //@ check c_int_ok: c_int == 1;
  //@ check c_enum_ok: c_enum == 0;
  return c_int;
}
```

```sh
frama-c -machdep gcc_x86_64 -print enum_const_type.c
frama-c -machdep gcc_x86_64 -wp -wp-rte -wp-fct get enum_const_type.c
frama-c -machdep gcc_x86_64 -wp -wp-rte -wp-fct lt enum_const_type.c
frama-c -machdep gcc_x86_64 -eva enum_const_type.c
frama-c -machdep gcc_x86_64 -enums int -eva enum_const_type.c
```

To verify GCC 14.2.0's actual rule (`enum_gcc.c`):

```c
#include <stdio.h>

enum E_fit { A = 0, B = 1 };
enum E_u32 { C = 0, D = 0x80000000U };
enum E_i64 { E = 0, F = 0x100000000LL };

#define T(x) _Generic((x), \
  int: "int", unsigned int: "uint", long: "long", unsigned long: "ulong", default: "other")

int main(void) {
  int i = -1;
  enum E_fit sv = (enum E_fit)-1;
  printf("E_fit: A=%s B=%s enum=%s (i<B)=%d (sv<B)=%d\n",
         T(A), T(B), T((enum E_fit)0), i < B, sv < B);
  printf("E_u32: C=%s D=%s enum=%s\n", T(C), T(D), T((enum E_u32)0));
  printf("E_i64: E=%s F=%s enum=%s\n", T(E), T(F), T((enum E_i64)0));
  return 0;
}
```

```sh
gcc -std=c11 enum_gcc.c -o enum_gcc && ./enum_gcc
gcc -std=gnu11 enum_gcc.c -o enum_gcc && ./enum_gcc
gcc -std=c23 enum_gcc.c -o enum_gcc && ./enum_gcc
```

### Expected behaviour

In ISO C11/C17 6.7.2.2p3 ("The identifiers in an enumerator list are declared as constants that
have type `int`") and ISO C23 6.7.2.2p12 ("If all values of all enumeration constants can be
represented as an `int`, each enumeration constant has type `int`"), `N`, `MAX`, `S0`, and `S1`
have type `int`, while `enum Small` has underlying type `unsigned int`.

`gcc` produces the same output under `-std=c11`, `-std=gnu11`, and `-std=c23`:

```text
E_fit: A=int B=int enum=uint (i<B)=1 (sv<B)=0
E_u32: C=uint D=uint enum=uint
E_i64: E=ulong F=ulong enum=ulong
```

Accordingly, on `enum_const_type.c` under `-machdep gcc_x86_64`:

- `if (i < N)` in `get` must remain a signed `int` comparison (no `(unsigned int)i < N` cast);
- `-wp -wp-rte -wp-fct get` must NOT prove the `0 <= i` index-bound RTE guard;
- `-wp -wp-rte -wp-fct lt` must NOT prove `ensures wrong: \result == 0`;
- `-eva` must validate both `c_int_ok` (`c_int == 1`) and `c_enum_ok` (`c_enum == 0`).

### Actual behaviour

`-print` casts the signed `int` operand `i` to `unsigned int`:

```c
enum __anonenum_1 {
    N = (unsigned int)4
};
int get(int i)
{
  int __retres;
  if ((unsigned int)i < N) {
    __retres = a[i];
    goto return_label;
  }
  __retres = -1;
  return_label: return __retres;
}
```

WP proves the out-of-bounds access in `get` safe and proves the false postcondition `wrong` in `lt`:

```text
$ frama-c -machdep gcc_x86_64 -wp -wp-rte -wp-fct get enum_const_type.c
[wp] Proved goals:    4 / 4
  Terminating:     1
  Unreachable:     1
  Qed:             2

$ frama-c -machdep gcc_x86_64 -wp -wp-rte -wp-fct lt enum_const_type.c
[wp] Proved goals:    3 / 3
  Terminating:     1
  Unreachable:     1
  Qed:             1
```

Eva marks the true check `c_int_ok` invalid under the default `-machdep gcc_x86_64`, while
`-enums int` flips the failure to `c_enum_ok`:

```text
$ frama-c -machdep gcc_x86_64 -eva enum_const_type.c
[eva:alarm] enum_const_type.c:25: Warning: check 'c_int_ok' got status invalid.

$ frama-c -machdep gcc_x86_64 -enums int -eva enum_const_type.c
[eva:alarm] enum_const_type.c:26: Warning: check 'c_enum_ok' got status invalid.
```

### Contextual information

- Frama-C installation mode: from source (`master`) and opam (Docker image based on `framac/frama-c:dev`)
- Frama-C version: 35.0~~dev (Bromine), `master` at 189053d4a2; also 34.0~beta (Selenium), same output
- Plug-in used: Kernel (C typing), observed in WP, Eva, and E-ACSL
- OS name: Debian GNU/Linux
- OS version: 13 (trixie; glibc 2.41, gcc 14.2.0)

### Additional information (optional)

**Cause.** In `src/kernel/internals/typing/cabs2cil.ml` (lines 4395-4408), commit `2da90c219f`
(merged via `7e9af986e2` for private issue `#@1682`) retypes every `enum.eitems` element to
`enum.ekind`, and `cabs2cil.ml:5538-5543` (`EnvEnum item`) takes the type of a reference to an
enumeration constant from `Cil.typeOf item.eival`.

Looking at `tests/syntax/enum_typing_issue_1682.i`, the change addressed two distinct enum shapes:

1. `typedef enum { secfalse = 0x55aa55aa, sectrue = 0xaa55aa55 } secbool;`: here `sectrue` exceeds
   `INT_MAX` (outside C11 6.7.2.2p2, a GCC extension / C23 feature). As shown by `E_u32` above, GCC
   and C23 6.7.2.2p12 indeed type ALL constants of such an enum (`secfalse` and `sectrue`) as
   `unsigned int` (`ekind`).
2. `typedef enum { NONE = 0, FATAL = 1 } loglevel;`: here every constant fits in `int`. Under ISO
   C11/C17 6.7.2.2p3, C23 6.7.2.2p12, and GCC (including `-fshort-enums`), `NONE` and `FATAL` have
   type `int`, while `loglevel` itself has underlying type `unsigned int`.

Retyping all enum items unconditionally to `enum.ekind` fixed case 1 at the cost of breaking case 2
for every standard non-negative enum. Note also the comment at `cabs2cil.ml:4364-4366`, which
states that GCC picks the enum constant's type "with a preference for unsigned types"; GCC only
applies that preference to the enum's underlying type and to constants of enums that contain a
value outside `int`.

**Design direction (no MR attached).** Because `#@1682` was an intentional change touching 121
files (mostly test oracles, plus `tests/syntax/enum_typing_issue_1682.i`), this report is filed as
an issue without a merge request pending maintainer guidance (also raised in #2832). A clean
ISO C11/C23/GCC-conformant rule in `cabs2cil.ml:4395-4408` would be:

- If all enumerators fit in `int` (`Cil.fitsInInt IInt !smallest && Cil.fitsInInt IInt !largest`),
  keep `item.eival` typed as `int` while keeping `enum.ekind` as chosen by `-enums` (`unsigned int`
  in GCC mode, or smaller under `-enums gcc-short-enums`).
- Otherwise (at least one enumerator is outside `int`, such as `secbool` in `#@1682`), retype all
  items to `enum.ekind`, matching GCC and C23 6.7.2.2p12.

**Workaround.** None that is sound in general: `-enums int` restores signed `int` enumeration
constants but changes enum-typed objects from `unsigned int` to `int`, reversing the result of
signedness-sensitive operations on enum variables.

The analysis was prepared with LLM assistance; I reviewed it and ran all reproducers and compiler
checks described above.
