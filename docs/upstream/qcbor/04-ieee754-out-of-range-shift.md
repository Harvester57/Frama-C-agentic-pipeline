# Out-of-range shifts in `IEEE754_SingleToHalf()` and `IEEE754_DoubleToSingle()`

Draft issue for https://github.com/laurencelundblade/QCBOR/issues. Not filed yet.
Patches:
- `dev`: [`patches/public/0003-Don-t-shift-by-an-out-of-range-amount-in-float-conve.patch`](patches/public/0003-Don-t-shift-by-an-out-of-range-amount-in-float-conve.patch);
- 1.x: [`patches/v1/0001-Don-t-shift-by-an-out-of-range-amount-in-float-conve.patch`](patches/v1/0001-Don-t-shift-by-an-out-of-range-amount-in-float-conve.patch), which also applies to v1.6.1.

## Summary

Both functions compute a subnormal significand by shifting **before** they check that the exponent
is in the subnormal range. For all other exponents, the shift amount is negative or at least the
width of the type. That is undefined behavior (C11 6.5.7p3). The result is then thrown away by the
range check, so common compilers produce the right output. But:

- **Most values reach it.** Any `float` that is not exactly a half reaches it (`1.1f`: shift −1),
  and so does any `double` that is not exactly a float (`0.1`: shift −93).
- **It runs during normal use:**
  - `QCBOREncode_AddFloat()` and `QCBOREncode_AddDouble()` with preferred serialization, which is
    the default;
  - on `dev`, decoding **untrusted input** with `QCBOR_DECODE_MODE_ONLY_SHORTEST_FLOAT`, which is
    part of `QCBOR_DECODE_MODE_PREFERRED`, CDE and dCBOR. For example `fa 3f 8c cc cd`.
- **QCBOR's own test suite triggers it** on both branches, so a UBSan build of the tests is never
  clean.
- **Trapping builds abort.** A build with `-fsanitize=shift -fsanitize-trap` stops at the first
  float it encodes.
- **The compiler is free to drop the check.** With the shift before the range check, a compiler
  may assume the shift amount is in range and simplify that check. We have not seen this happen.

| | |
| :--- | :--- |
| **Affected** | `dev` at 9bd0845 (`src/ieee754.c:466` and `:625`). 1.x `master` at 1d06057 and v1.6.1 (`src/ieee754.c:510` and `:666`). v2.0-alpha-6. |
| **Severity** | Low. No miscompilation has been observed. |
| **Reachability** | On `dev`: untrusted decode input in the preferred, CDE and dCBOR modes, and the float encode API. On 1.x: the float encode API. |

## Reproducer

[`repro/float_shift.c`](repro/float_shift.c), for `dev`, has four modes:

```c
QCBOREncode_AddDouble(&E, 0.1);                           /* enc-double */
QCBOREncode_AddFloat(&E, 1.1f);                           /* enc-float  */
/* dec-single: fa 3f 8c cc cd, dec-double: fb 3f b9 99 99 99 99 99 9a */
QCBORDecode_Init(&D, In, QCBOR_DECODE_MODE_PREFERRED);
QCBORDecode_VGetNext(&D, &Item);
```

```text
$ clang -g -O1 -fsanitize=undefined -Iinc -Isrc float_shift.c src/*.c -lm
$ ./a.out enc-double
src/ieee754.c:625:93: runtime error: shift exponent -93 is negative
$ ./a.out enc-float
src/ieee754.c:466:87: runtime error: shift exponent -1 is negative
$ ./a.out dec-single
src/ieee754.c:466:87: runtime error: shift exponent -1 is negative
$ ./a.out dec-double
src/ieee754.c:625:93: runtime error: shift exponent -93 is negative
```

[`repro/float_shift_v1.c`](repro/float_shift_v1.c), for 1.x, calls `AddDouble(0.1)` and
`AddFloat(1.1f)`:

```text
src/ieee754.c:666:93: runtime error: shift exponent -93 is negative
src/ieee754.c:510:87: runtime error: shift exponent -1 is negative
```

Very small normal values give the other kind of out-of-range shift, too large for the type. An
example is the float `0x00fa0000`, whose shift is 32 or more.

## Root cause

[`src/ieee754.c:458-482`](https://github.com/laurencelundblade/QCBOR/blob/9bd08456d46ac5fbaa7822420fd3e25e0e9c486f/src/ieee754.c#L458-L482) on `dev`:

```c
nShiftAmount = nExponentDifference + (SINGLE_NUM_SIGNIFICAND_BITS - HALF_NUM_SIGNIFICAND_BITS);
uHalfSignificand = (uSingleSignificand + (1 << SINGLE_NUM_SIGNIFICAND_BITS)) >> nShiftAmount;   /* 466 */

if(nSingleUnbiasedExponent < HALF_EXPONENT_MIN &&
   nSingleUnbiasedExponent >= HALF_EXPONENT_MIN - HALF_NUM_SIGNIFICAND_BITS &&
   uHalfSignificand << nShiftAmount == uSingleSignificand + (1 << SINGLE_NUM_SIGNIFICAND_BITS)) {
```

`nShiftAmount` is `-1 - nSingleUnbiasedExponent`:
- inside the half-subnormal range [−24, −15], it is 14 to 23;
- above that range, it is negative;
- below −32, it is 32 or more.

`IEEE754_DoubleToSingle()` at [`:625`](https://github.com/laurencelundblade/QCBOR/blob/9bd08456d46ac5fbaa7822420fd3e25e0e9c486f/src/ieee754.c#L625)
has the same structure with a `uint64_t`. There, the in-range shifts are 30 to 52.

## Fix

Set the "do not convert" result first, then shift only inside the range check:

```c
/* --- DO NOT CONVERT, unless it is a half subnormal --- */
result.uSize   = IEEE754_UNION_IS_SINGLE;
result.uValue  = uSingle;

if(nSingleUnbiasedExponent < HALF_EXPONENT_MIN &&
   nSingleUnbiasedExponent >= HALF_EXPONENT_MIN - HALF_NUM_SIGNIFICAND_BITS) {
   uHalfSignificand = (uSingleSignificand + (1 << SINGLE_NUM_SIGNIFICAND_BITS)) >> nShiftAmount;
   if(uHalfSignificand << nShiftAmount == uSingleSignificand + (1 << SINGLE_NUM_SIGNIFICAND_BITS)) {
      result.uSize  = IEEE754_UNION_IS_HALF;
      result.uValue = IEEE754_AssembleHalf(nIsNegative, uHalfSignificand, HALF_EXPONENT_ZERO);
   }
}
```

`IEEE754_DoubleToSingle()` gets the same change. The results are the same as before for every
input; only the shifts that were thrown away are gone. The 1.x patch makes the same change. It
uses `uSingleSign` and `uDoubleSign`, as 1.x does, in place of `nIsNegative`.

No new test is needed: the existing float tests already cover both the subnormal and the
non-subnormal paths, and they are what triggers the report under UBSan.

## Validation

Validated with clang 19.1.7 on Linux x86_64. The results are in
[`logs/dev-9bd0845.log`](logs/dev-9bd0845.log), [`logs/dev-patched.log`](logs/dev-patched.log)
and [`logs/v1-master.log`](logs/v1-master.log).

| Tree | Reproducers under UBSan | Test suite under ASan + recoverable UBSan |
| :--- | :--- | :--- |
| `dev` unpatched | 4/4 report | 89/89 pass, `ieee754.c:466` and `:625` reported |
| `dev` + patch | clean | 89/89 pass, no `ieee754.c` reports |
| 1.x unpatched | 2/2 report | 76/76 pass, `ieee754.c:510` and `:666` reported |
| 1.x + patch | clean | 76/76 pass, no `ieee754.c` reports |

The other UBSan reports in the test suite are on both branches, with and without the patches:
`memcpy`/`memcmp` passed a NULL pointer with length 0 (`UsefulBuf.h`, `UsefulBuf.c`). They are not
part of this report.
