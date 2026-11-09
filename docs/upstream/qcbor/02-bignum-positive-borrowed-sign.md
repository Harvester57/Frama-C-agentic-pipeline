# A positive big number encoded with `QCBOR_ENCODE_AS_BORROWED` comes out negative

Draft issue for https://github.com/laurencelundblade/QCBOR/issues. Not filed yet.
Patch: [`patches/public/0001-Fix-encoding-of-positive-big-numbers-that-are-not-ty.patch`](patches/public/0001-Fix-encoding-of-positive-big-numbers-that-are-not-ty.patch).

## Summary

`QCBOREncode_Private_AddTBigNumberMain()` passes its arguments to `QCBOREncode_AddTBigNumberRaw()`
in the wrong order. Two things go wrong, with no error reported:

1. **The sign flips.** With `QCBOR_ENCODE_AS_BORROWED`, a positive big number is encoded as tag 3,
   a negative big number. +258 comes out as `c3 42 01 02`, which is −259. This hits
   `AddTBigNumberNoPreferred()` for every positive value, and `AddTBigNumber()` for positive values
   of 2^64 and up.
2. **A valid encoding is refused.** Under `QCBOR_ENCODE_CONFIG_ONLY_PREFERRED_BIG_NUMBERS`,
   `AddTBigNumber()` of a positive value ≥ 2^64 fails with `QCBOR_ERR_NOT_PREFERRED` (79). A tag-2
   big number is the preferred serialization of such a value, and the negative counterpart is
   accepted.

| Call | Expected | Actual |
| :--- | :--- | :--- |
| `AddTBigNumberNoPreferred(BORROWED, +258)` | `42 01 02` | `c3 42 01 02` (−259) |
| `AddTBigNumber(BORROWED, +2^64)` | `49 01 00 00 00 00 00 00 00 00` | `c3 49 01 00 …` (−2^64−1) |
| `AddTBigNumberNoPreferred(TAG, +258)` | `c2 42 01 02` | `c2 42 01 02` (right by luck) |
| `AddTBigNumberNoPreferred(BORROWED, −258)` | `42 01 01` | `42 01 01` (negative path unaffected) |
| `ONLY_PREFERRED_BIG_NUMBERS`: `AddTBigNumber(TAG, +2^64)` | `c2 49 01 00 …` | error 79 |
| `ONLY_PREFERRED_BIG_NUMBERS`: `AddTBigNumber(TAG, −(2^64+2))` | `c3 49 01 00 … 01` | `c3 49 01 00 … 01` |

| | |
| :--- | :--- |
| **Affected** | `dev` at 9bd0845, and v2.0-alpha-6. Not 1.x. |
| **Severity** | Medium. Silent data corruption: the receiver decodes a different number, with the opposite sign. |
| **Reachability** | Public encode API, for any application that uses `QCBOR_ENCODE_AS_BORROWED` with big numbers, or the preferred-only configuration. |

## Reproducer

[`repro/bignum_borrowed.c`](repro/bignum_borrowed.c) prints the table above:

```c
static const uint8_t a258[] = {0x01, 0x02};
QCBOREncode_Init(&E, Out);
QCBOREncode_AddTBigNumberNoPreferred(&E, QCBOR_ENCODE_AS_BORROWED, false,
                                     UsefulBuf_FROM_BYTE_ARRAY_LITERAL(a258));
QCBOREncode_Finish(&E, &Enc);       /* c3 42 01 02, expected 42 01 02 */
```

```text
$ clang -g -O0 -Iinc -Isrc bignum_borrowed.c src/*.c -lm && ./a.out
NoPreferred(BORROWED, +258)    expect 42 01 02   err=0  c3 42 01 02
Preferred(BORROWED, +2^64)     expect 49 01 00 .. err=0  c3 49 01 00 00 00 00 00 00 00 00
NoPreferred(TAG, +258)         expect c2 42 01 02 err=0  c2 42 01 02
NoPreferred(BORROWED, -258)    expect 42 01 01   err=0  42 01 01
OnlyPreferred: Preferred(TAG, +2^64)             err=79
OnlyPreferred: Preferred(TAG, -(2^64+2))         err=0  c3 49 01 00 00 00 00 00 00 00 01
```

## Root cause

[`src/qcbor_number_encode.c:404`](https://github.com/laurencelundblade/QCBOR/blob/9bd08456d46ac5fbaa7822420fd3e25e0e9c486f/src/qcbor_number_encode.c#L404):

```c
QCBOREncode_AddTBigNumberRaw(pMe, false, uTagRequirement,BigNumberNLZ);
```

The prototype is `QCBOREncode_AddTBigNumberRaw(pCtx, uTagRequirement, bNegative, BigNumber)`
([`inc/qcbor/qcbor_number_encode.h`](https://github.com/laurencelundblade/QCBOR/blob/9bd08456d46ac5fbaa7822420fd3e25e0e9c486f/inc/qcbor/qcbor_number_encode.h#L506)).
The call therefore passes `false` (0, which is `QCBOR_ENCODE_AS_TAG`) as the tag requirement, and
`uTagRequirement` as `bNegative`:
- With `QCBOR_ENCODE_AS_TAG` (0), both arguments come out right by coincidence.
- With `QCBOR_ENCODE_AS_BORROWED` (1), the number gets a tag, which it should not have, and it is
  marked negative.

Going through the public `AddTBigNumberRaw()` also runs its usage guard for
`QCBOR_ENCODE_CONFIG_ONLY_PREFERRED_BIG_NUMBERS`. That guard is meant for callers who pick the raw
form. Here the number is too large for a type 0 integer, so the big number *is* the preferred
form. That causes the error 79.

## Fix

Output the tag and the byte string directly, as the negative path does:

```diff
-         QCBOREncode_AddTBigNumberRaw(pMe, false, uTagRequirement,BigNumberNLZ);
+         QCBOREncode_Private_BigNumberTag(pMe, uTagRequirement, false);
+         QCBOREncode_AddBytes(pMe, BigNumberNLZ);
```

Swapping the two arguments would fix the sign, but not the refused encoding.

The patch adds two tests:
- BORROWED +258 must give `42 01 02` (returns -5 otherwise);
- +2^64 under the preferred-only configuration must give `c2 49 01 00 …` (returns -6 otherwise).

## Validation

Validated with clang 19.1.7 on Linux x86_64:
- The reproducer gives the expected column with the patch.
- The test suite passes (89/89) in plain, ASan + recoverable UBSan, and MSan builds.
- On the sources before this patch, the new test fails: `BigNumEncodeTests FAILED (returned -5)`.
