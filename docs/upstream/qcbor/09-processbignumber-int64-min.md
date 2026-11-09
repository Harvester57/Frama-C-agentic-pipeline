# Signed overflow negating `INT64_MIN` in `QCBORDecode_ProcessBigNumber()`

Draft issue for https://github.com/laurencelundblade/QCBOR/issues. Not filed yet.
Patch: [`patches/public/0007-Don-t-negate-INT64_MIN-in-QCBORDecode_ProcessBigNumb.patch`](patches/public/0007-Don-t-negate-INT64_MIN-in-QCBORDecode_ProcessBigNumb.patch).

## Summary

For a `QCBOR_TYPE_INT64` item, `QCBORDecode_ProcessBigNumber()` computes the magnitude in `int64_t`,
in two places:
- `ABSOLUTE_VALUE(Item.val.int64)`;
- `-Item.val.int64`.

For `INT64_MIN` both negations overflow, which is undefined behavior (C11 6.5p5). The CBOR for it
is the negative integer `3b 7f ff ff ff ff ff ff ff`. It is reached from untrusted input. One
example is the decimal fraction `c4 82 00 3b 7f ff ff ff ff ff ff ff` decoded through
`QCBORDecode_GetTDecimalFractionBigMantissa()`.

**QCBOR's own test suite triggers it**, through the existing test vector at
`test/qcbor_decode_tests.c:9844`. A UBSan build of the tests therefore reports it.

On common compilers the wrapping negation gives 2^63, which is the right magnitude, so the decoded
value is correct.

| | |
| :--- | :--- |
| **Affected** | `dev` at 9bd0845 (`src/qcbor_number_decode.c:1964` and `:2008`); v2.0-alpha-6 (`:1943`, `:1974`). Not 1.x, which handles `INT64_MIN` explicitly. |
| **Severity** | Low. This is UB, but no miscompilation has been observed. |
| **Reachability** | Untrusted decode input: big-mantissa decimal fractions and bigfloats, and big-number conversion of a type 1 integer. |

## Reproducer

[`repro/int64min.c`](repro/int64min.c):

```c
static const uint8_t in[] = {0xc4, 0x82, 0x00, 0x3b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
QCBORDecode_Init(&D, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(in), QCBOR_DECODE_MODE_NORMAL);
QCBORDecode_GetTDecimalFractionBigMantissa(&D, QCBOR_TAG_REQUIREMENT_TAG, MantissaBuf,
                                           &Mantissa, &bIsNeg, &nExp);
```

```text
$ clang -g -O1 -fsanitize=undefined -Iinc -Isrc int64min.c src/*.c -lm && ./a.out
src/qcbor_number_decode.c:1964:65: runtime error: negation of -9223372036854775808 cannot be
represented in type 'int64_t' (aka 'long'); cast to an unsigned type to negate this value to itself
```

The test suite under recoverable UBSan reports both sites, `qcbor_number_decode.c:1964:65` and
`:2008:45`.

## Fix

Negate in `uint64_t`:

```diff
-         uLen = QCBORDecode_Private_CountNonZeroBytes((uint64_t)ABSOLUTE_VALUE(Item.val.int64));
+         uLen = QCBORDecode_Private_CountNonZeroBytes(bIsNegative ? 0 - (uint64_t)Item.val.int64 :
+                                                                    (uint64_t)Item.val.int64);
...
-         uIntTmp = (uint64_t)(bIsNegative ? -Item.val.int64 : Item.val.int64);
+         uIntTmp = bIsNegative ? 0 - (uint64_t)Item.val.int64 : (uint64_t)Item.val.int64;
```

For this item type, `bIsNegative` is set exactly when `Item.val.int64 < 0`
([`qcbor_number_decode.c:1914-1916`](https://github.com/laurencelundblade/QCBOR/blob/9bd08456d46ac5fbaa7822420fd3e25e0e9c486f/src/qcbor_number_decode.c#L1914-L1916)).
The new expressions therefore give the same values as before, including 2^63 for `INT64_MIN`. No
new test is needed, because the existing one covers it.

## Validation

Validated with clang 19.1.7 on Linux x86_64:
- The reproducer is clean under UBSan, and decodes `neg=1 len=8`.
- The test suite passes (89/89).
- The recoverable-UBSan run of the test suite no longer reports `qcbor_number_decode.c`.
