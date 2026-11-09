# A negative big number of value zero encodes as −1, −256 or −2^64

Draft issue for https://github.com/laurencelundblade/QCBOR/issues. Not filed yet.
Patch: [`patches/public/0002-Encode-a-negative-zero-big-number-as-zero.patch`](patches/public/0002-Encode-a-negative-zero-big-number-as-zero.patch). It applies on top of `patches/public/0001`.

## Summary

`QCBOREncode_AddTBigNumber()` and `QCBOREncode_AddTBigNumberNoPreferred()` accept `bNegative = true`
with a magnitude of zero, either empty or all zero bytes. They apply CBOR's offset of one for
negative numbers to that zero. The result is one of three different wrong values, depending on
the length and the call, and no error is set:

| Call | Magnitude | Encoded | Decodes as |
| :--- | :--- | :--- | :--- |
| `AddTBigNumber(-)` | `00` | `3b ff ff ff ff ff ff ff ff` | −2^64 |
| `AddTBigNumber(-)` | empty | `3b ff ff ff ff ff ff ff ff` | −2^64 |
| `AddTBigNumberNoPreferred(-)` | `00` | `c3 41 ff` | −256 |
| `AddTBigNumberNoPreferred(-)` | empty | `c3 40` | −1 |

The test table in `test/qcbor_encode_tests.c` has entries named "0 and error for no negative 0".
Their negative expectations are `NULLUsefulBufCConst`, so the negative side of zero is never tested.

| | |
| :--- | :--- |
| **Affected** | `dev` at 9bd0845, and v2.0-alpha-6. Not 1.x. |
| **Severity** | Low. The input is degenerate, but it occurs naturally: a sign-and-magnitude value of −0, or a sign flag carried over from data whose magnitude is zero. The output is a large wrong number and nothing reports it. |
| **Reachability** | Public encode API, with data the application chooses. |

## Reproducer

[`repro/bignum_negzero.c`](repro/bignum_negzero.c):

```c
static const uint8_t aZero[] = {0x00, 0x00};
QCBOREncode_Init(&E, Out);
QCBOREncode_AddTBigNumber(&E, QCBOR_ENCODE_AS_TAG, true, (UsefulBufC){aZero, 1});
QCBOREncode_Finish(&E, &Enc);                   /* 3b ff ff ff ff ff ff ff ff */
```

```text
$ clang -g -O0 -Iinc -Isrc bignum_negzero.c src/*.c -lm && ./a.out
Preferred(-, 00)         err=0  3b ff ff ff ff ff ff ff ff
NoPreferred(-, 00)       err=0  c3 41 ff
Preferred(-, empty)      err=0  3b ff ff ff ff ff ff ff ff
NoPreferred(-, empty)    err=0  c3 40
```

## Root cause

In [`QCBOREncode_Private_AddTBigNumberMain()`](https://github.com/laurencelundblade/QCBOR/blob/9bd08456d46ac5fbaa7822420fd3e25e0e9c486f/src/qcbor_number_encode.c#L384-L406),
`bNegative` is used as given:
- On the preferred path, `uInt--` turns 0 into `UINT64_MAX`, and the result is encoded as type 1.
- On the non-preferred path, `QCBOREncode_Private_AddTNegativeBigNumber()` subtracts one from the
  magnitude, and `00` wraps to `ff`.
- For an empty magnitude, nothing is subtracted. The output is a negative big number with an
  empty magnitude, which is −1.

## Fix

Zero has no sign, so treat a zero magnitude as non-negative. Leading zeros have already been
removed, so the number is zero if it is empty or starts with a zero byte:

```c
bIsNegative = bNegative &&
              BigNumberNLZ.len > 0 &&
              UsefulBufC_NTH_BYTE(BigNumberNLZ, 0) != 0x00;
```

`bIsNegative` then replaces `bNegative` in the rest of the function.

The patch also updates the zero rows of the test table:
- the existing rows now expect `c2 41 00` / `00` for −0, and are renamed "0; negative 0 is 0";
- a new row covers the empty string: `c2 40` without preferred serialization, `00` with it.

**Alternative:** if −0 should be rejected, as the old test names suggest, the same check can set
an encoder error instead. The table rows would then expect that error. Either way, the current
silent −1 / −256 / −2^64 is wrong. Which of the two is right is your call.

## Validation

Validated with clang 19.1.7 on Linux x86_64:
- The reproducer gives `00`, `c2 41 00`, `00` and `c2 40` with the patch.
- The test suite passes (89/89) in plain, ASan + recoverable UBSan, and MSan builds.
- On the sources before this patch, the updated table fails: `BigNumEncodeTests FAILED (returned 7003000)`.
