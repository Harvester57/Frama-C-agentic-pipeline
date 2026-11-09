# Encoding an all-zero big number reads 1 byte past the caller's buffer

**Report privately.** Send this to lgl@island-resort.com with "QCBOR SECURITY" in the subject, as
QCBOR's `SECURITY.md` asks, or use GitHub private vulnerability reporting on the repository, which
is enabled. Do not open a public issue or push this file before the fix is public.
Patch: [`patches/private/0001-Fix-1-byte-over-read-encoding-an-all-zero-big-number.patch`](patches/private/0001-Fix-1-byte-over-read-encoding-an-all-zero-big-number.patch).

## Summary

`QCBOREncode_AddTBigNumber()` and `QCBOREncode_AddTBigNumberNoPreferred()` read the byte just
after the caller's big number when the big number is all zero bytes (`00`, `00 00 00 00`, ...).
That byte is then encoded instead of the zero:

| Call | Big number | Expected | Actual |
| :--- | :--- | :--- | :--- |
| `AddTBigNumberNoPreferred(+)` | `00 00 00 00`, followed in memory by `a5` | `c2 41 00` | `c2 41 a5` |
| `AddTBigNumber(+)` | same | `00` | `18 a5` (165) |

So a zero is encoded as an arbitrary value, and one byte of adjacent memory ends up in the
encoded output. ASan reports a heap-buffer-overflow read when the big number is heap-allocated.

| | |
| :--- | :--- |
| **Affected** | `dev` at 9bd0845, and v2.0-alpha-6. Not 1.x: its big-number API copies the bytes through. |
| **Severity** | Medium. This is a deterministic out-of-bounds read, and the byte leaves the process in the encoding. Fixed-width big numbers, such as 32-byte values, are often zero-padded copies of external data. The encoded value is also wrong. |
| **Reachability** | Public encode API, with data the application chooses. Not reachable from decoding. |

## Reproducer

[`repro/bignum_zero.c`](repro/bignum_zero.c):

```c
static const uint8_t aFour[] = {0x00, 0x00, 0x00, 0x00, 0xA5};
UsefulBufC Zero4 = {aFour, 4};           /* the big number is the first 4 bytes */

QCBOREncode_Init(&E, Out);
QCBOREncode_AddTBigNumberNoPreferred(&E, QCBOR_ENCODE_AS_TAG, false, Zero4);
/* -> c2 41 a5, expected c2 41 00 */

QCBOREncode_Init(&E, Out);
QCBOREncode_AddTBigNumber(&E, QCBOR_ENCODE_AS_TAG, false, Zero4);
/* -> 18 a5, expected 00 */

uint8_t *pZero = malloc(1); pZero[0] = 0;
QCBOREncode_AddTBigNumberNoPreferred(&E, QCBOR_ENCODE_AS_TAG, false, (UsefulBufC){pZero, 1});
/* ASan: heap-buffer-overflow READ of size 1, 0 bytes after 1-byte region */
```

```text
$ clang -g -O0 -Iinc -Isrc bignum_zero.c src/*.c -lm && ./a.out
NoPreferred(+, 00 00 00 00)   expect c2 41 00  err=0  c2 41 a5
Preferred(+, 00 00 00 00)     expect 00        err=0  18 a5

$ clang -g -O1 -fsanitize=address -Iinc -Isrc bignum_zero.c src/*.c -lm && ./a.out
==ERROR: AddressSanitizer: heap-buffer-overflow ... READ of size 1
    #0 in __asan_memmove
    #1 in UsefulOutBuf_AppendUsefulBuf src/UsefulBuf.c:523:10
0x502000000011 is located 0 bytes after 1-byte region [0x502000000010,0x502000000011)
```

## Root cause

[`src/qcbor_number_encode.c:322-335`](https://github.com/laurencelundblade/QCBOR/blob/9bd08456d46ac5fbaa7822420fd3e25e0e9c486f/src/qcbor_number_encode.c#L322-L335):

```c
NLZ = UsefulBuf_SkipLeading(BigNumber, 0x00);

/* An all-zero string reduces to one 0, not an empty string. */
if(NLZ.len == 0 &&
   BigNumber.len > 0 &&
   UsefulBufC_NTH_BYTE(BigNumber, 0) == 0x00) {
   NLZ.len = 1;
}
```

For an all-zero input, `UsefulBuf_SkipLeading()` returns `{BigNumber.ptr + BigNumber.len, 0}`.
Setting `NLZ.len = 1` makes it `{one past the end, 1}`. Every consumer then reads that byte:
- `UsefulOutBuf_AppendUsefulBuf()` on the non-preferred path ([`UsefulBuf.c:523`](https://github.com/laurencelundblade/QCBOR/blob/9bd08456d46ac5fbaa7822420fd3e25e0e9c486f/src/UsefulBuf.c#L523));
- `QCBOREncode_Private_BigNumberToUInt()` on the preferred path ([`qcbor_number_encode.c:214`](https://github.com/laurencelundblade/QCBOR/blob/9bd08456d46ac5fbaa7822420fd3e25e0e9c486f/src/qcbor_number_encode.c#L214));
- `QCBOREncode_Private_AddTNegativeBigNumber()` for negative numbers ([`qcbor_number_encode.c:290`](https://github.com/laurencelundblade/QCBOR/blob/9bd08456d46ac5fbaa7822420fd3e25e0e9c486f/src/qcbor_number_encode.c#L290)).

QCBOR's own tests do not see this. Their all-zero test vectors are string literals, and the
literal's terminating NUL is the byte that gets read, so the output happens to be right.

## Fix

Point at the last byte of the big number:

```diff
-      NLZ.len = 1;
+      NLZ = UsefulBuf_Tail(BigNumber, BigNumber.len - 1);
```

The patch also adds a test whose all-zero big number is followed by a non-zero byte. It
expects `c2 41 00` from `AddTBigNumberNoPreferred()` (returns -3 otherwise) and `00` from
`AddTBigNumber()` (returns -4).

## Validation

Validated with clang 19.1.7 on Linux x86_64:
- The reproducer is clean under ASan and UBSan with the patch.
- The QCBOR test suite passes (89/89) in plain, ASan + recoverable UBSan, and MSan builds.
- On the unpatched sources, the new test fails: `BigNumEncodeTests FAILED (returned -3)`.

## Related

After this fix, a *negative* all-zero big number becomes a separate problem: `AddTBigNumber(-, 00)`
encodes `-2^64`. See [03-bignum-negative-zero.md](03-bignum-negative-zero.md).
