On `dev` (`19c3367`), `QCBOREncode_AddTBigNumber()` and `QCBOREncode_AddTBigNumberNoPreferred()` accept `bNegative = true` with a big number of value zero. They apply CBOR's offset of one for negative numbers to that zero, and the result is a large wrong number. No error is set.

For an empty big number:

| Call | Expected | Actual |
| :--- | :--- | :--- |
| `AddTBigNumber(TAG, negative, empty)` | `00` | `3b ff ff ff ff ff ff ff ff` (−2^64) |
| `AddTBigNumberNoPreferred(TAG, negative, empty)` | `c2 40` | `c3 40` (−1) |

The test table in `test/qcbor_encode_tests.c` has rows named "0 and error for no negative 0", but their negative expectations are `NULLUsefulBufCConst`, so the negative side of zero is never checked.

## Reproducer

```c
#include <stdio.h>
#include "qcbor/qcbor_encode.h"

static int Check(const char *szName, UsefulBufC Enc, UsefulBufC Expected)
{
   if(UsefulBuf_Compare(Enc, Expected) == 0) {
      return 0;
   }
   printf("BUG: %s: negative zero encoded as", szName);
   for(size_t i = 0; i < Enc.len; i++) {
      printf(" %02x", ((const uint8_t *)Enc.ptr)[i]);
   }
   printf("\n");
   return 1;
}

int main(void)
{
   static const uint8_t aPreferredZero[] = {0x00};          /* 0 */
   static const uint8_t aTaggedZero[]    = {0xc2, 0x40};    /* 2(h'') */
   const UsefulBufC Empty = {"", 0};   /* the big number zero, no bytes */
   UsefulBuf_MAKE_STACK_UB(Out, 16);
   QCBOREncodeContext E;
   UsefulBufC Enc;
   int nBugs = 0;

   QCBOREncode_Init(&E, Out);
   QCBOREncode_AddTBigNumber(&E, QCBOR_ENCODE_AS_TAG, true, Empty);
   if(QCBOREncode_Finish(&E, &Enc) != QCBOR_SUCCESS) {
      return 2;
   }
   nBugs += Check("AddTBigNumber", Enc,
                  UsefulBuf_FROM_BYTE_ARRAY_LITERAL(aPreferredZero));

   QCBOREncode_Init(&E, Out);
   QCBOREncode_AddTBigNumberNoPreferred(&E, QCBOR_ENCODE_AS_TAG, true, Empty);
   if(QCBOREncode_Finish(&E, &Enc) != QCBOR_SUCCESS) {
      return 2;
   }
   nBugs += Check("AddTBigNumberNoPreferred", Enc,
                  UsefulBuf_FROM_BYTE_ARRAY_LITERAL(aTaggedZero));

   if(nBugs) {
      return 1;
   }
   printf("OK\n");
   return 0;
}
```

```text
$ cc -Iinc -Isrc repro.c src/*.c -lm && ./a.out
BUG: AddTBigNumber: negative zero encoded as 3b ff ff ff ff ff ff ff ff
BUG: AddTBigNumberNoPreferred: negative zero encoded as c3 40
```

## Cause

[`QCBOREncode_Private_AddTBigNumberMain()`](https://github.com/laurencelundblade/QCBOR/blob/19c3367c0bf7db3ffcc8bc5626d7740dc5b8a76e/src/qcbor_number_encode.c#L384-L407) uses `bNegative` as given:

- On the preferred path, `uInt--` turns 0 into `UINT64_MAX`, which is encoded as a type 1 integer.
- On the non-preferred path, an empty magnitude goes out as a tag 3 big number with no bytes, which is −1.

Zero has no sign, so I think it should encode as 0. Rejecting it with an error, as the old test names suggest, would also be consistent. Either way, the silent −1 / −2^64 is wrong. Not in 1.x. I have a fix with tests and will open a PR.
