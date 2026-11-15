On `dev` (`19c3367`), a positive big number added with `QCBOR_ENCODE_AS_BORROWED` is encoded as a tag 3 (negative) big number. No error is set.

| Call | Expected | Actual |
| :--- | :--- | :--- |
| `AddTBigNumberNoPreferred(BORROWED, +258)` | `42 01 02` | `c3 42 01 02` (−259) |
| `AddTBigNumber(BORROWED, +2^64)` | `49 01 00 00 00 00 00 00 00 00` | `c3 49 01 00 …` (−2^64−1) |
| `ONLY_PREFERRED_BIG_NUMBERS`: `AddTBigNumber(TAG, +2^64)` | `c2 49 01 00 …` | `QCBOR_ERR_NOT_PREFERRED` |

`AddTBigNumberNoPreferred()` is wrong for every positive value. `AddTBigNumber()` is wrong for positive values of 2^64 and up. With `QCBOR_ENCODE_AS_TAG` the output is right by coincidence, and negative numbers are not affected.

## Reproducer

```c
#include <stdio.h>
#include "qcbor/qcbor_encode.h"

int main(void)
{
   static const uint8_t a258[]   = {0x01, 0x02};       /* +258 */
   static const uint8_t expect[] = {0x42, 0x01, 0x02}; /* h'0102', no tag */
   UsefulBuf_MAKE_STACK_UB(Out, 16);
   QCBOREncodeContext E;
   UsefulBufC Enc;

   QCBOREncode_Init(&E, Out);
   QCBOREncode_AddTBigNumberNoPreferred(&E, QCBOR_ENCODE_AS_BORROWED, false,
                                        UsefulBuf_FROM_BYTE_ARRAY_LITERAL(a258));
   if(QCBOREncode_Finish(&E, &Enc) != QCBOR_SUCCESS) {
      return 2;
   }
   if(UsefulBuf_Compare(Enc, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(expect))) {
      printf("BUG: +258 encoded as");
      for(size_t i = 0; i < Enc.len; i++) {
         printf(" %02x", ((const uint8_t *)Enc.ptr)[i]);
      }
      printf("\n");
      return 1;
   }
   printf("OK\n");
   return 0;
}
```

```text
$ cc -Iinc -Isrc repro.c src/*.c -lm && ./a.out
BUG: +258 encoded as c3 42 01 02
```

## Cause

[`src/qcbor_number_encode.c:404`](https://github.com/laurencelundblade/QCBOR/blob/19c3367c0bf7db3ffcc8bc5626d7740dc5b8a76e/src/qcbor_number_encode.c#L404) passes the arguments in the wrong order:

```c
QCBOREncode_AddTBigNumberRaw(pMe, false, uTagRequirement,BigNumberNLZ);
```

The prototype is `QCBOREncode_AddTBigNumberRaw(pCtx, uTagRequirement, bNegative, BigNumber)`. So `false` (0, which is `QCBOR_ENCODE_AS_TAG`) becomes the tag requirement, and `uTagRequirement` becomes `bNegative`. With `QCBOR_ENCODE_AS_BORROWED` (1), the number gets a tag it should not have, and that tag is 3.

Calling the public `AddTBigNumberRaw()` also runs its usage guard for `QCBOR_ENCODE_CONFIG_ONLY_PREFERRED_BIG_NUMBERS`. That guard is meant for callers who pick the raw form. Here the number is too large for a type 0 integer, so the big number is its preferred serialization, and the guard rejects it wrongly.

Not in 1.x. I have a fix with tests and will open a PR.
