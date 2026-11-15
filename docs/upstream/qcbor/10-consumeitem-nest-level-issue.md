On `dev` (`19c3367`), `QCBORDecode_VGetNextConsume()` on an array or map that ends early, such as the single byte `81`, sets the error `QCBOR_ERR_NO_MORE_ITEMS`. It also overwrites `pDecodedItem->uNextNestLevel` with an uninitialized byte.

`QCBORDecode_Private_ConsumeItem()` walks the members with a local `QCBORItem Item`. When `QCBORDecode_Private_GetNextMapOrArray()` stops on an error, it does not write `Item`. The loop breaks, and the line after it copies the unwritten field into the output:

```c
   do {
      uReturn = QCBORDecode_Private_GetNextMapOrArray(pMe, pEnd, &Item, NULL);

      if(QCBORDecode_IsHaltingError(uReturn)) {
         break;
      }
      if(uReturn == QCBOR_ERR_NO_MORE_ITEMS) {
         /* Should never occur. ... */
         break;
      }
   } while(Item.uNextNestLevel >= pItemToConsume->uNextNestLevel);

   *puNextNestLevel = Item.uNextNestLevel;
```

([`src/qcbor_main_decode.c:2099-2116`](https://github.com/laurencelundblade/QCBOR/blob/19c3367c0bf7db3ffcc8bc5626d7740dc5b8a76e/src/qcbor_main_decode.c#L2099-L2116)). The function's own documentation says `puNextNestLevel` is "Not set when traversal stops early". The `NO_MORE_ITEMS` branch is commented "Should never occur", but a truncated array or map reaches it.

`QCBORDecode_VGetNextConsume()` passes `&pDecodedItem->uNextNestLevel` as that output. So the 1 that `QCBORDecode_VGetNext()` had just stored for the array head is replaced with stack contents. The other callers of `ConsumeItem()` check the error before they use the nest level.

The error is set, so a caller that checks it is not affected. The impact is an uninitialized value in a returned item, and MemorySanitizer reports in applications that read it.

1.x has the same problem: on `master` (`1d06057`), v1.6.1 and v1.5.3, the loop in `src/qcbor_decode.c` stops on any error and the assignment after it is unconditional (`:3175` on `master`). The reproducer below gives the same MSan report there, with error 67. v2.0-alpha-6 is not affected: it jumps past the assignment on these errors.

## Reproducer

```c
#include <stdio.h>
#include "qcbor/qcbor_decode.h"

int main(void)
{
   static const uint8_t aIn[] = {0x81};   /* array of one item, item missing */
   QCBORDecodeContext D;
   QCBORItem Item;

   QCBORDecode_Init(&D, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(aIn), QCBOR_DECODE_MODE_NORMAL);
   QCBORDecode_VGetNextConsume(&D, &Item);
   printf("error %d\n", QCBORDecode_GetError(&D));   /* QCBOR_ERR_NO_MORE_ITEMS */
   /* The array head was decoded with uNextNestLevel 1. The consume
    * loop stops early and copies its own Item's uNextNestLevel, which
    * that last call never wrote, over it. */
   if(Item.uNextNestLevel != 1) {
      printf("BUG: uNextNestLevel overwritten with %d (uninitialized)\n",
             Item.uNextNestLevel);
      return 1;
   }
   printf("OK\n");
   return 0;
}
```

```text
$ cc -Iinc -Isrc repro.c src/*.c -lm && ./a.out
error 147
BUG: uNextNestLevel overwritten with 0 (uninitialized)

$ clang -g -fsanitize=memory -fsanitize-memory-track-origins=2 -Iinc -Isrc repro.c src/*.c -lm && ./a.out
==WARNING: MemorySanitizer: use-of-uninitialized-value
    #0 in main repro.c:21:7
  Uninitialized value was stored to memory at
    #0 in QCBORDecode_Private_ConsumeItem src/qcbor_main_decode.c:2116:21
  Uninitialized value was created by an allocation of 'Item' in the stack frame
    #0 in QCBORDecode_Private_ConsumeItem src/qcbor_main_decode.c:2090:4
```

The plain build's value is whatever was on the stack. MSan is the reliable check. A map whose pairs are missing, such as `b7` with nothing after it, behaves the same way.

I have a fix with a test for `dev` and for `master`, and will open PRs.
