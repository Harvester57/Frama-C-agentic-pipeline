On `dev` (`19c3367`), six getters copy `Item.val` into the caller's output unconditionally, even when decoding failed:

- `QCBORDecode_GetTEpochDate()`, `GetTEpochDateInMapN()` and `GetTEpochDateInMapSZ()`;
- `QCBORDecode_GetTEpochDays()`, `GetTEpochDaysInMapN()` and `GetTEpochDaysInMapSZ()`.

On error that value was never set:

- **An error is already latched.** `Item` is a local that nothing writes.
- **The label is not found.** `Item` is a copy of the map-search template, whose `val` was never set.

So `*pnTime` or `*pnDays` is overwritten with uninitialized stack memory. A caller that sets a default and keeps it when the label is missing loses the default, and MemorySanitizer reports the caller's next use of it.

Callers are told to check `QCBORDecode_GetError()` first, so a careful caller is not affected. But 1.x assigns the output only on success, and the other getters in `qcbor_tag_decode.c` (big numbers, MIME, strings) don't write on error either. Not in 1.x.

## Reproducer

```c
#include <stdio.h>
#include "qcbor/qcbor_decode.h"
#include "qcbor/qcbor_spiffy_decode.h"
#include "qcbor/qcbor_tag_decode.h"

int main(void)
{
   static const uint8_t aMap[] = {0xa1, 0x01, 0x02};   /* {1: 2} */
   QCBORDecodeContext D;
   int64_t nTime = 42;                                /* caller's default */

   QCBORDecode_Init(&D, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(aMap), QCBOR_DECODE_MODE_NORMAL);
   QCBORDecode_EnterMap(&D, NULL);
   QCBORDecode_GetTEpochDateInMapN(&D, 5, QCBOR_TAG_REQUIREMENT_OPTIONAL_TAG, &nTime);
   printf("error %d\n", QCBORDecode_GetError(&D));    /* label 5 not found */
   if(nTime != 42) {
      printf("BUG: output overwritten on error\n");
      return 1;
   }
   printf("OK\n");
   return 0;
}
```

```text
$ cc -Iinc -Isrc repro.c src/*.c -lm && ./a.out
error 148
BUG: output overwritten on error

$ clang -g -fsanitize=memory -fsanitize-memory-track-origins=2 -Iinc -Isrc repro.c src/*.c -lm && ./a.out
==WARNING: MemorySanitizer: use-of-uninitialized-value
    #0 in main repro.c:21:7
  Uninitialized value was stored to memory at
    #0 in QCBORDecode_GetTEpochDateInMapN src/qcbor_tag_decode.c:919:12
```

The latched-error case is the same: after `QCBORDecode_EnterMap()` on input `01` (not a map), `QCBORDecode_GetTEpochDate()` and `QCBORDecode_GetTEpochDays()` both overwrite the caller's value.

## Cause

For example [`src/qcbor_tag_decode.c:919`](https://github.com/laurencelundblade/QCBOR/blob/19c3367c0bf7db3ffcc8bc5626d7740dc5b8a76e/src/qcbor_tag_decode.c#L919):

```c
   QCBORDecode_Private_ProcessTagOne(pMe, ..., &Item);
   *pnTime = Item.val.epochDate.nSeconds;
```

The same line is at `:893`, `:945`, `:966`, `:992` and `:1018`. I have a fix with a test that assigns the output only on success, and will open a PR.
