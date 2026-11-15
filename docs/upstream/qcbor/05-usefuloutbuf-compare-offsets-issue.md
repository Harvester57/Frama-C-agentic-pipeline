`UsefulBuf.h` says that `UsefulOutBuf_Compare()` never reads beyond the buffer's end, "making the function safe regardless of the provided offsets". On `dev` (`19c3367`) the implementation adds the offsets and lengths to the buffer pointer before it checks them against the data length:

- An offset near `SIZE_MAX` wraps the pointer to just before the buffer, and the loop reads there. `Compare(SIZE_MAX, 2, 0, 2)` reads one byte before the buffer.
- A length near `SIZE_MAX` wraps the end pointer, so the loop never runs. `Compare(0, SIZE_MAX, 0, 10)` on the 4 bytes `"abcd"` returns −1, although both strings are `"abcd"` once cut to the data.
- Any offset more than one past the end forms an out-of-object pointer, which is undefined behavior (C11 6.5.6p8).

The documentation is also off in two smaller ways:

- The `@return` line has the sign backwards relative to the code and to the paragraph below it.
- "If either starting offset is beyond the end of the output buffer, the function returns zero" is not what the code or the existing tests do: a string that starts past the end is treated as empty, and sorts first.

QCBOR's own caller, map sorting in `qcbor_main_encode.c`, passes offsets from its own output, so this is only reachable through the public `UsefulBuf` API with out-of-range arguments. Not in 1.x, which has no `UsefulOutBuf_Compare()`.

## Reproducer

```c
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include "qcbor/UsefulBuf.h"

int main(void)
{
   UsefulOutBuf OB;
   uint8_t *pStorage = malloc(16);
   int nBugs = 0;
   int nResult;

   UsefulOutBuf_Init(&OB, (UsefulBuf){pStorage, 16});
   UsefulOutBuf_AppendData(&OB, "abcd", 4);

   /* An offset past the output data is an empty string, which sorts
    * first. pBase + SIZE_MAX is pBase - 1: ASan reports a
    * heap-buffer-overflow one byte before the allocation. */
   nResult = UsefulOutBuf_Compare(&OB, SIZE_MAX, 2, 0, 2);
   if(nResult != 1) {
      printf("BUG: Compare(SIZE_MAX, 2, 0, 2) = %d, expected 1\n", nResult);
      nBugs++;
   }

   /* Both strings are "abcd" once cut to the output data. pBase +
    * SIZE_MAX wraps, the loop never runs, and they compare unequal. */
   nResult = UsefulOutBuf_Compare(&OB, 0, SIZE_MAX, 0, 10);
   if(nResult != 0) {
      printf("BUG: Compare(0, SIZE_MAX, 0, 10) = %d, expected 0\n", nResult);
      nBugs++;
   }

   free(pStorage);
   if(nBugs) {
      return 1;
   }
   printf("OK\n");
   return 0;
}
```

```text
$ cc -g -fsanitize=address -Iinc -Isrc repro.c src/*.c -lm && ./a.out
==ERROR: AddressSanitizer: heap-buffer-overflow ... READ of size 1
    #0 in UsefulOutBuf_Compare src/UsefulBuf.c:753:27
SUMMARY: AddressSanitizer: heap-buffer-overflow src/UsefulBuf.c:753:27 in UsefulOutBuf_Compare

$ cc -g -fsanitize=undefined -Iinc -Isrc repro.c src/*.c -lm && ./a.out
src/UsefulBuf.c:744:20: runtime error: addition of unsigned offset to 0x... overflowed to 0x...
src/UsefulBuf.c:746:22: runtime error: addition of unsigned offset to 0x... overflowed to 0x...
BUG: Compare(SIZE_MAX, 2, 0, 2) = 97, expected 1
BUG: Compare(0, SIZE_MAX, 0, 10) = -1, expected 0
```

## Cause

[`src/UsefulBuf.c:742-757`](https://github.com/laurencelundblade/QCBOR/blob/19c3367c0bf7db3ffcc8bc5626d7740dc5b8a76e/src/UsefulBuf.c#L742-L757):

```c
p1Start = pBase + uStart1;
p2Start = pBase + uStart2;
p1End   = p1Start + uLen1;
p2End   = p2Start + uLen2;
...
for(p1 = p1Start, p2 = p2Start;
    p1 < pEnd && p2 < pEnd && p1 < p1End && p2 < p2End;
    p1++, p2++) {
   uComparison = *p2 - *p1;
```

The bounds checks compare pointers that have already wrapped. I have a fix with tests that works on offsets instead of pointers, and will open a PR.
