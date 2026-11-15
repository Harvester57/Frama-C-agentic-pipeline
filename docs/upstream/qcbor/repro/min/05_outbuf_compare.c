/* UsefulOutBuf_Compare() adds offsets and lengths to the buffer pointer
 * before checking them. A wrapping offset reads before the buffer; a
 * wrapping length gives a wrong result. */
// From the QCBOR source tree, with AddressSanitizer and UBSan:
//   cc -g -fsanitize=address,undefined -Iinc -Isrc 05_outbuf_compare.c src/*.c -lm && ./a.out
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
