/* QCBOR dev: UsefulOutBuf_Compare() reads before the buffer for wrapping
 * offsets, although UsefulBuf.h says it is safe whatever the offsets. */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include "qcbor/UsefulBuf.h"

int main(void)
{
   UsefulOutBuf OB;
   uint8_t *pStorage = malloc(16);
   setvbuf(stdout, NULL, _IONBF, 0);
   UsefulOutBuf_Init(&OB, (UsefulBuf){pStorage, 16});
   UsefulOutBuf_AppendData(&OB, "abcd", 4);

   /* Start offset past the end, no wrap: documented to return 0 */
   printf("Compare(10,1, 0,1)       = %d (doc says 0)\n",
          UsefulOutBuf_Compare(&OB, 10, 1, 0, 1));

   /* Start offset that wraps: pBase + SIZE_MAX is pBase - 1 */
   printf("Compare(SIZE_MAX,2, 0,2) = %d\n",
          UsefulOutBuf_Compare(&OB, SIZE_MAX, 2, 0, 2));
   free(pStorage);
   return 0;
}
