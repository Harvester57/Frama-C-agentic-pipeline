/* A failed QCBORDecode_GetTEpochDateInMapN() overwrites the
 * caller's output with an uninitialized value. With -fsanitize=memory,
 * MSan reports the use below. */
// From the QCBOR source tree:
//   cc -Iinc -Isrc 06_epoch_output_on_error.c src/*.c -lm && ./a.out
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
