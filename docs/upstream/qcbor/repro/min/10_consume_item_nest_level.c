/* QCBORDecode_VGetNextConsume() on a truncated array stores an
 * uninitialized byte in Item.uNextNestLevel. With -fsanitize=memory,
 * MSan reports the use below. */
// From the QCBOR source tree:
//   cc -Iinc -Isrc 10_consume_item_nest_level.c src/*.c -lm && ./a.out
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
