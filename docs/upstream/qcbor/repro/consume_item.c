/* QCBOR run-6 candidate b5ec324eae: QCBORDecode_Private_ConsumeItem()
 * copies Item.uNextNestLevel into the caller's QCBORItem after a
 * traversal that stopped before Item was ever written.
 * Usage: consume_item array1 | map23 | ok
 *   array1  input 81      (array of one item, item missing)
 *   map23   input b7      (map of 23 pairs, nothing after it)
 *   ok      input 81 01   (control: complete array [1])
 * Build with -fsanitize=memory to see the use of the indeterminate byte. */
#include <stdio.h>
#include <string.h>
#include "qcbor/qcbor_decode.h"

int main(int argc, char **argv)
{
   const char *szMode = argc > 1 ? argv[1] : "array1";
   static const uint8_t aArray1[] = {0x81};
   static const uint8_t aMap23[]  = {0xb7};
   static const uint8_t aOk[]     = {0x81, 0x01};
   UsefulBufC Input;
   QCBORDecodeContext D;
   QCBORItem Item;

   if(!strcmp(szMode, "map23")) {
      Input = UsefulBuf_FROM_BYTE_ARRAY_LITERAL(aMap23);
   } else if(!strcmp(szMode, "ok")) {
      Input = UsefulBuf_FROM_BYTE_ARRAY_LITERAL(aOk);
   } else {
      Input = UsefulBuf_FROM_BYTE_ARRAY_LITERAL(aArray1);
   }

   memset(&Item, 0, sizeof(Item));
   QCBORDecode_Init(&D, Input, QCBOR_DECODE_MODE_NORMAL);
   QCBORDecode_VGetNextConsume(&D, &Item);
   printf("error=%d type=%d\n", QCBORDecode_GetError(&D), Item.uDataType);
   /* First use of the field. MSan reports here when the library stored
    * an indeterminate byte into it. */
   if(Item.uNextNestLevel == 0) {
      printf("uNextNestLevel 0\n");
   } else {
      printf("uNextNestLevel nonzero\n");
   }
   return 0;
}
