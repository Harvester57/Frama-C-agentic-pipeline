/* Does QCBORDecode_Private_ConsumeItem() on dev 19c3367 branch on an
 * unwritten Item.uNextNestLevel? Needs GetNextMapOrArray() to return a
 * non-halting error (>= 140, not NO_MORE_ITEMS) from its ascend path
 * on the first iteration, before uNextNestLevel is assigned.
 * Usage: consume_indef <hex input> [decode mode]
 *   9f01f97e01ff : indefinite array [1, half NaN with payload]
 *   9f01f97e00ff : control, plain half NaN */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "qcbor/qcbor_decode.h"

int main(int argc, char **argv)
{
   static uint8_t aIn[256];
   size_t uLen = 0;
   const char *szHex = argc > 1 ? argv[1] : "9f01f97e01ff";
   int nMode = argc > 2 ? atoi(argv[2]) : 0;
   QCBORDecodeContext D;
   QCBORItem Item;

   while(szHex[0] && szHex[1] && uLen < sizeof(aIn)) {
      char b[3] = {szHex[0], szHex[1], 0};
      aIn[uLen++] = (uint8_t)strtoul(b, NULL, 16);
      szHex += 2;
   }
   memset(&Item, 0, sizeof(Item));
   QCBORDecode_Init(&D, (UsefulBufC){aIn, uLen}, (QCBORDecodeMode)nMode);
   QCBORDecode_VGetNextConsume(&D, &Item);
   printf("error=%d type=%d\n", QCBORDecode_GetError(&D), Item.uDataType);
   printf("uNextNestLevel %s\n", Item.uNextNestLevel == 0 ? "0" : "nonzero");
   return 0;
}
