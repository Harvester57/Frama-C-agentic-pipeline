/* QCBOR run-6 candidate c132f24cbe: QCBORDecode_Private_GetItemInMap()
 * passes its local uOffset, never written, to
 * QCBORDecode_Private_GetItemChecks() when an error is already latched.
 * Usage: getiteminmap latched | ok
 *   latched  EnterMap on empty input fails, then GetItemInMapSZ
 *   ok       control: {"x": 1}, EnterMap, GetItemInMapSZ("x")
 * Build with MSan twice: default (eager parameter checks) and with
 * -fno-sanitize-memory-param-retval (reports only real uses). */
#include <stdio.h>
#include <string.h>
#include "qcbor/qcbor_decode.h"
#include "qcbor/qcbor_spiffy_decode.h"

int main(int argc, char **argv)
{
   const char *szMode = argc > 1 ? argv[1] : "latched";
   static const uint8_t aEmpty[] = {0x00};
   static const uint8_t aOk[]    = {0xa1, 0x61, 0x78, 0x01};
   QCBORDecodeContext D;
   QCBORItem Item;
   UsefulBufC Input;

   if(!strcmp(szMode, "ok")) {
      Input = UsefulBuf_FROM_BYTE_ARRAY_LITERAL(aOk);
   } else {
      Input = (UsefulBufC){aEmpty, 0};
   }
   memset(&Item, 0, sizeof(Item));
   QCBORDecode_Init(&D, Input, QCBOR_DECODE_MODE_NORMAL);
   QCBORDecode_EnterMap(&D, NULL);
   printf("after EnterMap error=%d\n", QCBORDecode_GetError(&D));
   QCBORDecode_GetItemInMapSZ(&D, "x", QCBOR_TYPE_ANY, &Item);
   printf("after GetItemInMapSZ error=%d type=%d\n", QCBORDecode_GetError(&D), Item.uDataType);
   return 0;
}
