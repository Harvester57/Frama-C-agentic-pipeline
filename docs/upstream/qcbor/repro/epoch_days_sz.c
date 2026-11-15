/* The one draft-06 getter never run under MSan:
 * QCBORDecode_GetTEpochDaysInMapSZ() with a label that is not found.
 * Usage: epoch_days_sz notfound | ok */
#include <stdio.h>
#include <string.h>
#include "qcbor/qcbor_decode.h"
#include "qcbor/qcbor_spiffy_decode.h"
#include "qcbor/qcbor_tag_decode.h"

int main(int argc, char **argv)
{
   const char *szMode = argc > 1 ? argv[1] : "notfound";
   QCBORDecodeContext D;
   int64_t nOut = 0x1234;
   static const uint8_t aMap[] = {0xa1, 0x61, 0x78, 0x02};   /* {"x": 2} */

   QCBORDecode_Init(&D, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(aMap), QCBOR_DECODE_MODE_NORMAL);
   QCBORDecode_EnterMap(&D, NULL);
   QCBORDecode_GetTEpochDaysInMapSZ(&D, strcmp(szMode, "ok") ? "y" : "x",
                                    QCBOR_TAG_REQUIREMENT_OPTIONAL_TAG, &nOut);
   printf("error=%d\n", QCBORDecode_GetError(&D));
   printf("output %s\n", nOut == 0x1234 ? "unchanged" : "overwritten");
   return 0;
}
