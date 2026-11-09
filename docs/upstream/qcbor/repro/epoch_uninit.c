/* QCBOR dev: QCBORDecode_GetTEpochDate() and GetTEpochDays() (and their
 * InMapN/InMapSZ variants) write an indeterminate value to the caller's
 * output when decoding fails. Build with -fsanitize=memory.
 * Usage: epoch_uninit latched | days-latched | notfound-n | notfound-sz | days-notfound */
#include <stdio.h>
#include <string.h>
#include "qcbor/qcbor_decode.h"
#include "qcbor/qcbor_spiffy_decode.h"
#include "qcbor/qcbor_tag_decode.h"

int main(int argc, char **argv)
{
   const char *szMode = argc > 1 ? argv[1] : "";
   QCBORDecodeContext D;
   int64_t nOut = 0x1234;   /* the caller's own, initialized value */
   static const uint8_t aMap[]   = {0xa1, 0x01, 0x02};   /* {1: 2} */
   static const uint8_t aBreak[] = {0xff};               /* not well formed */

   if(!strcmp(szMode, "latched") || !strcmp(szMode, "days-latched")) {
      QCBORItem Item;
      QCBORDecode_Init(&D, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(aBreak), QCBOR_DECODE_MODE_NORMAL);
      QCBORDecode_VGetNext(&D, &Item);                    /* latches an error */
      if(!strcmp(szMode, "latched")) {
         QCBORDecode_GetTEpochDate(&D, QCBOR_TAG_REQUIREMENT_OPTIONAL_TAG, &nOut);
      } else {
         QCBORDecode_GetTEpochDays(&D, QCBOR_TAG_REQUIREMENT_OPTIONAL_TAG, &nOut);
      }
   } else {
      QCBORDecode_Init(&D, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(aMap), QCBOR_DECODE_MODE_NORMAL);
      QCBORDecode_EnterMap(&D, NULL);
      if(!strcmp(szMode, "notfound-n")) {
         QCBORDecode_GetTEpochDateInMapN(&D, 5, QCBOR_TAG_REQUIREMENT_OPTIONAL_TAG, &nOut);
      } else if(!strcmp(szMode, "notfound-sz")) {
         QCBORDecode_GetTEpochDateInMapSZ(&D, "x", QCBOR_TAG_REQUIREMENT_OPTIONAL_TAG, &nOut);
      } else {
         QCBORDecode_GetTEpochDaysInMapN(&D, 5, QCBOR_TAG_REQUIREMENT_OPTIONAL_TAG, &nOut);
      }
   }
   printf("error=%d\n", QCBORDecode_GetError(&D));
   /* First use of the output. MSan reports here if the library
    * overwrote the caller's value with uninitialized memory. */
   printf("output %s\n", nOut == 0x1234 ? "unchanged" : "overwritten");
   return 0;
}
