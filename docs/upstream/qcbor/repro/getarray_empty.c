/* QCBOR dev: QCBORDecode_GetArray()/GetMap() on an empty definite-length
 * array or map returns an indeterminate pEncodedCBOR->len.
 * Usage: getarray_empty top | nested | map | indef */
#include <stdio.h>
#include <string.h>
#include "qcbor/qcbor_decode.h"
#include "qcbor/qcbor_spiffy_decode.h"

static void Scribble(void)
{  /* Leave a recognizable pattern on the stack, for builds without MSan */
   volatile unsigned char a[4096];
   memset((void *)a, 0x41, sizeof(a));
}

static void Run(const char *szMode)
{
   QCBORDecodeContext D;
   QCBORItem  Item;
   UsefulBufC Enc;
   static const uint8_t aTop[]    = {0x80};               /* [] */
   static const uint8_t aNested[] = {0x82, 0x80, 0x01};   /* [[], 1] */
   static const uint8_t aMap[]    = {0xa0};               /* {} */
   static const uint8_t aIndef[]  = {0x9f, 0x80, 0xff};   /* [_ []] */

   if(!strcmp(szMode, "indef")) {
      QCBORDecode_Init(&D, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(aIndef), QCBOR_DECODE_MODE_NORMAL);
      QCBORDecode_EnterArray(&D, NULL);
      QCBORDecode_GetArray(&D, &Item, &Enc);
   } else if(!strcmp(szMode, "top")) {
      QCBORDecode_Init(&D, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(aTop), QCBOR_DECODE_MODE_NORMAL);
      QCBORDecode_GetArray(&D, &Item, &Enc);
   } else if(!strcmp(szMode, "nested")) {
      QCBORDecode_Init(&D, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(aNested), QCBOR_DECODE_MODE_NORMAL);
      QCBORDecode_EnterArray(&D, NULL);
      QCBORDecode_GetArray(&D, &Item, &Enc);
   } else {
      QCBORDecode_Init(&D, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(aMap), QCBOR_DECODE_MODE_NORMAL);
      QCBORDecode_GetMap(&D, &Item, &Enc);
   }
   printf("%-6s error=%d  len=%zu (expect 1)\n", szMode, QCBORDecode_GetError(&D), Enc.len);
}

int main(int argc, char **argv)
{
   Scribble();
   Run(argc > 1 ? argv[1] : "top");
   return 0;
}
