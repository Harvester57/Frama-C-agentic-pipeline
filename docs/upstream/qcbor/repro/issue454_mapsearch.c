/* The two behaviours of laurencelundblade/QCBOR issue 454, through the
 * public API QCBORDecode_GetItemsInMap(). They are not our findings: this
 * program only shows on which trees they exist. It builds on 1.x and dev.
 *
 *   issue454_mapsearch many N     map of N integer labels, query of N items + sentinel
 *   issue454_mapsearch empty-int  empty query, input is the integer 7
 *   issue454_mapsearch empty-arr  empty query inside an entered array [0]
 *
 * Build from a QCBOR checkout:
 *   clang -g -O1 -fsanitize=address,undefined -fsanitize-recover=undefined \
 *         -Iinc -Isrc issue454_mapsearch.c src/*.c -lm
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "qcbor/qcbor_encode.h"
#include "qcbor/qcbor_decode.h"
#include "qcbor/qcbor_spiffy_decode.h"

static int Many(int nItems)
{
   static uint8_t     spBuf[4096];
   QCBOREncodeContext EC;
   QCBORDecodeContext DC;
   UsefulBufC         Encoded;
   QCBORItem         *pList;
   QCBORError         uErr;
   int                i;

   QCBOREncode_Init(&EC, UsefulBuf_FROM_BYTE_ARRAY(spBuf));
   QCBOREncode_OpenMap(&EC);
   for(i = 0; i < nItems; i++) {
      QCBOREncode_AddInt64ToMapN(&EC, i, i);
   }
   QCBOREncode_CloseMap(&EC);
   if(QCBOREncode_Finish(&EC, &Encoded) != QCBOR_SUCCESS) {
      printf("  encode failed\n");
      return 1;
   }

   /* Exactly nItems entries and the terminating QCBOR_TYPE_NONE entry. */
   pList = calloc((size_t)nItems + 1, sizeof(QCBORItem));
   for(i = 0; i < nItems; i++) {
      pList[i].label.int64 = i;
      pList[i].uLabelType  = QCBOR_TYPE_INT64;
      pList[i].uDataType   = QCBOR_TYPE_ANY;
   }
   pList[nItems].uLabelType = QCBOR_TYPE_NONE;

   QCBORDecode_Init(&DC, Encoded, QCBOR_DECODE_MODE_NORMAL);
   QCBORDecode_EnterMap(&DC, NULL);
   QCBORDecode_GetItemsInMap(&DC, pList);
   uErr = QCBORDecode_GetError(&DC);
   printf("  many %d: err=%d (%s)\n", nItems, uErr, qcbor_err_to_str(uErr));
   free(pList);
   return 0;
}

static int Empty(int bArray)
{
   static const uint8_t spInt[]   = {0x07};
   static const uint8_t spArray[] = {0x81, 0x00};
   QCBORDecodeContext   DC;
   QCBORItem            List[1];
   QCBORError           uErr;

   memset(List, 0, sizeof(List));
   List[0].uLabelType = QCBOR_TYPE_NONE;

   if(bArray) {
      QCBORDecode_Init(&DC, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spArray), QCBOR_DECODE_MODE_NORMAL);
      QCBORDecode_EnterArray(&DC, NULL);
   } else {
      QCBORDecode_Init(&DC, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spInt), QCBOR_DECODE_MODE_NORMAL);
   }
   QCBORDecode_GetItemsInMap(&DC, List);
   uErr = QCBORDecode_GetError(&DC);
   printf("  empty query, %s: err=%d (%s)\n", bArray ? "entered array" : "integer input",
          uErr, qcbor_err_to_str(uErr));
   return 0;
}

int main(int argc, char **argv)
{
   if(argc == 3 && !strcmp(argv[1], "many")) {
      return Many(atoi(argv[2]));
   }
   if(argc == 2 && !strcmp(argv[1], "empty-int")) {
      return Empty(0);
   }
   if(argc == 2 && !strcmp(argv[1], "empty-arr")) {
      return Empty(1);
   }
   return 2;
}
