/* QCBOR dev: a "negative zero" big number is neither rejected nor encoded as 0. */
#include <stdio.h>
#include "qcbor/qcbor_encode.h"

static void Dump(const char *szWhat, QCBOREncodeContext *pE)
{
   UsefulBufC Enc;
   QCBORError uErr = QCBOREncode_Finish(pE, &Enc);
   printf("%-24s err=%d  ", szWhat, uErr);
   for(size_t i = 0; uErr == QCBOR_SUCCESS && i < Enc.len; i++) {
      printf("%02x ", ((const uint8_t *)Enc.ptr)[i]);
   }
   printf("\n");
}

int main(void)
{
   QCBOREncodeContext E;
   UsefulBuf_MAKE_STACK_UB(Out, 64);
   /* {aZero, 1} is the big number 00, {aZero, 0} is the empty string */
   static const uint8_t aZero[] = {0x00, 0x00};
   UsefulBufC Zero  = {aZero, 1};
   UsefulBufC Empty = {aZero, 0};

   QCBOREncode_Init(&E, Out);
   QCBOREncode_AddTBigNumber(&E, QCBOR_ENCODE_AS_TAG, true, Zero);
   Dump("Preferred(-, 00)", &E);
   QCBOREncode_Init(&E, Out);
   QCBOREncode_AddTBigNumberNoPreferred(&E, QCBOR_ENCODE_AS_TAG, true, Zero);
   Dump("NoPreferred(-, 00)", &E);
   QCBOREncode_Init(&E, Out);
   QCBOREncode_AddTBigNumber(&E, QCBOR_ENCODE_AS_TAG, true, Empty);
   Dump("Preferred(-, empty)", &E);
   QCBOREncode_Init(&E, Out);
   QCBOREncode_AddTBigNumberNoPreferred(&E, QCBOR_ENCODE_AS_TAG, true, Empty);
   Dump("NoPreferred(-, empty)", &E);
   return 0;
}
