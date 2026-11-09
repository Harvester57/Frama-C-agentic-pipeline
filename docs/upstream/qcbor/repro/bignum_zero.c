/* QCBOR dev: an all-zero big number makes the encoder read 1 byte past the input. */
#include <stdio.h>
#include <stdlib.h>
#include "qcbor/qcbor_encode.h"

static void Dump(const char *szWhat, QCBOREncodeContext *pE)
{
   UsefulBufC Enc;
   QCBORError uErr = QCBOREncode_Finish(pE, &Enc);
   printf("%-46s err=%d  ", szWhat, uErr);
   for(size_t i = 0; uErr == QCBOR_SUCCESS && i < Enc.len; i++) {
      printf("%02x ", ((const uint8_t *)Enc.ptr)[i]);
   }
   printf("\n");
}

int main(void)
{
   QCBOREncodeContext E;
   UsefulBuf_MAKE_STACK_UB(Out, 64);

   /* 1. No sanitizer needed: the byte after the big number ends up in
    *    the output. The big number is the first 4 bytes, all zero. */
   static const uint8_t aFour[] = {0x00, 0x00, 0x00, 0x00, 0xA5};
   UsefulBufC Zero4 = {aFour, 4};

   QCBOREncode_Init(&E, Out);
   QCBOREncode_AddTBigNumberNoPreferred(&E, QCBOR_ENCODE_AS_TAG, false, Zero4);
   Dump("NoPreferred(+, 00 00 00 00)   expect c2 41 00", &E);

   QCBOREncode_Init(&E, Out);
   QCBOREncode_AddTBigNumber(&E, QCBOR_ENCODE_AS_TAG, false, Zero4);
   Dump("Preferred(+, 00 00 00 00)     expect 00", &E);

   /* 2. With ASan: a 1-byte heap big number; the read is 0 bytes past it. */
   uint8_t *pZero = malloc(1);
   pZero[0] = 0x00;
   UsefulBufC Zero1 = {pZero, 1};
   QCBOREncode_Init(&E, Out);
   QCBOREncode_AddTBigNumberNoPreferred(&E, QCBOR_ENCODE_AS_TAG, false, Zero1);
   Dump("NoPreferred(+, heap 00)       expect c2 41 00", &E);
   free(pZero);
   return 0;
}
