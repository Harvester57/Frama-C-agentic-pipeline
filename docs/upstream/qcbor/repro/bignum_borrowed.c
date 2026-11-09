/* QCBOR dev: a positive big number encoded with QCBOR_ENCODE_AS_BORROWED
 * comes out as a tag-3 NEGATIVE big number. */
#include <stdio.h>
#include "qcbor/qcbor_encode.h"

static void Dump(const char *szWhat, QCBOREncodeContext *pE)
{
   UsefulBufC Enc;
   QCBORError uErr = QCBOREncode_Finish(pE, &Enc);
   printf("%-48s err=%d  ", szWhat, uErr);
   for(size_t i = 0; uErr == QCBOR_SUCCESS && i < Enc.len; i++) {
      printf("%02x ", ((const uint8_t *)Enc.ptr)[i]);
   }
   printf("\n");
}

int main(void)
{
   QCBOREncodeContext E;
   UsefulBuf_MAKE_STACK_UB(Out, 64);

   static const uint8_t a258[]   = {0x01, 0x02};
   static const uint8_t a2to64[] = {0x01, 0, 0, 0, 0, 0, 0, 0, 0};

   QCBOREncode_Init(&E, Out);
   QCBOREncode_AddTBigNumberNoPreferred(&E, QCBOR_ENCODE_AS_BORROWED, false,
                                        UsefulBuf_FROM_BYTE_ARRAY_LITERAL(a258));
   Dump("NoPreferred(BORROWED, +258)    expect 42 01 02", &E);

   QCBOREncode_Init(&E, Out);
   QCBOREncode_AddTBigNumber(&E, QCBOR_ENCODE_AS_BORROWED, false,
                             UsefulBuf_FROM_BYTE_ARRAY_LITERAL(a2to64));
   Dump("Preferred(BORROWED, +2^64)     expect 49 01 00 ..", &E);

   QCBOREncode_Init(&E, Out);
   QCBOREncode_AddTBigNumberNoPreferred(&E, QCBOR_ENCODE_AS_TAG, false,
                                        UsefulBuf_FROM_BYTE_ARRAY_LITERAL(a258));
   Dump("NoPreferred(TAG, +258)         expect c2 42 01 02", &E);

   QCBOREncode_Init(&E, Out);
   QCBOREncode_AddTBigNumberNoPreferred(&E, QCBOR_ENCODE_AS_BORROWED, true,
                                        UsefulBuf_FROM_BYTE_ARRAY_LITERAL(a258));
   Dump("NoPreferred(BORROWED, -258)    expect 42 01 01", &E);

   /* Preferred serialization of a number too big for type 0/1 is the
    * big number itself, so the preferred-only config should accept it. */
   QCBOREncode_Init(&E, Out);
   QCBOREncode_Config(&E, QCBOR_ENCODE_CONFIG_ONLY_PREFERRED_BIG_NUMBERS);
   QCBOREncode_AddTBigNumber(&E, QCBOR_ENCODE_AS_TAG, false,
                             UsefulBuf_FROM_BYTE_ARRAY_LITERAL(a2to64));
   Dump("OnlyPreferred: Preferred(TAG, +2^64)", &E);

   QCBOREncode_Init(&E, Out);
   QCBOREncode_Config(&E, QCBOR_ENCODE_CONFIG_ONLY_PREFERRED_BIG_NUMBERS);
   static const uint8_t a2to64p2[] = {0x01, 0, 0, 0, 0, 0, 0, 0, 2};
   QCBOREncode_AddTBigNumber(&E, QCBOR_ENCODE_AS_TAG, true,
                             UsefulBuf_FROM_BYTE_ARRAY_LITERAL(a2to64p2));
   Dump("OnlyPreferred: Preferred(TAG, -(2^64+2))", &E);
   return 0;
}
