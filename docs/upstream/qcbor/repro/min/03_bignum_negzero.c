/* A negative big number of value zero is encoded as -2^64 (preferred)
 * or -1 (not preferred) instead of 0. */
// From the QCBOR source tree:
//   cc -Iinc -Isrc 03_bignum_negzero.c src/*.c -lm && ./a.out
#include <stdio.h>
#include "qcbor/qcbor_encode.h"

static int Check(const char *szName, UsefulBufC Enc, UsefulBufC Expected)
{
   if(UsefulBuf_Compare(Enc, Expected) == 0) {
      return 0;
   }
   printf("BUG: %s: negative zero encoded as", szName);
   for(size_t i = 0; i < Enc.len; i++) {
      printf(" %02x", ((const uint8_t *)Enc.ptr)[i]);
   }
   printf("\n");
   return 1;
}

int main(void)
{
   static const uint8_t aPreferredZero[] = {0x00};          /* 0 */
   static const uint8_t aTaggedZero[]    = {0xc2, 0x40};    /* 2(h'') */
   const UsefulBufC Empty = {"", 0};   /* the big number zero, no bytes */
   UsefulBuf_MAKE_STACK_UB(Out, 16);
   QCBOREncodeContext E;
   UsefulBufC Enc;
   int nBugs = 0;

   QCBOREncode_Init(&E, Out);
   QCBOREncode_AddTBigNumber(&E, QCBOR_ENCODE_AS_TAG, true, Empty);
   if(QCBOREncode_Finish(&E, &Enc) != QCBOR_SUCCESS) {
      return 2;
   }
   nBugs += Check("AddTBigNumber", Enc,
                  UsefulBuf_FROM_BYTE_ARRAY_LITERAL(aPreferredZero));

   QCBOREncode_Init(&E, Out);
   QCBOREncode_AddTBigNumberNoPreferred(&E, QCBOR_ENCODE_AS_TAG, true, Empty);
   if(QCBOREncode_Finish(&E, &Enc) != QCBOR_SUCCESS) {
      return 2;
   }
   nBugs += Check("AddTBigNumberNoPreferred", Enc,
                  UsefulBuf_FROM_BYTE_ARRAY_LITERAL(aTaggedZero));

   if(nBugs) {
      return 1;
   }
   printf("OK\n");
   return 0;
}
