/* A positive big number with QCBOR_ENCODE_AS_BORROWED is encoded with a
 * tag 3 (negative) head in front of it. */
// From the QCBOR source tree:
//   cc -Iinc -Isrc 02_bignum_borrowed.c src/*.c -lm && ./a.out
#include <stdio.h>
#include "qcbor/qcbor_encode.h"

int main(void)
{
   static const uint8_t a258[]   = {0x01, 0x02};       /* +258 */
   static const uint8_t expect[] = {0x42, 0x01, 0x02}; /* h'0102', no tag */
   UsefulBuf_MAKE_STACK_UB(Out, 16);
   QCBOREncodeContext E;
   UsefulBufC Enc;

   QCBOREncode_Init(&E, Out);
   QCBOREncode_AddTBigNumberNoPreferred(&E, QCBOR_ENCODE_AS_BORROWED, false,
                                        UsefulBuf_FROM_BYTE_ARRAY_LITERAL(a258));
   if(QCBOREncode_Finish(&E, &Enc) != QCBOR_SUCCESS) {
      return 2;
   }
   if(UsefulBuf_Compare(Enc, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(expect))) {
      printf("BUG: +258 encoded as");
      for(size_t i = 0; i < Enc.len; i++) {
         printf(" %02x", ((const uint8_t *)Enc.ptr)[i]);
      }
      printf("\n");
      return 1;
   }
   printf("OK\n");
   return 0;
}
