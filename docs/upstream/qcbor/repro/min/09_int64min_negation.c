/* Decoding 4([0, -2^63]) negates INT64_MIN in
 * QCBORDecode_ProcessBigNumber(). The result is usually right anyway;
 * only UBSan shows the signed overflow, and aborts on it. */
// From the QCBOR source tree, with UBSan:
//   cc -g -fsanitize=undefined -fno-sanitize-recover=all -Iinc -Isrc 09_int64min_negation.c src/*.c -lm && ./a.out
#include <stdio.h>
#include "qcbor/qcbor_decode.h"
#include "qcbor/qcbor_number_decode.h"

int main(void)
{
   /* c4 82 00 3b 7f ff ff ff ff ff ff ff = 4([0, -9223372036854775808]) */
   static const uint8_t aIn[] = {0xc4, 0x82, 0x00, 0x3b,
                                 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
   QCBORDecodeContext D;
   UsefulBuf_MAKE_STACK_UB(MantissaBuf, 16);
   UsefulBufC Mantissa;
   bool       bIsNegative;
   int64_t    nExponent;

   QCBORDecode_Init(&D, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(aIn), QCBOR_DECODE_MODE_NORMAL);
   QCBORDecode_GetTDecimalFractionBigMantissa(&D, QCBOR_TAG_REQUIREMENT_TAG, MantissaBuf,
                                              &Mantissa, &bIsNegative, &nExponent);
   printf("error %d\n", QCBORDecode_GetError(&D));
   return 0;
}
