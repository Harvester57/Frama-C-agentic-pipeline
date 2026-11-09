/* QCBOR dev: -INT64_MIN in QCBORDecode_ProcessBigNumber(), from untrusted input.
 * c4 82 00 3b 7f ff ff ff ff ff ff ff = 4([0, -9223372036854775808]) */
#include <stdio.h>
#include "qcbor/qcbor_decode.h"
#include "qcbor/qcbor_number_decode.h"

int main(void)
{
   static const uint8_t in[] = {0xc4, 0x82, 0x00, 0x3b,
                                0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
   QCBORDecodeContext D;
   UsefulBuf_MAKE_STACK_UB(MantissaBuf, 16);
   UsefulBufC Mantissa = NULLUsefulBufC;
   bool       bIsNeg = false;
   int64_t    nExp = 0;

   QCBORDecode_Init(&D, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(in), QCBOR_DECODE_MODE_NORMAL);
   QCBORDecode_GetTDecimalFractionBigMantissa(&D, QCBOR_TAG_REQUIREMENT_TAG, MantissaBuf,
                                              &Mantissa, &bIsNeg, &nExp);
   printf("error=%d neg=%d len=%zu\n", QCBORDecode_GetError(&D), bIsNeg, Mantissa.len);
   return 0;
}
