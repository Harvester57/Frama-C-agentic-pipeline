/* QCBOR: out-of-range shift in IEEE754_SingleToHalf() / IEEE754_DoubleToSingle().
 * Usage: float_shift enc-double | enc-float | dec-single | dec-double */
#include <stdio.h>
#include <string.h>
#include "qcbor/qcbor_encode.h"
#include "qcbor/qcbor_decode.h"

int main(int argc, char **argv)
{
   const char *szMode = argc > 1 ? argv[1] : "";
   QCBOREncodeContext E;
   QCBORDecodeContext D;
   UsefulBuf_MAKE_STACK_UB(Out, 32);
   UsefulBufC Enc;
   QCBORItem  Item;

   if(!strcmp(szMode, "enc-double")) {          /* any double that is not exactly a float */
      QCBOREncode_Init(&E, Out);
      QCBOREncode_AddDouble(&E, 0.1);
      printf("finish=%d\n", QCBOREncode_Finish(&E, &Enc));
   } else if(!strcmp(szMode, "enc-float")) {    /* any float that is not exactly a half */
      QCBOREncode_Init(&E, Out);
      QCBOREncode_AddFloat(&E, 1.1f);
      printf("finish=%d\n", QCBOREncode_Finish(&E, &Enc));
   } else if(!strcmp(szMode, "dec-single")) {   /* fa 3f 8c cc cd = 1.1f */
      static const uint8_t in[] = {0xfa, 0x3f, 0x8c, 0xcc, 0xcd};
      QCBORDecode_Init(&D, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(in), QCBOR_DECODE_MODE_PREFERRED);
      QCBORDecode_VGetNext(&D, &Item);
      printf("finish=%d\n", QCBORDecode_Finish(&D));
   } else if(!strcmp(szMode, "dec-double")) {   /* fb 3f b9 99 99 99 99 99 9a = 0.1 */
      static const uint8_t in[] = {0xfb, 0x3f, 0xb9, 0x99, 0x99, 0x99, 0x99, 0x99, 0x9a};
      QCBORDecode_Init(&D, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(in), QCBOR_DECODE_MODE_PREFERRED);
      QCBORDecode_VGetNext(&D, &Item);
      printf("finish=%d\n", QCBORDecode_Finish(&D));
   } else {
      fprintf(stderr, "usage: %s enc-double|enc-float|dec-single|dec-double\n", argv[0]);
      return 2;
   }
   return 0;
}
