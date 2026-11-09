/* QCBOR v1 (master): the same out-of-range shifts when encoding floats
 * with preferred serialization, the default for AddDouble/AddFloat. */
#include <stdio.h>
#include "qcbor/qcbor_encode.h"

int main(void)
{
   QCBOREncodeContext E;
   UsefulBuf_MAKE_STACK_UB(Out, 32);
   UsefulBufC Enc;

   QCBOREncode_Init(&E, Out);
   QCBOREncode_AddDouble(&E, 0.1);   /* not exactly a float */
   QCBOREncode_AddFloat(&E, 1.1f);   /* not exactly a half */
   printf("finish=%d\n", QCBOREncode_Finish(&E, &Enc));
   return 0;
}
