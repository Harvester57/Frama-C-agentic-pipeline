/* QCBOREncode_EncodeHead() with uMinLen > 8 reads past
 * aIterate[] and writes before the start of Buffer. */
// From the QCBOR source tree:
//   cc -g -fsanitize=address,undefined -Iinc -Isrc 07_encodehead_uminlen.c src/*.c -lm && ./a.out
#include <stdio.h>
#include "qcbor/qcbor_encode.h"

int main(void)
{
   UsefulBuf_MAKE_STACK_UB(Head, QCBOR_HEAD_BUFFER_SIZE);

   UsefulBufC Out = QCBOREncode_EncodeHead(Head, CBOR_MAJOR_TYPE_POSITIVE_INT, 9, 0);
   if(!UsefulBuf_IsNULLC(Out)) {
      printf("BUG: uMinLen 9 accepted, len %zu\n", Out.len);
      return 1;
   }
   printf("OK\n");
   return 0;
}
