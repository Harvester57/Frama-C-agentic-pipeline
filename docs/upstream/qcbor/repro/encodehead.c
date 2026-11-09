/* QCBOR: QCBOREncode_EncodeHead() with uMinLen > 8 reads past aIterate[]
 * and writes before the start of the caller's buffer. */
#include <stdio.h>
#include "qcbor/qcbor_encode.h"

int main(void)
{
   UsefulBuf_MAKE_STACK_UB(Head, QCBOR_HEAD_BUFFER_SIZE);
   UsefulBufC Out = QCBOREncode_EncodeHead(Head, CBOR_MAJOR_TYPE_POSITIVE_INT, 9, 0);
   printf("len=%zu\n", Out.len);
   return 0;
}
