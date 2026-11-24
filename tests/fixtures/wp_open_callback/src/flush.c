/* The shape of QCBOR's UsefulOutBuf_Flush (QCBOR run-2, P10): a struct holding a callback the
   library's user installs and its context, and a function that calls it, then updates the struct.
   No function of type flush_cb exists in the program, so no `//@ calls` can name a target. */
#include <stddef.h>

typedef struct {
  const void *ptr;
  size_t len;
} BufC;

typedef int flush_cb(void *ctx, BufC bytes);

typedef struct {
  unsigned char *buf;
  size_t data_len;
  int err;
  flush_cb *pfFlush;
  void *pFlushCtx;
} OutBuf;

/*@ requires valid_ob: \valid(pMe);
  @ requires shape_buf: pMe->buf == \null || \object_pointer(pMe->buf);
  @ requires shape_ctx: pMe->pFlushCtx == \null || \object_pointer((char *)pMe->pFlushCtx);
  @ terminates \true;
  @ exits \false;
  @ assigns pMe->data_len, pMe->err;
  @ ensures keep_flush: pMe->pfFlush == \old(pMe->pfFlush);
  @ ensures keep_ctx: pMe->pFlushCtx == \old(pMe->pFlushCtx);
  @ ensures err_values: pMe->err == \old(pMe->err) || pMe->err == 1;
  @ ensures noop: \old(pMe->pfFlush) == \null ==> pMe->data_len == \old(pMe->data_len);
  @*/
void OutBuf_Flush(OutBuf *pMe)
{
  BufC bytes;
  int rc;

  if (pMe->err) {
    return;
  }
  if (pMe->pfFlush == NULL) {
    return;
  }
  bytes = (BufC){pMe->buf, pMe->data_len};
  rc = (*pMe->pfFlush)(pMe->pFlushCtx, bytes);
  if (rc) {
    pMe->err = 1;
  } else {
    pMe->data_len = 0;
  }
}
