/* tests/fixtures/wp_open_callback/src/flush.c with a declared stub named in `//@ calls`: WP then proves
   every goal but the `Call point` one (the pointer must equal the stub's address, which no execution
   gives), on the strength of the stub's unchecked contract. run_wp_function.py makes it Tier-B unsound. */
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

/*@ terminates \true;
  @ exits \false;
  @ assigns \nothing;
  @*/
int OutBuf_FlushCallback_contract(void *ctx, BufC bytes);

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
  //@ calls OutBuf_FlushCallback_contract;
  rc = (*pMe->pfFlush)(pMe->pFlushCtx, bytes);
  if (rc) {
    pMe->err = 1;
  } else {
    pMe->data_len = 0;
  }
}
