/* Same function, without -wp-counter-examples: a user probe annotation is
   enough to make keep_ptr unprovable. */
typedef struct {
  const void *ptr;
  unsigned long len;
  int err;
} buf;

/*@ requires \valid(p);
    assigns p->len, p->err;
    ensures keep_ptr: p->ptr == \old(p->ptr);
    ensures reset: p->len == 0 && p->err == 0;
*/
void buf_reset(buf *p)
{
  //@ probe P: p;
  p->len = 0;
  p->err = 0;
}
