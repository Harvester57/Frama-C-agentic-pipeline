/* With -wp-counter-examples, a postcondition on memory the function does not
   write (here the pointer field p->ptr) is no longer proved. */
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
  p->len = 0;
  p->err = 0;
}
