/* Without full memory tracking: the assertion makes E-ACSL track the formal
   p, so the callee pulls its temporal metadata, but the caller passes a
   constant and saves nothing for it. */
static int get(int *p) {
  /*@ assert \valid_read(&p); */
  return p ? *p : 0;
}

int main(void) { return get((int *)0); }
