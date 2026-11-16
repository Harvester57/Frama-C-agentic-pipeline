struct s { int n; };

/* The same failure in an assertion, with an explicit \at. */
int f(struct s *b) {
  int r = b->n == 0;
  b->n = 5;
  /*@ assert (r != 0) <==> (\at(b->n, Pre) == 0); */
  return r;
}

int main(void) { struct s x = { 0 }; return f(&x) - 1; }
