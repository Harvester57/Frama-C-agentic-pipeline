static int cb(int x) { return x + 1; }

static int apply(int (*f)(int), int *v) { return f(*v); }

int main(void) {
  int v = 1;
  return apply(&cb, &v) == 2 ? 0 : 1;
}
