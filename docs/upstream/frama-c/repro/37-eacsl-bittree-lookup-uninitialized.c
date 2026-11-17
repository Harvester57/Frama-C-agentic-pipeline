#include <stdlib.h>

static const char table[4] = {1, 2, 3, 0};

int main(int argc, char **argv) {
  const char *t = table;
  //@ check RO: \valid_read(t) && !\valid(t);

  int *q;
  {
    int x = 1;
    q = &x;
    //@ check IN_SCOPE: \valid(q) && \initialized(q);
  }
  //@ check OUT_OF_SCOPE: !\valid(q);

  int *p = malloc(sizeof(int));
  //@ check FREEABLE: \freeable(p);
  free(p);
  return 0;
}
