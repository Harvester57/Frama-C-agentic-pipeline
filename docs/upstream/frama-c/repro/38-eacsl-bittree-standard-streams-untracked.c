#include <stdio.h>

int main(int argc, char **argv) {
  /* \valid(stdout) itself is resolved when instrumenting: use copies */
  FILE *out = stdout, *err = stderr, *in = stdin;
  //@ check OUT: \valid(out);
  //@ check ERR: \valid(err);
  //@ check IN: \valid_read(in);
  //@ check OUT_OBJ: \object_pointer(stdout);
  return 0;
}
