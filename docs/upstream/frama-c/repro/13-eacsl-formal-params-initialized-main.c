int main(int argc, char **argv) {
  int *p = &argc;
  char ***q = &argv;
  /*@ assert \initialized(p); */
  /*@ assert \initialized(q); */
  return 0;
}
