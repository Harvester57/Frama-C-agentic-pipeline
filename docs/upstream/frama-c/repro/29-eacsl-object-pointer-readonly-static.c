static const char const_table[4] = {1, 2, 3, 0};
static char plain_table[4] = {1, 2, 3, 0};

static void check(const char *p) {
  /*@ assert \valid_read(p); */
  /*@ assert \object_pointer(p); */
}

int main(int argc, char **argv) {
  char local[4] = {1, 2, 3, 0};
  int which = argc > 1 ? argv[1][0] - '0' : 0;
  if (which == 0) check(local);
  if (which == 1) check(plain_table);
  if (which == 2) check(const_table);
  if (which == 3) check("abc");
  return 0;
}
