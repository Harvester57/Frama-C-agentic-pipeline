static const unsigned char const_table[4] = {1, 2, 3, 0};
static unsigned char plain_table[4] = {1, 2, 3, 0};

static int scan(const unsigned char *p) {
  int n = 0;
  while (*p) {
    unsigned char v = *p++;
    n += v;
  }
  return n;
}

int main(int argc, char **argv) {
  unsigned char local[4] = {1, 2, 3, 0};
  int which = argc > 1 ? argv[1][0] - '0' : 0;
  int n = 0;
  if (which == 0) n = scan(local);
  if (which == 1) n = scan(plain_table);
  if (which == 2) n = scan(const_table);
  if (which == 3) n = scan((const unsigned char *)"abc");
  return n == 6 || n == 'a' + 'b' + 'c' ? 0 : 1;
}
