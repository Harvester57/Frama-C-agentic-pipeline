enum { N = 4 };
int a[N];

int get(int i) {
  if (i < N)
    return a[i]; /* out of bounds for every negative i */
  return -1;
}

enum { MAX = 10 };

/*@ ensures wrong: \result == 0; */
int lt(int i) {
  i = -1;
  return i < MAX; /* C: 1 */
}

enum Small { S0 = 0, S1 = 1 };

int main(void) {
  int i = -1;
  enum Small sv = (enum Small)-1;
  int c_int = (i < N);       /* C11 6.7.2.2p3 and gcc: 1 */
  int c_enum = (sv < S1);    /* gcc: 0 (enum Small is unsigned int) */
  //@ check c_int_ok: c_int == 1;
  //@ check c_enum_ok: c_enum == 0;
  return c_int;
}
