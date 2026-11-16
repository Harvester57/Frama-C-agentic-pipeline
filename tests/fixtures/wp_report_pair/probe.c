/*@ requires n >= 0;
    requires \valid_read(a + (0 .. n - 1));
    assigns \nothing;
    ensures bad: \result == 42;
    ensures \result >= 0;
*/
int f(const int *a, int n, int x) {
  int s = 0;
  /*@ loop invariant 0 <= i <= n;
      loop invariant wrong: s == i;
      loop assigns i, s;
      loop variant n - i;
  */
  for (int i = 0; i < n; i++) {
    s += a[i];
    s += a[i] * x;
  }
  //@ assert s != 7;
  return s + x;
}
