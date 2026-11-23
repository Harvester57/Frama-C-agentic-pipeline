void main(void) {
  int s = 0;
  /*@ loop unroll 1 / 0; */
  for (int i = 0; i < 3; i++) {
    s += i;
  }
  /*@ loop unfold 0 / 0; */
  for (int j = 0; j < 2; j++) {
    s += j;
  }
}
