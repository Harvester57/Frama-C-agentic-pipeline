/*@ requires 0 <= x && x < 100;
    ensures \result == x * x && \result >= 0; */
int sq(int x) {
  return x * x;
}
