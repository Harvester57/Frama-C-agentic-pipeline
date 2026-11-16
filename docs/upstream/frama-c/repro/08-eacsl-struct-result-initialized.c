struct S { int a; };

/*@ requires x >= 0;
    ensures \result.a == x; */
struct S make_s(int x) {
  struct S s = { x };
  return s;
}

int main(void) {
  struct S s = make_s(0);
  return s.a;
}
