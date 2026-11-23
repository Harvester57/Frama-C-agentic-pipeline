/*@ check lemma bool_zero: (_Bool)0 == 0;
    check lemma bool_one: (_Bool)1 == 1;
    check lemma bool_two: (_Bool)2 == 1;
    check lemma bool_two_bad: (_Bool)2 == 2; */

enum { TWO = 2 };

int main(void) {
  int x = 2;
  //@ check c1: (_Bool)2 == 1;
  //@ check c2: (_Bool)2 == 2;
  //@ check c3: (_Bool)x == 1;
  //@ check c4: (_Bool)x == (_Bool)2;
  //@ check c5: (_Bool)TWO == 1;
  //@ check c6: (_Bool)TWO == 2;
  //@ check c7: (_Bool)256 == 1;
  return 0;
}
