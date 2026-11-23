/*@ check lemma exact_float: (float)16777216.0 == 16777216.0;
    check lemma inexact_float: (float)16777217.0 == 16777216.0;
    check lemma wrong_float: (float)16777217.0 == 16777217.0; */

int g;
void dead(int z) {
  //@ assert (float)16777217.0 == 16777216.0;
  g = 10 / z;
}

int main(void) {
  float lim = 2147483647.0f;
  float big = 1e11f;
  //@ check true_1: lim <= (float)2147483647.0;
  //@ check true_2: big == (float)1e11;
  //@ check true_3: (float)1e11 == 99999997952.0;
  dead(0);
  return 0;
}
