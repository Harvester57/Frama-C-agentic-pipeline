/* run.config*
   STDOPT: +"-eva-domains taint -eva-msg-key=d-taint -eva-taint-auto -eva-no-taint-singletons"
*/
#include "__fc_builtin.h"
#include <stdio.h>

extern int undet;

void taint_simplify_singletons(int taint_var) {
  int x;
  //@ \eva::taint test:taint_var;

  int y = taint_var;

  /*@ assert y == 4; */

  // here x shouldn't be tainted because y can take only 1 value
  x = 4 - y;
  /*@ check !\tainted(auto:x); */
  /*@ check !\tainted(test:x); */

  int i = 1;
  //@ \eva::taint i;
  int t[2] = {0};
  int z = t[i];
  /*@ check !\tainted(t[0]); */
  /*@ check !\tainted(z); */ // due to -eva-no-taint-singletons
}

void multi_taint_test(int* taint_var) {
  int t, y;
  //@ \eva::taint test:*taint_var;

  t = *taint_var;
  /*@ check \tainted(auto:t); */
  /*@ check \tainted(test:t); */

  y = 10;
  /*@ \eva::taint test:y; */
  /*@ check !\tainted(auto:y); */

  if (y)
    y = 3;
  /*@ check !\tainted(auto:y); */
  /*@ check !\tainted_directly(auto:y); */ // !tainted ==> !tainted_directly
  /*@ check !\tainted_indirectly(auto:y); */ // !tainted ==> !tainted_indirectly
  /*@ check !\tainted_directly(test:y); */
  /*@ check \tainted_indirectly(test:y); */

  //@ taint auto:undet;
  if (undet)
    y = 2;
  /*@ check !\tainted_directly(auto:y); */
  /*@ check !\tainted_directly(test:y); */

  /*@ check false: !\tainted_indirectly(auto:y); */
  /*@ assert !\tainted_indirectly(auto:y); */
  /*@ check true: !\tainted_indirectly(auto:y); */

  int i = Frama_C_interval(0, 2);
  int j = Frama_C_interval(5, 7);
  int buf[10] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
  //@ taint buf:buf[9];

  //@ taint buf:undet;
  if (undet)
    buf[i] = i + 1;
  else
    buf[j] = j + 1;
  /*@ check true: !\tainted(buf:buf[4]); */
  /*@ check true: !\tainted_directly(buf:buf[6]); */

  Frama_C_dump_each();
}

int main(void) {
  int taint_var;
  scanf("%d", &taint_var);
  /*@ check \tainted(auto:taint_var); */

  taint_simplify_singletons(taint_var);
  /*@ check !\tainted(test:taint_var); */

  multi_taint_test(&taint_var);
  /*@ check !\tainted(test:taint_var); */

  return 0;
}
