/*@ check lemma empty_plus_bad:   8 \in ((5..3) + (0..10));
    check lemma empty_minus_bad: -2 \in ((5..3) - (0..10));
    check lemma open_empty_bad:   0 \in ((..3) + (5..4));
    check lemma subset_empty_ok:  \subset((5..3) + (0..10), \empty); */

/*@ requires n == 0;
    ensures sym_bad: 5 \in ((0 .. n - 1) + (0 .. 10)); */
void g(int n) {}

/*@ requires n == 0;
    requires \valid(p + (0 .. n - 1) + (0 .. 1));
    assigns \nothing; */
void w2(int *p, int n) {
  //@ check f_valid2: \valid(p);
}

/*@ requires n == 0;
    assigns f_assigns3: *(p + (0 .. n - 1) + (0 .. 1)); */
void w3(int *p, int n) { *p = 1; }

/*@ requires n == 2;
    assigns f_assigns_ok: *(p + (0 .. n - 1) + (0 .. 1)); */
void w_ok(int *p, int n) { *p = 1; }
