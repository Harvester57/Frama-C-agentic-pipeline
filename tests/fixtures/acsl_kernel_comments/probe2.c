/* Probe: what the Frama-C kernel treats as a comment inside an ACSL annotation. */

/* A: the libmodbus run-1 shape, a `//` comment inside a block annotation. */
/*@ assigns a_frame: *p // , *q ,
      \from \nothing;
*/
void case_a(int *p, int *q);

/* B: a nested `//@` inside a block annotation. */
/*@ requires a > 0; //@ requires b > 0;
*/
void case_b(int a, int b);

/* C: a `//` comment inside a line annotation. */
//@ requires a > 0; // requires b > 0;
void case_c(int a, int b);

/* D: a nested `//@` inside a line annotation. */
//@ requires a > 0; //@ requires b > 0;
void case_d(int a, int b);

/* F: `//` inside a string literal. */
/*@ requires \valid_read("a // b") && b > 0;
*/
void case_f(int a, int b);

/* G: a `//` comment ending in a backslash, inside a block annotation. */
/*@ requires a > 0; // comment \
    requires b > 0;
*/
void case_g(int a, int b);

/* H: a line annotation ending in a backslash, followed by C code. */
int case_h(int a)
{
  //@ assert a > 0; \
  a = 5;
  return a;
}

/* I: a quote inside a comment, then a real clause. */
/*@ requires a > 0; // don't " stop
    requires b > 0;
*/
void case_i(int a, int b);

/* J: a character literal holding a quote, then a `//` comment. */
/*@ requires a != '"' && b > 0; // " requires a > 1;
*/
void case_j(int a, int b);

/* K: `@` in the middle of a line. */
/*@ assigns *p @ , *q;
*/
void case_k(int *p, int *q);

/* L: a comment between the clause keyword and its label. */
/*@ ensures // lbl_fake:
      lbl_real: \result == 0;
*/
int case_l(void);

/* M: a nested `//@` at the start of a line of a block annotation. */
/*@ requires a > 0;
  //@ requires b > 0;
*/
void case_m(int a, int b);

