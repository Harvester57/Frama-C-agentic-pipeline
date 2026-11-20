/* Issue 47: [MetAcsl] the \written instance at a call keeps the Old / Pre
   labels of the callee's assigns clause. See 47-metacsl-callee-old-label-in-written.sh. */

char out[8];
int secret;
int n;

/*@ logic integer len{L}(int *p) = \at(*p, L); */

#if defined(USE_OLD)
/*@ assigns d[0 .. \old(*p)]; */
#elif defined(USE_PRE)
/*@ assigns d[0 .. \at(*p, Pre)]; */
#else
/*@ assigns d[0 .. len(p)]; */ /* typed as len{Old}(p) */
#endif
void fill(char *d, int *p);

/*@ assigns n; ensures n == 7; */
void set7(void) { n = 7; } /* not a target: no instance here */

/*@ requires n == 2; */
void caller(void)
{
  set7();
  fill(out, &n); /* writes out[0 .. 7] */
}

int main(void)
{
  n = 2;
  caller();
  return 0;
}

/*@ meta \prop, \name(no_write_secret), \targets({caller}), \context(\writing),
      \separated(\written, &secret);
*/

/*@ meta \prop, \name(stays_in_prefix), \targets({caller}), \context(\writing),
      \subset(\written, out + (0 .. 3));
*/
