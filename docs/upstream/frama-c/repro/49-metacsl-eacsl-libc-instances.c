#include <string.h>

int auth_ok;
char out[4];
int out_i[4];

#ifdef USER_CONTRACT
/* What the Frama-C libc says about memcpy, assigns and from only. */
/*@ assigns ((char *)d)[0 .. n - 1] \from ((char *)s)[0 .. n - 1];
    assigns \result \from d; */
extern void *memcpy(void *restrict d, const void *restrict s, size_t n);
#endif

#ifdef OVERFLOW_PTR
void process(int *p)
{
  *p = 1; /* ordinary out-of-bounds write, no libc and no callee contract */
}
#else
void process(const char *in, size_t n)
{
#ifdef OVERFLOW
#ifdef BY_HAND
  /*@ assert \separated((char *)out + (0 .. n - 1), &auth_ok); */
#endif
  memcpy(out, in, n); /* writes 8 bytes into a 4-byte array */
#else
  (void)n;
  memcpy(&auth_ok, in, sizeof auth_ok); /* writes the protected global */
#endif
}
#endif

int main(void)
{
#ifdef OVERFLOW_PTR
  process(out_i + 10);
#else
  char buf[8] = "abcdefg";
  process(buf, sizeof buf);
#endif
  return 0;
}

#ifdef GUARDED
/*@ meta \prop, \name(auth_state), \targets({process}), \context(\writing),
      \valid(\written) ==> \separated(\written, &auth_ok);
*/
#else
/*@ meta \prop, \name(auth_state), \targets({process}), \context(\writing),
      \separated(\written, &auth_ok);
*/
#endif
