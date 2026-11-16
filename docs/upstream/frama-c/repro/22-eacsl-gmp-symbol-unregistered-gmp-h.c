#include <gmp.h>

int f(unsigned long a, unsigned long b)
{
  mpz_t z;
  mpz_init(z);
  mpz_clear(z);
  /*@ assert a * b + 1 > 0; */
  return 0;
}

int main(void)
{
  return f(3, 4);
}
