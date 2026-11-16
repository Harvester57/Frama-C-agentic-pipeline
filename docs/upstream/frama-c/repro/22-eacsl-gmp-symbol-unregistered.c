/* The program declares and calls two GMP functions itself (as <gmp.h> would
   make it do), and the assertion needs GMP: a * b can exceed 64 bits. */
struct my_mpz { int alloc; int size; unsigned long *d; };
void __gmpz_init(struct my_mpz *z);
void __gmpz_clear(struct my_mpz *z);

int f(unsigned long a, unsigned long b)
{
  struct my_mpz z;
  __gmpz_init(&z);
  __gmpz_clear(&z);
  /*@ assert a * b + 1 > 0; */
  return 0;
}

int main(void)
{
  return f(3, 4);
}
