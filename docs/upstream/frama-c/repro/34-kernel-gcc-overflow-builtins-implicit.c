/* No #include: nothing declares the overflow builtins. The first call fixes
   the implicit prototype, which then converts the arguments of the second. */
int add_int(void)
{
  int a = 0x7fffffff, b = 1, r;
  return __builtin_add_overflow(a, b, &r);   /* overflows in int: 1 */
}

int add_long(void)
{
  long a = 0x7fffffff, b = 1, r;
  return __builtin_add_overflow(a, b, &r);   /* fits in long: 0 */
}

int main(void)
{
  return add_int() * 10 + add_long();        /* gcc: 10 */
}
