int main(void)
{
  register unsigned i;
  unsigned sum = 0;
  for (i = 0; i < 4; i++)
    sum += i;
  return sum != 6;
}
