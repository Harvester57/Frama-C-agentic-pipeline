int main(void)
{
  register int i = 1;
  /*@ assert \initialized(&i); */
  return i - 1;
}
