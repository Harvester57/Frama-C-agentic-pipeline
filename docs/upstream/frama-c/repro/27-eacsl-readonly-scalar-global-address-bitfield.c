struct B { unsigned a : 3; unsigned b : 5; };
const struct B cb = { 1, 2 };

int main(void)
{
  return cb.a != 1;
}
