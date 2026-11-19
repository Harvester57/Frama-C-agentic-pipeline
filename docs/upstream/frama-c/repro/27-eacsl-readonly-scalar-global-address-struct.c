struct pair {
  int a;
  int b;
};

static const struct pair cp = { 1, 2 };

int main(void)
{
  return cp.a + cp.b != 3;
}
