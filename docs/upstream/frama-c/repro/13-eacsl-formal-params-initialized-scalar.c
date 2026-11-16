int f_scalar(int k) {
  k = 7;
  int *pk = &k;
  return *pk * 2;
}

int main(void) {
  return f_scalar(3) - 14;
}
