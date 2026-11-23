int main(void) {
  int h = '\377';
  char c = 255;
  char a[] = "\377";
  int eq = (a[0] == '\377');
  int sz = sizeof(char[('\377' > 0) ? 2 : 1]);
  //@ check h1: h == 255;
  //@ check h2: h == c;
  //@ check h3: '\377' == 255;
  //@ check h4: eq == 1;
  //@ check h5: sz == 2;
  return 0;
}
