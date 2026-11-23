int main(void) {
  int lt = ('ab' - 30000) < 0;
  int sz = sizeof('ab');
  int cmp4 = ('\377\377\377\377' < 0);
  long long hi4 = '\377\377\377\377';
  int gen = _Generic('ab', int: 1, unsigned long: 2, default: 0);
  int c0 = '\0\200';
  //@ check t1: lt == 1;
  //@ check t2: sz == sizeof(int);
  //@ check t3: cmp4 == 1;
  //@ check t4: hi4 == -1;
  //@ check t5: gen == 1;
  //@ check t6: c0 == 128;
  return 0;
}
