/* The same application bound by a \let: the translation of the \let looks up
   the type of the bound term. */
/*@ logic integer len3(char *s) =
      s[0] == '\0' ? 0 : s[1] == '\0' ? 1 : s[2] == '\0' ? 2 : 3; */

int walk(char *s) {
  int n = 0;
  /*@ loop variant \let k = len3(s); k; */
  while (*s) {
    s++;
    n++;
  }
  return n;
}

int main(void) {
  char buf[4] = "abc";
  return walk(buf) == 3 ? 0 : 1;
}
