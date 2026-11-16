/* A logic function whose body reads memory, applied as the whole term of a
   loop variant. len3(s) is the length of s, up to 3. */
/*@ logic integer len3(char *s) =
      s[0] == '\0' ? 0 : s[1] == '\0' ? 1 : s[2] == '\0' ? 2 : 3; */

int walk(char *s) {
  int n = 0;
  /*@ loop variant len3(s); */
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
