/* Issue 44: a call whose written bytes hold the NUL of the source. The BSD manual says the
 * behaviour is undefined when the strings overlap; Eva must not find `separation` valid. */
#include <string.h>

int main(void) {
  char buf[32] = "0123456789abcdefghij"; /* 20 characters, NUL at buf[20] */
  /* dest is "ghij" (buf + 16), src is the whole string: the call writes buf[20..23]. */
  strlcat(buf + 16, buf, 8);
  return 0;
}
