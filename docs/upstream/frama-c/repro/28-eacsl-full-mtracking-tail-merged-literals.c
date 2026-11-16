#include <stddef.h>

static int in_charset(const char *charset, size_t len, char c)
{
  for (size_t j = 0; j < len; j++) {
    /*@ assert \valid_read(charset + j); */
    if (charset[j] == c)
      return 1;
  }
  return 0;
}

int main(void)
{
  const char *comma = ","; /* "," is a suffix of " ," */
  return in_charset(" ,", 2, 'x') + (comma[0] == 'y');
}
