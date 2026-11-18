/* Compares the reference bodies (ref_strlcpy, ref_strlcat: reference.c built with
 * -Dstrlcpy=ref_strlcpy -Dstrlcat=ref_strlcat) with the C library's strlcpy and strlcat on every
 * combination of small lengths and sizes: same result, same bytes in the whole buffer.
 * Includes the calls the Eva / WP contracts refuse but the functions define (size 0, a size
 * larger than what is copied, a destination without a NUL within size). */
#include <stdio.h>
#include <string.h>

size_t ref_strlcpy(char *dst, const char *src, size_t size);
size_t ref_strlcat(char *dst, const char *src, size_t size);

#define BUF 32 /* every size below stays within it */
#define MAXLEN 10
#define MAXSIZE 14

static void fill(char *s, int len, char first) {
  for (int k = 0; k < len; k++)
    s[k] = (char)(first + k);
  s[len] = '\0';
}

int main(void) {
  long cases = 0, bad = 0;
  char src[MAXLEN + 1], a[BUF], b[BUF];

  for (int sl = 0; sl <= MAXLEN; sl++) {
    fill(src, sl, 'a');
    for (size_t size = 0; size <= MAXSIZE; size++) {
      memset(a, 0x5a, BUF);
      memset(b, 0x5a, BUF);
      size_t ra = strlcpy(a, src, size), rb = ref_strlcpy(b, src, size);
      cases++;
      if (ra != rb || memcmp(a, b, BUF) != 0) {
        bad++;
        printf("MISMATCH strlcpy src=%d size=%zu: libc %zu, reference %zu\n", sl, size, ra, rb);
      }
      for (int dl = 0; dl <= MAXLEN; dl++) {
        /* dst holds a string of dl bytes, then non-NUL filler: no NUL within size when size <= dl. */
        memset(a, 0x5a, BUF);
        memset(b, 0x5a, BUF);
        fill(a, dl, 'A');
        fill(b, dl, 'A');
        ra = strlcat(a, src, size);
        rb = ref_strlcat(b, src, size);
        cases++;
        if (ra != rb || memcmp(a, b, BUF) != 0) {
          bad++;
          printf("MISMATCH strlcat dst=%d src=%d size=%zu: libc %zu, reference %zu\n", dl, sl, size, ra, rb);
        }
      }
    }
  }
  printf("%s %ld cases, %ld mismatches\n", bad ? "DIFF_BAD" : "DIFF_OK", cases, bad);
  return bad != 0;
}
