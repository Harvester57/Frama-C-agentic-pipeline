/* Issue 44: two callers of strlcat for WP. `append_wrong` states the result against the length of
 * the destination after the call, which the compiled program refutes (main prints it); it must not
 * be provable. `append_right` states it against the length before the call and writes only the 16
 * bytes it owns; it must be provable. */
#include <stdio.h>
#include <string.h>

/*@ requires valid_string(d) && \valid(d + (0 .. 15)) && valid_read_string(s);
    requires strlen(d) + strlen(s) < 16;
    requires \separated(d + (0 .. 16), s + (0 .. strlen(s)));
    assigns d[0 .. 16];
    ensures post_state_length: \result == strlen(d) + strlen(s);
*/
size_t append_wrong(char *d, const char *s) { return strlcat(d, s, 16); }

/*@ requires valid_string(d) && \valid(d + (0 .. 15)) && valid_read_string(s);
    requires strlen(d) + strlen(s) < 16;
    requires \separated(d + (0 .. 16), s + (0 .. strlen(s)));
    assigns d[0 .. 15];
    ensures pre_state_length: \result == \old(strlen(d) + strlen(s));
*/
size_t append_right(char *d, const char *s) { return strlcat(d, s, 16); }

int main(void) {
  char d[16] = "ab";
  size_t before = strlen(d) + strlen("cd");
  size_t r = append_wrong(d, "cd");
  size_t after = strlen(d) + strlen("cd");
  printf("post_state_length: %s (result %zu, strlen(d) + strlen(s) after the call %zu)\n",
         r == after ? "holds" : "DOES NOT HOLD", r, after);
  printf("pre_state_length: %s (result %zu, strlen(d) + strlen(s) before the call %zu)\n",
         r == before ? "holds" : "DOES NOT HOLD", r, before);
  return 0;
}
