#include <syslog.h>

int main(void) {
  char buf[2] = {'a', 'b'}; /* not NUL-terminated */
  syslog(LOG_ERR, "%s", buf);
  return 0;
}
