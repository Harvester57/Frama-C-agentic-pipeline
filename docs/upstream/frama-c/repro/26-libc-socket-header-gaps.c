/* A common idiom on correct code: Eva reports an invalid memset, since
   Frama-C's struct sockaddr_in (no sin_zero) is 8 bytes, smaller than
   struct sockaddr (16 bytes, as in glibc). */
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>

int main(void)
{
  struct sockaddr_in sin;
  memset(&sin, 0, sizeof(struct sockaddr));
  sin.sin_family = AF_INET;
  return (int)sizeof sin;
}
