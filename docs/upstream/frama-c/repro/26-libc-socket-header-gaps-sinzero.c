/* sockaddr_in.sin_zero (glibc). Without it, struct sockaddr_in
   is 8 bytes instead of 16 = sizeof(struct sockaddr). */
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>

int bind_any(int fd, in_port_t port)
{
  struct sockaddr_in sin;
  memset(&sin, 0, sizeof(struct sockaddr));
  sin.sin_family = AF_INET;
  sin.sin_port = port;
  sin.sin_addr.s_addr = INADDR_ANY;
  memset(sin.sin_zero, 0, sizeof sin.sin_zero);
  return bind(fd, (struct sockaddr *)&sin, sizeof sin);
}
