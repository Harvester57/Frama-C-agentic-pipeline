/* fd_set after <sys/socket.h> alone: glibc makes it visible through
   <sys/types.h> -> <sys/select.h>. */
#include <sys/socket.h>

int count(fd_set *s)
{
  return s != 0;
}
