#include <sys/socket.h>

#ifndef OPTLEN
#define OPTLEN sizeof(int)
#endif

/*@ requires 0 <= fd < __FC_MAX_OPEN_SOCKETS; */
int get_rcvbuf(int fd) {
  int opt = 0;
  socklen_t olen = OPTLEN;
  int r = getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &opt, &olen);
  return r < 0 ? -1 : opt;
}

int main(void) { return get_rcvbuf(3); }
