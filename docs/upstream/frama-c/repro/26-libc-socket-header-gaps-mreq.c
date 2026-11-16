/* struct ip_mreq, the argument of IP_ADD_MEMBERSHIP (glibc). */
#include <sys/socket.h>
#include <netinet/in.h>

int join(int fd, struct in_addr group)
{
  struct ip_mreq mreq;
  mreq.imr_multiaddr = group;
  mreq.imr_interface.s_addr = INADDR_ANY;
  return setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof mreq);
}
