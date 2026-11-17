/* A minimal epoll event loop, the pattern of event-driven Linux daemons
   and resolvers. gcc with glibc compiles it; Frama-C stops at the
   include, since share/libc has no sys/epoll.h. */
#include <sys/epoll.h>
#include <unistd.h>

int main(void)
{
  int ep = epoll_create1(EPOLL_CLOEXEC);
  if (ep == -1)
    return 1;
  struct epoll_event ev;
  ev.events = EPOLLIN | EPOLLRDHUP | EPOLLET;
  ev.data.fd = 0;
  if (epoll_ctl(ep, EPOLL_CTL_ADD, 0, &ev) == -1) {
    close(ep);
    return 1;
  }
  struct epoll_event evs[8];
  int n = epoll_wait(ep, evs, 8, 1000);
  epoll_ctl(ep, EPOLL_CTL_DEL, 0, NULL);
  close(ep);
  return n < 0;
}
