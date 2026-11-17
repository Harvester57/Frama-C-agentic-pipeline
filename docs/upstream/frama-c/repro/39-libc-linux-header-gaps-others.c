/* The other Linux/glibc declarations missing from share/libc, one per
   GAP_* macro (the reproducer builds each one separately). They are
   listed in the issue as questions; the patch does not add them. */
#if defined(GAP_ip_icmp)
#include <netinet/ip_icmp.h>
int f(struct icmphdr *h) { return h->type == ICMP_ECHO; }
#elif defined(GAP_sys_syscall)
#include <unistd.h>
#include <sys/syscall.h>
long f(void) { return syscall(SYS_getpid); }
#elif defined(GAP_syscall)
#include <unistd.h>
long f(long n) { return syscall(n); }
#elif defined(GAP_explicit_bzero)
#include <string.h>
void f(char *p, size_t n) { explicit_bzero(p, n); }
#elif defined(GAP_ioctl_iowr)
#include <sys/ioctl.h>
struct s { int a; };
unsigned long f(void) { return _IOWR(0x42, 1, struct s); }
#elif defined(GAP_eventfd)
#include <sys/eventfd.h>
int f(void) { return eventfd(0, EFD_NONBLOCK); }
#elif defined(GAP_timerfd)
#include <sys/timerfd.h>
int f(void) { return timerfd_create(CLOCK_MONOTONIC, 0); }
#elif defined(GAP_signalfd)
#include <sys/signalfd.h>
int f(sigset_t *m) { return signalfd(-1, m, 0); }
#elif defined(GAP_pipe2)
#define _GNU_SOURCE
#include <fcntl.h>
#include <unistd.h>
int f(int p[2]) { return pipe2(p, O_CLOEXEC); }
#elif defined(GAP_dup3)
#define _GNU_SOURCE
#include <fcntl.h>
#include <unistd.h>
int f(int a, int b) { return dup3(a, b, O_CLOEXEC); }
#elif defined(GAP_accept4)
#define _GNU_SOURCE
#include <sys/socket.h>
int f(int s) { return accept4(s, 0, 0, SOCK_CLOEXEC); }
#endif
