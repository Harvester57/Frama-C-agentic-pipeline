/* The modem-line bits of TIOCMGET / TIOCMSET (glibc <sys/ioctl.h>,
   Linux <asm-generic/termios.h>), one CHECK_* macro per case: the
   reproducer parses each one separately. CHECK_rts is the line libmodbus
   (src/modbus-rtu.c) uses. */
#include <sys/ioctl.h>
#include <termios.h>

int f(int fd) {
  int flags;
  if (ioctl(fd, TIOCMGET, &flags) == -1)
    return -1;
#if defined(CHECK_rts)
  flags |= TIOCM_RTS;
#elif defined(CHECK_dtr)
  flags |= TIOCM_DTR;
#elif defined(CHECK_cts)
  return (flags & TIOCM_CTS) != 0;
#elif defined(CHECK_cd)
  return (flags & TIOCM_CD) != 0;
#elif defined(CHECK_ri)
  return (flags & TIOCM_RI) != 0;
#elif defined(CHECK_dsr)
  return (flags & TIOCM_DSR) != 0;
#endif
  return ioctl(fd, TIOCMSET, &flags);
}
