/* The modem-line bits of TIOCMGET / TIOCMSET that glibc's <sys/ioctl.h>
   defines (in <bits/ioctl-types.h>), one CHECK_* macro per bit: the
   reproducer parses each one separately, because Frama-C stops at the first
   unknown name. CHECK_rts is the line libmodbus (src/modbus-rtu.c) uses. */
#include <sys/ioctl.h>

int f(int fd) {
  int flags = 0;
  if (ioctl(fd, TIOCMGET, &flags) == -1)
    return -1;
#if defined(CHECK_le)
  return (flags & TIOCM_LE) != 0;
#elif defined(CHECK_dtr)
  flags |= TIOCM_DTR;
#elif defined(CHECK_rts)
  flags |= TIOCM_RTS;
#elif defined(CHECK_st)
  return (flags & TIOCM_ST) != 0;
#elif defined(CHECK_sr)
  return (flags & TIOCM_SR) != 0;
#elif defined(CHECK_cts)
  return (flags & TIOCM_CTS) != 0;
#elif defined(CHECK_car)
  return (flags & TIOCM_CAR) != 0;
#elif defined(CHECK_rng)
  return (flags & TIOCM_RNG) != 0;
#elif defined(CHECK_dsr)
  return (flags & TIOCM_DSR) != 0;
#elif defined(CHECK_cd)
  return (flags & TIOCM_CD) != 0;
#elif defined(CHECK_ri)
  return (flags & TIOCM_RI) != 0;
#endif
  return ioctl(fd, TIOCMSET, &flags);
}
