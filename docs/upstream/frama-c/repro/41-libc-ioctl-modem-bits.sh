#!/bin/sh
# Issue 41: [Libc] <sys/ioctl.h> defines TIOCMGET / TIOCMBIS / TIOCMBIC /
# TIOCMSET but none of the modem-line bits (TIOCM_RTS, TIOCM_DTR, ...).
#
# Images: framac-master-audit:9540804 (master 95408044f7) and
#         framac-analysis:latest (34.0~beta); same output on both.
# Command, from this directory:
#   docker run --rm -v "$PWD:/w" -w /w --entrypoint sh <image> \
#     41-libc-ioctl-modem-bits.sh
#
# Output before (master 95408044f7; 34.0~beta prints the same):
#   rts: frama-c Cannot resolve variable TIOCM_RTS; gcc ok
#   dtr: frama-c Cannot resolve variable TIOCM_DTR; gcc ok
#   cts: frama-c Cannot resolve variable TIOCM_CTS; gcc ok
#   cd: frama-c Cannot resolve variable TIOCM_CD; gcc ok
#   ri: frama-c Cannot resolve variable TIOCM_RI; gcc ok
#   dsr: frama-c Cannot resolve variable TIOCM_DSR; gcc ok
#   RESULT: bug present (6 of 6 checks fail)
#
# There is no patch: the "after" output would be one "ok" per line and
# "RESULT: fixed". gcc (glibc, default gnu17) compiles every case.
set -u
tmp=${TMPDIR:-/tmp}/repro41.$$
mkdir -p "$tmp"
failed=0
n=0
for c in rts dtr cts cd ri dsr; do
  n=$((n + 1))
  if gcc -c -o /dev/null -DCHECK_$c 41-libc-ioctl-modem-bits.c \
       > "$tmp/gcc.log" 2>&1; then gs=ok; else gs=FAIL; fi
  frama-c -no-unicode -cpp-extra-args=-DCHECK_$c \
    41-libc-ioctl-modem-bits.c > "$tmp/fc.log" 2>&1
  if grep -q -e 'User Error' -e 'fatal error' -e 'syntax error' "$tmp/fc.log"; then
    m=$(grep -m1 -o -e 'Cannot resolve variable [A-Za-z_0-9]*' \
          -e 'fatal error: [^:]*' -e 'syntax error' "$tmp/fc.log")
    failed=$((failed + 1))
  else m=ok
  fi
  echo "$c: frama-c ${m:-error}; gcc $gs"
done
rm -rf "$tmp"
if [ "$failed" = 0 ]; then echo "RESULT: fixed"; exit 0
else echo "RESULT: bug present ($failed of $n checks fail)"; exit 1
fi
