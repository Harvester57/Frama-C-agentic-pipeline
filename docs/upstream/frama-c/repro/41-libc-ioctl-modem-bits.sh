#!/bin/sh
# Issue 41: [Libc] <sys/ioctl.h> defines TIOCMGET / TIOCMBIS / TIOCMBIC /
# TIOCMSET but none of the modem-line bits (TIOCM_RTS, TIOCM_DTR, ...).
#
# Images: framac-master-audit:9540804 with its tree moved to master
#         b80fcac74f and reinstalled, and framac-analysis:latest (34.0~beta);
#         same "before" output on both, and on master 95408044f7.
# Command, from this directory:
#   docker run --rm -v "$PWD:/w" -w /w --entrypoint sh <image> \
#     41-libc-ioctl-modem-bits.sh
#
# The eleven checks are the eleven TIOCM_* names that glibc 2.41 defines in
# <sys/ioctl.h> (through <bits/ioctl-types.h>).
#
# Output before (master b80fcac74f; 34.0~beta prints the same), exit 1:
#   le: frama-c Cannot resolve variable TIOCM_LE; gcc ok
#   dtr: frama-c Cannot resolve variable TIOCM_DTR; gcc ok
#   rts: frama-c Cannot resolve variable TIOCM_RTS; gcc ok
#   st: frama-c Cannot resolve variable TIOCM_ST; gcc ok
#   sr: frama-c Cannot resolve variable TIOCM_SR; gcc ok
#   cts: frama-c Cannot resolve variable TIOCM_CTS; gcc ok
#   car: frama-c Cannot resolve variable TIOCM_CAR; gcc ok
#   rng: frama-c Cannot resolve variable TIOCM_RNG; gcc ok
#   dsr: frama-c Cannot resolve variable TIOCM_DSR; gcc ok
#   cd: frama-c Cannot resolve variable TIOCM_CD; gcc ok
#   ri: frama-c Cannot resolve variable TIOCM_RI; gcc ok
#   RESULT: bug present (11 of 11 checks fail)
#
# Output after (master b80fcac74f with patches/41-libc-ioctl-modem-bits.patch
# installed), exit 0: the same eleven lines with "frama-c ok; gcc ok", then
#   RESULT: fixed
set -u
tmp=${TMPDIR:-/tmp}/repro41.$$
mkdir -p "$tmp"
failed=0
n=0
for c in le dtr rts st sr cts car rng dsr cd ri; do
  n=$((n + 1))
  if gcc -c -o /dev/null -DCHECK_$c 41-libc-ioctl-modem-bits.c \
       > "$tmp/gcc.log" 2>&1; then gs=ok; else gs=FAIL; fi
  frama-c -no-unicode -cpp-extra-args=-DCHECK_$c \
    41-libc-ioctl-modem-bits.c > "$tmp/fc.log" 2>&1
  rc=$?
  if [ "$rc" != 0 ] \
     || grep -q -e 'User Error' -e 'fatal error' -e 'syntax error' "$tmp/fc.log"; then
    m=$(grep -m1 -o -e 'Cannot resolve variable [A-Za-z_0-9]*' \
          -e 'fatal error: [^:]*' -e 'syntax error' "$tmp/fc.log")
    m=${m:-error (exit $rc)}
    failed=$((failed + 1))
  else m=ok
  fi
  echo "$c: frama-c $m; gcc $gs"
done
rm -rf "$tmp"
if [ "$failed" = 0 ]; then echo "RESULT: fixed"; exit 0
else echo "RESULT: bug present ($failed of $n checks fail)"; exit 1
fi
