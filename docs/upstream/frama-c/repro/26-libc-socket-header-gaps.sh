#!/bin/sh
# Issue 26: [Libc] socket headers: struct sockaddr_in lacks sin_zero (and is
# smaller than struct sockaddr), struct ip_mreq is missing, and fd_set is not
# visible from <sys/socket.h> as with glibc in its default mode.
#
# Images: framac-master-audit:3dff90f (master 3dff90fc70, before),
#         framac-analysis:fc34 (34.0~beta, same output), and the master image
#         with ../patches/26-libc-socket-header-gaps.patch built and installed
#         (after).
# Command, from this directory:
#   docker run --rm -v "$PWD:/w" -w /w --entrypoint sh <image> \
#     26-libc-socket-header-gaps.sh
#
# Output before (master 3dff90fc70; 34.0~beta prints the same):
#   --- 26-libc-socket-header-gaps.c (Eva)
#   [eva:alarm] 26-libc-socket-header-gaps.c:11: Warning:
#     function memset: precondition 'valid_s' got status invalid.
#   --- 26-libc-socket-header-gaps-sinzero.c
#   [kernel] 26-libc-socket-header-gaps-sinzero.c:14: User Error:
#     Cannot find field sin_zero in type struct sockaddr_in
#   --- 26-libc-socket-header-gaps-mreq.c
#   [kernel] 26-libc-socket-header-gaps-mreq.c:8: User Error:
#     Cannot find field imr_multiaddr in type struct ip_mreq
#   --- 26-libc-socket-header-gaps-fdset.c
#   [kernel] 26-libc-socket-header-gaps-fdset.c:5: User Error:
#     syntax error:
#   RESULT: bug present (4 of 4 checks fail)
#
# Output after:
#   --- 26-libc-socket-header-gaps.c (Eva)
#   ok
#   --- 26-libc-socket-header-gaps-sinzero.c
#   ok
#   --- 26-libc-socket-header-gaps-mreq.c
#   ok
#   --- 26-libc-socket-header-gaps-fdset.c
#   ok
#   RESULT: fixed
#
# For comparison, gcc with glibc accepts all four files in its default mode
# (gnu17); with -std=c11 (no _DEFAULT_SOURCE), glibc hides fd_set from
# <sys/socket.h> and struct ip_mreq, but still has sin_zero.
set -u
tmp=${TMPDIR:-/tmp}/repro26.$$
mkdir -p "$tmp"
failed=0
echo "--- 26-libc-socket-header-gaps.c (Eva)"
frama-c -no-unicode 26-libc-socket-header-gaps.c -eva -eva-verbose 0 \
  > "$tmp/eva.log" 2>&1
if grep -q 'eva:alarm' "$tmp/eva.log"; then
  grep -A1 'eva:alarm' "$tmp/eva.log"; failed=$((failed + 1))
else echo ok
fi
for x in sinzero mreq fdset; do
  f=26-libc-socket-header-gaps-$x.c
  echo "--- $f"
  if frama-c -no-unicode "$f" > "$tmp/$x.log" 2>&1; then echo ok
  else grep -A1 'User Error' "$tmp/$x.log" | grep -v -e '^--$' -e 'stopping on'
       failed=$((failed + 1))
  fi
done
rm -rf "$tmp"
if [ "$failed" = 0 ]; then echo "RESULT: fixed"; exit 0
else echo "RESULT: bug present ($failed of 4 checks fail)"; exit 1
fi
