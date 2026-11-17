#!/bin/sh
# Issue 39: [Libc] Linux headers sys/epoll.h and sys/inotify.h are missing
# from share/libc (plus a list of smaller Linux/glibc gaps, informational).
#
# Images: framac-master-audit:9540804 (master 95408044f7, before),
#         framac-analysis:latest (34.0~beta, same output), and the master
#         image with ../patches/39-libc-linux-header-gaps.patch built and
#         installed (after).
# Command, from this directory:
#   docker run --rm -v "$PWD:/w" -w /w --entrypoint sh <image> \
#     39-libc-linux-header-gaps.sh
#
# Output before (master 95408044f7; 34.0~beta prints the same):
#   --- 39-libc-linux-header-gaps-epoll.c (Eva)
#   fatal error: sys/epoll.h
#   --- 39-libc-linux-header-gaps-inotify.c (Eva)
#   fatal error: sys/inotify.h
#   --- other gaps (informational)
#   ip_icmp: frama-c fatal error: netinet/ip_icmp.h; gcc ok
#   sys_syscall: frama-c fatal error: sys/syscall.h; gcc ok
#   syscall: frama-c Calling undeclared function syscall; gcc ok
#   explicit_bzero: frama-c Calling undeclared function explicit_bzero; gcc ok
#   ioctl_iowr: frama-c syntax error; gcc ok
#   eventfd: frama-c fatal error: sys/eventfd.h; gcc ok
#   timerfd: frama-c fatal error: sys/timerfd.h; gcc ok
#   signalfd: frama-c fatal error: sys/signalfd.h; gcc ok
#   pipe2: frama-c Calling undeclared function pipe2; gcc ok
#   dup3: frama-c Calling undeclared function dup3; gcc ok
#   accept4: frama-c Calling undeclared function accept4; gcc ok
#   RESULT: bug present (2 of 2 checks fail)
#
# Output after (master 95408044f7 + patch, commit 9b52dce322 in the audit
# container):
#   --- 39-libc-linux-header-gaps-epoll.c (Eva)
#   ok
#   --- 39-libc-linux-header-gaps-inotify.c (Eva)
#   ok
#   --- other gaps (informational)
#   (the same eleven lines as before)
#   RESULT: fixed
#
# Only the first two checks decide RESULT. The "other gaps" section is
# informational: the patch does not touch them, and it prints the same
# lines before and after. gcc (glibc, default gnu17) compiles every file.
set -u
tmp=${TMPDIR:-/tmp}/repro39.$$
mkdir -p "$tmp"
failed=0
for x in epoll inotify; do
  f=39-libc-linux-header-gaps-$x.c
  echo "--- $f (Eva)"
  frama-c -no-unicode "$f" -eva -eva-verbose 0 > "$tmp/$x.log" 2>&1
  if grep -q -e 'fatal error' -e 'User Error' "$tmp/$x.log"; then
    grep -m1 -o -e 'fatal error: [^:]*' -e 'User Error.*' "$tmp/$x.log"
    failed=$((failed + 1))
  elif grep -q 'eva:alarm' "$tmp/$x.log"; then
    grep -A1 'eva:alarm' "$tmp/$x.log"; failed=$((failed + 1))
  else echo ok
  fi
done
echo "--- other gaps (informational)"
for g in ip_icmp sys_syscall syscall explicit_bzero ioctl_iowr eventfd \
         timerfd signalfd pipe2 dup3 accept4; do
  if gcc -c -o /dev/null -DGAP_$g 39-libc-linux-header-gaps-others.c \
       > "$tmp/gcc.log" 2>&1; then gs=ok; else gs=FAIL; fi
  frama-c -no-unicode -cpp-extra-args=-DGAP_$g \
    39-libc-linux-header-gaps-others.c > "$tmp/o.log" 2>&1
  m=$(grep -m1 -o -e 'fatal error: [^:]*' -e 'Calling undeclared function [a-z_0-9]*' \
        -e 'syntax error' "$tmp/o.log")
  echo "$g: frama-c ${m:-ok}; gcc $gs"
done
rm -rf "$tmp"
if [ "$failed" = 0 ]; then echo "RESULT: fixed"; exit 0
else echo "RESULT: bug present ($failed of 2 checks fail)"; exit 1
fi
