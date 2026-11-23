#!/bin/sh
# Issue 46: [Libc] <sched.h> lacks cpu_set_t, CPU_* macros and
# sched_setaffinity / sched_getaffinity.
#
# Images: framac-master-audit:189053d (master 189053d4a2) and
#         framac-analysis:latest (34.0~beta); same "before" output on both.
# Command, from this directory:
#   docker run --rm -v "$PWD:/w" -w /w --entrypoint sh <image> \
#     46-libc-sched-cpu-set.sh
#
# Output before (master 189053d4a2; 34.0~beta prints the same), exit 1:
#   basic (x86_64): frama-c syntax error; gcc ok
#   basic (x86_32): frama-c syntax error; gcc ok
#   macros (x86_64): frama-c syntax error; gcc ok
#   dynamic_s (x86_64): frama-c syntax error; gcc ok
#   RESULT: bug present (4 of 4 checks fail)
#
# Output after (master 189053d4a2 with patches/46-libc-sched-cpu-set.patch
# installed), exit 0:
#   basic (x86_64): frama-c ok; gcc ok
#   basic (x86_32): frama-c ok; gcc ok
#   macros (x86_64): frama-c ok; gcc ok
#   dynamic_s (x86_64): frama-c ok; gcc ok
#   RESULT: fixed
set -u
tmp=${TMPDIR:-/tmp}/repro46.$$
mkdir -p "$tmp"
failed=0
n=0

run_check() {
  label=$1
  machdep=$2
  def=$3
  n=$((n + 1))
  if [ -n "$def" ]; then
    gcc_def="-D$def"
    fc_def="-cpp-extra-args=-D$def"
  else
    gcc_def=""
    fc_def=""
  fi
  if gcc -fsyntax-only -Wall -Wextra $gcc_def 46-libc-sched-cpu-set.c \
       > "$tmp/gcc.log" 2>&1; then
    gs=ok
  else
    gs=FAIL
  fi
  frama-c -no-unicode -machdep "$machdep" $fc_def \
    46-libc-sched-cpu-set.c > "$tmp/fc.log" 2>&1
  rc=$?
  if [ "$rc" != 0 ] \
     || grep -q -e 'User Error' -e 'fatal error' -e 'syntax error' "$tmp/fc.log"; then
    m=$(grep -m1 -o -e 'syntax error' -e 'Cannot resolve variable [A-Za-z_0-9]*' \
          -e 'fatal error: [^:]*' "$tmp/fc.log")
    m=${m:-error (exit $rc)}
    failed=$((failed + 1))
  else
    m=ok
  fi
  echo "$label: frama-c $m; gcc $gs"
}

run_check "basic (x86_64)" gcc_x86_64 ""
run_check "basic (x86_32)" x86_32 ""
run_check "macros (x86_64)" gcc_x86_64 CHECK_macros
run_check "dynamic_s (x86_64)" gcc_x86_64 CHECK_dynamic_s

rm -rf "$tmp"
if [ "$failed" = 0 ]; then
  echo "RESULT: fixed"
  exit 0
else
  echo "RESULT: bug present ($failed of $n checks fail)"
  exit 1
fi
