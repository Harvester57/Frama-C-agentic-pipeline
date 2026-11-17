#!/bin/sh
# E-ACSL --validate-format-strings without -M (--full-mtracking): every call
# to a format function aborts, even with a literal format string, because the
# memory tracking analysis does not monitor the blocks the RTL replacement of
# printf checks (the format string, and the "%s", "%p" and "%n" arguments).
#
# Images: framac-master-audit:9540804 (master 95408044f7, before),
#         the same tree with
#         patches/33-eacsl-format-literal-without-full-mtracking.patch (after),
#         framac-analysis:latest (34.0~beta, before).
# Command, from the repro directory:
#   docker run --rm -v "$PWD:/w" -w /w --entrypoint sh <image> 33-eacsl-format-literal-without-full-mtracking.sh
# The -M build of the cases is the control: it gives the expected results
# before and after. The programs that abort are run under prlimit --core=1:1.
#
# Output before the fix (master 95408044f7, 2026-11-17; 34.0~beta prints the
# same with "34.0~beta (Selenium)"):
#   35.0~~dev (Bromine)
#   --- e-acsl-gcc -q -c -G gcc --validate-format-strings 33-eacsl-format-literal-without-full-mtracking.c
#   build: exit 0
#   snprintf: invalid format string (unallocated or unterminated)
#   exit 134
#   --- e-acsl-gcc -q -c  -G gcc --validate-format-strings 33-eacsl-format-literal-without-full-mtracking-cases.c
#   build: exit 0
#   case 0: printf: invalid format string (unallocated or unterminated) exit 134
#   case 1: printf: invalid format string (unallocated or unterminated) exit 134
#   case 2: printf: invalid format string (unallocated or unterminated) exit 134
#   case 3: printf: invalid format string (unallocated or unterminated) exit 134
#   case 4: printf: invalid format string (unallocated or unterminated) exit 134
#   case 5: printf: invalid format string (unallocated or unterminated) exit 134
#   case 6: printf: invalid format string (unallocated or unterminated) exit 134
#   --- e-acsl-gcc -q -c -M -G gcc --validate-format-strings 33-eacsl-format-literal-without-full-mtracking-cases.c
#   build: exit 0
#   case 0: hey exit 0
#   case 1: hey exit 0
#   case 2: [hey] exit 0
#   case 3: ab n=2 exit 0
#   case 4: printf: directive 1 ('%d') expects argument of type 'int' but the corresponding argument has type 'char*' exit 134
#   case 5: printf: unterminated string in directive 1 ('%s') exit 134
#   case 6: printf: unterminated string in directive 1 ('%s') exit 134
# Case 4 is the example of the user manual ("Format String Vulnerabilities"),
# documented without -M with the type message.
#
# Output after the fix (master 95408044f7 + the patch); the -M part, not
# repeated here, is the same as before:
#   35.0~~dev (Bromine)
#   --- e-acsl-gcc -q -c -G gcc --validate-format-strings 33-eacsl-format-literal-without-full-mtracking.c
#   build: exit 0
#   192.168.1.200
#   exit 0
#   --- e-acsl-gcc -q -c  -G gcc --validate-format-strings 33-eacsl-format-literal-without-full-mtracking-cases.c
#   build: exit 0
#   case 0: hey exit 0
#   case 1: hey exit 0
#   case 2: [hey] exit 0
#   case 3: ab n=2 exit 0
#   case 4: printf: directive 1 ('%d') expects argument of type 'int' but the corresponding argument has type 'char*' exit 134
#   case 5: printf: unterminated string in directive 1 ('%s') exit 134
#   case 6: printf: unterminated string in directive 1 ('%s') exit 134
set -u
n=33-eacsl-format-literal-without-full-mtracking
tmp=$(mktemp -d)
frama-c -version
run() { # <binary> <args>...
  prlimit --core=1:1 "$@" > "$tmp/run.log" 2>&1
  status=$?
  grep -v '^Aborted' "$tmp/run.log"
  echo "exit $status"
}
opts="-q -c -G gcc --validate-format-strings"
echo "--- e-acsl-gcc $opts $n.c"
e-acsl-gcc $opts -o "$tmp/a.c" -O "$tmp/a" "$n.c" > "$tmp/build.log" 2>&1
echo "build: exit $?"
run "$tmp/a.e-acsl"
for m in "" "-M"; do
  opts="-q -c $m -G gcc --validate-format-strings"
  echo "--- e-acsl-gcc $opts $n-cases.c"
  rm -f "$tmp/b.e-acsl"
  e-acsl-gcc $opts -o "$tmp/b.c" -O "$tmp/b" "$n-cases.c" > "$tmp/build.log" 2>&1
  echo "build: exit $?"
  for k in 0 1 2 3 4 5 6; do
    printf 'case %s: ' "$k"
    run "$tmp/b.e-acsl" $k | tr '\n' ' ' | sed 's/ $//'
    echo
  done
done
rm -rf "$tmp"
