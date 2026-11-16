#!/bin/sh
# E-ACSL --validate-format-strings reads every variadic argument as a void *.
# A double or a long double is not passed where a void * is, so from there on
# the pointer checked for "%s", "%p" or "%n" belongs to the next argument.
#
# Images: framac-master-audit:3dff90f (master 3dff90fc70, before),
#         the same image with the patch (after), framac-analysis:fc34 (34.0~beta).
# Command, from the repro directory:
#   docker run --rm -v "$PWD:/w" -w /w --entrypoint sh <image> 31-eacsl-format-fp-argument-slots.sh
# -M (full memory tracking) avoids an unrelated stop on literal format strings
# without it ("invalid format string (unallocated or unterminated)").
# The programs that abort are run under prlimit --core=0.
#
# Output before the fix (master 3dff90fc70; 34.0~beta prints the same with
# "34.0~beta (Selenium)"):
#   35.0~~dev (Bromine)
#   --- e-acsl-gcc -q -c -M -G gcc --validate-format-strings 31-eacsl-format-fp-argument-slots.c
#   build: exit 0
#   snprintf: attempt to access unallocated memory via directive 2 ('%s')
#   exit 134
#   --- e-acsl-gcc -q -c -M -G gcc --validate-format-strings 31-eacsl-format-fp-argument-slots-cases.c
#   build: exit 0
#   case 0:
#   snprintf: attempt to access unallocated memory via directive 2 ('%s')
#   exit 134
#   case 1:
#   snprintf: argument 1 of directive %n not allocated or writeable
#   exit 134
#   case 2:
#   snprintf: unterminated string in directive 1 ('%s')
#   exit 134
#   case 3:
#   snprintf: attempt to access unallocated memory via directive 3 ('%s')
#   exit 134
#   case 4:
#   exit 0
# Case 3 never checks u (directive 3 is checked against what follows s), and
# case 4 runs: u is not checked at all, and vsnprintf reads past it.
#
# Output after the fix (master 3dff90fc70 + patches/31-eacsl-format-fp-argument-slots.patch):
#   35.0~~dev (Bromine)
#   --- e-acsl-gcc -q -c -M -G gcc --validate-format-strings 31-eacsl-format-fp-argument-slots.c
#   build: exit 0
#   1.500000 abc
#   exit 0
#   --- e-acsl-gcc -q -c -M -G gcc --validate-format-strings 31-eacsl-format-fp-argument-slots-cases.c
#   build: exit 0
#   case 0:
#   exit 0
#   case 1:
#   exit 0
#   case 2:
#   snprintf: unterminated string in directive 1 ('%s')
#   exit 134
#   case 3:
#   snprintf: unterminated string in directive 2 ('%s')
#   exit 134
#   case 4:
#   snprintf: unterminated string in directive 2 ('%s')
#   exit 134
set -u
n=31-eacsl-format-fp-argument-slots
tmp=$(mktemp -d)
frama-c -version
run() { # <binary> <args>...
  prlimit --core=0 "$@" > "$tmp/run.log" 2>&1
  status=$?
  grep -v '^Aborted' "$tmp/run.log"
  echo "exit $status"
}
opts="-q -c -M -G gcc --validate-format-strings"
echo "--- e-acsl-gcc $opts $n.c"
e-acsl-gcc $opts -o "$tmp/a.c" -O "$tmp/a" "$n.c" > "$tmp/build.log" 2>&1
echo "build: exit $?"
run "$tmp/a.e-acsl"
echo "--- e-acsl-gcc $opts $n-cases.c"
e-acsl-gcc $opts -o "$tmp/b.c" -O "$tmp/b" "$n-cases.c" > "$tmp/build.log" 2>&1
echo "build: exit $?"
for k in 0 1 2 3 4; do
  echo "case $k:"
  run "$tmp/b.e-acsl" $k
done
rm -rf "$tmp"
