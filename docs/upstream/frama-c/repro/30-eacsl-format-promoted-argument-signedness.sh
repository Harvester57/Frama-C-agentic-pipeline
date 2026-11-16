#!/bin/sh
# E-ACSL --validate-format-strings: an unsigned char or unsigned short passed
# to "%u" / "%x" is promoted to int, and the runtime rejects it as an int.
#
# Images: framac-master-audit:3dff90f (master 3dff90fc70, before),
#         the same image with the patch (after), framac-analysis:fc34 (34.0~beta).
# Command, from the repro directory:
#   docker run --rm -v "$PWD:/w" -w /w --entrypoint sh <image> 30-eacsl-format-promoted-argument-signedness.sh
# -M (full memory tracking) avoids an unrelated stop on literal format strings
# without it ("invalid format string (unallocated or unterminated)").
# The programs that abort are run under prlimit --core=0.
#
# Output before the fix (master 3dff90fc70; 34.0~beta prints the same with
# "34.0~beta (Selenium)"):
#   35.0~~dev (Bromine)
#   --- e-acsl-gcc -q -c -M -G gcc --validate-format-strings 30-eacsl-format-promoted-argument-signedness.c
#   build: exit 0
#   snprintf: directive 1 ('%u') expects argument of type 'unsigned int' but the corresponding argument has type 'int'
#   exit 134
#   --- e-acsl-gcc -q -c -M -G gcc --validate-format-strings 30-eacsl-format-promoted-argument-signedness-cases.c
#   build: exit 0
#   __e_acsl_builtin_printf("d"
#   __e_acsl_builtin_printf("d"
#   __e_acsl_builtin_printf("d"
#   __e_acsl_builtin_printf("d"
#   __e_acsl_builtin_printf("d"
#   __e_acsl_builtin_printf("D"
#   case 0:
#   printf: directive 1 ('%x') expects argument of type 'unsigned int' but the corresponding argument has type 'int'
#   exit 134
#   case 1:
#   printf: directive 1 ('%u') expects argument of type 'unsigned int' but the corresponding argument has type 'int'
#   exit 134
#   case 2:
#   200
#   exit 0
#   case 3:
#   printf: directive 1 ('%u') expects argument of type 'unsigned int' but the corresponding argument has type 'int'
#   exit 134
#   case 4:
#   printf: directive 1 ('%u') expects argument of type 'unsigned int' but the corresponding argument has type 'int'
#   exit 134
#   case 5:
#   printf: directive 1 ('%d') expects argument of type 'int' but the corresponding argument has type 'unsigned int'
#   exit 134
#
# Output after the fix (master 3dff90fc70 + patches/30-eacsl-format-promoted-argument-signedness.patch):
#   35.0~~dev (Bromine)
#   --- e-acsl-gcc -q -c -M -G gcc --validate-format-strings 30-eacsl-format-promoted-argument-signedness.c
#   build: exit 0
#   192.168.1.200
#   exit 0
#   --- e-acsl-gcc -q -c -M -G gcc --validate-format-strings 30-eacsl-format-promoted-argument-signedness-cases.c
#   build: exit 0
#   __e_acsl_builtin_printf("C"
#   __e_acsl_builtin_printf("H"
#   __e_acsl_builtin_printf("C"
#   __e_acsl_builtin_printf("d"
#   __e_acsl_builtin_printf("d"
#   __e_acsl_builtin_printf("D"
#   case 0:
#   c8
#   exit 0
#   case 1:
#   60000
#   exit 0
#   case 2:
#   200
#   exit 0
#   case 3:
#   printf: directive 1 ('%u') expects argument of type 'unsigned int' but the corresponding argument has type 'int'
#   exit 134
#   case 4:
#   printf: directive 1 ('%u') expects argument of type 'unsigned int' but the corresponding argument has type 'int'
#   exit 134
#   case 5:
#   printf: directive 1 ('%d') expects argument of type 'int' but the corresponding argument has type 'unsigned int'
#   exit 134
# Cases 3 to 5 (a negative signed char, an int and an unsigned int) keep
# aborting with the patch: see the issue for the int / unsigned int question.
set -u
n=30-eacsl-format-promoted-argument-signedness
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
grep -o '__e_acsl_builtin_printf("[A-Za-z]*"' "$tmp/b.c"
for k in 0 1 2 3 4 5; do
  echo "case $k:"
  run "$tmp/b.e-acsl" $k
done
rm -rf "$tmp"
