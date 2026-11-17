#!/bin/sh
# E-ACSL --validate-format-strings checks each directive against the argument
# at the directive's own position. A '*' field width or precision takes an int
# argument first, so every directive from the first '*' on is checked against
# the wrong argument, and the value of a '*' precision is never used.
#
# Images: framac-master-audit:9540804 (master 95408044f7, before),
#         the same tree with patches/32-eacsl-format-star-width-precision.patch
#         (after), framac-analysis:latest (34.0~beta, before; its installed
#         e_acsl_stdio.c has the same md5 as master's, the pipeline patches
#         only a copy it passes with --e-acsl-share).
# Command, from the repro directory:
#   docker run --rm -v "$PWD:/w" -w /w --entrypoint sh <image> 32-eacsl-format-star-width-precision.sh
# -M (full memory tracking) avoids an unrelated stop on literal format strings
# without it ("invalid format string (unallocated or unterminated)", Issue 33).
# The programs that abort are run under prlimit --core=1:1.
#
# Output before the fix (master 95408044f7, 2026-11-17; 34.0~beta prints the
# same with "34.0~beta (Selenium)"):
#   35.0~~dev (Bromine)
#   --- e-acsl-gcc -q -c -M -G gcc --validate-format-strings 32-eacsl-format-star-width-precision.c
#   build: exit 0
#   printf: directive 1 ('%.*s') expects argument of type 'char*' but the corresponding argument has type 'int'
#   exit 134
#   --- e-acsl-gcc -q -c -M -G clang --validate-format-strings 32-eacsl-format-star-width-precision.c
#   build: exit 1
#   compile errors: 5
#   a.c:254:9: error: call to undeclared function '__e_acsl_builtin_printf'; ISO C99 and later do not support implicit function declarations [-Wimplicit-function-declaration]
#   --- e-acsl-gcc -q -c -M -G gcc --validate-format-strings 32-eacsl-format-star-width-precision-cases.c
#   build: exit 0
#   case 0:
#   [   42]
#   exit 0
#   case 1:
#   printf: directive 1 ('%-*.*f') expects argument of type 'double' but the corresponding argument has type 'int'
#   exit 134
#   case 2:
#   printf: directive 1 ('%*s') expects argument of type 'char*' but the corresponding argument has type 'int'
#   exit 134
#   case 3:
#   printf: directive 1 ('%.*s') expects argument of type 'char*' but the corresponding argument has type 'int'
#   exit 134
#   case 4:
#   printf: directive 1 ('%05d') expects argument of type 'int' but the corresponding argument has type 'char*'
#   exit 134
#   case 5:
#   printf: directive 1 ('%*d') expects argument of type 'int' but the corresponding argument has type 'long'
#   exit 134
#   case 6:
#   printf: directive 1 ('%.*s') expects argument of type 'char*' but the corresponding argument has type 'int'
#   exit 134
#   case 7:
#   printf: directive 2 ('%s') expects argument of type 'char*' but the corresponding argument has type 'int'
#   exit 134
#   case 8:
#   Format error: illegal format specifier '1'
#   exit 134
# Case 0 passes only because the '*' int is checked against "%d". Case 4 has
# no '*': "%05d" (directive 2) is checked against argument 1. Case 6 aborts
# for the wrong reason, case 7 on the wrong argument. The -G clang build fails
# before and after the fix: the runtime does not compile with clang 19 under
# --validate-format-strings (5 implicit-declaration errors; #2810, not this bug).
#
# Output after the fix (master 95408044f7 + the patch):
#   35.0~~dev (Bromine)
#   --- e-acsl-gcc -q -c -M -G gcc --validate-format-strings 32-eacsl-format-star-width-precision.c
#   build: exit 0
#   RECORD:abcdefgh
#   exit 0
#   --- e-acsl-gcc -q -c -M -G clang --validate-format-strings 32-eacsl-format-star-width-precision.c
#   build: exit 1
#   compile errors: 5
#   a.c:254:9: error: call to undeclared function '__e_acsl_builtin_printf'; ISO C99 and later do not support implicit function declarations [-Wimplicit-function-declaration]
#   --- e-acsl-gcc -q -c -M -G gcc --validate-format-strings 32-eacsl-format-star-width-precision-cases.c
#   build: exit 0
#   case 0:
#   [   42]
#   exit 0
#   case 1:
#   [3.14      ]
#   exit 0
#   case 2:
#   [ abc|abc]
#   exit 0
#   case 3:
#   [xyz]
#   exit 0
#   case 4:
#   [abc 00005]
#   exit 0
#   case 5:
#   printf: directive 1 ('%*d') expects argument of type 'int' but the corresponding argument has type 'long'
#   exit 134
#   case 6:
#   printf: attempt to access partially unallocated memory via directive 1 ('%.*s')
#   exit 134
#   case 7:
#   printf: unterminated string in directive 2 ('%s')
#   exit 134
#   case 8:
#   Format error: illegal format specifier '1'
#   exit 134
# Case 8 (a numbered '*', POSIX "%2$*1$d") is still rejected by the parser.
set -u
n=32-eacsl-format-star-width-precision
tmp=$(mktemp -d)
frama-c -version
run() { # <binary> <args>...
  prlimit --core=1:1 "$@" > "$tmp/run.log" 2>&1
  status=$?
  grep -v '^Aborted' "$tmp/run.log"
  echo "exit $status"
}
for cc in gcc clang; do
  opts="-q -c -M -G $cc --validate-format-strings"
  echo "--- e-acsl-gcc $opts $n.c"
  rm -f "$tmp/a.e-acsl"
  e-acsl-gcc $opts -o "$tmp/a.c" -O "$tmp/a" "$n.c" > "$tmp/build.log" 2>&1
  echo "build: exit $?"
  if [ -x "$tmp/a.e-acsl" ]; then
    run "$tmp/a.e-acsl"
  else
    grep -c ' error: ' "$tmp/build.log" | sed 's/^/compile errors: /'
    grep -m 1 ' error: ' "$tmp/build.log" | sed 's|^[^ ]*/||'
  fi
done
opts="-q -c -M -G gcc --validate-format-strings"
echo "--- e-acsl-gcc $opts $n-cases.c"
e-acsl-gcc $opts -o "$tmp/b.c" -O "$tmp/b" "$n-cases.c" > "$tmp/build.log" 2>&1
echo "build: exit $?"
for k in 0 1 2 3 4 5 6 7 8; do
  echo "case $k:"
  run "$tmp/b.e-acsl" $k
done
rm -rf "$tmp"
