#!/bin/sh
# Issue 34: [Kernel/Libc] GCC's type-generic overflow builtins
# __builtin_{add,sub,mul}_overflow are modelled only by first-operand
# _Generic macros in __fc_gcc_builtins.h (wrong flag for mixed types, parse
# error for char/short operands), the _p forms are missing, and without that
# header the calls are implicit K&R declarations whose printed prototype gcc
# cannot link and clang rejects (stock e-acsl-gcc always runs without it).
#
# Images: framac-master-audit:9540804 (master 95408044f7) and
#         framac-analysis:latest (34.0~beta); same output. No patch.
# Command, from this directory:
#   docker run --rm -v "$PWD:/w" -w /w --entrypoint sh <image> \
#     34-kernel-gcc-overflow-builtins.sh
#
# Output (master 95408044f7; 34.0~beta prints the same):
#   --- Frama-C libc, -machdep gcc_x86_64, Eva value of the returned flag
#   case 1 mul(int, int, long *):          gcc 0, Eva {1}
#     expected 'int *' but got argument of type 'long *': & r
#   case 2 add(int, long, long *):         gcc 0, Eva {1}
#     expected 'int *' but got argument of type 'long *': & r
#   case 3 add(int, int, unsigned *):      gcc 1, Eva {0}
#     expected 'int *' but got argument of type 'unsigned int *': & r
#   case 4 add(uchar, uchar, uchar *):     gcc 1, Eva (parsing aborted)
#     no compatible types and no default type in _Generic selection:
#   case 5 add_overflow_p(int, int, int):  gcc 1, Eva [-2147483648..2147483647]
#     Calling undeclared function __builtin_add_overflow_p. Old style K&R code?
#   --- no declaration in scope (x86_64; gcc_x86_64; gcc_x86_64 -no-frama-c-stdlib)
#   x86_64: frama-c -print:
#     Calling undeclared function __builtin_add_overflow. Old style K&R code?
#     expected 'int *' but got argument of type 'long *': & r
#   extern int ( /* missing proto */ __builtin_add_overflow)(int x_0, int x_1,
#     tmp = __builtin_add_overflow((int)a,(int)b,(int *)(& r));
#   original, gcc: exit 10
#   printed, gcc: link FAILED: undefined reference to `__builtin_add_overflow'
#   printed, clang: FAILED: error: cannot redeclare builtin function '__builtin_add_overflow'
#   gcc_x86_64: (same output)
#   gcc_x86_64 -no-frama-c-stdlib: (same output)
#   --- stock e-acsl-gcc on the same file
#   e-acsl-gcc -c: exit 1, frama-c run with: -machdep gcc_x86_64 -no-frama-c-stdlib
#   undefined reference to `__builtin_add_overflow'
#   e-acsl-gcc: fatal error: fail to compile/link instrumented code
#   e-acsl-gcc -c -G clang: exit 1
#   error: cannot redeclare builtin function '__builtin_add_overflow'
#   RESULT: bug present
set -u
src=34-kernel-gcc-overflow-builtins.c
und=34-kernel-gcc-overflow-builtins-implicit.c
tmp=${TMPDIR:-/tmp}/repro34.$$
mkdir -p "$tmp"

echo "--- Frama-C libc, -machdep gcc_x86_64, Eva value of the returned flag"
for c in "1 mul(int, int, long *):         " "2 add(int, long, long *):        " \
         "3 add(int, int, unsigned *):     " "4 add(uchar, uchar, uchar *):    " \
         "5 add_overflow_p(int, int, int): "; do
  n=${c%% *}
  g=$(gcc -w -DCASE="$n" -o "$tmp/a.out" "$src" && { "$tmp/a.out"; echo $?; })
  frama-c -no-unicode -machdep gcc_x86_64 -cpp-extra-args="-DCASE=$n" "$src" \
    -eva -eva-msg-key=-summary > "$tmp/eva.log" 2>&1
  e=$(sed -n 's/.*Frama_C_show_each_overflow: //p' "$tmp/eva.log")
  echo "case $c gcc $g, Eva ${e:-(parsing aborted)}"
  grep -A1 -e 'incompatible-types-call' -e 'User Error' -e 'implicit-function' \
    "$tmp/eva.log" | grep -v -e '^--$' -e 'Warning' -e 'User Error' | head -1
done

echo "--- no declaration in scope (x86_64; gcc_x86_64; gcc_x86_64 -no-frama-c-stdlib)"
prev=
for cfg in "x86_64" "gcc_x86_64" "gcc_x86_64 -no-frama-c-stdlib"; do
  out=$(
    frama-c -no-unicode -machdep $cfg "$und" -print -ocode "$tmp/p.c" 2>&1 \
      | grep -e 'Calling undeclared' -e 'expected' -e 'User Error'
    grep -e 'missing proto' -e '(int)a' "$tmp/p.c"
    gcc -w -o "$tmp/o.out" "$und" && { "$tmp/o.out"; echo "original, gcc: exit $?"; }
    if gcc -w -o "$tmp/p.out" "$tmp/p.c" > "$tmp/gcc.log" 2>&1
    then echo "printed, gcc: ok"
    else echo "printed, gcc: link FAILED: $(grep -o 'undefined reference.*' "$tmp/gcc.log" | head -1)"
    fi
    if command -v clang > /dev/null 2>&1; then
      if clang -w -c -o "$tmp/p.o" "$tmp/p.c" > "$tmp/clang.log" 2>&1
      then echo "printed, clang: ok"
      else echo "printed, clang: FAILED: $(grep -o 'error: .*' "$tmp/clang.log" | head -1)"
      fi
    fi
  )
  if [ "$out" = "$prev" ]; then echo "$cfg: (same output)"
  else echo "$cfg: frama-c -print:"; echo "$out"; fi
  prev=$out
  rm -f "$tmp/p.c" "$tmp/p.out" "$tmp/p.o"
done

if command -v e-acsl-gcc > /dev/null 2>&1; then
  echo "--- stock e-acsl-gcc on the same file"
  cp "$und" "$tmp/"
  here=$PWD; cd "$tmp" || exit 2
  e-acsl-gcc -c -O prog "$und" > eacsl.log 2>&1
  echo "e-acsl-gcc -c: exit $?, frama-c run with:" \
    $(grep -o -e '-machdep [a-z0-9_]*' -e '-no-frama-c-stdlib' eacsl.log | sort -u)
  grep -o 'undefined reference to .*' eacsl.log | head -1
  grep 'fatal error' eacsl.log | head -1
  e-acsl-gcc -c -G clang -O progc "$und" > eacsl2.log 2>&1
  echo "e-acsl-gcc -c -G clang: exit $?"
  grep -o 'error: cannot redeclare.*' eacsl2.log | head -1
  cd "$here" || exit 2
fi
rm -rf "$tmp"
echo "RESULT: bug present"
exit 1
