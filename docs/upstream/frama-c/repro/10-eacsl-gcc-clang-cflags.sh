#!/bin/sh
# e-acsl-gcc -G clang overwrites CFLAGS instead of appending to it: -std=c99,
# -m64, -g/-O, -fno-builtin and the warning settings are all dropped.
#
# Image: framac-master-audit:3dff90f (master 3dff90fc70), framac-analysis:fc34 (34.0~beta).
# Run from the repro directory:
#   docker run --rm -v "$PWD:/w" -w /w --entrypoint sh <image> 10-eacsl-gcc-clang-cflags.sh
#
# Both images ship clang 19.1.7. Output on master 3dff90fc70 (same on
# 34.0~beta); the gcc part is unchanged by the fix:
#   == e-acsl-gcc -D -M -G gcc (--rt-debug: should add -g3 -O0 -fno-omit-frame-pointer)
#   exit=0
#   compile command of the un-instrumented program:
#   + /usr/bin/gcc -std=c99 -m64 -g3 -O0 -fno-omit-frame-pointer -fno-builtin -fno-merge-constants -Wall -Wno-long-long -Wno-attributes -Wno-nonnull -Wno-undef -Wno-unused -Wno-unused-function -Wno-unused-result -Wno-unused-value -Wno-unused-function -Wno-unused-variable -Wno-unused-but-set-variable -Wno-implicit-function-declaration -Wno-empty-body 10-eacsl-gcc-clang-cflags.c -o bw -no-pie
#   warnings: 1
#   bw.e-acsl exit=134 (Use of invalid address 0x1000 in unsafe_initialize)
#   backtrace frames: 7; frames in the program:
#   write_ptr at bw.c:216
#   main at bw.c:227
#   == e-acsl-gcc -D -M -G clang (--rt-debug: should add -g3 -O0 -fno-omit-frame-pointer)
#   exit=0
#   compile command of the un-instrumented program:
#   + /usr/bin/clang -Wno-unknown-warning-option -Wno-extra-semi -Wno-tautological-compare -Wno-gnu-empty-struct -Wno-incompatible-pointer-types-discards-qualifiers 10-eacsl-gcc-clang-cflags.c -o bw -no-pie
#   warnings: 172
#   bw.e-acsl exit=134 (Use of invalid address 0x1000 in unsafe_initialize)
#   backtrace frames: 0; frames in the program:
#
# Output of the clang part with the fix (on top of the _DEFAULT_SOURCE fix,
# which is why -D_DEFAULT_SOURCE also appears):
#   == e-acsl-gcc -D -M -G clang (--rt-debug: should add -g3 -O0 -fno-omit-frame-pointer)
#   exit=0
#   compile command of the un-instrumented program:
#   + /usr/bin/clang -std=c99 -D_DEFAULT_SOURCE -m64 -g3 -O0 -fno-omit-frame-pointer -fno-builtin -fno-merge-constants -Wall -Wno-long-long -Wno-attributes -Wno-nonnull -Wno-undef -Wno-unused -Wno-unused-function -Wno-unused-result -Wno-unused-value -Wno-unused-function -Wno-unused-variable -Wno-unused-but-set-variable -Wno-implicit-function-declaration -Wno-empty-body -Wno-unknown-warning-option -Wno-extra-semi -Wno-tautological-compare -Wno-gnu-empty-struct -Wno-incompatible-pointer-types-discards-qualifiers 10-eacsl-gcc-clang-cflags.c -o bw -no-pie
#   warnings: 8
#   bw.e-acsl exit=134 (Use of invalid address 0x1000 in unsafe_initialize)
#   backtrace frames: 7; frames in the program:
#   write_ptr at bw.c:216
#   main at bw.c:227

N=10-eacsl-gcc-clang-cflags
T=$(mktemp -d)
cp "$N.c" "$T/"
cd "$T" || exit 1

for cc in gcc clang; do
  echo "== e-acsl-gcc -D -M -G $cc (--rt-debug: should add -g3 -O0 -fno-omit-frame-pointer)"
  e-acsl-gcc -D -M -G $cc -o bw.c -O bw "$N.c" > bw.log 2>&1
  echo "exit=$?"
  echo "compile command of the un-instrumented program:"
  grep -- "-o bw " bw.log | sed -e 's/  */ /g'
  echo "warnings: $(grep -c 'warning:' bw.log)"
  ./bw.e-acsl > run.log 2>&1
  echo "bw.e-acsl exit=$? ($(grep -o 'Use of invalid address.*' run.log | sed -e 's/:.*//'))"
  echo "backtrace frames: $(grep -c ' at ' run.log); frames in the program:"
  grep ' at ' run.log | grep -E 'write_ptr|main' | sed -e 's/^ *- //'
  rm -f bw bw.e-acsl bw.c run.log
done

rm -rf "$T"
