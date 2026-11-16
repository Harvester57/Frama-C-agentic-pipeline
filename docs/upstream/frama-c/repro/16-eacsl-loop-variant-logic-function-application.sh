#!/bin/sh
# Issue 16: a loop variant that is one application of a memory-reading logic
# function, or such an application bound by \let, aborts E-ACSL with
# "typing was not performed on construct len3(s)".
#
# Images: framac-master-audit:3dff90f (35.0~~dev, master 3dff90fc70) and
# framac-analysis:fc34 (34.0~beta). From the repro directory:
#   docker run --rm -v "$PWD:/w" -w /w --entrypoint sh <image> \
#     16-eacsl-loop-variant-logic-function-application.sh
#
# Output on master 3dff90fc70 (34.0~beta prints the same after its version
# line):
#   35.0~~dev (Bromine)
#   == 16-eacsl-loop-variant-logic-function-application.c
#   e-acsl-gcc exit code: 1
#   [e-acsl] Failure: typing was not performed on construct len3(s)
#   == 16-eacsl-loop-variant-logic-function-application-let.c
#   e-acsl-gcc exit code: 1
#   [e-acsl] Failure: typing was not performed on construct len3(s)
#
# Output with the proposed fix:
#   35.0~~dev (Bromine)
#   == 16-eacsl-loop-variant-logic-function-application.c
#   e-acsl-gcc exit code: 0
#   prog.e-acsl exit code: 0
#   == 16-eacsl-loop-variant-logic-function-application-let.c
#   e-acsl-gcc exit code: 0
#   prog.e-acsl exit code: 0
set -u
out=$(mktemp -d)
cp 16-eacsl-loop-variant-logic-function-application.c \
  16-eacsl-loop-variant-logic-function-application-let.c "$out/"
cd "$out" || exit 1
frama-c -version
for f in 16-eacsl-loop-variant-logic-function-application \
         16-eacsl-loop-variant-logic-function-application-let; do
  echo "== $f.c"
  e-acsl-gcc -c -O prog "$f.c" > build.log 2>&1
  echo "e-acsl-gcc exit code: $?"
  grep -E '^\[e-acsl\] Failure' build.log
  if [ -x prog.e-acsl ]; then
    ./prog.e-acsl
    echo "prog.e-acsl exit code: $?"
  fi
  rm -f prog prog.e-acsl
done
