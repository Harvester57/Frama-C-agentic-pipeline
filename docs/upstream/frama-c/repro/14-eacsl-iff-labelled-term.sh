#!/bin/sh
# Issue 14: E-ACSL aborts with "labels pre-analysis was not performed" on a
# <==> whose operands contain a labelled term (\old, \at, or a formal in a
# postcondition).
#
# Images: framac-master-audit:3dff90f (35.0~~dev, master 3dff90fc70) and
# framac-analysis:fc34 (34.0~beta). From the repro directory:
#   docker run --rm -v "$PWD:/w" -w /w --entrypoint sh <image> \
#     14-eacsl-iff-labelled-term.sh
#
# Output on master 3dff90fc70 (34.0~beta prints the same after its version
# line):
#   35.0~~dev (Bromine)
#   == 14-eacsl-iff-labelled-term.c
#   e-acsl-gcc exit code: 1
#   [e-acsl] Failure: labels pre-analysis was not performed on construct \old(b)
#   == 14-eacsl-iff-labelled-term-at.c
#   e-acsl-gcc exit code: 1
#   [e-acsl] Failure: labels pre-analysis was not performed on construct \at(b->n,Pre)
#
# Output with the proposed fix:
#   35.0~~dev (Bromine)
#   == 14-eacsl-iff-labelled-term.c
#   e-acsl-gcc exit code: 0
#   prog.e-acsl exit code: 0
#   == 14-eacsl-iff-labelled-term-at.c
#   e-acsl-gcc exit code: 0
#   prog.e-acsl exit code: 0
set -u
out=$(mktemp -d)
cp 14-eacsl-iff-labelled-term.c 14-eacsl-iff-labelled-term-at.c "$out/"
cd "$out" || exit 1
frama-c -version
for f in 14-eacsl-iff-labelled-term 14-eacsl-iff-labelled-term-at; do
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
