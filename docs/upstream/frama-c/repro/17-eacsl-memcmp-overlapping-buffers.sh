#!/bin/sh
# Issue 17: with --libc-replacements, memcmp on identical or overlapping ranges
# aborts with "memcpy: overlapping memory areas".
#
# Images: framac-master-audit:3dff90f (35.0~~dev, master 3dff90fc70) and
# framac-analysis:fc34 (34.0~beta). From the repro directory:
#   docker run --rm -v "$PWD:/w" -w /w --entrypoint sh <image> \
#     17-eacsl-memcmp-overlapping-buffers.sh
#
# Output on master 3dff90fc70 (34.0~beta prints the same after its version
# line; the shell's "Aborted (core dumped)" line is left out):
#   35.0~~dev (Bromine)
#   e-acsl-gcc exit code: 0
#   prog (not instrumented) exit code: 0
#   memcpy: overlapping memory areas
#   prog.e-acsl exit code: 134
#
# Output with the proposed fix:
#   35.0~~dev (Bromine)
#   e-acsl-gcc exit code: 0
#   prog (not instrumented) exit code: 0
#   prog.e-acsl exit code: 0
set -u
out=$(mktemp -d)
cp 17-eacsl-memcmp-overlapping-buffers.c "$out/"
cd "$out" || exit 1
frama-c -version
e-acsl-gcc --libc-replacements -c -O prog 17-eacsl-memcmp-overlapping-buffers.c \
  > build.log 2>&1
echo "e-acsl-gcc exit code: $?"
./prog
echo "prog (not instrumented) exit code: $?"
./prog.e-acsl
echo "prog.e-acsl exit code: $?"
