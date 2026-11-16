#!/bin/sh
# Issue 18: when main takes argc and argv, the E-ACSL runtime initialization
# moves the global `environ` to its terminating NULL entry: getenv returns
# NULL for every variable. Segment (default) and bittree memory models.
#
# Images: framac-master-audit:3dff90f (35.0~~dev, master 3dff90fc70) and
# framac-analysis:fc34 (34.0~beta). From the repro directory:
#   docker run --rm -v "$PWD:/w" -w /w --entrypoint sh <image> \
#     18-eacsl-memory-init-clobbers-environ.sh
#
# Output on master 3dff90fc70 (34.0~beta prints the same after its version
# line):
#   35.0~~dev (Bromine)
#   == memory model: segment
#   e-acsl-gcc exit code: 0
#   argc=1 EACSL_REPRO_VAR=hello
#   prog (not instrumented) exit code: 0
#   argc=1 EACSL_REPRO_VAR=(null)
#   prog.e-acsl exit code: 1
#   == memory model: bittree
#   e-acsl-gcc exit code: 0
#   argc=1 EACSL_REPRO_VAR=hello
#   prog (not instrumented) exit code: 0
#   argc=1 EACSL_REPRO_VAR=(null)
#   prog.e-acsl exit code: 1
#
# Output with the proposed fix: both models print EACSL_REPRO_VAR=hello and
# "prog.e-acsl exit code: 0".
set -u
out=$(mktemp -d)
cp 18-eacsl-memory-init-clobbers-environ.c "$out/"
cd "$out" || exit 1
frama-c -version
for m in segment bittree; do
  echo "== memory model: $m"
  e-acsl-gcc -c -m "$m" -O prog 18-eacsl-memory-init-clobbers-environ.c \
    > build.log 2>&1
  echo "e-acsl-gcc exit code: $?"
  EACSL_REPRO_VAR=hello ./prog
  echo "prog (not instrumented) exit code: $?"
  EACSL_REPRO_VAR=hello ./prog.e-acsl
  echo "prog.e-acsl exit code: $?"
  rm -f prog prog.e-acsl
done
