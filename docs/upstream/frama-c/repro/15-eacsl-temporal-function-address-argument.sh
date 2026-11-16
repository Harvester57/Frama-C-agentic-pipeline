#!/bin/sh
# Issue 15: with temporal analysis (--temporal), an instrumented callee pulls
# temporal metadata for a tracked pointer formal that the caller did not save,
# and the program aborts with "Unreachable": a function address passed with
# full memory tracking (-M), or a constant passed to a formal that an
# annotation makes E-ACSL track.
#
# Images: framac-master-audit:3dff90f (35.0~~dev, master 3dff90fc70) and
# framac-analysis:fc34 (34.0~beta). From the repro directory:
#   docker run --rm -v "$PWD:/w" -w /w --entrypoint sh <image> \
#     15-eacsl-temporal-function-address-argument.sh
#
# Output on master 3dff90fc70 (34.0~beta prints the same after its version
# line; the shell's "Aborted (core dumped)" lines are left out):
#   35.0~~dev (Bromine)
#   == e-acsl-gcc --temporal 15-eacsl-temporal-function-address-argument.c
#   e-acsl-gcc exit code: 0
#   prog.e-acsl exit code: 0
#   == e-acsl-gcc --temporal -M 15-eacsl-temporal-function-address-argument.c
#   e-acsl-gcc exit code: 0
#   Unreachable
#   prog.e-acsl exit code: 134
#   == e-acsl-gcc --temporal 15-eacsl-temporal-function-address-argument-null.c
#   e-acsl-gcc exit code: 0
#   Unreachable
#   prog.e-acsl exit code: 134
#   == temporal calls in the instrumented code (-M):
#   __e_acsl_temporal_pull_parameter((void *)(& f),0U,8UL);
#   __e_acsl_temporal_pull_parameter((void *)(& v),1U,8UL);
#   __e_acsl_temporal_save_nblock_parameter((void *)(& v),1U);
#   tmp = apply(& cb,& v);
set -u
out=$(mktemp -d)
cp 15-eacsl-temporal-function-address-argument.c \
  15-eacsl-temporal-function-address-argument-null.c "$out/"
cd "$out" || exit 1
frama-c -version
run() {
  echo "== e-acsl-gcc --temporal $*"
  e-acsl-gcc -c --temporal -O prog "$@" > build.log 2>&1
  echo "e-acsl-gcc exit code: $?"
  ./prog.e-acsl
  echo "prog.e-acsl exit code: $?"
  rm -f prog prog.e-acsl
}
run 15-eacsl-temporal-function-address-argument.c
run -M 15-eacsl-temporal-function-address-argument.c
run 15-eacsl-temporal-function-address-argument-null.c
e-acsl-gcc --temporal -M -n -o instrumented.c \
  15-eacsl-temporal-function-address-argument.c > build.log 2>&1
echo "== temporal calls in the instrumented code (-M):"
grep -E '^ *(__e_acsl_temporal_(pull|save)_[a-z_]*parameter|tmp = apply)' \
  instrumented.c | sed -e 's/^ *//'
