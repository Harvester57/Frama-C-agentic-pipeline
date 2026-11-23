#!/bin/sh
# Issue 84: [Kernel] Logic_utils.constFoldBinOpToInt crashes with Division_by_zero
# on loop unroll/unfold annotations containing integer division by zero (e.g. 1/0).
#
# Images: framac-master-audit:189053d (master 189053d4a2, before),
#         framac-analysis:latest (34.0~beta), and the master tree with
#         ../patches/84-kernel-logic-constfold-div-zero.patch built and installed (after).
# Command, from this directory:
#   docker run --rm -v "$PWD:/w" -w /w --entrypoint sh <image> \
#     84-kernel-logic-constfold-div-zero.sh
#
# Output before (master 189053d4a2; 34.0~beta prints the same with
# "34.0~beta (Selenium)"):
#   35.0~~dev (Bromine)
#   eva_unroll: exit 125 ([kernel] Unexpected error (Division_by_zero).)
#   ulevel_unfold: exit 125 ([kernel] Unexpected error (Division_by_zero).)
#   RESULT: bug present (2 of 2 cases fail)
#
# Output after (master 189053d4a2 + patches/84-kernel-logic-constfold-div-zero.patch):
#   35.0~~dev (Bromine)
#   eva_unroll: exit 0 (ok)
#   ulevel_unfold: exit 0 (ok)
#   RESULT: fixed
set -u
command -v frama-c >/dev/null 2>&1 || { echo "frama-c is not in PATH" >&2; exit 2; }
n=84-kernel-logic-constfold-div-zero
tmp=$(mktemp -d)
fail=0
total=0
frama-c -version

run_case() {
  total=$((total + 1))
  name=$1
  shift
  frama-c "$@" "$n.i" > "$tmp/$name.log" 2>&1
  rc=$?
  err=$(grep -E 'Unexpected error|Division_by_zero' "$tmp/$name.log" | head -n 1)
  if [ "$rc" = 0 ] && [ -z "$err" ]; then
    echo "$name: exit 0 (ok)"
  else
    echo "$name: exit $rc (${err:-failed})"
    fail=$((fail + 1))
  fi
}

run_case eva_unroll -eva
run_case ulevel_unfold -ulevel-force -print

rm -rf "$tmp"
if [ "$fail" = 0 ]; then
  echo "RESULT: fixed"
  exit 0
else
  echo "RESULT: bug present ($fail of $total cases fail)"
  exit 1
fi
