#!/bin/sh
# Issue 52: [E-ACSL] Gmp.Q.add_cast converts rationals to double/float with
# __gmpq_get_d (which truncates toward zero) instead of IEEE 754
# round-to-nearest-even, and casts double->float with double rounding.
# True assertions abort and false assertions pass silently.
#
# Images: framac-master-audit:189053d (master 189053d4a2, before),
#         framac-analysis:latest (34.0~beta), and the master tree with
#         ../patches/52-eacsl-rational-cast-double-rounding.patch built
#         and installed (after).
# Command, from this directory:
#   docker run --rm -v "$PWD:/w" -w /w --entrypoint sh <image> \
#     52-eacsl-rational-cast-double-rounding.sh
#
# Output before (master 189053d4a2 and 34.0~beta, exit 1):
#   35.0~~dev (Bromine)  [or: 34.0~beta (Selenium)]
#   double_true: built, run exit 134
#   double_false_eq: built, run exit 0
#   double_false_lt: built, run exit 0
#   double_neg: built, run exit 134
#   double_tie: built, run exit 134
#   float_dr: built (double-rounding warning), run exit 134
#   subnormal: built (double-rounding warning), run exit 134
#   RESULT: bug present (7 of 7 cases fail)
#
# Output after (patched master, exit 0):
#   35.0~~dev (Bromine)
#   double_true: built, run exit 0
#   double_false_eq: built, run exit 134
#   double_false_lt: built, run exit 134
#   double_neg: built, run exit 0
#   double_tie: built, run exit 0
#   float_dr: built, run exit 0
#   subnormal: built, run exit 0
#   RESULT: fixed
set -u
command -v frama-c >/dev/null 2>&1 || { echo "frama-c is not in PATH" >&2; exit 2; }
EG=$(command -v e-acsl-gcc || command -v e-acsl-gcc.sh) || { echo "e-acsl-gcc is not in PATH" >&2; exit 2; }
n=52-eacsl-rational-cast-double-rounding
tmp=$(mktemp -d)
fail=0
total=0
frama-c -version
run() { # $1: case, $2: expected line once fixed
  total=$((total + 1))
  c=$1
  expect=$2
  if "$EG" -q -c -E "-DCASE_$c" -e "-DCASE_$c" -o "$tmp/$c.c" -O "$tmp/$c" "$n.c" > "$tmp/build.log" 2>&1; then
    warn=""
    grep -q 'double rounding might cause unsoundness' "$tmp/build.log" && warn=" (double-rounding warning)"
    prlimit --core=1:1 "$tmp/$c.e-acsl" > "$tmp/run.log" 2>&1
    rc=$?
    got="built${warn}, run exit $rc"
  else
    got="build failed (exit $?)"
  fi
  echo "$c: $got"
  [ "$got" = "$expect" ] || fail=$((fail + 1))
}
run double_true 'built, run exit 0'
run double_false_eq 'built, run exit 134'
run double_false_lt 'built, run exit 134'
run double_neg 'built, run exit 0'
run double_tie 'built, run exit 0'
run float_dr 'built, run exit 0'
run subnormal 'built, run exit 0'
rm -rf "$tmp"
if [ "$fail" = 0 ]; then echo "RESULT: fixed"; exit 0
else echo "RESULT: bug present ($fail of $total cases fail)"; exit 1
fi
