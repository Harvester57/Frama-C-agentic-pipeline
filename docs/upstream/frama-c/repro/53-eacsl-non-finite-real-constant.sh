#!/bin/sh
# Issue 53: [E-ACSL] Non-finite suffixed floating-point constants (1e40f,
# 1e400d, 0x1p2000d) have r_lower = r_upper = infinity; E-ACSL emits
# CReal(infinity, FDouble, None), failing compilation ('inf' undeclared)
# and passing infinity to __gmpq_set_d (SIGFPE at run time).
#
# Images: framac-master-audit:189053d (master 189053d4a2, before),
#         framac-analysis:latest (34.0~beta), and the master tree with
#         ../patches/53-eacsl-non-finite-real-constant.patch built
#         and installed (after).
# Command, from this directory:
#   docker run --rm -v "$PWD:/w" -w /w --entrypoint sh <image> \
#     53-eacsl-non-finite-real-constant.sh
#
# Output before (master 189053d4a2 and 34.0~beta, exit 1):
#   35.0~~dev (Bromine)  [or: 34.0~beta (Selenium)]
#   float_ovf: build stops: inf' undeclared
#   double_ovf: build stops: inf' undeclared
#   hex_ovf: build stops: inf' undeclared
#   gmp_ovf: build stops: inf' undeclared
#   float_ovf_hexprint: build stops: inf' undeclared
#   RESULT: bug present (5 of 5 cases fail)
#
# Output after (patched master, exit 0):
#   35.0~~dev (Bromine)
#   float_ovf: built (ignored: non-finite), run exit 0
#   double_ovf: built (ignored: non-finite), run exit 0
#   hex_ovf: built (ignored: non-finite), run exit 0
#   gmp_ovf: built (ignored: non-finite), run exit 0
#   float_ovf_hexprint: built (ignored: non-finite), run exit 0
#   RESULT: fixed
set -u
command -v frama-c >/dev/null 2>&1 || { echo "frama-c is not in PATH" >&2; exit 2; }
EG=$(command -v e-acsl-gcc || command -v e-acsl-gcc.sh) || { echo "e-acsl-gcc is not in PATH" >&2; exit 2; }
n=53-eacsl-non-finite-real-constant
tmp=$(mktemp -d)
fail=0
total=0
frama-c -version
run() { # $1: case, $2: expected line once fixed, $3: extra e-acsl-gcc flags
  total=$((total + 1))
  c=$1
  expect=$2
  extra=${3:-}
  if "$EG" -q -c $extra -E "-DCASE_$c" -e "-DCASE_$c" -o "$tmp/$c.c" -O "$tmp/$c" "$n.c" > "$tmp/build.log" 2>&1; then
    note=""
    grep -q "non-finite floating-point constant.*not yet supported" "$tmp/build.log" \
      && note=" (ignored: non-finite)"
    prlimit --core=1:1 "$tmp/$c.e-acsl" > "$tmp/run.log" 2>&1
    got="built${note}, run exit $?"
  else
    err=$(grep -oE "inf.*undeclared|fail to compile/link instrumented code" "$tmp/build.log" | head -n 1)
    got="build stops: ${err:-exit $?}"
  fi
  echo "$c: $got"
  [ "$got" = "$expect" ] || fail=$((fail + 1))
}
run float_ovf 'built (ignored: non-finite), run exit 0'
run double_ovf 'built (ignored: non-finite), run exit 0'
run hex_ovf 'built (ignored: non-finite), run exit 0'
run gmp_ovf 'built (ignored: non-finite), run exit 0'
run float_ovf_hexprint 'built (ignored: non-finite), run exit 0' '-F -float-print -F hex'
rm -rf "$tmp"
if [ "$fail" = 0 ]; then echo "RESULT: fixed"; exit 0
else echo "RESULT: bug present ($fail of $total cases fail)"; exit 1
fi
