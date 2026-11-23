#!/bin/sh
# Issue 55: [Eva] numerors domain uses a decimal-only parser (Rational.of_string)
# and passes non-finite CReal strings directly to Scalar.of_string
# (IEEE754.Make.constant): loses a sure out-of-bounds alarm on DBL_MAX,
# miscomputes 0x1.8p1, and crashes on 0x1.ep0, FLT_MAX, 1.5d, and INFINITY.
#
# Images: framac-master-audit:189053d (master 189053d4a2, before),
#         framac-analysis:latest (34.0~beta), and the master tree with
#         ../patches/55-eva-numerors-float-literal-parsing.patch built
#         and installed (after).
# Command, from this directory:
#   docker run --rm -v "$PWD:/w" -w /w --entrypoint sh <image> \
#     55-eva-numerors-float-literal-parsing.sh
#
# Output before (master 189053d4a2 and 34.0~beta, exit 1):
#   35.0~~dev (Bromine)  [or: 34.0~beta (Selenium)]
#   dbl_max_alarm: exit 0: 0 alarms generated
#   hex_val: exit 0: Real     : [0.048 .. 0.096]
#   hex_e: crash exit 125: Unexpected error (Failure("int_of_string")).
#   flt_max: crash exit 125: Unexpected error (Failure("int_of_string")).
#   suffix_d: crash exit 125: Unexpected error (Invalid_argument("Z.of_substring_base: invalid digit")).
#   infinity: crash exit 125: Unexpected error (Invalid_argument("Z.of_substring_base: invalid digit")).
#   RESULT: bug present (6 of 6 cases fail)
#
# Output after (patched master, exit 0):
#   35.0~~dev (Bromine)
#   dbl_max_alarm: exit 0: 1 alarm generated
#   hex_val: exit 0: Real     : [3. .. 6.]
#   hex_e: exit 0: Real     : [1.875 .. 1.875]
#   flt_max: exit 0: 0 alarms generated
#   suffix_d: exit 0: Real     : [1.5 .. 1.5]
#   infinity: exit 0: 1 alarm generated
#   RESULT: fixed
set -u
command -v frama-c >/dev/null 2>&1 || { echo "frama-c is not in PATH" >&2; exit 2; }
n=55-eva-numerors-float-literal-parsing
tmp=$(mktemp -d)
fail=0
total=0
frama-c -version
run() { # $1: case, $2: check pattern, $3: expected line once fixed
  total=$((total + 1))
  c=$1
  pat=$2
  expect=$3
  frama-c -machdep gcc_x86_64 -cpp-extra-args="-DCASE_$c" \
    -eva -eva-domains numerors -eva-msg-key=d-numerors "$n.c" > "$tmp/$c.log" 2>&1
  rc=$?
  if [ "$rc" = 0 ]; then
    hit=$(grep -oE "$pat" "$tmp/$c.log" | head -n 1)
    got="exit 0: ${hit:-no match}"
  else
    err=$(grep -oE 'Unexpected error \(.*\)\.' "$tmp/$c.log" | head -n 1)
    got="crash exit $rc: ${err:-unknown}"
  fi
  echo "$c: $got"
  [ "$got" = "$expect" ] || fail=$((fail + 1))
}
run dbl_max_alarm '1 alarm generated|0 alarms generated' 'exit 0: 1 alarm generated'
run hex_val 'Real[ ]*: \[[^]]+\]' 'exit 0: Real     : [3. .. 6.]'
run hex_e 'Real[ ]*: \[[^]]+\]' 'exit 0: Real     : [1.875 .. 1.875]'
run flt_max '0 alarms generated' 'exit 0: 0 alarms generated'
run suffix_d 'Real[ ]*: \[[^]]+\]' 'exit 0: Real     : [1.5 .. 1.5]'
run infinity '1 alarm generated' 'exit 0: 1 alarm generated'
rm -rf "$tmp"
if [ "$fail" = 0 ]; then echo "RESULT: fixed"; exit 0
else echo "RESULT: bug present ($fail of $total cases fail)"; exit 1
fi
