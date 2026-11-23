#!/bin/sh
# Issue 56: [Kernel] Cil.isExactFloat drops (float) casts on double-exact
# literals that are not exact as single-precision float (e.g. 16777217.0, 1e11).
#
# Images: framac-master-audit:189053d (master 189053d4a2, before),
#         framac-analysis:latest (34.0~beta, before), and master +
#         ../patches/56-kernel-float-cast-dropped-exact.patch (after).
# Command, from this directory:
#   docker run --rm -v "$PWD:/w" -w /w --entrypoint sh <image> \
#     56-kernel-float-cast-dropped-exact.sh
set -u
command -v frama-c >/dev/null 2>&1 || { echo "frama-c is not in PATH" >&2; exit 2; }
n=56-kernel-float-cast-dropped-exact
tmp=$(mktemp -d)
fail=0
total=0
frama-c -version

# 1. -print must preserve (float) on 16777217.0 while still simplifying exact 16777216.0
total=$((total + 1))
frama-c -print "$n.c" > "$tmp/print.log" 2>&1
if grep -q '(float)16777217.0' "$tmp/print.log" && grep -q 'exact_float: 16777216.0' "$tmp/print.log"; then
  echo "print_cast_kept: PASS"
else
  echo "print_cast_kept: FAIL ((float)16777217.0 was dropped)"
  fail=$((fail + 1))
fi

# 2. Eva must prove all 4 assertions valid and still report the division-by-zero alarm
total=$((total + 1))
frama-c -eva "$n.c" > "$tmp/eva.log" 2>&1
if grep -q 'Assertions[[:space:]]*4 valid[[:space:]]*0 unknown[[:space:]]*0 invalid' "$tmp/eva.log" \
   && grep -q '1 division by zero' "$tmp/eva.log"; then
  echo "eva_valid_and_alarm: PASS"
else
  echo "eva_valid_and_alarm: FAIL (true assertions invalid or div-by-zero alarm lost)"
  fail=$((fail + 1))
fi

# 3. WP Qed must prove inexact_float and NOT prove wrong_float
total=$((total + 1))
frama-c -wp -wp-prover none -wp-print "$n.c" > "$tmp/wp.log" 2>&1
if awk '/Goal Check Lemma .wrong_float./{f=1} f && /Prove: true\./{exit 1} f && /Prove: false\./{exit 0}' "$tmp/wp.log"; then
  echo "wp_wrong_float_not_proved: PASS"
else
  echo "wp_wrong_float_not_proved: FAIL (WP Qed proved false lemma wrong_float)"
  fail=$((fail + 1))
fi

rm -rf "$tmp"
if [ "$fail" = 0 ]; then echo "RESULT: fixed"; exit 0
else echo "RESULT: bug present ($fail of $total checks fail)"; exit 1
fi
