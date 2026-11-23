#!/bin/sh
# Issue 62: [Kernel] Cil.interpret_character_constant types multi-character
# constants as unsigned long / unsigned long long instead of int (ISO C11
# 6.4.4.4p10).
#
# Images: framac-master-audit:189053d (master 189053d4a2, before),
#         framac-analysis:latest (34.0~beta, before), and master +
#         ../patches/62-kernel-multichar-const-type.patch (after).
# Command, from this directory:
#   docker run --rm -v "$PWD:/w" -w /w --entrypoint sh <image> \
#     62-kernel-multichar-const-type.sh
set -u
command -v frama-c >/dev/null 2>&1 || { echo "frama-c is not in PATH" >&2; exit 2; }
n=62-kernel-multichar-const-type
tmp=$(mktemp -d)
fail=0
total=0
frama-c -version

# 1. -print must emit signed int constants (no 24930UL / 4294967295ULL)
total=$((total + 1))
frama-c -print "$n.c" > "$tmp/print.log" 2>&1
if ! grep -q '24930UL' "$tmp/print.log" && ! grep -q '4294967295ULL' "$tmp/print.log" && grep -q 'gen = 1;' "$tmp/print.log"; then
  echo "print_int_type: PASS"
else
  echo "print_int_type: FAIL (emitted UL/ULL or _Generic picked unsigned long)"
  fail=$((fail + 1))
fi

# 2. Eva must validate all 6 checks
total=$((total + 1))
frama-c -eva "$n.c" > "$tmp/eva.log" 2>&1
if grep -q 'Assertions[[:space:]]*6 valid[[:space:]]*0 unknown[[:space:]]*0 invalid' "$tmp/eva.log"; then
  echo "eva_multichar_valid: PASS"
else
  echo "eva_multichar_valid: FAIL (Eva marks multi-char checks invalid)"
  fail=$((fail + 1))
fi

rm -rf "$tmp"
if [ "$fail" = 0 ]; then echo "RESULT: fixed"; exit 0
else echo "RESULT: bug present ($fail of $total checks fail)"; exit 1
fi
