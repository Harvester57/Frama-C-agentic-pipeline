#!/bin/sh
# Issue 59: [Kernel] ACSL lexer splits hexadecimal escapes into byte pairs,
# crashes with Invalid_argument("Char.chr") on octal escapes above \377
# (including valid L'\777'), and fails to truncate L'...' to wchar_t.
#
# Images: framac-master-audit:189053d (master 189053d4a2, before),
#         framac-analysis:latest (34.0~beta, before), and master +
#         ../patches/59-kernel-acsl-hex-octal-escapes.patch (after).
# Command, from this directory:
#   docker run --rm -v "$PWD:/w" -w /w --entrypoint sh <image> \
#     59-kernel-acsl-hex-octal-escapes.sh
set -u
command -v frama-c >/dev/null 2>&1 || { echo "frama-c is not in PATH" >&2; exit 2; }
n=59-kernel-acsl-hex-octal-escapes
tmp=$(mktemp -d)
fail=0
total=0
frama-c -version

# 1. Valid C/ACSL escapes: '\x041', L'\x20AC', L'\777', L'ab', "\x041"
total=$((total + 1))
frama-c -eva "$n.c" > "$tmp/ok.log" 2>&1
rc=$?
if [ "$rc" = 0 ] && grep -q 'Assertions[[:space:]]*5 valid[[:space:]]*0 unknown[[:space:]]*0 invalid' "$tmp/ok.log"; then
  echo "valid_hex_oct_wide: PASS"
else
  echo "valid_hex_oct_wide: FAIL (exit $rc)"
  fail=$((fail + 1))
fi

# 2. Out-of-range narrow octal/hex escapes must produce exit 1 user error, not exit 4/125 Char.chr crash
for macro in CASE_OCT_CHAR CASE_OCT_STR CASE_HEX_STR; do
  total=$((total + 1))
  frama-c -cpp-extra-args="-D$macro" "$n.c" > "$tmp/$macro.log" 2>&1
  rc=$?
  if [ "$rc" = 1 ] && grep -q 'out of range' "$tmp/$macro.log" && ! grep -q 'Char\.chr' "$tmp/$macro.log"; then
    printf '%s\n' "$macro: PASS (clean out-of-range user error, exit 1)"
  else
    printf '%s\n' "$macro: FAIL (exit $rc, Char.chr crash or silently accepted)"
    fail=$((fail + 1))
  fi
done

rm -rf "$tmp"
if [ "$fail" = 0 ]; then echo "RESULT: fixed"; exit 0
else echo "RESULT: bug present ($fail of $total checks fail)"; exit 1
fi
