#!/bin/sh
# Issue 60: [Kernel] ACSL wide-string wcharlist_of_string accepts 8 and 9 as
# octal digits (L"\18" -> [16] instead of [1, '8']) and omits \v.
#
# Images: framac-master-audit:189053d (master 189053d4a2, before),
#         framac-analysis:latest (34.0~beta, before), and master +
#         ../patches/60-kernel-acsl-wstring-octal-escapes.patch (after).
# Command, from this directory:
#   docker run --rm -v "$PWD:/w" -w /w --entrypoint sh <image> \
#     60-kernel-acsl-wstring-octal-escapes.sh
set -u
command -v frama-c >/dev/null 2>&1 || { echo "frama-c is not in PATH" >&2; exit 2; }
n=60-kernel-acsl-wstring-octal-escapes
tmp=$(mktemp -d)
fail=0
total=0
frama-c -version

frama-c -print "$n.c" > "$tmp/print.log" 2>&1

# 1. L"\18" must not collapse to L"\\020" (16); must keep '8' as second element
total=$((total + 1))
if grep -q 'L"\\\\001" "8"' "$tmp/print.log"; then
  printf '%s\n' 'wstring_oct_18: PASS'
else
  printf '%s\n' 'wstring_oct_18: FAIL (L"\18" parsed 8 as octal digit)'
  fail=$((fail + 1))
fi

# 2. L"\79" must keep '9' as second element
total=$((total + 1))
if grep -q 'L"\\\\a" "9"' "$tmp/print.log"; then
  printf '%s\n' 'wstring_oct_79: PASS'
else
  printf '%s\n' 'wstring_oct_79: FAIL (L"\79" parsed 9 as octal digit)'
  fail=$((fail + 1))
fi

# 3. L"\v" must be parsed as vertical tab (11) with no ill-formed escape warning
total=$((total + 1))
if grep -q 'L"\\\\v"' "$tmp/print.log" && ! grep -q 'Ill-formed escape sequence' "$tmp/print.log"; then
  printf '%s\n' 'wstring_esc_v: PASS'
else
  printf '%s\n' 'wstring_esc_v: FAIL (L"\v" rejected as ill-formed escape)'
  fail=$((fail + 1))
fi

rm -rf "$tmp"
if [ "$fail" = 0 ]; then echo "RESULT: fixed"; exit 0
else echo "RESULT: bug present ($fail of $total checks fail)"; exit 1
fi
