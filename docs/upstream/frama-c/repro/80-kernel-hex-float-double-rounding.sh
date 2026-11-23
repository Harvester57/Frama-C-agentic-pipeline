#!/bin/sh
# Issue 80: [Kernel] Hexadecimal floating-point literals with f/f32 suffix suffer
# double rounding through double precision in Typed_float.parse_hexadecimal.
#
# Images: framac-master-audit:189053d (master 189053d4a2, before),
#         framac-analysis:latest (34.0~beta), and the master tree with
#         ../patches/80-kernel-hex-float-double-rounding.patch built and installed (after).
# Command, from this directory:
#   docker run --rm -v "$PWD:/w" -w /w --entrypoint sh <image> \
#     80-kernel-hex-float-double-rounding.sh
#
# Output before (master 189053d4a2; 34.0~beta prints the same with
# "34.0~beta (Selenium)"):
#   35.0~~dev (Bromine)
#   eva exit: 0
#     Floating-point constant 0x1.0000010000000001p0f is not represented exactly. Will use 0x1.0000000000000p0.
#     check got status invalid.
#     check got status invalid.
#     check got status invalid.
#       Assertions        2 valid     0 unknown     3 invalid      5 total
#   summary:     Assertions        2 valid     0 unknown     3 invalid      5 total (invalid_lines=3)
#   RESULT: bug present
#
# Output after (master 189053d4a2 + patches/80-kernel-hex-float-double-rounding.patch):
#   35.0~~dev (Bromine)
#   eva exit: 0
#     Floating-point constant 0x1.0000010000000001p0f is not represented exactly. Will use 0x1.0000020000000p0.
#       Assertions        5 valid     0 unknown     0 invalid      5 total
#   summary:     Assertions        5 valid     0 unknown     0 invalid      5 total (invalid_lines=0)
#   RESULT: fixed
set -u
command -v frama-c >/dev/null 2>&1 || { echo "frama-c is not in PATH" >&2; exit 2; }
n=80-kernel-hex-float-double-rounding
tmp=$(mktemp -d)
fail=0
frama-c -version

frama-c -eva "$n.c" > "$tmp/eva.log" 2>&1
rc=$?
echo "eva exit: $rc"
grep -E 'Will use|check got status|Assertions' "$tmp/eva.log" | head -n 30

summary=$(grep -E 'Assertions[[:space:]]+[0-9]+ valid' "$tmp/eva.log" | head -n 1)
invalid_count=$(grep -c 'check got status invalid' "$tmp/eva.log")
echo "summary: ${summary:-none} (invalid_lines=$invalid_count)"
if [ "$rc" != 0 ] || [ "$invalid_count" != 0 ] || ! echo "$summary" | grep -qE 'Assertions[[:space:]]+5 valid[[:space:]]+0 unknown[[:space:]]+0 invalid[[:space:]]+5 total'; then
  fail=1
fi

rm -rf "$tmp"
if [ "$fail" = 0 ]; then
  echo "RESULT: fixed"
  exit 0
else
  echo "RESULT: bug present"
  exit 1
fi
