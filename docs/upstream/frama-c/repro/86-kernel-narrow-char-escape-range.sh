#!/bin/sh
# Issue 86: [Kernel] Narrow character constants with out-of-range octal/hex escapes
# ('\777', '\x1ff', 'a\x100') are silently accepted as 511UL/256UL instead of being
# rejected like out-of-range narrow string escapes (C11 6.4.4.4p9).
#
# Images: framac-master-audit:189053d (master 189053d4a2, before),
#         framac-analysis:latest (34.0~beta), and the master tree with
#         ../patches/86-kernel-narrow-char-escape-range.patch built and installed (after).
# Command, from this directory:
#   docker run --rm -v "$PWD:/w" -w /w --entrypoint sh <image> \
#     86-kernel-narrow-char-escape-range.sh
#
# Output before (master 189053d4a2; 34.0~beta prints the same with
# "34.0~beta (Selenium)"):
#   35.0~~dev (Bromine)
#   oct: exit 0 (int c = 511;)
#   hex: exit 0 (int c = 511;)
#   multi: exit 0 (int c = 25088;)
#   valid: accepted exit 0
#   RESULT: bug present (3 of 4 cases fail)
#
# Output after (master 189053d4a2 + patches/86-kernel-narrow-char-escape-range.patch):
#   35.0~~dev (Bromine)
#   oct: rejected exit 1 (  integral literal 0x1ff too big:)
#   hex: rejected exit 1 (  integral literal 0x1ff too big:)
#   multi: rejected exit 1 (  integral literal 0x100 too big:)
#   valid: accepted exit 0
#   RESULT: fixed
set -u
command -v frama-c >/dev/null 2>&1 || { echo "frama-c is not in PATH" >&2; exit 2; }
n=86-kernel-narrow-char-escape-range
tmp=$(mktemp -d)
fail=0
total=0
frama-c -version

run_reject() {
  total=$((total + 1))
  c=$1
  frama-c -no-autoload-plugins -cpp-extra-args="-DCASE_$c" -print "$n.c" > "$tmp/$c.log" 2>&1
  rc=$?
  err=$(grep -E 'integral literal .* too big' "$tmp/$c.log" | head -n 1)
  if [ "$rc" = 1 ] && [ -n "$err" ]; then
    echo "$c: rejected exit 1 ($err)"
  else
    val=$(grep -E 'int c =' "$tmp/$c.log" | head -n 1)
    echo "$c: exit $rc (${val:-unexpected})"
    fail=$((fail + 1))
  fi
}

run_accept() {
  total=$((total + 1))
  c=$1
  frama-c -no-autoload-plugins -cpp-extra-args="-DCASE_$c" -print "$n.c" > "$tmp/$c.log" 2>&1
  rc=$?
  if [ "$rc" = 0 ]; then
    echo "$c: accepted exit 0"
  else
    echo "$c: unexpected exit $rc"
    fail=$((fail + 1))
  fi
}

run_reject oct
run_reject hex
run_reject multi
run_accept valid

rm -rf "$tmp"
if [ "$fail" = 0 ]; then
  echo "RESULT: fixed"
  exit 0
else
  echo "RESULT: bug present ($fail of $total cases fail)"
  exit 1
fi
