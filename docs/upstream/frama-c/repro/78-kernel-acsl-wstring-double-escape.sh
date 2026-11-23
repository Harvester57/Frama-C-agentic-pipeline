#!/bin/sh
# Issue 78: [Kernel] ACSL wide-string printer (LWStr) escapes characters twice
# via %S and prints empty L"" as invalid bare identifier L.
#
# Images: framac-master-audit:189053d (master 189053d4a2, before),
#         framac-analysis:latest (34.0~beta), and the master tree with
#         ../patches/78-kernel-acsl-wstring-double-escape.patch built and installed (after).
#
# Output before (master 189053d4a2; 34.0~beta prints the same with
# "34.0~beta (Selenium)"):
#   35.0~~dev (Bromine)
#   esc_reparse_eva: eva exit 0 (invalid=5)
#   esc_reparse_wp: wp exit 0 (true=2, false=5)
#   empty_reparse_eva: eva failed (  unbound logic variable L. Ignoring code annotation)
#   RESULT: bug present (3 of 3 cases fail)
#
# Output after (master 189053d4a2 + patches/78-kernel-acsl-wstring-double-escape.patch):
#   35.0~~dev (Bromine)
#   esc_reparse_eva: eva exit 0 (invalid=0)
#   esc_reparse_wp: wp exit 0 (true=7, false=0)
#   empty_reparse_eva: eva exit 0 (invalid=0)
#   RESULT: fixed
set -u
command -v frama-c >/dev/null 2>&1 || { echo "frama-c is not in PATH" >&2; exit 2; }
n=78-kernel-acsl-wstring-double-escape
tmp=$(mktemp -d)
fail=0
total=0
frama-c -version

check() {
  total=$((total + 1))
  echo "$1: $3"
  [ "$3" = "$2" ] || fail=$((fail + 1))
}

# 1. Escaped ACSL wide strings round-trip through -print -ocode -> Eva and WP
frama-c -cpp-extra-args="-DCASE_esc" "$n.c" -print -ocode "$tmp/esc_out.c" >/dev/null 2>&1
if frama-c -eva "$tmp/esc_out.c" >"$tmp/eva.log" 2>&1; then
  inv=$(grep -c "got status invalid" "$tmp/eva.log" || true)
  got="eva exit 0 (invalid=$inv)"
else
  got="eva failed"
fi
check esc_reparse_eva "eva exit 0 (invalid=0)" "$got"

if frama-c -wp -wp-prover none -wp-print "$tmp/esc_out.c" >"$tmp/wp.log" 2>&1; then
  falses=$(grep -c "Prove: false." "$tmp/wp.log" || true)
  trues=$(grep -c "Prove: true." "$tmp/wp.log" || true)
  got="wp exit 0 (true=$trues, false=$falses)"
else
  got="wp failed"
fi
check esc_reparse_wp "wp exit 0 (true=7, false=0)" "$got"

# 2. Empty ACSL wide string L"" round-trips through -print -ocode
frama-c -cpp-extra-args="-DCASE_empty" "$n.c" -print -ocode "$tmp/empty_out.c" >/dev/null 2>&1
if frama-c -eva "$tmp/empty_out.c" >"$tmp/empty_eva.log" 2>&1; then
  inv=$(grep -c "got status invalid" "$tmp/empty_eva.log" || true)
  got="eva exit 0 (invalid=$inv)"
else
  err=$(grep -m1 "unbound logic variable" "$tmp/empty_eva.log" || echo "parse error")
  got="eva failed ($err)"
fi
check empty_reparse_eva "eva exit 0 (invalid=0)" "$got"

rm -rf "$tmp"
if [ "$fail" = 0 ]; then
  echo "RESULT: fixed"
  exit 0
else
  echo "RESULT: bug present ($fail of $total cases fail)"
  exit 1
fi
