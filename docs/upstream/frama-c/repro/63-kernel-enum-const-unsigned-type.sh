#!/bin/sh
# Issue 63: [Kernel] Enumeration constants of non-negative enums are typed as
# unsigned int (enum.ekind) instead of int, violating ISO C11 6.7.2.2p3,
# C23 6.7.2.2p12, and GCC semantics (regression from #@1682).
#
# Images: framac-master-audit:189053d (master 189053d4a2),
#         framac-analysis:latest (34.0~beta).
# Command, from this directory:
#   docker run --rm -v "$PWD:/w" -w /w --entrypoint sh <image> \
#     63-kernel-enum-const-unsigned-type.sh
#
# Issue-only package (no patch yet; awaits maintainer design direction on #@1682).
# Exits 1 while the defect is present and 0 if fixed.
set -u
command -v frama-c >/dev/null 2>&1 || { echo "frama-c is not in PATH" >&2; exit 2; }
n=63-kernel-enum-const-unsigned-type
tmp=$(mktemp -d)
fail=0
total=0
frama-c -version

# Case 1: default gcc_x86_64 prints N as unsigned int and casts i to unsigned int
total=$((total + 1))
frama-c -machdep gcc_x86_64 -print "$n.c" > "$tmp/print.log" 2>&1
if grep -q '(unsigned int)i < N' "$tmp/print.log"; then
  echo "print_unsigned_cmp: FAIL (emits (unsigned int)i < N)"
  fail=$((fail + 1))
else
  echo "print_unsigned_cmp: PASS"
fi

# Case 2: WP proves out-of-bounds read a[i] in get() safe (4/4 proved)
total=$((total + 1))
frama-c -machdep gcc_x86_64 -wp -wp-rte -wp-fct get "$n.c" > "$tmp/wp_get.log" 2>&1
if grep -q 'Proved goals:[[:space:]]*4 / 4' "$tmp/wp_get.log"; then
  echo "wp_oob_proved: FAIL (WP proves all 4/4 goals including 0 <= i on negative i)"
  fail=$((fail + 1))
else
  echo "wp_oob_proved: PASS"
fi

# Case 3: Eva evaluates -1 < MAX to 0 and marks c_int_ok invalid
total=$((total + 1))
frama-c -machdep gcc_x86_64 -eva "$n.c" > "$tmp/eva_main.log" 2>&1
if grep -q "check 'c_int_ok' got status invalid" "$tmp/eva_main.log"; then
  echo "eva_signed_cmp: FAIL (check c_int_ok invalid under -machdep gcc_x86_64)"
  fail=$((fail + 1))
else
  echo "eva_signed_cmp: PASS"
fi

# Case 4: -enums int is not a sound workaround (breaks enum Small sv = -1; sv < S1)
total=$((total + 1))
frama-c -machdep gcc_x86_64 -enums int -eva "$n.c" > "$tmp/eva_int.log" 2>&1
if grep -q "check 'c_enum_ok' got status invalid" "$tmp/eva_int.log"; then
  echo "enums_int_control: FAIL (check c_enum_ok invalid under -enums int)"
  fail=$((fail + 1))
else
  echo "enums_int_control: PASS"
fi

rm -rf "$tmp"
if [ "$fail" = 0 ]; then
  echo "RESULT: fixed"
  exit 0
else
  echo "RESULT: bug present ($fail of $total checks fail)"
  exit 1
fi
