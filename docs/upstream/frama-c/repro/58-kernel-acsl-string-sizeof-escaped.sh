#!/bin/sh
# Issue 58: [Kernel] ACSL string literal sizeof counts raw escaped source text
# instead of unescaped bytes (logic_typing.ml:2685).
#
# Images: framac-master-audit:189053d (master 189053d4a2, before),
#         framac-analysis:latest (34.0~beta, before), and master +
#         ../patches/58-kernel-acsl-string-sizeof-escaped.patch (after).
# Command, from this directory:
#   docker run --rm -v "$PWD:/w" -w /w --entrypoint sh <image> \
#     58-kernel-acsl-string-sizeof-escaped.sh
set -u
command -v frama-c >/dev/null 2>&1 || { echo "frama-c is not in PATH" >&2; exit 2; }
n=58-kernel-acsl-string-sizeof-escaped
tmp=$(mktemp -d)
fail=0
total=0
frama-c -version

# 1. Eva proves all 5 checks and greet's precondition valid (no NON TERMINATING)
total=$((total + 1))
frama-c -eva "$n.c" > "$tmp/eva.log" 2>&1
if grep -q 'Assertions[[:space:]]*5 valid[[:space:]]*0 unknown[[:space:]]*0 invalid' "$tmp/eva.log" \
   && grep -q 'Preconditions[[:space:]]*1 valid[[:space:]]*0 unknown[[:space:]]*0 invalid' "$tmp/eva.log"; then
  echo "eva_sizeof_valid: PASS"
else
  echo "eva_sizeof_valid: FAIL (Eva marks sizeof checks or precondition invalid)"
  fail=$((fail + 1))
fi

# 2. WP Qed proves greeting_size postcondition len and all 5 checks
total=$((total + 1))
frama-c -wp -wp-prover none -wp-print "$n.c" > "$tmp/wp.log" 2>&1
if grep -q 'Prove: false\.' "$tmp/wp.log"; then
  echo "wp_sizeof_valid: FAIL (WP Qed refutes true sizeof postcondition/check)"
  fail=$((fail + 1))
else
  echo "wp_sizeof_valid: PASS"
fi

rm -rf "$tmp"
if [ "$fail" = 0 ]; then echo "RESULT: fixed"; exit 0
else echo "RESULT: bug present ($fail of $total checks fail)"; exit 1
fi
