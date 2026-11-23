#!/bin/sh
# Issue 61: [Kernel] Cil.charConstToInt always sign-extends character constants
# >= 128 even on machdeps where char is unsigned (e.g. ppc_32).
#
# Images: framac-master-audit:189053d (master 189053d4a2, before),
#         framac-analysis:latest (34.0~beta, before), and master +
#         ../patches/61-kernel-char-const-unsigned-machdep.patch (after).
# Command, from this directory:
#   docker run --rm -v "$PWD:/w" -w /w --entrypoint sh <image> \
#     61-kernel-char-const-unsigned-machdep.sh
set -u
command -v frama-c >/dev/null 2>&1 || { echo "frama-c is not in PATH" >&2; exit 2; }
n=61-kernel-char-const-unsigned-machdep
tmp=$(mktemp -d)
fail=0
total=0
frama-c -version

# 1. Under -machdep ppc_32, sizeof(char[('\377' > 0) ? 2 : 1]) must fold to char [2]
total=$((total + 1))
frama-c -machdep ppc_32 -print "$n.c" > "$tmp/print.log" 2>&1
if grep -q 'sizeof(char \[2\])' "$tmp/print.log"; then
  printf '%s\n' 'ppc32_sizeof_fold: PASS'
else
  printf '%s\n' "ppc32_sizeof_fold: FAIL (folded to char [1] because '\377' was -1)"
  fail=$((fail + 1))
fi

# 2. Under -machdep ppc_32 -eva, all 5 assertions must be valid
total=$((total + 1))
frama-c -machdep ppc_32 -eva "$n.c" > "$tmp/eva.log" 2>&1
if grep -q 'Assertions[[:space:]]*5 valid[[:space:]]*0 unknown[[:space:]]*0 invalid' "$tmp/eva.log"; then
  echo "ppc32_eva_valid: PASS"
else
  echo "ppc32_eva_valid: FAIL (assertions invalid under -machdep ppc_32)"
  fail=$((fail + 1))
fi

rm -rf "$tmp"
if [ "$fail" = 0 ]; then echo "RESULT: fixed"; exit 0
else echo "RESULT: bug present ($fail of $total checks fail)"; exit 1
fi
