#!/bin/sh
# Issue 64: [WP] void object sized as int (sizeof(int) instead of 1 byte).
#
# Images: framac-master-audit:189053d (master 189053d4a2, before),
#         framac-analysis:latest (34.0~beta, same output), and master with
#         ../patches/64-wp-void-object-size.patch installed (after).
# Command, from this directory:
#   docker run --rm -v "$PWD:/w" -w /w --entrypoint sh <image> \
#     64-wp-void-object-size.sh
#
# Exits 1 when the bug is present, 0 when fixed.
set -u
command -v frama-c >/dev/null 2>&1 || { echo "frama-c is not in PATH" >&2; exit 2; }
F=64-wp-void-object-size.c
W="-no-unicode -wp -wp-prover none -wp-print -wp-cache none"
fail=0

echo "##### typed (block_length)"
out=$(frama-c "$F" $W -wp-fct bl_true,bl_false 2>&1 | grep '^Prove:')
echo "$out"
if ! echo "$out" | grep -q '= 8\.$' || ! echo "$out" | grep -q '= 32\.$'; then
  fail=$((fail + 1))
fi

echo "##### bytes (shift and diff)"
out=$(frama-c "$F" $W -wp-model Bytes -wp-fct shift_true,shift_false,diff_true,diff_false 2>&1 \
  | awk '/Goal Check /{g=$0} /^Prove:/{print g " -> " $0}')
echo "$out"
if ! echo "$out" | grep -q "sh_4.*Prove: true\." \
   || ! echo "$out" | grep -q "sh_16.*Prove: false\." \
   || ! echo "$out" | grep -q "diff_4.*Prove: true\." \
   || ! echo "$out" | grep -q "diff_1.*Prove: false\."; then
  fail=$((fail + 1))
fi

echo "##### x86_16 (block_length)"
out=$(frama-c "$F" -machdep x86_16 $W -wp-fct bl_true 2>&1 | grep '^Prove:')
echo "$out"
if ! echo "$out" | grep -q '= 8\.$'; then
  fail=$((fail + 1))
fi

echo "##### mempcpy (Bytes + Alt-Ergo)"
out=$(frama-c "$F" -cpp-extra-args="-DCASE_mempcpy" -no-unicode -wp -wp-model Bytes \
  -wp-prover alt-ergo -wp-cache none -wp-prop wrong 2>&1 \
  | grep -E 'Proved goals:|Unknown|Timeout|Valid')
echo "$out"
if echo "$out" | grep -q 'Proved goals:.*1 / 1'; then
  fail=$((fail + 1))
fi

if [ "$fail" = 0 ]; then echo "RESULT: fixed"; exit 0
else echo "RESULT: bug present ($fail of 4 cases fail)"; exit 1
fi
