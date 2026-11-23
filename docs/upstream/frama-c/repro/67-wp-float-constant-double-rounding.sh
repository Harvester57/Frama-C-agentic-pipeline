#!/bin/sh
# Issue 67: [WP] Converting rational/integer constants to IEEE 754 float32
# double-rounds through double in Cfloat.qmake.
#
# Images: framac-master-audit:189053d (master 189053d4a2, before),
#         framac-analysis:latest (34.0~beta, same output), and master with
#         ../patches/67-wp-float-constant-double-rounding.patch installed (after).
# Command, from this directory:
#   docker run --rm -v "$PWD:/w" -w /w --entrypoint sh <image> \
#     67-wp-float-constant-double-rounding.sh
#
# Exits 1 when the bug is present, 0 when fixed.
set -u
command -v frama-c >/dev/null 2>&1 || { echo "frama-c is not in PATH" >&2; exit 2; }
F=67-wp-float-constant-double-rounding.c
out=$(frama-c "$F" -no-unicode -wp -wp-prover none -wp-print -wp-cache none \
  -wp-prop=@lemma,@ensures 2>&1 \
  | awk '/^Goal /{g=$0} /^Prove:/{print g " -> " $0}')
echo "$out"
fail=0
for name in dr_above_mid_ok dr_fltmax_ok dr_subnormal_ok to_float_ok; do
  if ! echo "$out" | grep -q "'$name'.*Prove: true\."; then
    fail=$((fail + 1))
  fi
done
for name in dr_above_mid_bad to_float_bad; do
  if ! echo "$out" | grep -q "'$name'.*Prove: false\."; then
    fail=$((fail + 1))
  fi
done
if [ "$fail" = 0 ]; then echo "RESULT: fixed"; exit 0
else echo "RESULT: bug present ($fail of 6 goals fail)"; exit 1
fi
