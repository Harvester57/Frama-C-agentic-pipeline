#!/bin/sh
# Issue 65: [WP] \floor/\ceil/\truncate and float-to-integer casts of constants
# go through int_of_float (Q.to_float r) and prove false facts.
#
# Images: framac-master-audit:189053d (master 189053d4a2, before),
#         framac-analysis:latest (34.0~beta, same output), and master with
#         ../patches/65-wp-floor-ceil-truncate-float-cast.patch installed (after).
# Command, from this directory:
#   docker run --rm -v "$PWD:/w" -w /w --entrypoint sh <image> \
#     65-wp-floor-ceil-truncate-float-cast.sh
#
# Exits 1 when the bug is present, 0 when fixed.
set -u
command -v frama-c >/dev/null 2>&1 || { echo "frama-c is not in PATH" >&2; exit 2; }
F=65-wp-floor-ceil-truncate-float-cast.c
out=$(frama-c "$F" -no-unicode -wp -wp-prover none -wp-print -wp-cache none \
  -wp-prop=@lemma,@ensures 2>&1 \
  | awk '/^Goal /{g=$0} /^Prove:/{print g " -> " $0}')
echo "$out"
fail=0
for name in floor_near_ok ceil_near_ok trunc_near_ok floor_big_ok cast_int_ok \
            floor_huge_ok ok_ll ok_ull; do
  if ! echo "$out" | grep -q "'$name'.*Prove: true\."; then
    fail=$((fail + 1))
  fi
done
for name in floor_near_bad ceil_near_bad trunc_near_bad floor_big_bad cast_int_bad \
            floor_huge_bad bad_ll bad_ull; do
  if ! echo "$out" | grep -q "'$name'.*Prove: false\."; then
    fail=$((fail + 1))
  fi
done
if [ "$fail" = 0 ]; then echo "RESULT: fixed"; exit 0
else echo "RESULT: bug present ($fail of 16 goals fail)"; exit 1
fi
