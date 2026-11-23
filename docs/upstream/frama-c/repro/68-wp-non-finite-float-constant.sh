#!/bin/sh
# Issue 68: [WP] Non-finite float constants become infinite Kreal constants in
# Qed (wrong real proofs) and crash Why3 export with
# Invalid_argument("Wp.Cfloat.const_float").
#
# Images: framac-master-audit:189053d (master 189053d4a2, before),
#         framac-analysis:latest (34.0~beta, same output), and master with
#         ../patches/68-wp-non-finite-float-constant.patch installed (after).
# Command, from this directory:
#   docker run --rm -v "$PWD:/w" -w /w --entrypoint sh <image> \
#     68-wp-non-finite-float-constant.sh
#
# Exits 1 when the bug is present, 0 when fixed.
set -u
command -v frama-c >/dev/null 2>&1 || { echo "frama-c is not in PATH" >&2; exit 2; }
F=68-wp-non-finite-float-constant.c
fail=0

echo "##### qed"
pairs=$(frama-c "$F" -no-unicode -wp -wp-prover none -wp-print -wp-cache none 2>&1 \
  | awk '/^Goal /{g=$0} /^Prove:/{print g " -> " $0}')
echo "$pairs"
if ! echo "$pairs" | grep -q "'ovf_f32_plus1_bad'.*Prove: false\."; then fail=$((fail + 1)); fi
if ! echo "$pairs" | grep -q "'ovf_f32_sub_ok'.*Prove: true\."; then fail=$((fail + 1)); fi
for name in plus1_bad twice_bad lit_bad acsl_bad; do
  if echo "$pairs" | grep -q "'$name'.*Prove: true\."; then fail=$((fail + 1)); fi
done

echo "##### rte + alt-ergo (Why3 export)"
out=$(frama-c "$F" -no-unicode -wp -wp-rte -wp-prover alt-ergo -wp-cache none \
  -wp-fct ovf_mul,ovf_lit 2>&1 \
  | grep -E 'const_float|\[Failure\]|Proved goals:|Failed:')
echo "$out"
if echo "$out" | grep -qE 'const_float|\[Failure\]'; then
  fail=$((fail + 1))
fi

if [ "$fail" = 0 ]; then echo "RESULT: fixed"; exit 0
else echo "RESULT: bug present ($fail checks fail)"; exit 1
fi
