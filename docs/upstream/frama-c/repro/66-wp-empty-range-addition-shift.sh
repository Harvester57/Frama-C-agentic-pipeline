#!/bin/sh
# Issue 66: [WP] Adding/subtracting two integer ranges (Vset.ml) or shifting a
# pointer range by a range (Cvalues.ml) ignores empty ranges and proves false
# memberships, validity, and assigns clauses.
#
# Images: framac-master-audit:189053d (master 189053d4a2, before),
#         framac-analysis:latest (34.0~beta, same output), and master with
#         ../patches/66-wp-empty-range-addition-shift.patch installed (after).
# Command, from this directory:
#   docker run --rm -v "$PWD:/w" -w /w --entrypoint sh <image> \
#     66-wp-empty-range-addition-shift.sh
#
# Exits 1 when the bug is present, 0 when fixed.
set -u
command -v frama-c >/dev/null 2>&1 || { echo "frama-c is not in PATH" >&2; exit 2; }
F=66-wp-empty-range-addition-shift.c
full=$(frama-c "$F" -no-unicode -wp -wp-prover none -wp-print -wp-cache none 2>&1)
pairs=$(echo "$full" | awk '/^Goal /{g=$0} /^Prove:/{print g " -> " $0}')
echo "$pairs"
fail=0
for name in empty_plus_bad empty_minus_bad open_empty_bad sym_bad f_assigns3; do
  if ! echo "$pairs" | grep -q "'$name'.*Prove: false\."; then
    fail=$((fail + 1))
  fi
done
for name in subset_empty_ok f_assigns_ok; do
  if ! echo "$pairs" | grep -q "'$name'.*Prove: true\."; then
    fail=$((fail + 1))
  fi
done
if echo "$full" | grep -q 'valid_rw(Malloc_0, shift_sint32(p, 0), 1)'; then
  echo "ERROR: w2 still receives spurious valid_rw(Malloc_0, shift_sint32(p, 0), 1) hypothesis"
  fail=$((fail + 1))
fi
if [ "$fail" = 0 ]; then echo "RESULT: fixed"; exit 0
else echo "RESULT: bug present ($fail of 8 checks fail)"; exit 1
fi
