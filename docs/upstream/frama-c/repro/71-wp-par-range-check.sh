#!/bin/sh
# Issue 71: [WP] -wp-par 0 (and negative values) crash with
# Unexpected error (Invalid_argument("Prove_client.set_max_running_provers")).
#
# Images: framac-master-audit:189053d (master 189053d4a2, before),
#         framac-analysis:latest (34.0~beta, same output), and master with
#         ../patches/71-wp-par-range-check.patch installed (after).
# Command, from this directory:
#   docker run --rm -v "$PWD:/w" -w /w --entrypoint sh <image> \
#     71-wp-par-range-check.sh
#
# Exits 1 when the bug is present, 0 when fixed.
set -u
command -v frama-c >/dev/null 2>&1 || { echo "frama-c is not in PATH" >&2; exit 2; }
F=71-wp-par-range-check.c
fail=0

for bad in 0 -1; do
  echo "##### -wp-par $bad"
  out=$(frama-c -no-unicode -wp -wp-cache none -wp-par "$bad" "$F" 2>&1)
  rc=$?
  echo "$out" | grep -E 'User Error|Unexpected error' | head -n 4
  echo "exit=$rc"
  if [ "$rc" != 1 ] || echo "$out" | grep -q 'Unexpected error' \
     || ! echo "$out" | grep -q 'User Error'; then
    fail=$((fail + 1))
  fi
done

echo "##### -wp-par 1 (valid control)"
out=$(frama-c -no-unicode -wp -wp-cache none -wp-par 1 "$F" 2>&1)
rc=$?
echo "$out" | grep -E 'Proved goals|User Error|Unexpected error' | head -n 4
echo "exit=$rc"
if [ "$rc" != 0 ]; then
  fail=$((fail + 1))
fi

if [ "$fail" = 0 ]; then echo "RESULT: fixed"; exit 0
else echo "RESULT: bug present ($fail of 3 cases fail)"; exit 1
fi
