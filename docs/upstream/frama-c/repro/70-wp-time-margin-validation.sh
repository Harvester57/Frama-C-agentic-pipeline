#!/bin/sh
# Issue 70: [WP] -wp-time-margin is an unchecked String option that crashes
# after provers run with Unexpected error (Failure("float_of_string")), accepts
# nan/inf silently, and its manual states "Default is 5s" while the code
# defaults to 0.5.
#
# Images: framac-master-audit:189053d (master 189053d4a2, before),
#         framac-analysis:latest (34.0~beta, same output), and master with
#         ../patches/70-wp-time-margin-validation.patch installed (after).
# Command, from this directory:
#   docker run --rm -v "$PWD:/w" -w /w --entrypoint sh <image> \
#     70-wp-time-margin-validation.sh
#
# Exits 1 when the bug is present, 0 when fixed.
set -u
command -v frama-c >/dev/null 2>&1 || { echo "frama-c is not in PATH" >&2; exit 2; }
F=70-wp-time-margin-validation.c
fail=0

for bad in 1s nan inf -1; do
  echo "##### -wp-time-margin $bad"
  out=$(frama-c -no-unicode -wp -wp-cache none -wp-timeout 5 -wp-time-margin "$bad" "$F" 2>&1)
  rc=$?
  echo "$out" | grep -E 'User Error|Unexpected error|Proved goals' | head -n 4
  echo "exit=$rc"
  if [ "$rc" != 1 ] || echo "$out" | grep -q 'Unexpected error' \
     || ! echo "$out" | grep -q 'User Error'; then
    fail=$((fail + 1))
  fi
done

echo "##### -wp-time-margin 0.25 (valid control)"
out=$(frama-c -no-unicode -wp -wp-cache none -wp-timeout 5 -wp-time-margin 0.25 "$F" 2>&1)
rc=$?
echo "$out" | grep -E 'Proved goals|User Error|Unexpected error' | head -n 4
echo "exit=$rc"
if [ "$rc" != 0 ]; then
  fail=$((fail + 1))
fi

if [ "$fail" = 0 ]; then echo "RESULT: fixed"; exit 0
else echo "RESULT: bug present ($fail of 5 cases fail)"; exit 1
fi
