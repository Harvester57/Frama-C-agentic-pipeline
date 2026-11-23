#!/bin/sh
# Issue 69: [WP] strategy timeout with a suffix or integer overflow aborts with
# an internal error (Failure("int_of_string"|"float_of_string")) because
# ProofStrategy.parse_provers catches Invalid_argument instead of Failure.
#
# Images: framac-master-audit:189053d (master 189053d4a2, before),
#         framac-analysis:latest (34.0~beta, same output), and master with
#         ../patches/69-wp-strategy-timeout-exception.patch installed (after).
# Command, from this directory:
#   docker run --rm -v "$PWD:/w" -w /w --entrypoint sh <image> \
#     69-wp-strategy-timeout-exception.sh
#
# Exits 1 when the bug is present, 0 when fixed.
set -u
command -v frama-c >/dev/null 2>&1 || { echo "frama-c is not in PATH" >&2; exit 2; }
F=69-wp-strategy-timeout-exception.c
fail=0

for val in 2u 2.5f 99999999999999999999; do
  echo "##### timeout=$val"
  out=$(frama-c -no-unicode -cpp-extra-args="-DTIMEOUT_VAL=$val" -wp -wp-timeout 5 "$F" 2>&1)
  rc=$?
  echo "$out" | grep -E 'internal error|Invalid timeout|invalid user input|Failure:' | head -n 5
  echo "exit=$rc"
  if [ "$rc" != 1 ] || echo "$out" | grep -q 'internal error' \
     || ! echo "$out" | grep -q 'Invalid timeout'; then
    fail=$((fail + 1))
  fi
done

if [ "$fail" = 0 ]; then echo "RESULT: fixed"; exit 0
else echo "RESULT: bug present ($fail of 3 cases fail)"; exit 1
fi
