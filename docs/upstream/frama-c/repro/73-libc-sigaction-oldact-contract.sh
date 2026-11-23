#!/bin/sh
# Issue 73: [Libc] sigaction assigns *oldact from &__fc_sigaction and omits
# \old in oldact_assigned.
#
# Images: framac-master-audit:189053d (master 189053d4a2) and
#         framac-analysis:latest (34.0~beta); same "before" output on both.
# Command, from this directory:
#   docker run --rm -v "$PWD:/w" -w /w --entrypoint sh <image> \
#     73-libc-sigaction-oldact-contract.sh
#
# Output before (master 189053d4a2; 34.0~beta prints the same), exit 1:
#   two_call: FAIL (ensures-false; NON TERMINATING FUNCTION)
#   single_call: FAIL (ensures-false; NON TERMINATING FUNCTION)
#   query_after_install: FAIL (assertion invalid; NON TERMINATING FUNCTION)
#   RESULT: bug present (3 of 3 checks fail)
#
# Output after (master 189053d4a2 with
# patches/73-libc-sigaction-oldact-contract.patch installed), exit 0:
#   two_call: ok
#   single_call: ok
#   query_after_install: ok
#   RESULT: fixed
set -u
tmp=${TMPDIR:-/tmp}/repro73.$$
mkdir -p "$tmp"
failed=0
n=0

run_case() {
  fn=$1
  n=$((n + 1))
  frama-c -no-unicode -eva -main "$fn" \
    73-libc-sigaction-oldact-contract.c > "$tmp/$fn.log" 2>&1
  rc=$?
  if [ "$rc" != 0 ] \
     || grep -q 'NON TERMINATING FUNCTION' "$tmp/$fn.log" \
     || grep -q 'eva:ensures-false' "$tmp/$fn.log" \
     || grep -q 'got status invalid' "$tmp/$fn.log"; then
    reasons=""
    grep -q 'eva:ensures-false' "$tmp/$fn.log" && reasons="ensures-false"
    if grep -q 'got status invalid' "$tmp/$fn.log"; then
      reasons="${reasons:+$reasons; }assertion invalid"
    fi
    if grep -q 'NON TERMINATING FUNCTION' "$tmp/$fn.log"; then
      reasons="${reasons:+$reasons; }NON TERMINATING FUNCTION"
    fi
    echo "$fn: FAIL (${reasons:-exit $rc})"
    failed=$((failed + 1))
  else
    echo "$fn: ok"
  fi
}

run_case two_call
run_case single_call
run_case query_after_install

rm -rf "$tmp"
if [ "$failed" = 0 ]; then
  echo "RESULT: fixed"
  exit 0
else
  echo "RESULT: bug present ($failed of $n checks fail)"
  exit 1
fi
