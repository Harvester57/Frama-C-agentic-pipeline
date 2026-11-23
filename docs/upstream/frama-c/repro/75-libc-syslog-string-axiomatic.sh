#!/bin/sh
# Issue 75: [Libc] syslog with only <syslog.h> drops string preconditions
# because share/libc/syslog.h does not include __fc_string_axiomatic.h.
#
# Images: framac-master-audit:189053d (master 189053d4a2) and
#         framac-analysis:latest (34.0~beta); same "before" output on both.
# Command, from this directory:
#   docker run --rm -v "$PWD:/w" -w /w --entrypoint sh <image> \
#     75-libc-syslog-string-axiomatic.sh
#
# Output before (master 189053d4a2; 34.0~beta prints the same), exit 1:
#   syslog_s: FAIL (Unable to locate valid_read_string; 0 preconditions)
#   RESULT: bug present (1 of 1 checks fail)
#
# Output after (master 189053d4a2 with
# patches/75-libc-syslog-string-axiomatic.patch installed), exit 0:
#   syslog_s: ok (no warning; invalid precondition caught)
#   RESULT: fixed
set -u
tmp=${TMPDIR:-/tmp}/repro75.$$
mkdir -p "$tmp"
failed=0
n=1

frama-c -no-unicode -eva \
  75-libc-syslog-string-axiomatic.c > "$tmp/eva.log" 2>&1
rc=$?

if [ "$rc" = 0 ] \
   && ! grep -q 'Unable to locate ACSL predicate' "$tmp/eva.log" \
   && grep -q "precondition 'valid_read_string' got status invalid" "$tmp/eva.log" \
   || { [ "$rc" = 0 ] && ! grep -q 'Unable to locate ACSL predicate' "$tmp/eva.log" \
        && grep -q 'Preconditions[[:space:]]*1 valid[[:space:]]*0 unknown[[:space:]]*1 invalid[[:space:]]*2 total' "$tmp/eva.log"; }; then
  echo "syslog_s: ok (no warning; invalid precondition caught)"
else
  reasons=""
  grep -q 'Unable to locate ACSL predicate' "$tmp/eva.log" && reasons="Unable to locate valid_read_string"
  if grep -q 'No logical properties have been reached' "$tmp/eva.log"; then
    reasons="${reasons:+$reasons; }0 preconditions"
  fi
  echo "syslog_s: FAIL (${reasons:-exit $rc})"
  failed=$((failed + 1))
fi

rm -rf "$tmp"
if [ "$failed" = 0 ]; then
  echo "RESULT: fixed"
  exit 0
else
  echo "RESULT: bug present ($failed of $n checks fail)"
  exit 1
fi
