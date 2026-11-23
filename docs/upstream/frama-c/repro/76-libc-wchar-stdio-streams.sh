#!/bin/sh
# Issue 76: [Libc] <wchar.h> alone cannot locate __fc_stdout / __fc_stdin for
# wprintf and wscanf.
#
# Images: framac-master-audit:189053d (master 189053d4a2) and
#         framac-analysis:latest (34.0~beta); same "before" output on both.
# Command, from this directory:
#   docker run --rm -v "$PWD:/w" -w /w --entrypoint sh <image> \
#     76-libc-wchar-stdio-streams.sh
#
# Output before (master 189053d4a2; 34.0~beta prints the same), exit 1:
#   wprintf_stdout: FAIL (Unable to locate __fc_stdout; stream effect missing)
#   wscanf_stdin: FAIL (Unable to locate __fc_stdin; stream effect missing)
#   RESULT: bug present (2 of 2 checks fail)
#
# Output after (master 189053d4a2 with
# patches/76-libc-wchar-stdio-streams.patch installed), exit 0:
#   wprintf_stdout: ok
#   wscanf_stdin: ok
#   RESULT: fixed
set -u
tmp=${TMPDIR:-/tmp}/repro76.$$
mkdir -p "$tmp"
failed=0
n=0

frama-c -no-unicode -print \
  76-libc-wchar-stdio-streams.c > "$tmp/print.log" 2>&1
rc=$?

n=$((n + 1))
if [ "$rc" = 0 ] \
   && ! grep -q 'Unable to locate global __fc_stdout' "$tmp/print.log" \
   && grep -q '__fc_stdout->__fc_FILE_data' "$tmp/print.log"; then
  echo "wprintf_stdout: ok"
else
  echo "wprintf_stdout: FAIL (Unable to locate __fc_stdout; stream effect missing)"
  failed=$((failed + 1))
fi

n=$((n + 1))
if [ "$rc" = 0 ] \
   && ! grep -q 'Unable to locate global __fc_stdin' "$tmp/print.log" \
   && grep -q '__fc_stdin->__fc_FILE_data' "$tmp/print.log"; then
  echo "wscanf_stdin: ok"
else
  echo "wscanf_stdin: FAIL (Unable to locate __fc_stdin; stream effect missing)"
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
