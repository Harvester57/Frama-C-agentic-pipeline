#!/bin/sh
# Issue 72: [Libc] pclose proves \false under WP because is_open_pipe has no
# reads clause and pclose assigns no memory state.
#
# Images: framac-master-audit:189053d (master 189053d4a2) and
#         framac-analysis:latest (34.0~beta); same "before" output on both.
# Command, from this directory:
#   docker run --rm -v "$PWD:/w" -w /w --entrypoint sh <image> \
#     72-libc-pclose-pipe-status-soundness.sh
#
# Output before (master 189053d4a2; 34.0~beta prints the same), exit 1:
#   false_assertion: FAIL (Qed proved \false; reads-nothing warning present)
#   smoke_tests: FAIL (Doomed call reported)
#   read_then_close: ok
#   RESULT: bug present (2 of 3 checks fail)
#
# Output after (master 189053d4a2 with
# patches/72-libc-pclose-pipe-status-soundness.patch installed), exit 0:
#   false_assertion: ok
#   smoke_tests: ok
#   read_then_close: ok
#   RESULT: fixed
set -u
tmp=${TMPDIR:-/tmp}/repro72.$$
mkdir -p "$tmp"
failed=0
n=0

# Check 1: \false must NOT be proved by Qed and is_open_pipe must not warn.
n=$((n + 1))
frama-c -no-unicode -wp -wp-par 1 -wp-prover none -wp-print \
  -wp-fct close_immediately -wp-prop unreachable_false \
  72-libc-pclose-pipe-status-soundness.c > "$tmp/c1.log" 2>&1
rc1=$?
if [ "$rc1" != 0 ] \
   || grep -q 'Prove: true\.' "$tmp/c1.log" \
   || grep -q "interpreted as reads nothing" "$tmp/c1.log"; then
  reasons=""
  grep -q 'Prove: true\.' "$tmp/c1.log" && reasons='Qed proved \false'
  if grep -q "interpreted as reads nothing" "$tmp/c1.log"; then
    reasons="${reasons:+$reasons; }reads-nothing warning present"
  fi
  printf '%s\n' "false_assertion: FAIL (${reasons:-exit $rc1})"
  failed=$((failed + 1))
else
  printf '%s\n' "false_assertion: ok"
fi

# Check 2: -wp-smoke-tests (Qed only) must not report a Doomed pclose call.
n=$((n + 1))
frama-c -no-unicode -wp -wp-par 1 -wp-prover qed -wp-smoke-tests \
  -wp-fct close_immediately \
  72-libc-pclose-pipe-status-soundness.c > "$tmp/c2.log" 2>&1
rc2=$?
if [ "$rc2" != 0 ] || grep -q 'Doomed' "$tmp/c2.log"; then
  printf '%s\n' "smoke_tests: FAIL (Doomed call reported)"
  failed=$((failed + 1))
else
  printf '%s\n' "smoke_tests: ok"
fi

# Check 3: fread between popen and pclose must preserve is_open_pipe(p).
n=$((n + 1))
frama-c -no-unicode -wp -wp-par 1 -wp-prover none -wp-print \
  -wp-fct read_then_close -wp-prop open_pipe \
  72-libc-pclose-pipe-status-soundness.c > "$tmp/c3.log" 2>&1
rc3=$?
if [ "$rc3" = 0 ] && grep -q 'Prove: true\.' "$tmp/c3.log"; then
  printf '%s\n' "read_then_close: ok"
else
  printf '%s\n' "read_then_close: FAIL (open_pipe not proved after fread)"
  failed=$((failed + 1))
fi

rm -rf "$tmp"
if [ "$failed" = 0 ]; then
  printf '%s\n' "RESULT: fixed"
  exit 0
else
  printf '%s\n' "RESULT: bug present ($failed of $n checks fail)"
  exit 1
fi
