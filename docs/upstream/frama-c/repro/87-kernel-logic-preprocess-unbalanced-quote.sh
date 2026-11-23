#!/bin/sh
# Issue 87: [Kernel] Unbalanced quote or C23 digit separator (1'000) in an ACSL
# annotation crashes logic preprocessing with Kernel.fatal ("too few annotations
# in result file while preprocessing annotations").
#
# Images: framac-master-audit:189053d (master 189053d4a2, before),
#         framac-analysis:latest (34.0~beta), and the master tree with
#         ../patches/87-kernel-logic-preprocess-unbalanced-quote.patch built and installed (after).
# Command, from this directory:
#   docker run --rm -v "$PWD:/w" -w /w --entrypoint sh <image> \
#     87-kernel-logic-preprocess-unbalanced-quote.sh
#
# Output before (master 189053d4a2; 34.0~beta prints the same with
# "34.0~beta (Selenium)"):
#   35.0~~dev (Bromine)
#   unbalanced_str: exit 4 ([kernel] Failure: too few annotations in result file while preprocessing annotations)
#   c23_sep: exit 4 ([kernel] Failure: too few annotations in result file while preprocessing annotations)
#   unbalanced_char: exit 4 ([kernel] Failure: too few annotations in result file while preprocessing annotations)
#   RESULT: bug present (3 of 3 cases fail)
#
# Output after (master 189053d4a2 + patches/87-kernel-logic-preprocess-unbalanced-quote.patch):
#   35.0~~dev (Bromine)
#   unbalanced_str: clean user error exit 1 ([kernel] 87-kernel-logic-preprocess-unbalanced-quote.c:5: User Error: )
#   c23_sep: clean user error exit 1 ([kernel] 87-kernel-logic-preprocess-unbalanced-quote.c:9: User Error: )
#   unbalanced_char: clean user error exit 1 ([kernel] 87-kernel-logic-preprocess-unbalanced-quote.c:13: User Error: )
#   RESULT: fixed
set -u
command -v frama-c >/dev/null 2>&1 || { echo "frama-c is not in PATH" >&2; exit 2; }
n=87-kernel-logic-preprocess-unbalanced-quote
tmp=$(mktemp -d)
fail=0
total=0
frama-c -version

for c in unbalanced_str c23_sep unbalanced_char; do
  total=$((total + 1))
  frama-c -no-autoload-plugins -cpp-extra-args="-DCASE_$c" "$n.c" > "$tmp/$c.log" 2>&1
  rc=$?
  fatal=$(grep -E 'internal error|too few annotations|Unexpected error' "$tmp/$c.log" | head -n 1)
  if [ "$rc" = 1 ] && [ -z "$fatal" ]; then
    uerr=$(grep -E 'User Error:' "$tmp/$c.log" | head -n 1)
    echo "$c: clean user error exit 1 ($uerr)"
  else
    echo "$c: exit $rc (${fatal:-unexpected})"
    fail=$((fail + 1))
  fi
done

rm -rf "$tmp"
if [ "$fail" = 0 ]; then
  echo "RESULT: fixed"
  exit 0
else
  echo "RESULT: bug present ($fail of $total cases fail)"
  exit 1
fi
