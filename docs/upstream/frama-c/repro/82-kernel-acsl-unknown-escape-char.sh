#!/bin/sh
# Issue 82: [Kernel] ACSL lexer silently keeps unknown escape sequences (and GCC
# \e/\E) as two raw characters ('\\' and the letter) instead of handling \e/\E
# like the C lexer and rejecting unknown escapes.
#
# Images: framac-master-audit:189053d (master 189053d4a2, before),
#         framac-analysis:latest (34.0~beta), and the master tree with
#         ../patches/82-kernel-acsl-unknown-escape-char.patch built and installed (after).
# Command, from this directory:
#   docker run --rm -v "$PWD:/w" -w /w --entrypoint sh <image> \
#     82-kernel-acsl-unknown-escape-char.sh
#
# Output before (master 189053d4a2; 34.0~beta prints the same with
# "34.0~beta (Selenium)"):
#   35.0~~dev (Bromine)
#   esc: exit 0 (    Assertions        0 valid     0 unknown     3 invalid      3 total, invalid_lines=3)
#   unknown: exit 0 (accepted silently)
#   unknown_str: exit 0 (accepted silently)
#   RESULT: bug present (3 of 3 cases fail)
#
# Output after (master 189053d4a2 + patches/82-kernel-acsl-unknown-escape-char.patch):
#   35.0~~dev (Bromine)
#   esc: exit 0 (    Assertions        3 valid     0 unknown     0 invalid      3 total, invalid_lines=0)
#   unknown: rejected exit 1 (  lexical error, unrecognized escape sequence: \z)
#   unknown_str: rejected exit 1 (  lexical error, unrecognized escape sequence: \z)
#   RESULT: fixed
set -u
command -v frama-c >/dev/null 2>&1 || { echo "frama-c is not in PATH" >&2; exit 2; }
n=82-kernel-acsl-unknown-escape-char
tmp=$(mktemp -d)
fail=0
total=0
frama-c -version

total=$((total + 1))
frama-c -eva -cpp-extra-args="-DCASE_esc" "$n.c" > "$tmp/esc.log" 2>&1
rc=$?
summary=$(grep -E 'Assertions[[:space:]]+[0-9]+ valid' "$tmp/esc.log" | head -n 1)
inv=$(grep -c 'check got status invalid' "$tmp/esc.log")
echo "esc: exit $rc (${summary:-none}, invalid_lines=$inv)"
if [ "$rc" != 0 ] || [ "$inv" != 0 ] || ! echo "$summary" | grep -qE 'Assertions[[:space:]]+3 valid[[:space:]]+0 unknown[[:space:]]+0 invalid[[:space:]]+3 total'; then
  fail=$((fail + 1))
fi

for c in unknown unknown_str; do
  total=$((total + 1))
  frama-c -no-autoload-plugins -kernel-warn-key annot-error=abort -cpp-extra-args="-DCASE_$c" "$n.c" > "$tmp/$c.log" 2>&1
  rc=$?
  uerr=$(grep -E 'unrecognized escape sequence' "$tmp/$c.log" | head -n 1)
  if [ "$rc" = 1 ] && [ -n "$uerr" ]; then
    echo "$c: rejected exit 1 ($uerr)"
  else
    echo "$c: exit $rc (${uerr:-accepted silently})"
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
