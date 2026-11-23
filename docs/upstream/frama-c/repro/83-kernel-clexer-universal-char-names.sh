#!/bin/sh
# Issue 83: [Kernel] C lexer rejects ISO C99/C11 universal character names
# (\uXXXX and \UXXXXXXXX) in character and string literals.
#
# Images: framac-master-audit:189053d (master 189053d4a2, before),
#         framac-analysis:latest (34.0~beta), and the master tree with
#         ../patches/83-kernel-clexer-universal-char-names.patch built and installed (after).
# Command, from this directory:
#   docker run --rm -v "$PWD:/w" -w /w --entrypoint sh <image> \
#     83-kernel-clexer-universal-char-names.sh
#
# Output before (master 189053d4a2; 34.0~beta prints the same with
# "34.0~beta (Selenium)"):
#   35.0~~dev (Bromine)
#   valid: exit 1 (none, invalid_lines=0) ([kernel] 83-kernel-clexer-universal-char-names.c:3: User Error: )
#   surrogate: exit 1 (  Unrecognized escape sequence: \u:)
#   low: exit 1 (  Unrecognized escape sequence: \u:)
#   high: exit 1 (  Unrecognized escape sequence: \U:)
#   RESULT: bug present (4 of 4 cases fail)
#
# Output after (master 189053d4a2 + patches/83-kernel-clexer-universal-char-names.patch):
#   35.0~~dev (Bromine)
#   valid: exit 0 (    Assertions        4 valid     0 unknown     0 invalid      4 total, invalid_lines=0) 
#   surrogate: rejected exit 1 (  Invalid universal character name: \uD800:)
#   low: rejected exit 1 (  Invalid universal character name: \u0041:)
#   high: rejected exit 1 (  Invalid universal character name: \U00110000:)
#   RESULT: fixed
set -u
command -v frama-c >/dev/null 2>&1 || { echo "frama-c is not in PATH" >&2; exit 2; }
n=83-kernel-clexer-universal-char-names
tmp=$(mktemp -d)
fail=0
total=0
frama-c -version

total=$((total + 1))
frama-c -eva -cpp-extra-args="-DCASE_valid" "$n.c" > "$tmp/valid.log" 2>&1
rc=$?
summary=$(grep -E 'Assertions[[:space:]]+[0-9]+ valid' "$tmp/valid.log" | head -n 1)
inv=$(grep -c 'check got status invalid' "$tmp/valid.log")
err=$(grep -E 'User Error:' "$tmp/valid.log" | head -n 1)
echo "valid: exit $rc (${summary:-none}, invalid_lines=$inv) ${err:+($err)}"
if [ "$rc" != 0 ] || [ "$inv" != 0 ] || ! echo "$summary" | grep -qE 'Assertions[[:space:]]+4 valid[[:space:]]+0 unknown[[:space:]]+0 invalid[[:space:]]+4 total'; then
  fail=$((fail + 1))
fi

for c in surrogate low high; do
  total=$((total + 1))
  frama-c -no-autoload-plugins -cpp-extra-args="-DCASE_$c" "$n.c" > "$tmp/$c.log" 2>&1
  rc=$?
  msg=$(grep -E 'Invalid universal character name|Unrecognized escape sequence' "$tmp/$c.log" | head -n 1)
  if [ "$rc" = 1 ] && grep -q 'Invalid universal character name' "$tmp/$c.log"; then
    printf '%s: rejected exit 1 (%s)\n' "$c" "$msg"
  else
    printf '%s: exit %s (%s)\n' "$c" "$rc" "${msg:-unexpected}"
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
