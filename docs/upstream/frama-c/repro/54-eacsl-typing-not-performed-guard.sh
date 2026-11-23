#!/bin/sh
# Issue 54: [E-ACSL] Internal error "typing was not performed" on quantifiers
# with unsupported guards and on binary operations / libc contracts (stpncpy,
# strlcat) where an unsupported subterm short-circuits Typing before sibling
# subterms or quantifier goals are typed.
#
# Images: framac-master-audit:189053d (master 189053d4a2, before),
#         framac-analysis:latest (34.0~beta), and the master tree with
#         ../patches/54-eacsl-typing-not-performed-guard.patch built
#         and installed (after).
# Command, from this directory:
#   docker run --rm -v "$PWD:/w" -w /w --entrypoint sh <image> \
#     54-eacsl-typing-not-performed-guard.sh
#
# Output before (master 189053d4a2 and 34.0~beta, exit 1):
#   35.0~~dev (Bromine)  [or: 34.0~beta (Selenium)]
#   quant: aborted exit 4: Failure: typing was not performed on construct 0
#   binop_reads: aborted exit 4: Failure: typing was not performed on construct 1
#   stpncpy: aborted exit 4: Failure: typing was not performed on construct 1
#   strlcat: aborted exit 4: Failure: typing was not performed on construct 1
#   RESULT: bug present (4 of 4 cases fail)
#
# Output after (patched master, exit 0):
#   35.0~~dev (Bromine)
#   quant: ok (exit 0)
#   binop_reads: ok (exit 0)
#   stpncpy: ok (exit 0)
#   strlcat: ok (exit 0)
#   RESULT: fixed
set -u
command -v frama-c >/dev/null 2>&1 || { echo "frama-c is not in PATH" >&2; exit 2; }
n=54-eacsl-typing-not-performed-guard
tmp=$(mktemp -d)
fail=0
total=0
frama-c -version
run() { # $1: case, $2: expected line once fixed
  total=$((total + 1))
  c=$1
  expect=$2
  frama-c -cpp-extra-args="-DCASE_$c" "$n.c" -e-acsl -then-last -print -ocode "$tmp/$c.gen.c" > "$tmp/$c.log" 2>&1
  rc=$?
  if [ "$rc" = 0 ]; then
    got="ok (exit 0)"
  else
    err=$(grep -oE 'Failure: typing was not performed on construct [^ ]+' "$tmp/$c.log" | head -n 1)
    got="aborted exit $rc: ${err:-unknown}"
  fi
  echo "$c: $got"
  [ "$got" = "$expect" ] || fail=$((fail + 1))
}
run quant 'ok (exit 0)'
run binop_reads 'ok (exit 0)'
run stpncpy 'ok (exit 0)'
run strlcat 'ok (exit 0)'
rm -rf "$tmp"
if [ "$fail" = 0 ]; then echo "RESULT: fixed"; exit 0
else echo "RESULT: bug present ($fail of $total cases fail)"; exit 1
fi
