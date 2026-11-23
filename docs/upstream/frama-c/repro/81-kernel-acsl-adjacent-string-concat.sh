#!/bin/sh
# Issue 81: [Kernel] Adjacent string literals in ACSL annotations are concatenated
# as raw text before unescaping, turning "\x4" "1" into "\x41" ("A") and
# "\01" "2" into "\012" ("\n") (violating ISO C11 5.1.1.2p1 phase 6).
#
# Images: framac-master-audit:189053d (master 189053d4a2, before),
#         framac-analysis:latest (34.0~beta), and the master tree with
#         ../patches/81-kernel-acsl-adjacent-string-concat.patch built and installed (after).
# Command, from this directory:
#   docker run --rm -v "$PWD:/w" -w /w --entrypoint sh <image> \
#     81-kernel-acsl-adjacent-string-concat.sh
#
# Output before (master 189053d4a2; 34.0~beta prints the same with
# "34.0~beta (Selenium)"):
#   35.0~~dev (Bromine)
#   print exit: 0
#     /*@ check c1: (\let tmp = "A"; tmp[0]) ≡ 4; */ ;
#     /*@ check c2: (\let tmp = "\n"; tmp[0]) ≡ 1; */ ;
#     /*@ check c3: (\let tmp = "\\n"; tmp[0]) ≡ '\\'; */ ;
#     /*@ check c4: (\let tmp = L"A" ; tmp[0]) ≡ 4; */ ;
#     /*@ check c5: (\let tmp = L"\\n" ; tmp[0]) ≡ 1; */ ;
#   c1: MISMATCH (  /*@ check c1: (\let tmp = "A"; tmp[0]) ≡ 4; */ ;)
#   c2: MISMATCH (  /*@ check c2: (\let tmp = "\n"; tmp[0]) ≡ 1; */ ;)
#   c3: ok
#   c4: MISMATCH (  /*@ check c4: (\let tmp = L"A" ; tmp[0]) ≡ 4; */ ;)
#   c5: MISMATCH (  /*@ check c5: (\let tmp = L"\\n" ; tmp[0]) ≡ 1; */ ;)
#   RESULT: bug present (4 of 5 cases fail)
#
# Output after (master 189053d4a2 + patches/81-kernel-acsl-adjacent-string-concat.patch):
#   35.0~~dev (Bromine)
#   print exit: 0
#     /*@ check c1: (\let tmp = "\0041"; tmp[0]) ≡ 4; */ ;
#     /*@ check c2: (\let tmp = "\0012"; tmp[0]) ≡ 1; */ ;
#     /*@ check c3: (\let tmp = "\\n"; tmp[0]) ≡ '\\'; */ ;
#     /*@ check c4: (\let tmp = L"\\004" "1" ; tmp[0]) ≡ 4; */ ;
#     /*@ check c5: (\let tmp = L"\\001" "2" ; tmp[0]) ≡ 1; */ ;
#   c1: ok
#   c2: ok
#   c3: ok
#   c4: ok
#   c5: ok
#   RESULT: fixed
set -u
command -v frama-c >/dev/null 2>&1 || { echo "frama-c is not in PATH" >&2; exit 2; }
n=81-kernel-acsl-adjacent-string-concat
tmp=$(mktemp -d)
fail=0
total=0
frama-c -version

frama-c -no-autoload-plugins -print "$n.c" > "$tmp/out.log" 2>&1
rc=$?
echo "print exit: $rc"
grep -E 'check c[1-5]:' "$tmp/out.log"

check_line() {
  total=$((total + 1))
  tag=$1
  pat=$2
  line=$(grep -F "check $tag:" "$tmp/out.log" | head -n 1)
  if printf '%s\n' "$line" | grep -qF -- "$pat"; then
    printf '%s: ok\n' "$tag"
  else
    printf '%s: MISMATCH (%s)\n' "$tag" "$line"
    fail=$((fail + 1))
  fi
}

check_line c1 '"\0041"'
check_line c2 '"\0012"'
check_line c3 '"\\n"'
check_line c4 '004" "1"'
check_line c5 '001" "2"'

rm -rf "$tmp"
if [ "$rc" = 0 ] && [ "$fail" = 0 ]; then
  echo "RESULT: fixed"
  exit 0
else
  echo "RESULT: bug present ($fail of $total cases fail)"
  exit 1
fi
