#!/bin/sh
# Issue 79: [Kernel] __int128 and unsigned __int128 constants printed with LL/ULL
# suffix are silently truncated by gcc/clang and rejected on Frama-C re-parse.
#
# Images: framac-master-audit:189053d (master 189053d4a2, before),
#         framac-analysis:latest (34.0~beta), and the master tree with
#         ../patches/79-kernel-int128-const-printing.patch built and installed (after).
#
# Output before (master 189053d4a2; 34.0~beta prints the same with
# "34.0~beta (Selenium)"):
#   35.0~~dev (Bromine)
#   int128_gcc: 0 5 | 0 ffffffffffffffff | ffffffffffffffff 0 | ffffffffffffffff fffffffffffffffb | 0 2a
#   int128_clang: compile failed
#   int128_reparse: reparse failed
#   int128_eacsl: 0 5 | 0 ffffffffffffffff | ffffffffffffffff 0 | ffffffffffffffff fffffffffffffffb | 0 2a
#   RESULT: bug present (4 of 4 cases fail)
#
# Output after (master 189053d4a2 + patches/79-kernel-int128-const-printing.patch):
#   35.0~~dev (Bromine)
#   int128_gcc: 1000000000 5 | ffffffffffffffff ffffffffffffffff | 8000000000000000 0 | ffffffefffffffff fffffffffffffffb | 0 2a
#   int128_clang: 1000000000 5 | ffffffffffffffff ffffffffffffffff | 8000000000000000 0 | ffffffefffffffff fffffffffffffffb | 0 2a
#   int128_reparse: reparse ok
#   int128_eacsl: 1000000000 5 | ffffffffffffffff ffffffffffffffff | 8000000000000000 0 | ffffffefffffffff fffffffffffffffb | 0 2a
#   RESULT: fixed
set -u
command -v frama-c >/dev/null 2>&1 || { echo "frama-c is not in PATH" >&2; exit 2; }
command -v gcc >/dev/null 2>&1 || { echo "gcc is not in PATH" >&2; exit 2; }
EG=$(command -v e-acsl-gcc || command -v e-acsl-gcc.sh) || { echo "e-acsl-gcc is not in PATH" >&2; exit 2; }
n=79-kernel-int128-const-printing
tmp=$(mktemp -d)
fail=0
total=0
frama-c -version

check() {
  total=$((total + 1))
  echo "$1: $3"
  [ "$3" = "$2" ] || fail=$((fail + 1))
}

gcc "$n.c" -o "$tmp/ref" && ref=$("$tmp/ref")

# 1. -constfold -print -ocode -> gcc, clang, Frama-C re-parse
frama-c -machdep gcc_x86_64 -no-frama-c-stdlib -constfold "$n.c" \
  -print -ocode "$tmp/out.c" >/dev/null 2>&1

if gcc -Wall -Wextra "$tmp/out.c" -o "$tmp/out_gcc" 2>"$tmp/err.log"; then
  got=$("$tmp/out_gcc")
else
  got="compile failed"
fi
check int128_gcc "$ref" "$got"

if command -v clang >/dev/null 2>&1; then
  if clang -Wall -Wextra "$tmp/out.c" -o "$tmp/out_cl" 2>"$tmp/err.log"; then
    got=$("$tmp/out_cl")
  else
    got="compile failed"
  fi
  check int128_clang "$ref" "$got"
fi

if frama-c -machdep gcc_x86_64 -no-frama-c-stdlib "$tmp/out.c" >/dev/null 2>"$tmp/err.log"; then
  got="reparse ok"
else
  got="reparse failed"
fi
check int128_reparse "reparse ok" "$got"

# 2. default e-acsl-gcc (passes -constfold)
if "$EG" -q -c -F "-machdep gcc_x86_64" \
    -o "$tmp/e.gen.c" -O "$tmp/e" "$n.c" >"$tmp/err.log" 2>&1; then
  got=$("$tmp/e.e-acsl")
else
  got="build failed"
fi
check int128_eacsl "$ref" "$got"

rm -rf "$tmp"
if [ "$fail" = 0 ]; then
  echo "RESULT: fixed"
  exit 0
else
  echo "RESULT: bug present ($fail of $total cases fail)"
  exit 1
fi
