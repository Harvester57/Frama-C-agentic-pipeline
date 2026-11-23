#!/bin/sh
# Issue 77: [Kernel] Wide-string printer emits invalid/miscompiled \u escapes,
# crashes above 2^32, and resets trigraph state per character.
#
# Images: framac-master-audit:189053d (master 189053d4a2, before),
#         framac-analysis:latest (34.0~beta), and the master tree with
#         ../patches/77-kernel-wstring-escape-trigraph.patch built and installed (after).
#
# Output before (master 189053d4a2; 34.0~beta prints the same with
# "34.0~beta (Selenium)"):
#   35.0~~dev (Bromine)
#   wstring_gcc_c99: a=20ac b=1f60/8 c=1f60,30/12 e=1100 t=6:61,7c,62,0,0
#   wstring_clang_c99: a=20ac b=1f60/8 c=1f60,30/12 e=1100 t=6:61,7c,62,0,0
#   wstring_eacsl: a=20ac b=1f60/8 c=1f60,30/12 e=1100 t=6:61,7c,62,0,0
#   surrogate_gcc: compile failed (... error: \ud800 is not a valid universal character)
#   wstring_reparse: reparse failed
#   huge_no_crash: print exit 125 (Unexpected error (Invalid_argument("Cprint.escape_string_intlist")).)
#   RESULT: bug present (6 of 6 cases fail)
#
# Output after (master 189053d4a2 + patches/77-kernel-wstring-escape-trigraph.patch):
#   35.0~~dev (Bromine)
#   wstring_gcc_c99: a=20ac b=1f600/8 c=1f600,41/12 e=110000 t=6:61,3f,3f,21,62
#   wstring_clang_c99: a=20ac b=1f600/8 c=1f600,41/12 e=110000 t=6:61,3f,3f,21,62
#   wstring_eacsl: a=20ac b=1f600/8 c=1f600,41/12 e=110000 t=6:61,3f,3f,21,62
#   surrogate_gcc: d=d800/8
#   wstring_reparse: reparse ok
#   huge_no_crash: print exit 0
#   RESULT: fixed
set -u
command -v frama-c >/dev/null 2>&1 || { echo "frama-c is not in PATH" >&2; exit 2; }
command -v gcc >/dev/null 2>&1 || { echo "gcc is not in PATH" >&2; exit 2; }
EG=$(command -v e-acsl-gcc || command -v e-acsl-gcc.sh) || { echo "e-acsl-gcc is not in PATH" >&2; exit 2; }
n=77-kernel-wstring-escape-trigraph
tmp=$(mktemp -d)
fail=0
total=0
frama-c -version

check() {
  total=$((total + 1))
  echo "$1: $3"
  [ "$3" = "$2" ] || fail=$((fail + 1))
}

gcc -std=c99 -DCASE_run "$n.c" -o "$tmp/run_ref" && ref_run=$("$tmp/run_ref")
gcc -std=c99 -DCASE_surrogate "$n.c" -o "$tmp/sur_ref" && ref_sur=$("$tmp/sur_ref")

# 1. -print -ocode -> gcc -std=c99 (covers >0xFFFF, hex-digit adjacency, >0x10FFFF, trigraph)
frama-c -machdep gcc_x86_64 -no-frama-c-stdlib -cpp-extra-args="-DCASE_run" \
  "$n.c" -print -ocode "$tmp/run_out.c" >/dev/null 2>&1
if gcc -std=c99 "$tmp/run_out.c" -o "$tmp/run_out" 2>"$tmp/err.log"; then
  got=$("$tmp/run_out")
else
  got="compile failed"
fi
check wstring_gcc_c99 "$ref_run" "$got"

if command -v clang >/dev/null 2>&1; then
  if clang -std=c99 "$tmp/run_out.c" -o "$tmp/run_out_cl" 2>"$tmp/err.log"; then
    got=$("$tmp/run_out_cl")
  else
    got="compile failed"
  fi
  check wstring_clang_c99 "$ref_run" "$got"
fi

# 2. e-acsl-gcc -c (compiles with -std=c99)
if "$EG" -q -c -E "-DCASE_run" -e "-DCASE_run" \
    -o "$tmp/run.gen.c" -O "$tmp/run_e" "$n.c" >"$tmp/err.log" 2>&1; then
  got=$("$tmp/run_e.e-acsl")
else
  got="build failed"
fi
check wstring_eacsl "$ref_run" "$got"

# 3. surrogate L"\xD800" -> gcc
frama-c -machdep gcc_x86_64 -no-frama-c-stdlib -cpp-extra-args="-DCASE_surrogate" \
  "$n.c" -print -ocode "$tmp/sur_out.c" >/dev/null 2>&1
if gcc -std=c99 "$tmp/sur_out.c" -o "$tmp/sur_out" 2>"$tmp/err.log"; then
  got=$("$tmp/sur_out")
else
  err=$(grep -m1 "error:" "$tmp/err.log")
  got="compile failed ($err)"
fi
check surrogate_gcc "$ref_sur" "$got"

# 4. Frama-C re-parse of printed wide literals
frama-c -cpp-extra-args="-DCASE_reparse" "$n.c" -print -ocode "$tmp/rep_out.c" >/dev/null 2>&1
if frama-c "$tmp/rep_out.c" >/dev/null 2>"$tmp/err.log"; then
  got="reparse ok"
else
  got="reparse failed"
fi
check wstring_reparse "reparse ok" "$got"

# 5. >= 2^32 (L"\x100000000") must not crash
frama-c -cpp-extra-args="-DCASE_huge" "$n.c" -print >"$tmp/huge.log" 2>&1
rc=$?
if [ "$rc" = 0 ]; then
  got="print exit 0"
else
  err=$(grep -oE 'Unexpected error.*' "$tmp/huge.log" | head -n 1)
  got="print exit $rc (${err:-failed})"
fi
check huge_no_crash "print exit 0" "$got"

rm -rf "$tmp"
if [ "$fail" = 0 ]; then
  echo "RESULT: fixed"
  exit 0
else
  echo "RESULT: bug present ($fail of $total cases fail)"
  exit 1
fi
