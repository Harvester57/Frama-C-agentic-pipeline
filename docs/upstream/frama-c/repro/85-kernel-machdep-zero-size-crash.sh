#!/bin/sh
# Issue 85: [Kernel] Custom YAML machdep with non-positive type size or alignment
# (e.g. sizeof_int: 0) crashes Frama-C with Invalid_argument("Z.shift_left: count
# argument must be positive") instead of reporting a user error.
#
# Images: framac-master-audit:189053d (master 189053d4a2, before),
#         framac-analysis:latest (34.0~beta), and the master tree with
#         ../patches/85-kernel-machdep-zero-size-crash.patch built and installed (after).
# Command, from this directory:
#   docker run --rm -v "$PWD:/w" -w /w --entrypoint sh <image> \
#     85-kernel-machdep-zero-size-crash.sh
#
# Output before (master 189053d4a2; 34.0~beta prints the same with
# "34.0~beta (Selenium)"):
#   35.0~~dev (Bromine)
#   sizeof_int_0: exit 125 ([kernel] Unexpected error (Invalid_argument("Z.shift_left: count argument must be positive")).)
#   sizeof_long_neg: exit 125 ([kernel] Unexpected error (Invalid_argument("Z.shift_left: count argument must be positive")).)
#   alignof_ptr_0: exit 0 (accepted without error)
#   RESULT: bug present (3 of 3 cases fail)
#
# Output after (master 189053d4a2 + patches/85-kernel-machdep-zero-size-crash.patch):
#   35.0~~dev (Bromine)
#   sizeof_int_0: exit 1 ([kernel] User Error: Error during machdep parsing: Field sizeof_int must be strictly positive (got 0))
#   sizeof_long_neg: exit 1 ([kernel] User Error: Error during machdep parsing: Field sizeof_long must be strictly positive (got -1))
#   alignof_ptr_0: exit 1 ([kernel] User Error: Error during machdep parsing: Field alignof_ptr must be strictly positive (got 0))
#   RESULT: fixed
set -u
command -v frama-c >/dev/null 2>&1 || { echo "frama-c is not in PATH" >&2; exit 2; }
n=85-kernel-machdep-zero-size-crash
tmp=$(mktemp -d)
fail=0
total=0
frama-c -version

share=$(frama-c -print-share-path)
base="$share/machdeps/machdep_x86_64.yaml"
if [ ! -f "$base" ]; then
  echo "base machdep not found: $base" >&2
  rm -rf "$tmp"
  exit 2
fi

run_case() {
  total=$((total + 1))
  name=$1
  pattern=$2
  sed "$pattern" "$base" > "$tmp/$name.yaml"
  frama-c -no-autoload-plugins -machdep "$tmp/$name.yaml" "$n.c" > "$tmp/$name.log" 2>&1
  rc=$?
  crash=$(grep -E 'Unexpected error|Invalid_argument' "$tmp/$name.log" | head -n 1)
  uerr=$(grep -E 'User Error: Error during machdep parsing:' "$tmp/$name.log" | head -n 1)
  if [ "$rc" = 1 ] && [ -z "$crash" ] && [ -n "$uerr" ]; then
    echo "$name: exit 1 ($uerr)"
  else
    echo "$name: exit $rc (${crash:-${uerr:-accepted without error}})"
    fail=$((fail + 1))
  fi
}

run_case sizeof_int_0 's/^sizeof_int: .*/sizeof_int: 0/'
run_case sizeof_long_neg 's/^sizeof_long: .*/sizeof_long: -1/'
run_case alignof_ptr_0 's/^alignof_ptr: .*/alignof_ptr: 0/'

rm -rf "$tmp"
if [ "$fail" = 0 ]; then
  echo "RESULT: fixed"
  exit 0
else
  echo "RESULT: bug present ($fail of $total cases fail)"
  exit 1
fi
