#!/bin/sh
# Issue 43: [E-ACSL] a real constant that is not exactly a double is only read
# when it is a plain decimal expansion. With an exponent (1e-9) or in
# hexadecimal notation, Frama-C stops on an unexpected error. With a suffix
# (0.1L), the constant is 0 at run time, without any message.
#
# Images: framac-master-audit:9540804 with its tree moved to master b80fcac74f
#         (before), framac-analysis:latest (34.0~beta), and the master tree
#         with ../patches/43-eacsl-real-constant-notation.patch built and
#         installed (after).
# Command, from this directory:
#   docker run --rm -v "$PWD:/w" -w /w --entrypoint sh <image> \
#     43-eacsl-real-constant-notation.sh
# The program that aborts is run under prlimit --core=0.
#
# Output before (master b80fcac74f):
#   35.0~~dev (Bromine)
#   exponent: build stops: Unexpected error (E_ACSL__Gmp.Q.Not_a_decimal("1e-1")).
#   tolerance: build stops: Unexpected error (E_ACSL__Gmp.Q.Not_a_decimal("1e-9")).
#   exponent_false: build stops: Unexpected error (E_ACSL__Gmp.Q.Not_a_decimal("1e-1")).
#   hexadecimal: build stops: Unexpected error (E_ACSL__Gmp.Q.Not_a_decimal("0x1.00000000000000001p0")).
#   long_double: built, run exit 134
#   long_double_false: built, run exit 0
#   RESULT: bug present (6 of 6 cases fail)
#
# Output after:
#   35.0~~dev (Bromine)
#   exponent: built, run exit 0
#   tolerance: built, run exit 0
#   exponent_false: built, run exit 134
#   hexadecimal: built, run exit 0
#   long_double: built (annotation ignored: not yet supported), run exit 0
#   long_double_false: built (annotation ignored: not yet supported), run exit 0
#   RESULT: fixed
#
# Before, "0.1L > 0.05" (true) aborts and "0.1L == 0" (false) holds: the
# generated code calls __gmpq_set_str(q, "0.1L", 10), which fails and leaves 0.
# After, E-ACSL says that it does not check these two annotations.
set -u
command -v frama-c >/dev/null 2>&1 || { echo "frama-c is not in PATH" >&2; exit 2; }
EG=$(command -v e-acsl-gcc || command -v e-acsl-gcc.sh) || { echo "e-acsl-gcc is not in PATH" >&2; exit 2; }
n=43-eacsl-real-constant-notation
tmp=$(mktemp -d)
fail=0
frama-c -version
run() { # $1: case, $2: the line expected once fixed
  if "$EG" -c -E "-DCASE_$1" -o "$tmp/$1.c" -O "$tmp/$1" "$n.c" > "$tmp/build.log" 2>&1; then
    got="built"
    grep -q 'not yet supported' "$tmp/build.log" \
      && got="built (annotation ignored: not yet supported)"
    prlimit --core=0 "$tmp/$1.e-acsl" > "$tmp/run.log" 2>&1
    got="$got, run exit $?"
  else
    got="build stops: $(grep -o 'Unexpected error.*' "$tmp/build.log" | head -n 1)"
  fi
  echo "$1: $got"
  [ "$got" = "$2" ] || fail=$((fail + 1))
}
run exponent 'built, run exit 0'
run tolerance 'built, run exit 0'
run exponent_false 'built, run exit 134'
run hexadecimal 'built, run exit 0'
run long_double 'built (annotation ignored: not yet supported), run exit 0'
run long_double_false 'built (annotation ignored: not yet supported), run exit 0'
rm -rf "$tmp"
if [ "$fail" = 0 ]; then echo "RESULT: fixed"; exit 0
else echo "RESULT: bug present ($fail of 6 cases fail)"; exit 1
fi
