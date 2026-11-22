#!/bin/sh
# Issue 50: [E-ACSL] --validate-format-strings crashes with Assert_failure in
# plugins/e-acsl/src/libraries/functions.ml:156 on enum arguments to printf-family
# functions, and with Options.fatal on pointers to enum (e.g. %n / %p).
#
# Images: framac-master-audit:189053d (master 189053d4a2, before),
#         framac-analysis:latest (34.0~beta), and the master tree with
#         ../patches/50-eacsl-format-enum-argument.patch built and installed (after).
# Command, from this directory:
#   docker run --rm -v "$PWD:/w" -w /w --entrypoint sh <image> \
#     50-eacsl-format-enum-argument.sh
# -M (full memory tracking) avoids an unrelated stop on literal format strings
# without it ("invalid format string (unallocated or unterminated)", #2821).
# The programs that abort are run under prlimit --core=0.
#
# Output before (master 189053d4a2; 34.0~beta prints the same with
# "34.0~beta (Selenium)"):
#   35.0~~dev (Bromine)
#   unsigned_enum: build stops: Unexpected error (File "plugins/e-acsl/src/libraries/functions.ml", line 156, characters 33-39: Assertion failed).
#   signed_enum: build stops: Unexpected error (File "plugins/e-acsl/src/libraries/functions.ml", line 156, characters 33-39: Assertion failed).
#   long_enum: build stops: Unexpected error (File "plugins/e-acsl/src/libraries/functions.ml", line 156, characters 33-39: Assertion failed).
#   typedef_const_bf: build stops: Unexpected error (File "plugins/e-acsl/src/libraries/functions.ml", line 156, characters 33-39: Assertion failed).
#   packed_enum: build stops: Unexpected error (File "plugins/e-acsl/src/libraries/functions.ml", line 156, characters 33-39: Assertion failed).
#   enum_ptr_n: build stops: Failure: unexpected argument type in printf: type enum S of arg & s
#   snprintf_enum: build stops: Unexpected error (File "plugins/e-acsl/src/libraries/functions.ml", line 156, characters 33-39: Assertion failed).
#   enums_int: build stops: Unexpected error (File "plugins/e-acsl/src/libraries/functions.ml", line 156, characters 33-39: Assertion failed).
#   mismatch_str: build stops: Unexpected error (File "plugins/e-acsl/src/libraries/functions.ml", line 156, characters 33-39: Assertion failed).
#   mismatch_width: build stops: Unexpected error (File "plugins/e-acsl/src/libraries/functions.ml", line 156, characters 33-39: Assertion failed).
#   mismatch_sign: build stops: Unexpected error (File "plugins/e-acsl/src/libraries/functions.ml", line 156, characters 33-39: Assertion failed).
#   mismatch_ptr_n: build stops: Failure: unexpected argument type in printf: type enum U of arg & u
#   RESULT: bug present (12 of 12 cases fail)
#
# Output after (master 189053d4a2 + patches/50-eacsl-format-enum-argument.patch):
#   35.0~~dev (Bromine)
#   unsigned_enum: built, run exit 0
#   signed_enum: built, run exit 0
#   long_enum: built, run exit 0
#   typedef_const_bf: built, run exit 0
#   packed_enum: built, run exit 0
#   enum_ptr_n: built, run exit 0
#   snprintf_enum: built, run exit 0
#   enums_int: built, run exit 0
#   mismatch_str: built, run exit 134 (printf: directive 1 ('%s') expects argument of type 'char*' but the corresponding argument has type 'int')
#   mismatch_width: built, run exit 134 (printf: directive 1 ('%lu') expects argument of type 'unsigned long' but the corresponding argument has type 'unsigned int')
#   mismatch_sign: built, run exit 134 (printf: directive 1 ('%d') expects argument of type 'int' but the corresponding argument has type 'unsigned int')
#   mismatch_ptr_n: built, run exit 134 (printf: directive 1 ('%n') expects argument of type 'int*' but the corresponding argument has type 'unsigned int*')
#   RESULT: fixed
set -u
command -v frama-c >/dev/null 2>&1 || { echo "frama-c is not in PATH" >&2; exit 2; }
EG=$(command -v e-acsl-gcc || command -v e-acsl-gcc.sh) || { echo "e-acsl-gcc is not in PATH" >&2; exit 2; }
n=50-eacsl-format-enum-argument
tmp=$(mktemp -d)
fail=0
total=0
frama-c -version
run() { # $1: case, $2: expected line once fixed, $3: extra e-acsl-gcc flags (optional)
  total=$((total + 1))
  c=$1
  expect=$2
  extra=${3:-}
  if "$EG" -q -c -M -G gcc --validate-format-strings $extra \
      -E "-DCASE_$c" -e "-DCASE_$c" \
      -o "$tmp/$c.c" -O "$tmp/$c" "$n.c" > "$tmp/build.log" 2>&1; then
    prlimit --core=0 "$tmp/$c.e-acsl" > "$tmp/run.log" 2>&1
    rc=$?
    msg=$(grep -E 'expects argument of type' "$tmp/run.log" | head -n 1)
    if [ -n "$msg" ]; then
      got="built, run exit $rc ($msg)"
    else
      got="built, run exit $rc"
    fi
  else
    brc=$?
    err=$(grep -oE 'Unexpected error.*|Failure: unexpected argument type.*' "$tmp/build.log" | head -n 1)
    got="build stops: ${err:-exit $brc}"
  fi
  echo "$c: $got"
  [ "$got" = "$expect" ] || fail=$((fail + 1))
}
run unsigned_enum 'built, run exit 0'
run signed_enum 'built, run exit 0'
run long_enum 'built, run exit 0'
run typedef_const_bf 'built, run exit 0'
run packed_enum 'built, run exit 0'
run enum_ptr_n 'built, run exit 0'
run snprintf_enum 'built, run exit 0'
run enums_int 'built, run exit 0' '-F -enums -F int'
run mismatch_str "built, run exit 134 (printf: directive 1 ('%s') expects argument of type 'char*' but the corresponding argument has type 'int')"
run mismatch_width "built, run exit 134 (printf: directive 1 ('%lu') expects argument of type 'unsigned long' but the corresponding argument has type 'unsigned int')"
run mismatch_sign "built, run exit 134 (printf: directive 1 ('%d') expects argument of type 'int' but the corresponding argument has type 'unsigned int')"
run mismatch_ptr_n "built, run exit 134 (printf: directive 1 ('%n') expects argument of type 'int*' but the corresponding argument has type 'unsigned int*')"
rm -rf "$tmp"
if [ "$fail" = 0 ]; then echo "RESULT: fixed"; exit 0
else echo "RESULT: bug present ($fail of $total cases fail)"; exit 1
fi
