#!/bin/bash
# Build QCBOR (from $1) with ASan+UBSan, ASan, UBSan, MSan and no
# sanitizer, and run every reproducer in this directory against it.
# usage: run_all.sh <qcbor-tree> <build-dir> [tests]
#   <qcbor-tree>  a checkout of the QCBOR dev branch (patched or not)
#   tests         also build and run QCBOR's own test suite under the
#                 sanitizers and list the distinct UB sites it hits
# Needs clang (tested with 19.1.7) on Linux x86_64. MSan inside Docker
# needs --security-opt seccomp=unconfined.
# float_shift_v1.c is for the 1.x master branch and is built by hand:
#   clang -g -O1 -fsanitize=undefined -I<v1>/inc -I<v1>/src float_shift_v1.c <v1>/src/*.c -lm
set -u
SRC=$1
OUT=$2
WANT_TESTS=${3:-}
REPRO=$(dirname "$0")
CC=${CC:-clang}
mkdir -p "$OUT"

declare -A FLAGS=(
  [asan]="-g -O1 -fno-omit-frame-pointer -fsanitize=address,undefined -fno-sanitize-recover=all"
  [asanonly]="-g -O1 -fno-omit-frame-pointer -fsanitize=address"
  [ubsan]="-g -O1 -fsanitize=undefined"
  [msan]="-g -O1 -fno-omit-frame-pointer -fsanitize=memory -fsanitize-memory-track-origins=2"
  [plain]="-g -O0"
)

build_lib() {  # $1 = config
  local cfg=$1 d="$OUT/obj-$1"
  mkdir -p "$d"
  for f in "$SRC"/src/*.c; do
    $CC ${FLAGS[$cfg]} -I"$SRC/inc" -I"$SRC/src" -c "$f" -o "$d/$(basename "$f" .c).o" || return 1
  done
  ar rcs "$OUT/libqcbor-$cfg.a" "$d"/*.o
}

link() {  # $1 = config, $2 = repro name
  $CC ${FLAGS[$1]} -I"$SRC/inc" -I"$SRC/src" "$REPRO/$2.c" "$OUT/libqcbor-$1.a" -lm -o "$OUT/$2.$1"
}

run() {  # $1 = binary, rest = args
  local b=$1; shift
  echo "----- $(basename "$b") $*"
  "$b" "$@" 2>&1 | grep -v "^    #[2-9][0-9]* \|^    #1[0-9] " | head -40
  echo "exit=${PIPESTATUS[0]}"
}

for cfg in asan asanonly ubsan msan plain; do build_lib $cfg || { echo "lib build failed: $cfg"; exit 1; }; done

for r in bignum_zero bignum_borrowed bignum_negzero outbuf_compare encodehead int64min getarray_empty float_shift; do
  link asan $r; link plain $r
done
link asanonly outbuf_compare
link asanonly encodehead
link ubsan float_shift
link msan epoch_uninit
link msan getarray_empty

echo "===== C1 all-zero big number"
run "$OUT/bignum_zero.plain"
run "$OUT/bignum_zero.asan"
echo "===== NEW borrowed positive big number"
run "$OUT/bignum_borrowed.plain"
echo "===== NEW negative zero big number"
run "$OUT/bignum_negzero.plain"
echo "===== C2 float shifts (UBSan, recoverable)"
for m in enc-double enc-float dec-single dec-double; do run "$OUT/float_shift.ubsan" $m; done
echo "===== C3 UsefulOutBuf_Compare"
run "$OUT/outbuf_compare.asan"
run "$OUT/outbuf_compare.asanonly"
echo "===== C4 epoch outputs (MSan)"
for m in latched days-latched notfound-n notfound-sz days-notfound; do run "$OUT/epoch_uninit.msan" $m; done
echo "===== EncodeHead uMinLen > 8"
run "$OUT/encodehead.asan"
run "$OUT/encodehead.asanonly"
echo "===== QCBOR-01 INT64_MIN"
run "$OUT/int64min.asan"
echo "===== NEW GetArray/GetMap on empty container"
for m in top nested map indef; do run "$OUT/getarray_empty.plain" $m; done
for m in top nested map indef; do run "$OUT/getarray_empty.msan" $m; done

if [ -n "$WANT_TESTS" ]; then
  echo "===== QCBOR test suite, ASan + recoverable UBSan: distinct UB sites"
  $CC ${FLAGS[ubsan]} -fsanitize=address -I"$SRC/inc" -I"$SRC/src" -I"$SRC/test" -I"$SRC" "$SRC"/src/*.c "$SRC"/test/*.c \
      "$SRC"/cmd_line_main.c "$SRC"/example.c "$SRC"/tag-examples.c "$SRC"/ub-example.c -lm -o "$OUT/qcbortest.ubrec" \
    && { "$OUT/qcbortest.ubrec" > "$OUT/qcbortest.ubrec.log" 2>&1; echo "exit=$?";
         grep "runtime error" "$OUT/qcbortest.ubrec.log" | sed 's/^.*\/src\//src\//' | sort | uniq -c;
         grep "FAILED\|tests failed" "$OUT/qcbortest.ubrec.log" | head; }
  for cfg in asan msan; do
    echo "===== QCBOR test suite ($cfg)"
    $CC ${FLAGS[$cfg]} -I"$SRC/inc" -I"$SRC/src" -I"$SRC/test" -I"$SRC" "$SRC"/test/*.c "$SRC"/cmd_line_main.c \
        "$SRC"/example.c "$SRC"/tag-examples.c "$SRC"/ub-example.c \
        "$OUT/libqcbor-$cfg.a" -lm -o "$OUT/qcbortest.$cfg" || { echo "test build failed"; continue; }
    "$OUT/qcbortest.$cfg" > "$OUT/qcbortest.$cfg.log" 2>&1
    echo "exit=$?"
    grep -i "fail\|error:\|runtime error\|Sanitizer" "$OUT/qcbortest.$cfg.log" | head -20
    tail -3 "$OUT/qcbortest.$cfg.log"
  done
fi
