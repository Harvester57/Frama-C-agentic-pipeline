#!/bin/sh
# Issue 36: e-acsl-gcc --zone-sizes heap:<n> (and stack:<n>, thread-stack:<n>)
# for n >= 2048: the segment-model runtime multiplies the size in MB by
# MB = 1024 * 1024 in `int` arithmetic. 2048 * MB overflows; gcc warns
# "integer overflow in expression of type 'int' results in '-2147483648'".
# Every run of the instrumented program then crashes at start-up (heap:2048
# to heap:4095, stack:2048), or gets a heap of (n mod 4096) MB (heap:4096
# gives an empty heap, heap:4097 a 1 MB heap: the 2 MB malloc below aborts).
#
# Images: framac-master-audit:9540804 (35.0~~dev, master 95408044f7) and
# framac-analysis:latest (34.0~beta). From the repro directory:
#   docker run --rm -v "$PWD:/w" -w /w --entrypoint sh <image> \
#     36-eacsl-heap-zone-size-overflow.sh
# Optional: EACSL_SHARE=<dir> passes --e-acsl-share=<dir> to e-acsl-gcc (a
# patched copy of share/frama-c/share/e-acsl).
#
# The program allocates and writes 2 MB. Output on master 95408044f7
# (34.0~beta prints the same after its version line; paths shortened):
#   35.0~~dev (Bromine)
#   gcc heap:1024: exit 0
#   gcc heap:2047: exit 0
#   gcc heap:2048: exit 139 Segmentation fault
#   gcc heap:4095: exit 139 Segmentation fault
#   gcc heap:4096: exit 134 e_acsl_segment_tracking.c:528: Exceeded heap allocation limit of 4096MB -- heap memory space moved. Aborted
#   gcc heap:4097: exit 134 e_acsl_segment_tracking.c:528: Exceeded heap allocation limit of 4097MB -- heap memory space moved. Aborted
#   gcc stack:2047: exit 0
#   gcc stack:2048: exit 139 Segmentation fault
#   gcc: int overflow warnings for heap:2048: 1
#   clang heap:1024: exit 0
#   clang heap:2047: exit 0
#   clang heap:2048: exit 139 Segmentation fault
#   clang heap:4095: exit 139 Segmentation fault
#   clang heap:4096: exit 134 e_acsl_segment_tracking.c:532: Exceeded heap allocation limit of 4096MB -- heap memory space moved. Aborted
#   clang heap:4097: exit 134 e_acsl_segment_tracking.c:532: Exceeded heap allocation limit of 4097MB -- heap memory space moved. Aborted
#   clang stack:2047: exit 0
#   clang stack:2048: exit 139 Segmentation fault
#   clang: int overflow warnings for heap:2048: 0
# (clang prints no warning because e-acsl-gcc drops the warning flags under
# -G clang, #2810.)
#
# Output with the proposed fix (master + patch 36): every line "exit 0", and
# "int overflow warnings for heap:2048: 0" for both compilers.
set -u
src=36-eacsl-heap-zone-size-overflow.c
tmp=$(mktemp -d)
share=${EACSL_SHARE:+--e-acsl-share=$EACSL_SHARE}
frama-c -version
for cc in gcc clang; do
  for z in heap:1024 heap:2047 heap:2048 heap:4095 heap:4096 heap:4097 \
           stack:2047 stack:2048; do
    # shellcheck disable=SC2086
    if ! e-acsl-gcc -c $share -G "$cc" --zone-sizes "$z" -o "$tmp/i.c" \
           -O "$tmp/t" "$src" > "$tmp/build-$z.log" 2>&1; then
      echo "$cc $z: e-acsl-gcc failed"; continue
    fi
    prlimit --core=1:1 "$tmp/t.e-acsl" > "$tmp/run.log" 2>&1
    status=$?
    msg=$(sed -e 's/^.*share\/e-acsl\/observation_model\/segment_model\///' \
              "$tmp/run.log" | tr '\n' ' ' | tr -s ' ')
    echo "$cc $z: exit $status $msg"
  done
  echo "$cc: int overflow warnings for heap:2048:" \
       "$(grep -c 'integer overflow' "$tmp/build-heap:2048.log")"
done
rm -rf "$tmp"
