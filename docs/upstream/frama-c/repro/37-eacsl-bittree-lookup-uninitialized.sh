#!/bin/sh
# Issue 37: in the bittree memory model, pt_lookup() (the exact-address
# lookup behind bt_lookup) never assigns its result when it finds the block,
# and eacsl_memory_clean() crashes when no block was ever stored.
#  - 37-...-empty.c, `int main(void) { return 0; }`: stores no block without
#    -M, and its cleanup dereferences a NULL tree (segmentation fault).
#  - 37-....c: every operation that looks a block up by its start address
#    (full_init, mark_readonly, \freeable, delete_block, free) gets an
#    uninitialized pointer. With gcc -O2 it behaves as "not found" (checks
#    fail, free aborts); without optimisation (-G clang, which loses -O2,
#    #2810; or --rt-debug) it is garbage, and the program crashes.
# The segment model (default) is not affected.
#
# Images: framac-master-audit:9540804 (35.0~~dev, master 95408044f7) and
# framac-analysis:latest (34.0~beta). From the repro directory:
#   docker run --rm -v "$PWD:/w" -w /w --entrypoint sh <image> \
#     37-eacsl-bittree-lookup-uninitialized.sh
# Optional: EACSL_SHARE=<dir> passes --e-acsl-share=<dir> to e-acsl-gcc.
#
# Output on master 95408044f7 (34.0~beta prints the same after its version
# line). The 8 segment lines are all "exit 0; failed checks: none; -" and are
# left out; "e" is 37-eacsl-bittree-lookup-uninitialized-empty.c and "l" is
# 37-eacsl-bittree-lookup-uninitialized.c:
#   35.0~~dev (Bromine)
#   e -m bittree: exit 139; failed checks: none; Segmentation fault
#   l -m bittree: exit 134; failed checks: RO IN_SCOPE OUT_OF_SCOPE FREEABLE ; Not a start of block (0x...) in free
#   e -m bittree -M: exit 0; failed checks: none; -
#   l -m bittree -M: exit 134; failed checks: RO IN_SCOPE OUT_OF_SCOPE FREEABLE ; Not a start of block (0x...) in free
#   e -m bittree -G clang: exit 139; failed checks: none; Segmentation fault
#   l -m bittree -G clang: exit 134; failed checks: none; -
#   e -m bittree -G clang -M: exit 134; failed checks: none; -
#   l -m bittree -G clang -M: exit 134; failed checks: none; -
# (The clang aborts come from the allocator, which is handed garbage by
# full_init or free, before any check runs.)
#
# Output with the proposed fix (master + patch 37): all 16 lines
# "exit 0; failed checks: none; -".
set -u
n=37-eacsl-bittree-lookup-uninitialized
tmp=$(mktemp -d)
share=${EACSL_SHARE:+--e-acsl-share=$EACSL_SHARE}
frama-c -version
run() { # <source> <e-acsl-gcc options>...
  src=$1; shift
  # shellcheck disable=SC2086
  if ! e-acsl-gcc -q -c $share "$@" -o "$tmp/i.c" -O "$tmp/t" "$src" \
         > "$tmp/build.log" 2>&1; then
    echo "$src $*: e-acsl-gcc failed"; return
  fi
  prlimit --core=1:1 "$tmp/t.e-acsl" > "$tmp/run.log" 2>&1
  status=$?
  # names of the failed checks, and the last line (crash or abort message)
  failed=$(grep -A2 'Assertion failed' "$tmp/run.log" |
             sed -n -e 's/^[[:space:]]*\([A-Z_]*\):$/\1/p' | tr '\n' ' ')
  last=$(grep -v -e '^[[:space:]]' -e 'Assertion failed' -e 'In function' \
           -e '^Aborted' "$tmp/run.log" | tail -1 | sed -e 's/0x[0-9a-f-]*/0x.../')
  echo "$src $*: exit $status; failed checks: ${failed:-none}; ${last:--}"
}
for m in segment bittree; do
  for opts in "" "-M" "-G clang" "-G clang -M"; do
    # shellcheck disable=SC2086
    run "$n-empty.c" -m $m $opts
    # shellcheck disable=SC2086
    run "$n.c" -m $m $opts
  done
done
rm -rf "$tmp"
