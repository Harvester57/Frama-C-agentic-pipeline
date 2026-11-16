#!/bin/sh
# Issue 20: [Kernel] _Alignas printed after the declarator of a struct/union
# member, and after the '*' of a pointer declarator.
#
# Images: framac-master-audit:3dff90f (master 3dff90fc70, before the fix),
#         framac-analysis:fc34 (34.0~beta, same output), and the master image
#         with ../patches/20-kernel-alignas-member-printed-after-declarator.patch
#         built and installed (after the fix).
# Command, from this directory:
#   docker run --rm -v "$PWD:/w" -w /w --entrypoint sh <image> \
#     20-kernel-alignas-member-printed-after-declarator.sh
#
# Output before the fix (master 3dff90fc70; 34.0~beta prints the same):
#   --- _Alignas in the code printed by frama-c -print
#   4:   uint64_t u64[2] _Alignas(16) ;
#   9:   char d _Alignas(8) ;
#   10:   int *p _Alignas(16) ;
#   12:int *_Alignas(16) gp;
#   13:int (*_Alignas(16) gfp)(int );
#   14:char * _Alignas(8)gap[2];
#   15:uint64_t  _Alignas(16)ga[2];
#   19:  int *_Alignas(16) lp = (int *)0;
#   --- gcc -fsyntax-only: FAILED
#   --- clang -fsyntax-only: FAILED
#   --- frama-c re-parse: FAILED
#   RESULT: bug present
#
# Output after the fix:
#   --- _Alignas in the code printed by frama-c -print
#   4:   uint64_t _Alignas(16) u64[2] ;
#   9:   char _Alignas(8) d ;
#   10:   int _Alignas(16) *p ;
#   12:int _Alignas(16) *gp;
#   13:int _Alignas(16) (*gfp)(int );
#   14:char _Alignas(8) *gap[2];
#   15:uint64_t _Alignas(16) ga[2];
#   19:  int _Alignas(16) *lp = (int *)0;
#   --- gcc -fsyntax-only: ok
#   --- clang -fsyntax-only: ok
#   --- frama-c re-parse: ok
#   RESULT: fixed (printed code compiles, alignments preserved)
set -u
src=20-kernel-alignas-member-printed-after-declarator.c
tmp=${TMPDIR:-/tmp}/repro20.$$
mkdir -p "$tmp"
out=$tmp/printed.c
if ! frama-c -no-unicode "$src" -print -ocode "$out" > "$tmp/fc.log" 2>&1; then
  cat "$tmp/fc.log"; echo "RESULT: frama-c failed"; exit 2
fi
echo "--- _Alignas in the code printed by frama-c -print"
grep -n '_Alignas' "$out"
# Check that the printed code keeps the alignments (not only that it parses).
cp "$out" "$tmp/checked.c"
printf '%s\n' \
  '_Static_assert(_Alignof(union blk) == 16, "blk");' \
  '_Static_assert(_Alignof(struct s) == 16, "s");' \
  '_Static_assert(__alignof__(gp) == 16 && __alignof__(gap) == 8, "globals");' \
  >> "$tmp/checked.c"
fail=0
for cc in gcc clang; do
  if command -v "$cc" > /dev/null 2>&1; then
    if "$cc" -std=gnu11 -fsyntax-only "$tmp/checked.c" > "$tmp/$cc.log" 2>&1
    then echo "--- $cc -fsyntax-only: ok"
    else echo "--- $cc -fsyntax-only: FAILED"; fail=1
    fi
  fi
done
if frama-c -no-unicode "$out" > "$tmp/reparse.log" 2>&1
then echo "--- frama-c re-parse: ok"
else echo "--- frama-c re-parse: FAILED"; fail=1
fi
rm -rf "$tmp"
if [ "$fail" = 0 ]; then
  echo "RESULT: fixed (printed code compiles, alignments preserved)"; exit 0
else
  echo "RESULT: bug present"; exit 1
fi
