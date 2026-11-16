#!/bin/sh
# E-ACSL: with initialization checks, `ensures \result.a == x` fails on every
# call of a function returning a struct: the wrapper's __retres is never
# marked initialized and its fields get an \initialized guard.
#
# Images: framac-master-audit:3dff90f (master 3dff90fc70, before),
#         the same image with the patch (after), framac-analysis:fc34 (34.0~beta).
# Command, from the repro directory:
#   docker run --rm -v "$PWD:/w" -w /w --entrypoint sh <image> 08-eacsl-struct-result-initialized.sh
#
# Output before the fix (master 3dff90fc70; 34.0~beta prints the same):
#   35.0~~dev (Bromine)
#   --- e-acsl-gcc 08-eacsl-struct-result-initialized.c
#   run: exit 0
#   --- e-acsl-gcc -F "-rte -rte-initialized @all" 08-eacsl-struct-result-initialized.c
#   run: exit 134
#   08-eacsl-struct-result-initialized.c: In function 'make_s'
#   08-eacsl-struct-result-initialized.c:4: Error: E-ACSL RTE failed:
#   uninitialized:
#   \initialized(&\result.a).
#   - uninitialized: \initialized(&\result.a): 0
#
# Output after the fix:
#   35.0~~dev (Bromine)
#   --- e-acsl-gcc 08-eacsl-struct-result-initialized.c
#   run: exit 0
#   --- e-acsl-gcc -F "-rte -rte-initialized @all" 08-eacsl-struct-result-initialized.c
#   run: exit 0
set -u
ulimit -c 0 # a failed E-ACSL check aborts; skip the (large) core dump
src=08-eacsl-struct-result-initialized.c
tmp=$(mktemp -d)
frama-c -version
for opts in "" "-rte -rte-initialized @all"; do
  echo "--- e-acsl-gcc ${opts:+-F \"$opts\" }$src"
  if [ -n "$opts" ]; then set -- -F "$opts"; else set --; fi
  if ! e-acsl-gcc "$@" -o "$tmp/inst.c" -O "$tmp/t" "$src" > "$tmp/build.log" 2>&1; then
    tail -3 "$tmp/build.log"; echo 'build: FAILED'; continue
  fi
  "$tmp/t.e-acsl" > "$tmp/run.log" 2>&1
  echo "run: exit $?"
  grep -E 'Error|initialized' "$tmp/run.log" | sed 's/^\s*//'
done
rm -rf "$tmp"
