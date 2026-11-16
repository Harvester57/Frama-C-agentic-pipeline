#!/bin/sh
# E-ACSL crashes with Unregistered("__gmpz_clear") when the program itself
# declares and uses a GMP function (here directly, or through <gmp.h>) and an
# annotation needs E-ACSL's own GMP code. Either condition alone is fine.
#
# Images: framac-master-audit:3dff90f (master 3dff90fc70, before),
#         the same image with the patch (after), framac-analysis:fc34 (34.0~beta).
# Command, from the repro directory:
#   docker run --rm -v "$PWD:/w" -w /w --entrypoint sh <image> 22-eacsl-gmp-symbol-unregistered.sh
# e-acsl-gcc -X builds the instrumented program only. The script prints the
# error lines of the build log (Frama-C errors and e-acsl-gcc's own verdict),
# not the warnings, the backtrace or the compiler command lines.
#
# Output before the fix (master 3dff90fc70; 34.0~beta prints the same with
# "34.0~beta (Selenium)"; the temporary directory name varies):
#   35.0~~dev (Bromine)
#   --- e-acsl-gcc -q -X  22-eacsl-gmp-symbol-unregistered.c
#   [kernel] Unexpected error (E_ACSL__Rtl.Symbols.Unregistered("__gmpz_clear")).
#   e-acsl-gcc: fatal error: aborted by Frama-C
#   build: exit 1
#   (control: the same program without the assertion)
#   --- e-acsl-gcc -q -X  /tmp/tmp.c9tDvzkPgc/noassert.c
#   build: exit 0
#   run: exit 0
#   --- e-acsl-gcc -q -X -l -lgmp 22-eacsl-gmp-symbol-unregistered-gmp-h.c
#   [kernel] Unexpected error (E_ACSL__Rtl.Symbols.Unregistered("__gmpz_clear")).
#   e-acsl-gcc: fatal error: aborted by Frama-C
#   build: exit 1
#
# Output after the fix (master 3dff90fc70 + patches/22-eacsl-gmp-symbol-unregistered.patch):
#   35.0~~dev (Bromine)
#   --- e-acsl-gcc -q -X  22-eacsl-gmp-symbol-unregistered.c
#   build: exit 0
#   run: exit 0
#   (control: the same program without the assertion)
#   --- e-acsl-gcc -q -X  /tmp/tmp.RTccYwzJZ9/noassert.c
#   build: exit 0
#   run: exit 0
#   --- e-acsl-gcc -q -X -l -lgmp 22-eacsl-gmp-symbol-unregistered-gmp-h.c
#   build: exit 0
#   run: exit 0
set -u
n=22-eacsl-gmp-symbol-unregistered
tmp=$(mktemp -d)
frama-c -version
build_and_run() { # <source> <e-acsl-gcc options>...
  src=$1; shift
  echo "--- e-acsl-gcc -q -X $* $src"
  e-acsl-gcc -q -X "$@" -o "$tmp/inst.c" -O "$tmp/t" "$src" > "$tmp/build.log" 2>&1
  status=$?
  grep -E '^\[kernel\] (Failure|Unexpected error)|^e-acsl-gcc: ' "$tmp/build.log"
  echo "build: exit $status"
  if [ "$status" -eq 0 ]; then
    "$tmp/t.e-acsl"
    echo "run: exit $?"
  fi
  rm -f "$tmp/t.e-acsl" "$tmp/inst.c"
}
build_and_run "$n.c"
echo "(control: the same program without the assertion)"
grep -v '@ assert' "$n.c" > "$tmp/noassert.c"
build_and_run "$tmp/noassert.c"
build_and_run "$n-gmp-h.c" -l -lgmp
rm -rf "$tmp"
