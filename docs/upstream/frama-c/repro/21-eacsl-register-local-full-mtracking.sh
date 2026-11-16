#!/bin/sh
# E-ACSL aborts with "Taking the address of a register variable" on a
# `register` local that it monitors: every local under -e-acsl-full-mtracking
# (e-acsl-gcc -M), or a local named in a memory predicate such as
# \initialized(&i).
#
# Images: framac-master-audit:3dff90f (master 3dff90fc70, before),
#         the same image with the patch (after), framac-analysis:fc34 (34.0~beta).
# Command, from the repro directory:
#   docker run --rm -v "$PWD:/w" -w /w --entrypoint sh <image> 21-eacsl-register-local-full-mtracking.sh
# e-acsl-gcc -X builds the instrumented program only. The script prints the
# error lines of the build log (Frama-C errors and e-acsl-gcc's own verdict),
# not the warnings, the backtrace or the compiler command lines.
#
# Output before the fix (master 3dff90fc70; 34.0~beta prints the same with
# "34.0~beta (Selenium)"):
#   35.0~~dev (Bromine)
#   --- e-acsl-gcc -q -X  21-eacsl-register-local-full-mtracking.c
#   build: exit 0
#   run: exit 0
#   --- e-acsl-gcc -q -X -M 21-eacsl-register-local-full-mtracking.c
#   [kernel] Failure: Taking the address of a register variable with &[ i ]
#   e-acsl-gcc: fatal error: aborted by Frama-C
#   build: exit 1
#   --- e-acsl-gcc -q -X  21-eacsl-register-local-full-mtracking-assert.c
#   [kernel] Failure: Taking the address of a register variable with &[ i ]
#   e-acsl-gcc: fatal error: aborted by Frama-C
#   build: exit 1
#
# Output after the fix (master 3dff90fc70 + patches/21-eacsl-register-local-full-mtracking.patch):
#   35.0~~dev (Bromine)
#   --- e-acsl-gcc -q -X  21-eacsl-register-local-full-mtracking.c
#   build: exit 0
#   run: exit 0
#   --- e-acsl-gcc -q -X -M 21-eacsl-register-local-full-mtracking.c
#   build: exit 0
#   run: exit 0
#   --- e-acsl-gcc -q -X  21-eacsl-register-local-full-mtracking-assert.c
#   build: exit 0
#   run: exit 0
set -u
n=21-eacsl-register-local-full-mtracking
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
build_and_run "$n.c" -M
build_and_run "$n-assert.c"
rm -rf "$tmp"
