#!/bin/sh
# \object_pointer(p) is false at run time when p points into read-only data
# (a const global array, a string literal), although \valid_read(p) holds:
# the runtime implements it with eacsl_valid, which requires writability.
# With -warn-invalid-pointer, the "invalid pointer" RTE guard on every read of
# such a pointer fails the same way.
#
# Images: framac-master-audit:3dff90f (master 3dff90fc70, before),
#         the same image with the patch (after), framac-analysis:fc34 (34.0~beta).
# Command, from the repro directory:
#   docker run --rm -v "$PWD:/w" -w /w --entrypoint sh <image> 29-eacsl-object-pointer-readonly-static.sh
# Each program is run with its argument 0 to 3: 0 a local array, 1 a writable
# global array, 2 a static const global array, 3 a string literal. The script
# prints the run-time output of the default build (gcc, no -M) with the
# addresses replaced by 0x..., then the exit codes of the four objects in
# every build.
#
# Output before the fix (master 3dff90fc70; 34.0~beta prints the same with
# "34.0~beta (Selenium)"):
#   35.0~~dev (Bromine)
#   --- e-acsl-gcc -q -c  29-eacsl-object-pointer-readonly-static.c
#   [0]
#   [0] exit 0
#   [1]
#   [1] exit 0
#   [2]
#   29-eacsl-object-pointer-readonly-static.c: In function 'check'
#   29-eacsl-object-pointer-readonly-static.c:6: Error: Assertion failed:
#   	The failing predicate is:
#   	\object_pointer(p).
#   	With values at failure point:
#   	- \object_pointer(p): 0
#   	- sizeof(char const): 1
#   	- p: 0x...
#   Aborted (core dumped)
#   [2] exit 134
#   [3]
#   (the same as [2])
#   [3] exit 134
#   --- e-acsl-gcc -q -c -F -rte -warn-invalid-pointer 29-eacsl-object-pointer-readonly-static-rte.c
#   [0]
#   [0] exit 0
#   [1]
#   [1] exit 0
#   [2]
#   29-eacsl-object-pointer-readonly-static-rte.c: In function 'scan'
#   29-eacsl-object-pointer-readonly-static-rte.c:6: Error: E-ACSL RTE failed:
#   	The failing predicate is:
#   	invalid pointer:
#   		\null ≡ p ∨ \object_pointer(p).
#   	With values at failure point:
#   	- \object_pointer(p): 0
#   	- sizeof(unsigned char const): 1
#   	- p: 0x...
#   Aborted (core dumped)
#   [2] exit 134
#   [3]
#   (the same as [2])
#   [3] exit 134
#   --- exit codes of objects 0 1 2 3
#   29-eacsl-object-pointer-readonly-static.c : 0 0 134 134
#   29-eacsl-object-pointer-readonly-static-rte.c -F -rte -warn-invalid-pointer: 0 0 134 134
#   29-eacsl-object-pointer-readonly-static.c -M: 0 0 134 134
#   29-eacsl-object-pointer-readonly-static-rte.c -F -rte -warn-invalid-pointer -M: 0 0 134 134
#   29-eacsl-object-pointer-readonly-static.c -G clang: 0 0 134 134
#   29-eacsl-object-pointer-readonly-static-rte.c -F -rte -warn-invalid-pointer -G clang: 0 0 134 134
#   29-eacsl-object-pointer-readonly-static.c -G clang -M: 0 0 134 134
#   29-eacsl-object-pointer-readonly-static-rte.c -F -rte -warn-invalid-pointer -G clang -M: 0 0 134 134
#   29-eacsl-object-pointer-readonly-static.c --temporal: 0 0 134 134
#   29-eacsl-object-pointer-readonly-static-rte.c -F -rte -warn-invalid-pointer --temporal: 0 0 134 134
#   29-eacsl-object-pointer-readonly-static.c -m bittree: 0 0 0 0
#   29-eacsl-object-pointer-readonly-static-rte.c -F -rte -warn-invalid-pointer -m bittree: 0 0 0 0
# (-m bittree passes before the fix only because that model loses the
# read-only mark: there, \valid(p) is also true on the const array and the
# literal.)
#
# Output after the fix (master 3dff90fc70 + patches/29-eacsl-object-pointer-readonly-static.patch):
#   35.0~~dev (Bromine)
#   --- e-acsl-gcc -q -c  29-eacsl-object-pointer-readonly-static.c
#   [0]
#   [0] exit 0
#   [1]
#   [1] exit 0
#   [2]
#   [2] exit 0
#   [3]
#   [3] exit 0
#   --- e-acsl-gcc -q -c -F -rte -warn-invalid-pointer 29-eacsl-object-pointer-readonly-static-rte.c
#   [0]
#   [0] exit 0
#   [1]
#   [1] exit 0
#   [2]
#   [2] exit 0
#   [3]
#   [3] exit 0
#   --- exit codes of objects 0 1 2 3
#   29-eacsl-object-pointer-readonly-static.c : 0 0 0 0
#   (and 0 0 0 0 on every other line)
set -u
n=29-eacsl-object-pointer-readonly-static
tmp=$(mktemp -d)
frama-c -version
build() { # <source> <e-acsl-gcc options>...
  src=$1; shift
  e-acsl-gcc -q -c "$@" -o "$tmp/inst.c" -O "$tmp/t" "$src" > "$tmp/build.log" 2>&1
  status=$?
  if [ "$status" -ne 0 ]; then
    echo "build: exit $status"
    grep -E '^\[kernel\] (Failure|Unexpected error)|^e-acsl-gcc: |rror' "$tmp/build.log"
  fi
  return "$status"
}
show_runs() { # <source> <e-acsl-gcc options>...
  src=$1; shift
  echo "--- e-acsl-gcc -q -c $* $src"
  build "$src" "$@" || return
  for i in 0 1 2 3; do
    prlimit --core=0 "$tmp/t.e-acsl" $i > "$tmp/run.log" 2>&1
    status=$?
    echo "[$i]"
    sed -e 's/0x[0-9a-f]\{6,\}/0x.../' "$tmp/run.log"
    echo "[$i] exit $status"
  done
}
codes() { # <source> <e-acsl-gcc options>...
  src=$1; shift
  printf '%s' "$src $*:"
  build "$src" "$@" || return
  for i in 0 1 2 3; do
    prlimit --core=0 "$tmp/t.e-acsl" $i > /dev/null 2>&1
    printf ' %s' "$?"
  done
  echo
}
show_runs "$n.c"
show_runs "$n-rte.c" -F "-rte -warn-invalid-pointer"
echo "--- exit codes of objects 0 1 2 3"
for opts in "" "-M" "-G clang" "-G clang -M" "--temporal" "-m bittree"; do
  # shellcheck disable=SC2086
  codes "$n.c" $opts
  # shellcheck disable=SC2086
  codes "$n-rte.c" -F "-rte -warn-invalid-pointer" $opts
done
rm -rf "$tmp"
