#!/bin/sh
# E-ACSL rejects its own code for a const union global that it monitors
# ("implicit cast: cast from union u to void *"): it passes the union's value
# to __e_acsl_mark_readonly instead of its address. Same root cause as
# 27-eacsl-readonly-scalar-global-address, fixed by the same patch.
#
# Images: framac-master-audit:3dff90f (master 3dff90fc70, before),
#         the same image with the patch (after), framac-analysis:fc34 (34.0~beta).
# Command, from the repro directory:
#   docker run --rm -v "$PWD:/w" -w /w --entrypoint sh <image> 23-eacsl-static-const-union-cast.sh
# e-acsl-gcc -X builds the instrumented program only. The script prints the
# error lines of the build log (Frama-C errors and e-acsl-gcc's own verdict),
# not the warnings, the backtrace or the compiler command lines.
#
# Output before the fix (master 3dff90fc70; 34.0~beta prints the same with
# "34.0~beta (Selenium)"):
#   35.0~~dev (Bromine)
#   --- e-acsl-gcc -q -X  -e -DDEFAULT -E -DDEFAULT 23-eacsl-static-const-union-cast.c
#   build: exit 0
#   run: exit 0
#   --- e-acsl-gcc -q -X -M -e -DDEFAULT -E -DDEFAULT 23-eacsl-static-const-union-cast.c
#   [kernel] 23-eacsl-static-const-union-cast.c:20: User Error:
#     implicit cast: cast from union u to void *
#   e-acsl-gcc: fatal error: aborted by Frama-C
#   build: exit 1
#   --- e-acsl-gcc -q -X -M -e -DLOCAL_STATIC -E -DLOCAL_STATIC 23-eacsl-static-const-union-cast.c
#   [kernel] 23-eacsl-static-const-union-cast.c:6: User Error:
#     implicit cast: cast from union u to void *
#   e-acsl-gcc: fatal error: aborted by Frama-C
#   build: exit 1
#   --- e-acsl-gcc -q -X -M -e -DINITIALIZED -E -DINITIALIZED 23-eacsl-static-const-union-cast.c
#   [kernel] 23-eacsl-static-const-union-cast.c:8: User Error:
#     implicit cast: cast from union u to void *
#   e-acsl-gcc: fatal error: aborted by Frama-C
#   build: exit 1
#   --- e-acsl-gcc -q -X -M -e -DNON_STATIC -E -DNON_STATIC 23-eacsl-static-const-union-cast.c
#   [kernel] 23-eacsl-static-const-union-cast.c:11: User Error:
#     implicit cast: cast from union u to void *
#   e-acsl-gcc: fatal error: aborted by Frama-C
#   build: exit 1
#   --- e-acsl-gcc -q -X -M -e -DCONST_STRUCT -E -DCONST_STRUCT 23-eacsl-static-const-union-cast.c
#   build: exit 0
#       __e_acsl_mark_readonly((void *)(& zero_block.b));
#       __e_acsl_mark_readonly((void *)(& zero_block.w));
#   run: exit 0
#   --- e-acsl-gcc -q -X -M -e -DNON_CONST_UNION -E -DNON_CONST_UNION 23-eacsl-static-const-union-cast.c
#   build: exit 0
#   run: exit 0
#   --- frama-c -print 23-eacsl-static-const-union-cast.c (no E-ACSL)
#   frama-c: exit 0
#
# Output after the fix (master 3dff90fc70 + patches/27-eacsl-readonly-scalar-global-address.patch):
# every variant builds and runs (exit 0); the union variants print
#       __e_acsl_mark_readonly((void *)(& zero_block));
# (LOCAL_STATIC: (& main_zero_block)), CONST_STRUCT and NON_CONST_UNION are
# unchanged, and frama-c -print still exits 0.
set -u
n=23-eacsl-static-const-union-cast
tmp=$(mktemp -d)
frama-c -version
build_and_run() { # <variant> <e-acsl-gcc options>...
  v=$1; shift
  echo "--- e-acsl-gcc -q -X $* -e -D$v -E -D$v $n.c"
  e-acsl-gcc -q -X "$@" -e "-D$v" -E "-D$v" -o "$tmp/inst.c" -O "$tmp/t" "$n.c" > "$tmp/build.log" 2>&1
  status=$?
  grep -E -A1 '^\[kernel\] [^ ]*: User Error' "$tmp/build.log"
  grep -E '^\[kernel\] (Failure|Unexpected error)|^e-acsl-gcc: ' "$tmp/build.log"
  echo "build: exit $status"
  if [ "$status" -eq 0 ]; then
    grep '__e_acsl_mark_readonly(' "$tmp/inst.c" | grep -v FC_BUILTIN
    "$tmp/t.e-acsl"
    echo "run: exit $?"
  fi
  rm -f "$tmp/t.e-acsl" "$tmp/inst.c"
}
build_and_run DEFAULT
build_and_run DEFAULT -M
for v in LOCAL_STATIC INITIALIZED NON_STATIC CONST_STRUCT NON_CONST_UNION; do
  build_and_run "$v" -M
done
echo "--- frama-c -print $n.c (no E-ACSL)"
frama-c "$n.c" -print > "$tmp/print.log" 2>&1
echo "frama-c: exit $?"
rm -rf "$tmp"
