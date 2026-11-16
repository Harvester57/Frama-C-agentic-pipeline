#!/bin/sh
# Under -e-acsl-full-mtracking, E-ACSL registers each string literal of the
# program as a block of its own and prints it as a literal. clang puts literals
# in a mergeable section and GNU ld stores "," inside " ,": the two registered
# blocks overlap, and \valid_read(" ," + 1) fails on correct code. gcc
# (e-acsl-gcc passes -fno-merge-constants) and the default memory tracking
# (which turns the monitored literals into named arrays) are not affected.
#
# Images: framac-master-audit:3dff90f (master 3dff90fc70, before),
#         the same image with the patch (after), framac-analysis:fc34 (34.0~beta).
# Command, from the repro directory:
#   docker run --rm -v "$PWD:/w" -w /w --entrypoint sh <image> 28-eacsl-full-mtracking-tail-merged-literals.sh
# The script prints the registration of the literals in the instrumented code
# (__e_acsl_globals_init), then the exit status and the error lines of the run.
#
# Output before the fix (master 3dff90fc70; 34.0~beta prints the same with
# "34.0~beta (Selenium)"):
#   35.0~~dev (Bromine)
#   --- e-acsl-gcc -q -G clang -F -e-acsl-full-mtracking 28-eacsl-full-mtracking-tail-merged-literals.c
#   build: exit 0
#       __e_acsl_store_block((void *)" ,",3UL);
#       __e_acsl_store_block((void *)",",2UL);
#   28-eacsl-full-mtracking-tail-merged-literals.c:6: Error: Assertion failed:
#   	\valid_read(charset + j).
#   	- \valid_read(charset + j): 0
#   	- j: 1
#   run: exit 134
#   --- e-acsl-gcc -q -G gcc -F -e-acsl-full-mtracking 28-eacsl-full-mtracking-tail-merged-literals.c
#   build: exit 0
#       __e_acsl_store_block((void *)" ,",3UL);
#       __e_acsl_store_block((void *)",",2UL);
#   run: exit 0
#   --- e-acsl-gcc -q -G clang 28-eacsl-full-mtracking-tail-merged-literals.c
#   build: exit 0
#       __e_acsl_store_block((void *)(__fc_lit_string2),3UL);
#   run: exit 0
#
# Output after the fix (master 3dff90fc70 + patches/28-eacsl-full-mtracking-tail-merged-literals.patch):
#   35.0~~dev (Bromine)
#   --- e-acsl-gcc -q -G clang -F -e-acsl-full-mtracking 28-eacsl-full-mtracking-tail-merged-literals.c
#   build: exit 0
#       __e_acsl_store_block((void *)(__fc_lit_string2),3UL);
#       __e_acsl_store_block((void *)(__fc_lit_string1),2UL);
#   run: exit 0
#   --- e-acsl-gcc -q -G gcc -F -e-acsl-full-mtracking 28-eacsl-full-mtracking-tail-merged-literals.c
#   build: exit 0
#       __e_acsl_store_block((void *)(__fc_lit_string2),3UL);
#       __e_acsl_store_block((void *)(__fc_lit_string1),2UL);
#   run: exit 0
#   --- e-acsl-gcc -q -G clang 28-eacsl-full-mtracking-tail-merged-literals.c
#   build: exit 0
#       __e_acsl_store_block((void *)(__fc_lit_string2),3UL);
#   run: exit 0
set -u
n=28-eacsl-full-mtracking-tail-merged-literals
tmp=$(mktemp -d)
frama-c -version
build_and_run() { # <e-acsl-gcc options>...
  echo "--- e-acsl-gcc -q $* $n.c"
  e-acsl-gcc -q "$@" -o "$tmp/inst.c" -O "$tmp/t" "$n.c" > "$tmp/build.log" 2>&1
  status=$?
  grep -E '^\[kernel\] (Failure|Unexpected error)|^e-acsl-gcc: ' "$tmp/build.log"
  echo "build: exit $status"
  if [ "$status" -eq 0 ]; then
    grep -E '__e_acsl_store_block\(\(void \*\)\(?("|__fc_lit_string)' "$tmp/inst.c"
    prlimit --core=0 "$tmp/t.e-acsl" > "$tmp/run.log" 2>&1
    status=$?
    grep -E 'Error|valid_read|j:' "$tmp/run.log"
    echo "run: exit $status"
  fi
  rm -f "$tmp/t.e-acsl" "$tmp/inst.c"
}
build_and_run -G clang -F -e-acsl-full-mtracking
build_and_run -G gcc -F -e-acsl-full-mtracking
build_and_run -G clang
rm -rf "$tmp"
