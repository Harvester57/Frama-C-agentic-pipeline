#!/bin/sh
# E-ACSL: annotations on pointers to an incomplete (opaque) struct emit
# sizeof/__alignof__ of the incomplete type: the instrumented code does not
# compile.
#
# Images: framac-master-audit:3dff90f (master 3dff90fc70, before),
#         the same image with the patch (after), framac-analysis:fc34 (34.0~beta).
# Command, from the repro directory:
#   docker run --rm -v "$PWD:/w" -w /w --entrypoint sh <image> 05-eacsl-incomplete-type-sizeof.sh
#
# Output before the fix (master 3dff90fc70; 34.0~beta prints the same):
#   35.0~~dev (Bromine)
#   --- ov: e-acsl-gcc  05-eacsl-incomplete-type-sizeof.c
#   [e-acsl] 05-eacsl-incomplete-type-sizeof.c:3: Warning:
#     cannot create the pointer alignment guard of obj because json_object const is an incomplete type
#   [e-acsl] 05-eacsl-incomplete-type-sizeof.c:3: Warning:
#     cannot create the pointer alignment guard of obj because json_object const is an incomplete type
#   ov.inst.c:354:60: error: invalid application of ‘sizeof’ to incomplete type ‘json_object’
#   ov.inst.c:361:45: error: invalid application of ‘sizeof’ to incomplete type ‘json_object’
#   e-acsl-gcc: fatal error: fail to compile/link instrumented code
#   build: FAILED
#   --- oc: e-acsl-gcc -F -rte 05-eacsl-incomplete-type-sizeof-cast.c
#   [e-acsl] 05-eacsl-incomplete-type-sizeof-cast.c:4: Warning:
#     cannot create the pointer alignment guard of p because void is an incomplete type
#   oc.inst.c:322:56: error: invalid application of ‘__alignof__’ to incomplete type ‘json_object’
#   oc.inst.c:325:45: error: invalid application of ‘__alignof__’ to incomplete type ‘json_object’
#   e-acsl-gcc: fatal error: fail to compile/link instrumented code
#   build: FAILED
#
# Output after the fix:
#   35.0~~dev (Bromine)
#   --- ov: e-acsl-gcc  05-eacsl-incomplete-type-sizeof.c
#   [e-acsl] 05-eacsl-incomplete-type-sizeof.c:3: Warning:
#     cannot create the pointer alignment guard of obj because json_object const is an incomplete type
#   [e-acsl] 05-eacsl-incomplete-type-sizeof.c:3: Warning:
#     cannot create the pointer alignment guard of obj because json_object const is an incomplete type
#   [e-acsl] 05-eacsl-incomplete-type-sizeof.c:3: Warning:
#     E-ACSL construct `memory predicate on a pointer to an incomplete type'
#     is not yet supported.
#     Ignoring annotation.
#   build: OK
#   run: exit 0
#   --- oc: e-acsl-gcc -F -rte 05-eacsl-incomplete-type-sizeof-cast.c
#   [e-acsl] 05-eacsl-incomplete-type-sizeof-cast.c:4: Warning:
#     cannot create the pointer alignment guard of p because void is an incomplete type
#   [e-acsl] 05-eacsl-incomplete-type-sizeof-cast.c:4: Warning:
#     E-ACSL construct `sizeof or alignof of an incomplete type'
#     is not yet supported.
#     Ignoring annotation.
#   build: OK
#   run: exit 0
set -u
ulimit -c 0 # a failed E-ACSL check aborts; skip the (large) core dump
tmp=$(mktemp -d)
frama-c -version
run() { # run <label> <source> [e-acsl-gcc options]
  label=$1; src=$2; shift 2
  echo "--- $label: e-acsl-gcc $* $src"
  e-acsl-gcc "$@" -o "$tmp/$label.inst.c" -O "$tmp/$label" "$src" \
    > "$tmp/$label.log" 2>&1
  status=$?
  # E-ACSL messages (header line and text), compiler errors, e-acsl-gcc errors
  awk '/^\[e-acsl\] .*(Warning|Error): *$/ { p = 1; print; next }
       /^  / { if (p) print; next }
       { p = 0 }' "$tmp/$label.log"
  grep -E 'error: |^e-acsl-gcc: fatal' "$tmp/$label.log" | sed "s|$tmp/||"
  if [ "$status" -ne 0 ]; then echo 'build: FAILED'; return; fi
  echo 'build: OK'
  "$tmp/$label.e-acsl" > "$tmp/$label.run" 2>&1
  echo "run: exit $?"
}
# \valid_read on an opaque handle (user contract).
run ov 05-eacsl-incomplete-type-sizeof.c
# RTE pointer_alignment assertion on a cast to an opaque handle.
run oc 05-eacsl-incomplete-type-sizeof-cast.c -F -rte
rm -rf "$tmp"
