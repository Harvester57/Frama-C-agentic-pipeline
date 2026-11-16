#!/bin/sh
# E-ACSL: formal parameters are registered in shadow memory but never marked
# initialized, so \initialized on a formal (or on a field of a by-value struct
# formal) fails on every call. Regression of issue #177.
#
# Images: framac-master-audit:3dff90f (master 3dff90fc70, before),
#         the same image with the patch (after), framac-analysis:fc34 (34.0~beta).
# Command, from the repro directory:
#   docker run --rm -v "$PWD:/w" -w /w --entrypoint sh <image> 13-eacsl-formal-params-initialized.sh
#
# Output before the fix (master 3dff90fc70; 34.0~beta prints the same):
#   35.0~~dev (Bromine)
#   --- struct: e-acsl-gcc  13-eacsl-formal-params-initialized.c
#   run: exit 134
#   13-eacsl-formal-params-initialized.c: In function 'f_req'
#   13-eacsl-formal-params-initialized.c:3: Error: Precondition failed:
#   \initialized(&s.len).
#   - \initialized(&s.len): 0
#   --- scalar: e-acsl-gcc -F -rte -rte-initialized @all 13-eacsl-formal-params-initialized-scalar.c
#   run: exit 134
#   13-eacsl-formal-params-initialized-scalar.c: In function 'f_scalar'
#   13-eacsl-formal-params-initialized-scalar.c:4: Error: E-ACSL RTE failed:
#   uninitialized:
#   \initialized(pk).
#   - uninitialized: \initialized(pk): 0
#
# Output after the fix:
#   35.0~~dev (Bromine)
#   --- struct: e-acsl-gcc  13-eacsl-formal-params-initialized.c
#   run: exit 0
#   --- scalar: e-acsl-gcc -F -rte -rte-initialized @all 13-eacsl-formal-params-initialized-scalar.c
#   run: exit 0
set -u
ulimit -c 0 # a failed E-ACSL check aborts; skip the (large) core dump
tmp=$(mktemp -d)
frama-c -version
run() { # run <label> <source> [e-acsl-gcc options]
  label=$1; src=$2; shift 2
  echo "--- $label: e-acsl-gcc $* $src"
  if ! e-acsl-gcc "$@" -o "$tmp/$label.inst.c" -O "$tmp/$label" "$src" \
       > "$tmp/$label.log" 2>&1; then
    tail -3 "$tmp/$label.log"; echo 'build: FAILED'; return
  fi
  "$tmp/$label.e-acsl" > "$tmp/$label.run" 2>&1
  echo "run: exit $?"
  grep -E 'Error|initialized' "$tmp/$label.run" | sed 's/^\s*//'
}
# requires \initialized(&s.len) on a fully initialized by-value struct: no option.
run struct 13-eacsl-formal-params-initialized.c
# a scalar formal assigned, then read through its address: RTE initialization checks.
run scalar 13-eacsl-formal-params-initialized-scalar.c -F "-rte -rte-initialized @all"
rm -rf "$tmp"
