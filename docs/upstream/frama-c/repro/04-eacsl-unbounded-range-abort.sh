#!/bin/sh
# E-ACSL: an unbounded range (p + (0..)) in any annotation aborts the whole
# instrumentation instead of ignoring that annotation.
#
# Images: framac-master-audit:3dff90f (master 3dff90fc70, before),
#         the same image with the patch (after), framac-analysis:fc34 (34.0~beta).
# Command, from the repro directory:
#   docker run --rm -v "$PWD:/w" -w /w --entrypoint sh <image> 04-eacsl-unbounded-range-abort.sh
#
# Output before the fix (master 3dff90fc70; 34.0~beta prints the same):
#   35.0~~dev (Bromine)
#   --- user: e-acsl-gcc  04-eacsl-unbounded-range-abort.c
#   [e-acsl] 04-eacsl-unbounded-range-abort.c:3: User Error:
#     unbounded ranges are not part of E-ACSl
#   [kernel] Plug-in e-acsl aborted: invalid user input.
#   e-acsl-gcc: fatal error: aborted by Frama-C
#   instrumentation: FAILED
#   --- strtok: e-acsl-gcc -L -e -D_DEFAULT_SOURCE 04-eacsl-unbounded-range-abort-strtok.c
#   [e-acsl] FRAMAC_SHARE/libc/string.h:352: User Error:
#     unbounded ranges are not part of E-ACSl
#   [kernel] Plug-in e-acsl aborted: invalid user input.
#   e-acsl-gcc: fatal error: aborted by Frama-C
#   instrumentation: FAILED
#
# Output after the fix:
#   35.0~~dev (Bromine)
#   --- user: e-acsl-gcc  04-eacsl-unbounded-range-abort.c
#   [e-acsl] 04-eacsl-unbounded-range-abort.c:1: Warning:
#     invalid E-ACSL construct `unbounded range'. Ignoring annotation.
#   instrumentation: OK
#   run: exit 134
#   04-eacsl-unbounded-range-abort.c:2: Error: Precondition failed:
#     The failing predicate is:
#     n ≥ 0.
#   --- strtok: e-acsl-gcc -L -e -D_DEFAULT_SOURCE 04-eacsl-unbounded-range-abort-strtok.c
#   instrumentation: OK
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
  # E-ACSL messages about the range (header line and text), and errors
  grep -B1 -E 'unbounded range' "$tmp/$label.log" | grep -v '^--'
  grep -E '^\[kernel\] Plug-in|^e-acsl-gcc: fatal' "$tmp/$label.log"
  if [ "$status" -ne 0 ]; then echo 'instrumentation: FAILED'; return; fi
  echo 'instrumentation: OK'
  "$tmp/$label.e-acsl" > "$tmp/$label.run" 2>&1
  echo "run: exit $?"
  grep -A1 -E 'Error|failing predicate' "$tmp/$label.run" | grep -v '^--'
}
# A user annotation with an unbounded range, next to a checkable clause.
run user 04-eacsl-unbounded-range-abort.c
# A libc contract with an unbounded range (strtok_r), instrumented with -L.
# (-e -D_DEFAULT_SOURCE works around a separate e-acsl-gcc issue: the compiler
# gets -std=c99 without -D_DEFAULT_SOURCE, so strtok_r is not declared.)
run strtok 04-eacsl-unbounded-range-abort-strtok.c -L -e -D_DEFAULT_SOURCE
rm -rf "$tmp"
