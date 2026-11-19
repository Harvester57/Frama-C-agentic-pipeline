#!/bin/sh
# E-ACSL: formal parameters are registered in shadow memory but never marked
# initialized, so \initialized on a formal (a field of a by-value struct
# formal, a scalar formal via &k, or main's argc/argv via &argc/&argv in both
# segment and bittree models) fails on every call. Regression of issue #177.
#
# Images: framac-master-audit:b80fcac (master b80fcac74f, before),
#         the same image with the patch (after), framac-analysis:fc34 (34.0~beta).
# Command, from the repro directory:
#   docker run --rm -v "$PWD:/w" -w /w --entrypoint sh <image> 13-eacsl-formal-params-initialized.sh
#
# Output before the fix (master b80fcac74f):
#   35.0~~dev (Bromine)
#   --- struct: e-acsl-gcc 13-eacsl-formal-params-initialized.c
#   run: exit 134
#   13-eacsl-formal-params-initialized.c: In function 'f_req'
#   13-eacsl-formal-params-initialized.c:3: Error: Precondition failed:
#   \initialized(&s.len).
#   - \initialized(&s.len): 0
#   --- scalar: e-acsl-gcc -F "-rte -rte-initialized @all" 13-eacsl-formal-params-initialized-scalar.c
#   run: exit 134
#   13-eacsl-formal-params-initialized-scalar.c: In function 'f_scalar'
#   13-eacsl-formal-params-initialized-scalar.c:4: Error: E-ACSL RTE failed:
#   uninitialized:
#   \initialized(pk).
#   - uninitialized: \initialized(pk): 0
#   --- main-seg: e-acsl-gcc 13-eacsl-formal-params-initialized-main.c
#   run: exit 134
#   13-eacsl-formal-params-initialized-main.c: In function 'main'
#   13-eacsl-formal-params-initialized-main.c:4: Error: Assertion failed:
#   \initialized(p).
#   - \initialized(p): 0
#   --- main-bittree: e-acsl-gcc -m bittree 13-eacsl-formal-params-initialized-main.c
#   run: exit 134
#   13-eacsl-formal-params-initialized-main.c: In function 'main'
#   13-eacsl-formal-params-initialized-main.c:4: Error: Assertion failed:
#   \initialized(p).
#   - \initialized(p): 0
#
# Output after the fix:
#   35.0~~dev (Bromine)
#   --- struct: e-acsl-gcc 13-eacsl-formal-params-initialized.c
#   run: exit 0
#   --- scalar: e-acsl-gcc -F "-rte -rte-initialized @all" 13-eacsl-formal-params-initialized-scalar.c
#   run: exit 0
#   --- main-seg: e-acsl-gcc 13-eacsl-formal-params-initialized-main.c
#   run: exit 0
#   --- main-bittree: e-acsl-gcc -m bittree 13-eacsl-formal-params-initialized-main.c
#   run: exit 0
set -u
ulimit -c 1 2>/dev/null || ulimit -c 0 2>/dev/null || true
tmp=$(mktemp -d)
frama-c -version
run() { # run <label> <source> [e-acsl-gcc options]
  label=$1; src=$2; shift 2
  opts=""
  for a in "$@"; do
    case "$a" in
      *" "*) opts="$opts \"$a\"" ;;
      *)     opts="$opts $a" ;;
    esac
  done
  echo "--- $label: e-acsl-gcc$opts $src"
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
# main's argc/argv read through &argc/&argv in both segment and bittree models.
run main-seg 13-eacsl-formal-params-initialized-main.c
run main-bittree 13-eacsl-formal-params-initialized-main.c -m bittree
rm -rf "$tmp"
