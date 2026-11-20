#!/bin/sh
# Issue 47: [MetAcsl] at a call to a function known by its contract, the
# \written instance is the callee's assigns location with the formals replaced
# by the actuals, but with the labels of the callee's contract kept. Old (an
# explicit \old, or the default label of a labelled logic function such as
# strlen) is not allowed in the statement assertion it becomes: the printed code
# does not re-parse, WP stops with LabelError and E-ACSL with "invalid label
# 'Old'". Pre is allowed but means the pre-state of the caller, so the instance
# checks another location and WP proves a false property. This is a report for
# the MetAcsl tracker (pub/meta), not pub/frama-c.
#
# Image: framac-analysis:latest (Frama-C 34.0~beta, MetAcsl 0.12~beta, E-ACSL).
# Needs Alt-Ergo. Command, from this directory:
#   docker run --rm -v "$PWD:/w" -w /w --entrypoint sh framac-analysis:latest \
#     47-metacsl-callee-old-label-in-written.sh
#
# Output before (34.0~beta, MetAcsl 0.12~beta):
#   34.0~beta (Selenium)
#   len: bound len{Old}(&n)
#   len: reparse: logic label `Old' not found. Ignoring code annotation
#   len: wp: [kernel] Unexpected error (Wp__NormAtLabels.LabelError(_)).
#   len: e-acsl: [kernel] Plug-in e-acsl aborted: internal error (invalid label 'Old' within statement annotation 'Assertion' in '&n').
#   old: bound \old(*(&n))
#   old: reparse: \old undefined in this context. Ignoring code annotation
#   old: wp: [kernel] Unexpected error (Wp__NormAtLabels.LabelError(_)).
#   old: e-acsl: [kernel] Plug-in e-acsl aborted: internal error (invalid label 'Old' within statement annotation 'Assertion' in '\old(*(&n))').
#   pre: bound \at(*(&n),Pre)
#   pre: reparse: ok
#   pre: wp: stays_in_prefix proved
#   pre: e-acsl: translated
#   RESULT: the instance keeps the labels of the callee (3 of 3 cases)
#
# Output after, observed with MetAcsl master 4f43801390 + the patch, built
# against the installed 34.0~beta kernel (master minus its one
# PLpointer_comparable case, a constructor 34.0~beta does not have):
#   34.0~beta (Selenium)
#   len: bound len(&n)
#   len: reparse: ok
#   len: wp: stays_in_prefix not proved
#   len: e-acsl: translated
#   old: bound \at(*(&n),Here)
#   old: reparse: ok
#   old: wp: stays_in_prefix not proved
#   old: e-acsl: translated
#   pre: bound \at(*(&n),Here)
#   pre: reparse: ok
#   pre: wp: stays_in_prefix not proved
#   pre: e-acsl: translated
#   RESULT: the instance is in the state before the call
#
# stays_in_prefix is false: fill writes out[0 .. 7] (n is 7 at the call), and
# the property asks for out[0 .. 3]. "not proved" is the right answer.
set -u
command -v frama-c >/dev/null 2>&1 || { echo "frama-c is not in PATH" >&2; exit 2; }
f=47-metacsl-callee-old-label-in-written.c
tmp=$(mktemp -d)
bad=0
frama-c -version
for v in len old pre; do
  case $v in len) d="";; old) d="-DUSE_OLD";; pre) d="-DUSE_PRE";; esac
  frama-c -cpp-extra-args="$d" "$f" -meta -then-last -print -ocode "$tmp/o.c" > "$tmp/log" 2>&1
  b=$(sed -n 's/.*\\subset(&(out\[0\]) + (0 \.\. \(.*\)), &out\[0 \.\. 3\]);.*/\1/p' "$tmp/o.c")
  printf '%s\n' "$v: bound $b"
  case $b in *Old*|*old*|*Pre*) bad=$((bad + 1));; esac
  if frama-c "$tmp/o.c" > "$tmp/log" 2>&1; then r=ok
  else r=$(grep -A1 'Failure' "$tmp/log" | sed -n '2s/^ *//p'); fi
  printf '%s\n' "$v: reparse: $r"
  frama-c -cpp-extra-args="$d" "$f" -meta -then-last -wp -wp-timeout 10 -wp-cache none \
    -wp-status > "$tmp/log" 2>&1
  if grep -q 'Unexpected error' "$tmp/log"; then w=$(grep 'Unexpected error' "$tmp/log")
  elif grep -qE '^\[wp\] \[(Unknown|Timeout|Failed)\] .*stays_in_prefix' "$tmp/log"; then
    w="stays_in_prefix not proved"
  elif grep -q '^\[wp\] Proved goals' "$tmp/log"; then w="stays_in_prefix proved"
  else w="no result"; fi
  printf '%s\n' "$v: wp: $w"
  frama-c -cpp-extra-args="$d" "$f" -meta -then-last -e-acsl > "$tmp/log" 2>&1
  if grep -q 'aborted' "$tmp/log"; then e=$(grep 'aborted' "$tmp/log")
  elif grep -q 'translation done' "$tmp/log"; then e=translated
  else e="no result"; fi
  printf '%s\n' "$v: e-acsl: $e"
done
rm -rf "$tmp"
if [ "$bad" = 0 ]; then echo 'RESULT: the instance is in the state before the call'; exit 0
else echo "RESULT: the instance keeps the labels of the callee ($bad of 3 cases)"; exit 1
fi
