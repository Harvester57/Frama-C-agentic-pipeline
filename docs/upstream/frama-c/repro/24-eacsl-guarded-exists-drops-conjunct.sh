#!/bin/sh
# E-ACSL translates \exists integer n; 0 <= n < size && P && Q as if it were
# \exists integer n; 0 <= n < size && Q: every conjunct between the guard and
# the last one is dropped, so a false predicate passes. In \forall, nested
# implications inside an implication hypothesis and conjunctions outside a
# hypothesis are also mis-translated into weaker valid predicates. Each
# precondition of the reproducer is false for size == 5 and must fail or be
# rejected at instrumentation time.
#
# Images: framac-master-audit:b80fcac (master b80fcac74f, before),
#         the same image with the patch (after), framac-analysis:fc34 (34.0~beta).
# Command, from the repro directory:
#   docker run --rm -v "$PWD:/w" -w /w --entrypoint sh <image> 24-eacsl-guarded-exists-drops-conjunct.sh
# e-acsl-gcc -X builds the instrumented program only. The script prints
# E-ACSL's warnings about the annotations and the first line of each verdict.
set -u
n=24-eacsl-guarded-exists-drops-conjunct
tmp=$(mktemp -d)
frama-c -version
e-acsl-gcc -q -X -o "$tmp/inst.c" -O "$tmp/t" "$n.c" > "$tmp/build.log" 2>&1
echo "build: exit $?"
grep -E -A4 '^\[e-acsl\] .*Warning' "$tmp/build.log"
i=0
for f in two_conjuncts three_conjuncts parenthesized swapped \
  forall_guard_in_hypothesis forall_nested_implication \
  forall_nested_implication_conj forall_conj_after_implication; do
  # argc selects the function: 1 + number of extra arguments
  set --
  j=0
  while [ "$j" -lt "$i" ]; do set -- "$@" x; j=$((j + 1)); done
  "$tmp/t.e-acsl" "$@" > "$tmp/run.log" 2>&1
  status=$?
  echo "$f(5): exit $status $(grep -E 'Error' "$tmp/run.log")"
  i=$((i + 1))
done
rm -rf "$tmp"
