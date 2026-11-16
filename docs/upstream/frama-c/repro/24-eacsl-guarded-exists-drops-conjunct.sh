#!/bin/sh
# E-ACSL translates \exists integer n; 0 <= n < size && P && Q as if it were
# \exists integer n; 0 <= n < size && Q: every conjunct between the guard and
# the last one is dropped, so a false predicate passes. Each precondition of
# the reproducer is false for size == 5 and must fail.
#
# Images: framac-master-audit:3dff90f (master 3dff90fc70, before),
#         the same image with the patch (after), framac-analysis:fc34 (34.0~beta).
# Command, from the repro directory:
#   docker run --rm -v "$PWD:/w" -w /w --entrypoint sh <image> 24-eacsl-guarded-exists-drops-conjunct.sh
# e-acsl-gcc -X builds the instrumented program only. The script prints
# E-ACSL's warnings about the annotations and the first line of each verdict.
#
# Output before the fix (master 3dff90fc70; 34.0~beta prints the same with
# "34.0~beta (Selenium)"): only swapped() fails, the four others pass.
#   35.0~~dev (Bromine)
#   build: exit 0
#   two_conjuncts(5): exit 0
#   three_conjuncts(5): exit 0
#   parenthesized(5): exit 0
#   swapped(5): exit 134 24-eacsl-guarded-exists-drops-conjunct.c:13: Error: Precondition failed:
#   forall_guard_in_hypothesis(5): exit 0
#
# Output after the fix (master 3dff90fc70 + patches/24-eacsl-guarded-exists-drops-conjunct.patch):
# the four \exists preconditions fail; the \forall one is rejected with a
# warning (and not checked) instead of being checked as a weaker predicate.
#   35.0~~dev (Bromine)
#   build: exit 0
#   [e-acsl] 24-eacsl-guarded-exists-drops-conjunct.c:17: Warning:
#     invalid E-ACSL construct
#     `invalid quantification guard, found '⇒'
#     after the end of the guard of an hypothesis in quantification ∀ ℤ n; (0 ≤ n < size ⇒ n ≡ 1000) ⇒ n < size'.
#   two_conjuncts(5): exit 134 24-eacsl-guarded-exists-drops-conjunct.c:3: Error: Precondition failed:
#   three_conjuncts(5): exit 134 24-eacsl-guarded-exists-drops-conjunct.c:6: Error: Precondition failed:
#   parenthesized(5): exit 134 24-eacsl-guarded-exists-drops-conjunct.c:9: Error: Precondition failed:
#   swapped(5): exit 134 24-eacsl-guarded-exists-drops-conjunct.c:13: Error: Precondition failed:
#   forall_guard_in_hypothesis(5): exit 0
set -u
n=24-eacsl-guarded-exists-drops-conjunct
tmp=$(mktemp -d)
frama-c -version
e-acsl-gcc -q -X -o "$tmp/inst.c" -O "$tmp/t" "$n.c" > "$tmp/build.log" 2>&1
echo "build: exit $?"
grep -E -A3 '^\[e-acsl\] .*Warning' "$tmp/build.log"
i=0
for f in two_conjuncts three_conjuncts parenthesized swapped forall_guard_in_hypothesis; do
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
