#!/bin/sh
# Issue 40: [wp] with several provers, -wp-report-json and the console keep
# one result per goal (the "best" prover's), so the other provers' answers
# (Timeout vs Unknown, steps, time) are lost; the manual's description of
# the JSON "time" unit and of "cached" does not match the output.
#
# Images: framac-master-audit:9540804 (master 95408044f7, Alt-Ergo 2.6.4,
#         Z3 4.13.3, CVC5 1.1.2) and framac-analysis:latest (34.0~beta,
#         Alt-Ergo 2.4.3; same results). No patch.
# Command, from this directory:
#   docker run --rm -v "$PWD:/w" -w /w --entrypoint sh <image> \
#     40-wp-report-per-prover-results.sh
#
# Output (master 95408044f7; 34.0~beta prints the same with Alt-Ergo 2.4.3
# and its own timings):
#   --- alt-ergo alone
#   [wp] [Timeout] typed_fast_unknown_ensures_fast_false (Alt-Ergo)
#   [wp] [Timeout] typed_hard_true_assert_fermat3 (Alt-Ergo)
#   --- z3 alone
#   [wp] [Timeout] typed_fast_unknown_ensures_fast_false (Z3)
#   [wp] [Unknown] typed_hard_true_assert_fermat3 (Z3)
#   --- cvc5 alone
#   [wp] [Unknown] typed_fast_unknown_ensures_fast_false (CVC5)
#   [wp] [Timeout] typed_hard_true_assert_fermat3 (CVC5)
#   --- three provers: console
#   [wp] [Timeout] typed_fast_unknown_ensures_fast_false (Alt-Ergo)
#   [wp] [Timeout] typed_hard_true_assert_fermat3 (Alt-Ergo)
#   --- three provers: -wp-status (every prover's answer is known)
#         2 Prover Alt-Ergo 2.6.4 returns Timeout
#         1 Prover CVC5 1.1.2 returns Timeout
#         1 Prover CVC5 1.1.2 returns Unknown
#         1 Prover Z3 4.13.3 returns Timeout
#         1 Prover Z3 4.13.3 returns Unknown
#   --- three provers: r3.json, provers listed per goal
#   "goal":"typed_fast_unknown_ensures_fast_false" "prover":"qed" "time":0 "prover":"Alt-Ergo:2.6.4" "time":0
#   "goal":"typed_hard_true_assert_fermat3" "prover":"qed" "time":0.000774 "prover":"Alt-Ergo:2.6.4" "time":0
#   "goal":"typed_product_ensures_bounded" "prover":"qed" "time":0.00171 "prover":"Alt-Ergo:2.6.4" "time":0.0111
#   --- cache: second run with -wp-cache update, "cached" in the JSON
#   [wp] [Timeout] typed_fast_unknown_ensures_fast_false (Alt-Ergo) (Cached)
#   [wp] [Timeout] typed_hard_true_assert_fermat3 (Qed 0.68ms) (Alt-Ergo) (Cached)
#   [wp] [Cache] found:7
#   "goal":"typed_fast_unknown_ensures_fast_false" "cached":3 "goal":"typed_hard_true_assert_fermat3" "cached":3 "goal":"typed_product_ensures_bounded" "cached":1
#   RESULT: present (r3.json keeps one prover per goal, -wp-status saw three)
#
# Reading it: the JSON keeps Alt-Ergo's Timeout and drops Z3's and CVC5's
# answers (CVC5 said Unknown on fast_false); "time" is 0 on unproved goals
# and in seconds on the proved one (0.0111 for about 11 ms, where the manual
# says milliseconds); "cached" is 3 on one goal, one per prover cache hit,
# where the manual says it counts cached sub-goals.
#
# Prover answers on unproved goals depend on the machine (Timeout and
# Unknown can swap); the lost information does not.
set -u
tmp=${TMPDIR:-/tmp}/repro40.$$
mkdir -p "$tmp"
cp 40-wp-report-per-prover-results.c "$tmp/t.c"
cd "$tmp"
B="frama-c -no-unicode t.c -wp -wp-timeout 4 -wp-par 1"
for p in alt-ergo z3 cvc5; do
  echo "--- $p alone"
  timeout 300 $B -wp-prover $p -wp-cache none 2>&1 \
    | grep '^\[wp\] \[' | grep -v -e '\[Valid\]' | sed 's/ (Qed [^)]*)//'
done
echo "--- three provers: console"
timeout 300 $B -wp-prover alt-ergo,z3,cvc5 -wp-cache none \
  -wp-report-json r3.json -wp-status > out3.log 2>&1
grep '^\[wp\] \[' out3.log | grep -v '\[Valid\]' | sed 's/ (Qed [^)]*)//'
echo "--- three provers: -wp-status (every prover's answer is known)"
grep -o 'Prover [A-Za-z0-9.-]* [0-9.]* returns [A-Za-z]*' out3.log | sort | uniq -c
echo "--- three provers: r3.json, provers listed per goal"
flat() { tr -d '[:space:]' < "$1"; }
flat r3.json | grep -o '"goal":"[^"]*"\|"prover":"[^"]*"\|"time":[0-9.e-]*' \
  | awk '/^"goal"/ { if (l != "") print l; l = $0; next } { l = l " " $0 }
         END { print l }'
echo "--- cache: second run with -wp-cache update, \"cached\" in the JSON"
mkdir cache
timeout 300 $B -wp-prover alt-ergo,z3,cvc5 -wp-cache update -wp-cache-dir cache \
  > c1.log 2>&1
timeout 300 $B -wp-prover alt-ergo,z3,cvc5 -wp-cache update -wp-cache-dir cache \
  -wp-report-json c2.json > c2.log 2>&1
grep -e 'Cache' c2.log
flat c2.json | grep -o '"goal":"[^"]*"\|"cached":[0-9]*' | paste -s -d ' ' -
lost=0
if grep -q 'returns' out3.log; then
  np=$(flat r3.json | grep -o '"prover":"[^"]*"' | grep -v -c '"qed"')
  ng=$(flat r3.json | grep -o '"goal":"[^"]*"' | grep -c .)
  [ "$np" -le "$ng" ] && lost=1
fi
cd / && rm -rf "$tmp"
if [ "$lost" = 1 ]; then
  echo "RESULT: present (r3.json keeps one prover per goal, -wp-status saw three)"
  exit 1
else echo "RESULT: r3.json lists more than one prover per goal"; exit 0
fi
