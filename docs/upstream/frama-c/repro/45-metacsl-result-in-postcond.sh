#!/bin/sh
# Issue 45: [MetAcsl] \result is refused in a \postcond property ("\result
# meaningless"), although such a property becomes an ensures clause of each
# target. Under \tguard the property becomes \true, so a false property is
# proved. This is a report for the MetAcsl tracker (pub/meta), not pub/frama-c.
#
# Image: framac-analysis:latest (Frama-C 34.0~beta, MetAcsl 0.12~beta). Needs
# Alt-Ergo. Command, from this directory:
#   docker run --rm -v "$PWD:/w" -w /w --entrypoint sh framac-analysis:latest \
#     45-metacsl-result-in-postcond.sh
#
# Output before (34.0~beta, MetAcsl 0.12~beta and unpatched master 4f43801390):
#   34.0~beta (Selenium)
#   plain: refused: \result meaningless
#   plain_violated: refused: \result meaningless
#   guarded_violated: ensures \true, 3 / 3 proved
#   by_hand: 3 / 3 proved
#   by_hand_violated: 2 / 3 proved
#   RESULT: \result is refused in \postcond (2 of 2 cases)
#
# Output after, observed with MetAcsl master 4f43801390 + the patch, built
# against the installed 34.0~beta kernel (master minus its one
# PLpointer_comparable case, a constructor 34.0~beta does not have):
#   34.0~beta (Selenium)
#   plain: 3 / 3 proved
#   plain_violated: 2 / 3 proved
#   guarded_violated: 2 / 3 proved
#   by_hand: 3 / 3 proved
#   by_hand_violated: 2 / 3 proved
#   RESULT: \result is accepted in \postcond
#
# guarded_violated is printed for information and does not count: \tguard is
# documented to give \true when the predicate does not type.
set -u
command -v frama-c >/dev/null 2>&1 || { echo "frama-c is not in PATH" >&2; exit 2; }
n=45-metacsl-result-in-postcond
tmp=$(mktemp -d)
fail=0
frama-c -version
meta() { # $1: cpp flags
  frama-c -cpp-extra-args="$1" "$n.c" -meta -meta-no-simpl -then-last -print \
    -wp -wp-timeout 10 > "$tmp/log" 2>&1
  if grep -q 'result meaningless' "$tmp/log"; then
    printf '%s\n' 'refused: \result meaningless'
  else
    post=""
    grep -q 'ensures unchanged_on_failure: meta: \\true' "$tmp/log" && post='ensures \true, '
    printf '%s\n' "$post$(sed -n 's/^\[wp\] Proved goals: *//p' "$tmp/log") proved"
  fi
}
check() { # $1: label, $2: cpp flags, $3: the line expected once fixed
  got=$(meta "$2")
  printf '%s\n' "$1: $got"
  [ "$got" = "$3" ] || fail=$((fail + 1))
}
check plain "-DPLAIN" '3 / 3 proved'
check plain_violated "-DVIOLATE" '2 / 3 proved'
printf '%s\n' "guarded_violated: $(meta '-DGUARDED -DVIOLATE')"
for v in "" "-DVIOLATE"; do
  frama-c -cpp-extra-args="-DBY_HAND $v" "$n.c" -wp -wp-timeout 10 > "$tmp/log" 2>&1
  l=by_hand; [ -n "$v" ] && l=by_hand_violated
  echo "$l: $(sed -n 's/^\[wp\] Proved goals: *//p' "$tmp/log") proved"
done
rm -rf "$tmp"
if [ "$fail" = 0 ]; then printf '%s\n' 'RESULT: \result is accepted in \postcond'; exit 0
else printf '%s\n' "RESULT: \\result is refused in \\postcond ($fail of 2 cases)"; exit 1
fi
