#!/bin/sh
# Issue 44: [Libc] strlcat: the contract states the result against the length
# of the destination after the call, and assigns one byte past the n bytes.
#
# Images: framac-master-audit:b80fcac (master b80fcac74f) and
#         framac-analysis:latest (34.0~beta); same "before" output on both.
# Command, from this directory:
#   docker run --rm -v "$PWD:/w" -w /w --entrypoint sh <image> \
#     44-libc-strlcat-contract.sh
#
# Nine checks. The first five compare Eva with the compiled program
# (44-libc-strlcat-contract.c); the next two are WP on two callers
# (44-libc-strlcat-contract-wp.c: the first postcondition is false at run
# time and must not be proved, the second caller is right and must be); the
# eighth is WP on a byte-loop strlcat (44-libc-strlcat-contract-body.c); the
# last one is Eva on a call that overwrites the NUL of its source
# (44-libc-strlcat-contract-overlap.c), whose precondition must be invalid.
#
# Output before (master b80fcac74f; 34.0~beta prints the same), exit 1:
#   appended: gcc holds; eva unknown
#   truncated: gcc holds; eva unknown
#   no_nul_within_n: gcc holds; eva invalid
#   zero_size: gcc holds; eva invalid
#   next_kept: gcc holds; eva unknown
#   post_state_length: gcc DOES NOT HOLD (result 4, strlen(d) + strlen(s) after the call 6); wp proved 1 / 1
#   pre_state_length: gcc holds (result 4, strlen(d) + strlen(s) before the call 4); wp proved 8 / 10
#   body: wp proved 34 / 35
#   overlap: eva separation valid
#   RESULT: bug present (9 of 9 checks fail)
#
# Output after (master b80fcac74f with patches/44-libc-strlcat-contract.patch
# installed), exit 0:
#   appended: gcc holds; eva valid
#   truncated: gcc holds; eva valid
#   no_nul_within_n: gcc holds; eva valid
#   zero_size: gcc holds; eva valid
#   next_kept: gcc holds; eva valid
#   post_state_length: gcc DOES NOT HOLD (result 4, strlen(d) + strlen(s) after the call 6); wp proved 0 / 1
#   pre_state_length: gcc holds (result 4, strlen(d) + strlen(s) before the call 4); wp proved 10 / 10
#   body: wp proved 35 / 35
#   overlap: eva separation invalid
#   RESULT: fixed
set -u
p=44-libc-strlcat-contract
tmp=${TMPDIR:-/tmp}/repro44.$$
mkdir -p "$tmp"
failed=0
n=0

# "p / t" of a WP run: wp_goals <file> <options...>
wp_goals() {
  f=$1
  shift
  frama-c -no-unicode "$f" -wp -wp-cache none -wp-prover alt-ergo \
    -wp-timeout 20 "$@" > "$tmp/wp.log" 2>&1
  g=$(sed -n 's/.*Proved goals: *\([0-9]*\) *\/ *\([0-9]*\).*/\1 \/ \2/p' "$tmp/wp.log")
  echo "${g:-none (see the WP log)}"
}

# 1. Eva against the compiled program
: > "$tmp/run.log"
gcc -o "$tmp/prog" $p.c > "$tmp/gcc.log" 2>&1 && "$tmp/prog" > "$tmp/run.log" 2>&1
# -eva-show-progress: Eva prints a valid status only among its progress messages.
frama-c -no-unicode $p.c -eva -eva-show-progress > "$tmp/eva.log" 2>&1
for c in appended truncated no_nul_within_n zero_size next_kept; do
  n=$((n + 1))
  g=$(sed -n "s/^$c: //p" "$tmp/run.log")
  s=$(grep -m1 -o "check '$c' got status [a-z]*" "$tmp/eva.log" | sed 's/.* //')
  s=${s:-not reached}
  [ "$s" = valid ] || failed=$((failed + 1))
  echo "$c: gcc ${g:-no output}; eva $s"
done

# 2. WP on two callers
: > "$tmp/run.log"
gcc -o "$tmp/prog" $p-wp.c > "$tmp/gcc.log" 2>&1 && "$tmp/prog" > "$tmp/run.log" 2>&1
n=$((n + 1))
g=$(sed -n 's/^post_state_length: //p' "$tmp/run.log")
w=$(wp_goals $p-wp.c -wp-fct append_wrong -wp-prop post_state_length)
[ "$w" = "0 / 1" ] || failed=$((failed + 1))
echo "post_state_length: gcc ${g:-no output}; wp proved $w"
n=$((n + 1))
g=$(sed -n 's/^pre_state_length: //p' "$tmp/run.log")
w=$(wp_goals $p-wp.c -wp-fct append_right)
[ "${w% / *}" = "${w#* / }" ] || failed=$((failed + 1))
echo "pre_state_length: gcc ${g:-no output}; wp proved $w"

# 3. WP on a byte-loop strlcat
n=$((n + 1))
w=$(wp_goals $p-body.c -wp-rte)
[ "${w% / *}" = "${w#* / }" ] || failed=$((failed + 1))
echo "body: wp proved $w"

# 4. Eva on a call whose written bytes hold the NUL of the source
n=$((n + 1))
frama-c -no-unicode $p-overlap.c -eva -eva-show-progress > "$tmp/eva.log" 2>&1
s=$(grep -m1 -o "precondition 'separation' got status [a-z]*" "$tmp/eva.log" | sed 's/.* //')
s=${s:-not reached}
[ "$s" = invalid ] || failed=$((failed + 1))
echo "overlap: eva separation $s"

rm -rf "$tmp"
if [ "$failed" = 0 ]; then echo "RESULT: fixed"; exit 0
else echo "RESULT: bug present ($failed of $n checks fail)"; exit 1
fi
