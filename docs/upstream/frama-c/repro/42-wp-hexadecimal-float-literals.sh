#!/bin/sh
# Issue 42: [WP] hexadecimal floating-point literals, and the f32/f64
# suffixes, are not read: a hypothesis is dropped, a lemma stops WP, and with
# -wp-model +real a suffixed hexadecimal literal is read as 0.
#
# Images: framac-master-audit:9540804 with its tree moved to master b80fcac74f
#         (before), framac-analysis:latest (34.0~beta, same output), and the
#         master tree with ../patches/42-wp-hexadecimal-float-literals.patch
#         built and installed (after). No prover is needed: Qed decides.
# Command, from this directory:
#   docker run --rm -v "$PWD:/w" -w /w --entrypoint sh <image> \
#     42-wp-hexadecimal-float-literals.sh
#
# Output before (master b80fcac74f; the image as built, at 95408044f7, and
# 34.0~beta print the same):
#   ##### contract
#   Unexpected constant literal "0x1.fffffffffffffp+1023"
#   Prove: r <= w.
#   ##### lemma
#   Unexpected constant literal "0x1.8p1"
#   ##### suffix
#   Unexpected constant literal "1.5f32"
#   ##### real -wp-model +real
#   Prove: true.
#   Prove: true.
#   RESULT: bug present (4 of 4 cases fail)
#
# Output after:
#   ##### contract
#   Prove: true.
#   ##### lemma
#   Prove: true.
#   ##### suffix
#   Prove: true.
#   ##### real -wp-model +real
#   Prove: false.
#   Prove: false.
#   RESULT: fixed
#
# In the contract case, r is of_f64(x) and w an unknown value: the bound is lost
# (the message is printed once here; WP repeats it for each use).
# In the lemma and suffix cases the message is a "User Error" and WP stops.
# In the last case the two goals are false: "Prove: true." is the wrong proof.
set -u
command -v frama-c >/dev/null 2>&1 || { echo "frama-c is not in PATH" >&2; exit 2; }
F=42-wp-hexadecimal-float-literals.c
W="-no-unicode -wp -wp-prover none -wp-print -wp-cache none"
fail=0
run() { # $1: case, $2: the Prove line of every goal once fixed, $3: extra option
  echo "##### $1${3:+ $3}"
  # shellcheck disable=SC2086
  shown=$(frama-c "$F" -cpp-extra-args="-DCASE_$1" $W -wp-prop=@lemma,@ensures \
            ${3:-} 2>&1 | grep -o -e 'Unexpected constant literal.*' -e '^Prove:.*' \
            | awk '/^Prove:/ || !seen[$0]++')
  echo "$shown"
  if echo "$shown" | grep -q 'Unexpected' \
     || [ -n "$(echo "$shown" | grep '^Prove:' | grep -v -x "$2")" ] \
     || ! echo "$shown" | grep -q -x "$2"; then
    fail=$((fail + 1))
  fi
}
run contract 'Prove: true.'
run lemma 'Prove: true.'
run suffix 'Prove: true.'
run real 'Prove: false.' '-wp-model +real'
if [ "$fail" = 0 ]; then echo "RESULT: fixed"; exit 0
else echo "RESULT: bug present ($fail of 4 cases fail)"; exit 1
fi
