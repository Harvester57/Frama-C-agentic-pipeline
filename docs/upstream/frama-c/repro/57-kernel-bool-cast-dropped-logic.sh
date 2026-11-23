#!/bin/sh
# Issue 57: [Kernel] Cil.fitsInInt and Cil.truncateInteger64 treat IBool as an
# 8-bit unsigned integer (0..255), dropping (_Bool) casts on literals 2..255 in
# ACSL logic.
#
# Images: framac-master-audit:189053d (master 189053d4a2, before),
#         framac-analysis:latest (34.0~beta, before), and master +
#         ../patches/57-kernel-bool-cast-dropped-logic.patch (after).
# Command, from this directory:
#   docker run --rm -v "$PWD:/w" -w /w --entrypoint sh <image> \
#     57-kernel-bool-cast-dropped-logic.sh
set -u
command -v frama-c >/dev/null 2>&1 || { echo "frama-c is not in PATH" >&2; exit 2; }
n=57-kernel-bool-cast-dropped-logic
tmp=$(mktemp -d)
fail=0
total=0
frama-c -version

# 1. -print keeps (_Bool)2 and (_Bool)TWO while still simplifying (_Bool)0 and (_Bool)1
total=$((total + 1))
frama-c -print "$n.c" > "$tmp/print.log" 2>&1
if grep -q 'c1: (_Bool)2' "$tmp/print.log" && grep -q 'c5: (_Bool)TWO' "$tmp/print.log"; then
  echo "print_bool_cast_kept: PASS"
else
  echo "print_bool_cast_kept: FAIL ((_Bool)2 or (_Bool)TWO cast was dropped)"
  fail=$((fail + 1))
fi

# 2. Eva marks c1/c3/c4/c5/c7 valid and c2/c6 invalid
total=$((total + 1))
frama-c -eva "$n.c" > "$tmp/eva.log" 2>&1
if grep -q "check 'c2' got status invalid" "$tmp/eva.log" \
   && grep -q "check 'c6' got status invalid" "$tmp/eva.log" \
   && ! grep -q "check 'c1' got status invalid" "$tmp/eva.log" \
   && ! grep -q "check 'c5' got status invalid" "$tmp/eva.log"; then
  echo "eva_bool_checks: PASS"
else
  echo "eva_bool_checks: FAIL (Eva marks (_Bool)2==1 invalid and (_Bool)2==2 valid)"
  fail=$((fail + 1))
fi

# 3. WP Qed refutes false lemma bool_two_bad
total=$((total + 1))
frama-c -wp -wp-prover none -wp-print "$n.c" > "$tmp/wp.log" 2>&1
if awk '/Goal Check Lemma .bool_two_bad./{f=1} f && /Prove: true\./{exit 1} f && /Prove: false\./{exit 0}' "$tmp/wp.log"; then
  echo "wp_bool_two_bad_refuted: PASS"
else
  echo "wp_bool_two_bad_refuted: FAIL (WP Qed proved false lemma (_Bool)2 == 2)"
  fail=$((fail + 1))
fi

rm -rf "$tmp"
if [ "$fail" = 0 ]; then echo "RESULT: fixed"; exit 0
else echo "RESULT: bug present ($fail of $total checks fail)"; exit 1
fi
