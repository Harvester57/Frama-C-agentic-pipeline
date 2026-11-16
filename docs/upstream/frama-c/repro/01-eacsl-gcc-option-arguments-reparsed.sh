#!/bin/sh
# e-acsl-gcc re-reads the words of an option argument as e-acsl-gcc options.
#
# Image: framac-master-audit:3dff90f (master 3dff90fc70), framac-analysis:fc34 (34.0~beta).
# Run from the repro directory:
#   docker run --rm -v "$PWD:/w" -w /w --entrypoint sh <image> 01-eacsl-gcc-option-arguments-reparsed.sh
#
# Output on master 3dff90fc70 (same on 34.0~beta). In A, -g inside the -e
# argument turned on --gmp, the first input file is gone and -o lost its
# argument:
#   == A: -e "-g -O1" (debug info for the compiler), two input files, instrument only
#   exit=1
#   fatal error: aborted by Frama-C
#   frama-c files and E-ACSL options:
#   01-eacsl-gcc-option-arguments-reparsed-helper.c -e-acsl -e-acsl-O-gmp-only -then-last -print -ocode --
#   == B: -E "-I inc" (separated include path), instrument only
#   exit=1
#   fatal error: no input files
#   == C: -l "-L /usr/lib -lm" (separated library path), build and run
#   exit=1
#   fatal error: no input files
#
# Output with the fix:
#   == A: -e "-g -O1" (debug info for the compiler), two input files, instrument only
#   exit=0
#   frama-c files and E-ACSL options:
#   01-eacsl-gcc-option-arguments-reparsed.c 01-eacsl-gcc-option-arguments-reparsed-helper.c -e-acsl -then-last -print -ocode a.c
#   main() and helper() in a.c: 2 line(s)
#   == B: -E "-I inc" (separated include path), instrument only
#   exit=0
#   == C: -l "-L /usr/lib -lm" (separated library path), build and run
#   exit=0
#   c.e-acsl exit=0

N=01-eacsl-gcc-option-arguments-reparsed
T=$(mktemp -d)
mkdir "$T/inc"
cp "$N.c" "$N-helper.c" "$T/"
cp "$N-inc.h" "$T/inc/"
cd "$T" || exit 1

echo '== A: -e "-g -O1" (debug info for the compiler), two input files, instrument only'
e-acsl-gcc -n -E -Iinc -e "-g -O1" -o a.c "$N.c" "$N-helper.c" > a.log 2>&1
echo "exit=$?"
grep -o 'fatal error.*' a.log
echo "frama-c files and E-ACSL options:"
grep '^++ .*frama-c' a.log | sed -e 's/.*-no-frama-c-stdlib //' -e 's/-e-acsl-share=[^ ]* //'
[ -f a.c ] && echo "main() and helper() in a.c: $(grep -c -E 'int (main|helper)\(' a.c) line(s)"

echo '== B: -E "-I inc" (separated include path), instrument only'
e-acsl-gcc -n -E "-I inc" -o b.c "$N.c" > b.log 2>&1
echo "exit=$?"
grep -o 'fatal error.*' b.log

echo '== C: -l "-L /usr/lib -lm" (separated library path), build and run'
e-acsl-gcc -E -Iinc -e -Iinc -l "-L /usr/lib -lm" -o c.c -O c "$N.c" > c.log 2>&1
echo "exit=$?"
grep -o 'fatal error.*' c.log
[ -x c.e-acsl ] && { ./c.e-acsl; echo "c.e-acsl exit=$?"; }

rm -rf "$T"
