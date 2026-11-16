#!/bin/sh
# e-acsl-gcc preprocesses for Frama-C with -std=c99 -D_DEFAULT_SOURCE but
# compiles with -std=c99 alone: POSIX declarations (strdup, ...) disappear.
#
# Image: framac-master-audit:3dff90f (master 3dff90fc70), framac-analysis:fc34 (34.0~beta).
# Run from the repro directory:
#   docker run --rm -v "$PWD:/w" -w /w --entrypoint sh <image> 12-eacsl-gcc-default-source.sh
#
# Both images ship gcc 14.2.0, which rejects the implicit int-to-pointer
# conversion. Output on master 3dff90fc70 (same on 34.0~beta):
#   == e-acsl-gcc  (gcc)
#   exit=1
#   error: fail to compile/link un-instrumented code
#   error: initialization of ‘char *’ from ‘int’ makes pointer from integer without a cast [-Wint-conversion]
#   == e-acsl-gcc -L (gcc)
#   exit=1
#   error: fail to compile/link un-instrumented code
#   error: initialization of ‘char *’ from ‘int’ makes pointer from integer without a cast [-Wint-conversion]
#
# Output with the fix (-D_DEFAULT_SOURCE added to CFLAGS):
#   == e-acsl-gcc  (gcc)
#   exit=0
#   pd.e-acsl exit=0
#   == e-acsl-gcc -L (gcc)
#   exit=0
#   pd.e-acsl exit=0

N=12-eacsl-gcc-default-source
T=$(mktemp -d)
cp "$N.c" "$T/"
cd "$T" || exit 1

for opts in "" "-L"; do
  echo "== e-acsl-gcc $opts (gcc)"
  e-acsl-gcc $opts -o pd.c -O pd "$N.c" > pd.log 2>&1
  echo "exit=$?"
  grep -E "error:|fatal error" pd.log | sed -e 's/^.*\(error:\)/\1/' | sort -u
  if [ -x pd.e-acsl ]; then ./pd.e-acsl; echo "pd.e-acsl exit=$?"; fi
  rm -f pd pd.e-acsl pd.c
done

rm -rf "$T"
