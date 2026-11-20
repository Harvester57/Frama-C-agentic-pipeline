#!/bin/sh
# Issue 49: [MetAcsl] With e-acsl-gcc (system headers, -no-frama-c-stdlib),
# memcpy has no specification, so a \writing property gets no instance at
# memcpy(&protected, ...) and MetAcsl says nothing; the E-ACSL binary runs
# clean. With the Frama-C libc (plain frama-c, or e-acsl-gcc -L) the call has
# its instance. Once memcpy has an assigns clause, an overflowing memcpy is
# reported by the validity guard of the instance, at "<unknown>:0", instead of
# by E-ACSL's memcpy replacement (the same assertion written by hand is
# reported at its line); a property written as \valid(\written) ==> P keeps
# the replacement's message. -M and --libc-replacements are on throughout. This is a report for
# the MetAcsl tracker (pub/meta), not pub/frama-c.
#
# Image: framac-analysis:latest (Frama-C 34.0~beta, MetAcsl 0.12~beta, with
# E-ACSL, e-acsl-gcc and gcc).
# Command, from this directory:
#   docker run --rm -v "$PWD:/w" -w /w --entrypoint sh framac-analysis:latest \
#     49-metacsl-eacsl-libc-instances.sh
#
# Output before (34.0~beta, MetAcsl 0.12~beta as installed):
#   34.0~beta (Selenium)
#   frama-c, Frama-C libc:          instance at memcpy: yes
#   frama-c, system headers:        instance at memcpy: no, footprint warnings: 0
#   e-acsl-gcc, write:              exit 0
#   e-acsl-gcc -L, write:           exit 134, 49-metacsl-eacsl-libc-instances.c:39: Error: Assertion failed:
#   overflow, no property:          exit 134, memcpy: insufficient space in destination space , at least 8 bytes required
#   overflow, contract:             exit 134, <unknown>:0: Error: E-ACSL RTE failed:
#   overflow, -L:                   exit 134, <unknown>:0: Error: E-ACSL RTE failed:
#   overflow, assertion by hand:    exit 134, 49-metacsl-eacsl-libc-instances.c:17: Error: E-ACSL RTE failed:
#   overflow, contract, guarded:    exit 134, memcpy: insufficient space in destination space , at least 8 bytes required
#   write, contract, guarded:       exit 134, 49-metacsl-eacsl-libc-instances.c:35: Error: Assertion failed:
#   RESULT: the call without specification is skipped silently
#
# Output after, observed with MetAcsl master 4f43801390 plus the patch
# 49-metacsl-eacsl-libc-instances.patch, built and installed with dune in a
# throwaway container of the same image (the build also needs one line of
# meta_parse.ml removed, the PLpointer_comparable case, which 34.0~beta does
# not have; that is not part of the patch). Every other line is unchanged:
#   frama-c, system headers:        instance at memcpy: no, footprint warnings: 1
#   RESULT: the call without specification is reported (no-footprint warning)
#
# The patch covers the warning only. The "overflow, contract" line is the
# second request of the issue and has no patch.
set -u
command -v frama-c >/dev/null 2>&1 || { echo "frama-c is not in PATH" >&2; exit 2; }
command -v e-acsl-gcc >/dev/null 2>&1 || { echo "e-acsl-gcc is not in PATH" >&2; exit 2; }
n=49-metacsl-eacsl-libc-instances
tmp=$(mktemp -d)
cp "$n.c" "$tmp/"
cd "$tmp" || exit 2
frama-c -version
inst() { # $1: label, rest: frama-c options
  l=$1; shift
  frama-c -machdep gcc_x86_64 "$@" "$n.c" -meta -then-last -print > log 2>&1
  i=no; grep -q 'auth_state: meta' log && i=yes
  w=$(grep -c 'Cannot analyze footprint of function memcpy' log)
  case $l in *libc*) printf '%-32s%s\n' "$l:" "instance at memcpy: $i" ;;
    *) printf '%-32s%s\n' "$l:" "instance at memcpy: $i, footprint warnings: $w" ;; esac
  warnings=$w
}
run() { # $1: label, rest: e-acsl-gcc options
  l=$1; shift
  rm -rf b; mkdir b
  if ! e-acsl-gcc -M --libc-replacements "$@" -c -o b/t.frama.c -O b/t "$n.c" > b/build.log 2>&1; then
    printf '%-32s%s\n' "$l:" "build failed"; return
  fi
  ./b/t.e-acsl > b/run.log 2>&1
  e=$?
  first=$(grep -m1 -E 'Error:|^memcpy:' b/run.log)
  printf '%-32s%s\n' "$l:" "exit $e${first:+, $first}"
}
inst "frama-c, Frama-C libc"
inst "frama-c, system headers" -no-frama-c-stdlib
run "e-acsl-gcc, write" -F -meta --then-last
run "e-acsl-gcc -L, write" -L -F -meta --then-last
run "overflow, no property" -E -DOVERFLOW
run "overflow, contract" -E "-DOVERFLOW -DUSER_CONTRACT" -F -meta --then-last
run "overflow, -L" -L -E -DOVERFLOW -F -meta --then-last
run "overflow, assertion by hand" -E "-DOVERFLOW -DBY_HAND"
run "overflow, contract, guarded" -E "-DOVERFLOW -DUSER_CONTRACT -DGUARDED" -F -meta --then-last
run "write, contract, guarded" -E "-DUSER_CONTRACT -DGUARDED" -F -meta --then-last
cd / && rm -rf "$tmp"
if [ "$warnings" -ge 1 ]; then
  echo "RESULT: the call without specification is reported (no-footprint warning)"; exit 0
else
  echo "RESULT: the call without specification is skipped silently"; exit 1
fi
