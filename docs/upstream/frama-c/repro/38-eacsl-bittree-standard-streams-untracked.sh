#!/bin/sh
# Issue 38: the bittree memory model never registers stdin, stdout, stderr
# and errno as safe locations: its eacsl_memory_init() does not call
# collect_safe_locations(), which the segment model calls at start-up. Every
# run-time check on a standard stream then fails in that model:
#  - 38-....c: \valid(out) with out == stdout, \valid(err), \valid_read(in),
#    \object_pointer(stdout). (\valid(stdout) written on the global itself is
#    resolved at instrumentation time and does not show the bug.)
#  - 38-...-rte.c with -rte -warn-invalid-pointer: the "invalid pointer"
#    guard on the first fputs(..., stdout).
#
# Images: framac-master-audit:9540804 (35.0~~dev, master 95408044f7) and
# framac-analysis:latest (34.0~beta). From the repro directory:
#   docker run --rm -v "$PWD:/w" -w /w --entrypoint sh <image> \
#     38-eacsl-bittree-standard-streams-untracked.sh
# Optional: EACSL_SHARE=<dir> passes --e-acsl-share=<dir> to e-acsl-gcc.
#
# Output on master 95408044f7 (34.0~beta prints the same after its version
# line). The 6 segment lines are all "exit 0; failed checks: none" and are
# left out; "s" is 38-eacsl-bittree-standard-streams-untracked.c and "r" is
# 38-eacsl-bittree-standard-streams-untracked-rte.c:
#   35.0~~dev (Bromine)
#   s -m bittree: exit 0; failed checks: OUT ERR IN OUT_OBJ
#   r -m bittree -F -rte -warn-invalid-pointer: exit 134; failed checks: none; RTE: \null ≡ stdout ∨ \object_pointer(stdout).
#   s -m bittree -M: exit 0; failed checks: OUT ERR IN OUT_OBJ
#   r -m bittree -M -F -rte -warn-invalid-pointer: exit 134; failed checks: none; RTE: \null ≡ stdout ∨ \object_pointer(stdout).
#   s -m bittree -G clang: exit 134; failed checks: none
#   r -m bittree -G clang -F -rte -warn-invalid-pointer: exit 134; failed checks: none; RTE: \null ≡ stdout ∨ \object_pointer(stdout).
#
# Output with the proposed fix (master + patch 38): every line "exit 0;
# failed checks: none", except "s -m bittree -G clang: exit 134", which is
# issue 37 (without -O2, the uninitialized result of pt_lookup reaches the
# allocator, which aborts). With patches 37 and 38, all 12
# lines are "exit 0; failed checks: none".
set -u
n=38-eacsl-bittree-standard-streams-untracked
tmp=$(mktemp -d)
share=${EACSL_SHARE:+--e-acsl-share=$EACSL_SHARE}
frama-c -version
run() { # <source> <e-acsl-gcc options>...
  src=$1; shift
  # shellcheck disable=SC2086
  if ! e-acsl-gcc -q -c $share "$@" -o "$tmp/i.c" -O "$tmp/t" "$src" \
         > "$tmp/build.log" 2>&1; then
    echo "$src $*: e-acsl-gcc failed"; return
  fi
  prlimit --core=1:1 "$tmp/t.e-acsl" > "$tmp/run.log" 2>&1 < /dev/null
  status=$?
  failed=$(grep -A2 'Assertion failed' "$tmp/run.log" |
             sed -n -e 's/^[[:space:]]*\([A-Z_]*\):$/\1/p' | tr '\n' ' ')
  # the predicate of a failed RTE check (dash's echo would expand "\n...")
  rte=$(grep -A3 'RTE failed' "$tmp/run.log" | tail -1 | tr -s '\t ' ' ')
  printf '%s\n' "$src $*: exit $status; failed checks: ${failed:-none}${rte:+; RTE:$rte}"
}
for m in segment bittree; do
  for opts in "" "-M" "-G clang"; do
    # shellcheck disable=SC2086
    run "$n.c" -m $m $opts
    # shellcheck disable=SC2086
    run "$n-rte.c" -m $m $opts -F "-rte -warn-invalid-pointer"
  done
done
rm -rf "$tmp"
