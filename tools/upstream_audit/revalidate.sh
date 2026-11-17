#!/bin/bash
# Re-validate upstream filing packages inside the audit image (tools/upstream_audit/Dockerfile:
# upstream master built in /home/opam/frama-c, branch `master`).
#
#   revalidate.sh before NN...                  run the reproducers on the pristine install
#   revalidate.sh package NN                    apply patch NN on a branch from master, run the checks
#   revalidate.sh combined NN MM [dev-test...]  apply both patches, run the given tests in `dev`
#
# /w/patches and /w/repro hold copies of docs/upstream/frama-c/{patches,repro}; this script is
# copied to /w too (docker cp, then chown -R opam /w). Run it as the user opam and keep the
# output: every step prints its exit status, and a failing step does not stop the script.
#
# `package` checks, in order: A. each new test against master's sources (the default
# configuration must fail when the fix changes the generated code, the `dev` configuration when
# the fix is in the runtime); B. the same with the patch (must pass); C. the default configuration
# of the whole E-ACSL suite and of any other touched test directory; D. upstream's lint and
# header check on the commit; E. the reproducer on the installed patched tree.
# One container per run in parallel: the install prefix is shared by the branches of a container.
set -u
JOBS=${JOBS:-8}
cd /home/opam/frama-c || exit 2
# A piped core_pattern (WSL2) ignores a core limit of 0 and makes each abort slow; 1 avoids it.
ulimit -c 1 2>/dev/null || true
export PATH=/home/opam/.opam/5.5/bin:$PATH

log() { echo; echo "===== $* ====="; }
step() { # step <timeout-seconds> <label> <command...>
  local t=$1 label=$2; shift 2
  log "$label"
  timeout "$t" "$@"
  local rc=$?
  echo "[exit=$rc] $label"
  return "$rc"
}

run_repro() { # run_repro <NN> <tag>
  local nn=$1 tag=$2 d=/tmp/repro-$1-$2
  rm -rf "$d"; mkdir -p "$d"; cp /w/repro/"$nn"-* "$d"/
  # Older scripts use `prlimit --core=0`, which a piped core_pattern ignores.
  sed -i 's/prlimit --core=0/prlimit --core=1:1/g' "$d"/*.sh
  local sh; sh=$(ls "$d"/"$nn"-*.sh | head -n 1)
  (cd "$d" && step 1200 "reproducer $nn ($tag)" sh "$(basename "$sh")")
}

case "$1" in
before)
  shift
  frama-c -version
  git log -1 --format='%H %s'
  for nn in "$@"; do run_repro "$nn" before; done
  ;;

package)
  nn=$2
  patch=$(ls /w/patches/"$nn"-*.patch | head -n 1)
  git checkout -q -f master && git clean -fdq && git checkout -q -B "p$nn" master
  step 120 "git am $patch" git am --keep-non-patch "$patch" || exit 1
  ncommits=$(git rev-list --count master..HEAD)
  git log --format='%an <%ae> | %s' -n "$ncommits"
  # A test path is plugins/<p>/tests/... or, for the kernel, tests/... at the root.
  srcs=$(git diff --name-only master..HEAD | grep -v -E '(^|/)tests/')
  modsrcs=$(git diff --name-only --diff-filter=M master..HEAD | grep -v -E '(^|/)tests/')
  addsrcs=$(git diff --name-only --diff-filter=A master..HEAD | grep -v -E '(^|/)tests/')
  git diff --summary master..HEAD | grep -E 'mode change' && echo "[exit=1] the patch changes file modes"
  newtests=$(git diff --name-only --diff-filter=A master..HEAD | grep -E '(^|/)tests/' | grep -v '/oracle' | grep -E '[.](c|i)$')
  testdirs=$(git diff --name-only master..HEAD | grep -E '(^|/)tests/' | sed -E 's#^((.*/)?tests/[^/]+)/.*#\1#' | sort -u)
  echo "sources: $srcs"; echo "new tests: $newtests"; echo "test dirs: $testdirs"

  # A. the new tests against master's sources: changed files as on master, added files removed
  [ -n "$modsrcs" ] && git checkout -q master -- $modsrcs
  [ -n "$addsrcs" ] && rm -f $addsrcs
  step 2400 "A0 build with master sources" opam exec -- dune build -j "$JOBS" @install
  for t in $newtests; do
    step 1500 "A1 default: $t with master sources (must FAIL if the fix changes the generated code)" ./dev/test.sh -p "$t" -- -j "$JOBS"
    step 1500 "A2 dev: $t with master sources (must FAIL if the bug shows at run time)" ./dev/test.sh -p -c dev "$t" -- -j "$JOBS"
  done

  # B. the same with the patched sources
  git checkout -q HEAD -- $srcs
  step 2400 "B0 build with patched sources" opam exec -- dune build -j "$JOBS" @install
  for t in $newtests; do
    step 1500 "B1 default: $t patched (must PASS)" ./dev/test.sh -p "$t" -- -j "$JOBS"
    step 1500 "B2 dev: $t patched (must PASS)" ./dev/test.sh -p -c dev "$t" -- -j "$JOBS"
  done

  # C. default configuration of the whole E-ACSL suite, and of any other touched directory
  step 3000 "C1 default: plugins/e-acsl (must PASS)" ./dev/test.sh -p plugins/e-acsl -- -j "$JOBS"
  for d in $testdirs; do
    case "$d" in plugins/e-acsl/*) ;; *) step 3000 "C2 default: $d (must PASS)" ./dev/test.sh -p "$d" -- -j "$JOBS" ;; esac
  done

  # D. lint and headers on the files of the commit(s)
  step 900 "D lint: check-files.sh -p HEAD~$ncommits" ./dev/check-files.sh -p "HEAD~$ncommits"
  git status --short | grep -v '^??' | head -n 20

  # E. install the patched tree and rerun the reproducer
  step 1200 "E0 install" opam exec -- dune install --release --prefix /home/opam/.opam/5.5
  run_repro "$nn" after
  ;;

combined)
  a=$2; b=$3; shift 3
  git checkout -q -f master && git clean -fdq && git checkout -q -B "p$a-$b" master
  step 120 "git am $a" git am --keep-non-patch "$(ls /w/patches/"$a"-*.patch | head -n 1)" || exit 1
  step 120 "git am --3way $b" git am --3way --keep-non-patch "$(ls /w/patches/"$b"-*.patch | head -n 1)" || exit 1
  step 2400 "build $a+$b" opam exec -- dune build -j "$JOBS" @install
  for t in "$@"; do
    step 2400 "dev: $t with $a+$b (must PASS)" ./dev/test.sh -p -c dev "$t" -- -j "$JOBS"
  done
  ;;

*)
  echo "usage: revalidate.sh before NN... | package NN | combined NN MM [dev-test...]" >&2
  exit 2
  ;;
esac
