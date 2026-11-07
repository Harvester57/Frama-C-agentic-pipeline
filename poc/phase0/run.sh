#!/bin/sh
# Phase 0 PoC runner (POSIX). Same modes as run.ps1:
#   poc/phase0/run.sh reproducers [rNN_name ...]
#   poc/phase0/run.sh fetch
#   poc/phase0/run.sh targets [target-id ...]
#   poc/phase0/run.sh extract <dir> [build-command]
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
OUT="$HERE/out"
IMAGE=${IMAGE:-framac-pipeline:latest}
mkdir -p "$OUT"
mode=${1:?usage: run.sh reproducers|fetch|targets|extract ...}
shift
only=""
if [ $# -gt 0 ] && [ "$mode" != extract ]; then only="--only $*"; fi
case "$mode" in
  fetch)
    set --
    for id in $(python3 -c "import json,sys; print(' '.join(json.load(open(sys.argv[1]))))" "$HERE/targets.json"); do
      set -- "$@" --target "$id"
    done
    exec python3 -I "$REPO/scripts/benchmark.py" fetch --work-dir "$OUT/checkouts" "$@" ;;
  reproducers)
    exec docker run --rm --network none -v "$REPO:/repo:ro" -v "$OUT:/out" --entrypoint "" "$IMAGE" \
      python3 -B /repo/poc/phase0/score.py reproducers --out /out/reproducers $only ;;
  targets)
    exec docker run --rm --network none -v "$REPO:/repo:ro" -v "$OUT:/out" --entrypoint "" "$IMAGE" \
      python3 -B /repo/poc/phase0/score.py targets --checkouts /out/checkouts --out /out/targets $only ;;
  extract)
    target=$(cd "${1:?target dir}" && pwd); build=${2:-make}
    exec docker run --rm --network none -v "$REPO:/repo:ro" -v "$OUT:/out" -v "$target:/target:ro" --entrypoint "" "$IMAGE" \
      python3 -B /repo/poc/phase0/phase0b.py extract --target /target --out "/out/extract/$(basename "$target")" --build "$build" ;;
  *) echo "unknown mode: $mode" >&2; exit 2 ;;
esac
