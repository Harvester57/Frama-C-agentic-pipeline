#!/usr/bin/env bash
# Executes a command inside a hardened pipeline container.
#
#   framac-docker.sh [--target DIR] (--run-dir DIR | --new-run) [--repo NAME]
#                    [--target-packages "pkg1 pkg2"] [--build-if-missing]
#                    [--build-image | --codeql] [--scratch] [--remove-scratch]
#                    [--allow-run-dir-in-target] [--engine docker|podman|auto]
#                    [--class CLASS] [--no-broker] [--cpus N] [--memory SIZE] [--pids-limit N]
#                    [--cache-dir DIR|off] [--cache-rw] [--script-file FILE] -- <command...>
#
# --build-image runs the command in the build image (framac-build:latest, Dockerfile stage framac-build:
# the target's own build and tests, e.g. scripts/build_capture.py); with --target-packages the derived
# build image framac-build:<repo key> is built and used. FRAMAC_DOCKER_IMAGE still overrides the name.
# Every other command runs in the analysis image (framac-analysis:latest), which holds no target package:
# the target's headers and libraries come from the run's snapshot (workspace/snapshot/, written by the
# build capture), so --target-packages only derives the build image. FRAMAC_DOCKER_IMAGE only renames the
# image: a missing one is built from the matching stage (framac-analysis or framac-build) with --build-if-missing.
# --codeql runs the command in the CodeQL image (optional trust facts, scripts/codeql_trust.py, plan step
# I7): framac-codeql:latest (Dockerfile.codeql: the build image plus the pinned CodeQL CLI). With
# --target-packages, framac-build:<repo key> is derived first, then framac-codeql:<repo key> from it, copying
# /opt/codeql out of framac-codeql:latest (wrappers/codeql-derived.Dockerfile, no download); it carries both
# base image ids as labels and is rebuilt when either changes. Local only: never push or share it.
# --scratch creates (once) and mounts the run's named volume framac-scratch-<repo>-<run id>-<hash of
# the run dir> at /framac-scratch (the build capture's scratch tree); --remove-scratch removes it and exits.
#
# Run identity: the repo key <repo>-<12 hex of sha256(resolved target path)> tells apart two targets with
# the same folder name (derived image tags, cache partition); the run tag <run id>-<12 hex of sha256(resolved
# run dir)> tells apart runs. Both reach the container and the host broker as FRAMAC_REPO_KEY / FRAMAC_RUN_TAG,
# and label every container (and the scratch volume) as framac.repo / framac.run. --new-run claims run-<N>
# with a mkdir that fails when the directory exists, so concurrent wrappers never share a run.
#
# Mounts: /target (read-only), /framac-run (run dir, read-write, working dir),
# /opt/framac-pipeline/{scripts,templates,schemas,skills,docs/references} (read-only) and, on the
# broker path, the shared cache /framac-cache: this repository's partition of FRAMAC_CACHE_DIR,
# writable only for the exactly allowlisted trusted commands (read-only everywhere with
# FRAMAC_CACHE_RW=off; --cache-rw is the default and kept for compatibility).
# Hardening: --network none, --cap-drop ALL, no-new-privileges, the engine's default
# seccomp and AppArmor/SELinux profiles, cpu/memory/pids limits, allowlisted environment.
# The container is the isolation boundary; target-controlled binaries run through
# scripts/sandbox_exec.py (rlimits, env allowlist, timeout) with no filesystem
# isolation inside the container.
#
# Sizing: by default the host broker (scripts/resources.py exec, needs a host python3 >= 3.10)
# measures the machine on every call, takes a lease for the job class (inferred from the
# command unless --class) and starts the container with --cpus/--memory/--pids-limit from that
# lease, so concurrent containers never oversubscribe the node; when a gated lease releases and
# no tickets are waiting, running elastic containers are grown via `<engine> update` (never
# shrunk). --cpus/--memory/--pids-limit (or FRAMAC_CPUS/FRAMAC_MEMORY/FRAMAC_PIDS_LIMIT) request
# a fixed grant, still registered with the broker. --no-broker or FRAMAC_BROKER=off (and, with a
# warning, a missing host python3 >= 3.10) keep the legacy static sizing: per-container
# FRAMAC_CPUS/FRAMAC_MEMORY/FRAMAC_PIDS_LIMIT, divided by --agents / FRAMAC_CONCURRENT_AGENTS.
# Engine: --engine or FRAMAC_CONTAINER_ENGINE = docker | podman | auto (docker when usable).
# SELinux (enforcing): pipeline-owned mounts get :z; the target mount needs
# FRAMAC_SELINUX_TARGET=relabel (:z) or FRAMAC_SELINUX_TARGET=disable (label=disable).
# The legacy --no-inner-sandbox and --allow-degraded-sandbox flags were removed
# together with bubblewrap; passing either one fails with exit 2.
set -euo pipefail

export PYTHONIOENCODING="utf-8"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PIPELINE_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
TARGET_DIR="${TARGET_DIR:-$(pwd)}"
IMAGE="${FRAMAC_DOCKER_IMAGE:-framac-analysis:latest}"
BUILD_IMAGE=0
CODEQL=0
SCRATCH=0
REMOVE_SCRATCH=0
ENGINE_PREF="${FRAMAC_CONTAINER_ENGINE:-auto}"
CPUS="${FRAMAC_CPUS:-}"
MEMORY="${FRAMAC_MEMORY:-}"
AGENTS="${FRAMAC_CONCURRENT_AGENTS:-}"
PIDS="${FRAMAC_PIDS_LIMIT:-}"
JOB_CLASS=""
NO_BROKER=0
[[ "${FRAMAC_BROKER:-}" == "off" ]] && NO_BROKER=1
CACHE_DIR=""
CACHE_RW=0
RUN_DIR=""
NEW_RUN=0
REPO=""
TARGET_PACKAGES=""
BUILD=0
ALLOW_IN_TARGET=0
SCRIPT_FILE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --target) TARGET_DIR="$2"; shift 2 ;;
        --run-dir) RUN_DIR="$2"; shift 2 ;;
        --new-run) NEW_RUN=1; shift ;;
        --repo) REPO="$2"; shift 2 ;;
        --target-packages) TARGET_PACKAGES="$2"; shift 2 ;;
        --build-if-missing) BUILD=1; shift ;;
        --build-image) BUILD_IMAGE=1; shift ;;
        --codeql) CODEQL=1; shift ;;
        --scratch) SCRATCH=1; shift ;;
        --remove-scratch) REMOVE_SCRATCH=1; shift ;;
        --agents) AGENTS="$2"; shift 2 ;;
        --cpus) CPUS="$2"; shift 2 ;;
        --memory) MEMORY="$2"; shift 2 ;;
        --pids-limit) PIDS="$2"; shift 2 ;;
        --class) JOB_CLASS="$2"; shift 2 ;;
        --engine) ENGINE_PREF="$2"; shift 2 ;;
        --no-broker) NO_BROKER=1; shift ;;
        --cache-dir) CACHE_DIR="$2"; shift 2 ;;
        --cache-rw) CACHE_RW=1; shift ;;
        --script-file) SCRIPT_FILE="$2"; shift 2 ;;
        --no-inner-sandbox|--allow-degraded-sandbox)
            echo "[framac-docker] ERROR: $1 is no longer supported. The bubblewrap inner sandbox was removed;" \
                 "the hardened container (default seccomp/AppArmor) is the isolation boundary and target-controlled" \
                 "binaries run under scripts/sandbox_exec.py (rlimits, env allowlist, timeout). Drop $1 from the command line." >&2
            exit 2 ;;
        --allow-run-dir-in-target) ALLOW_IN_TARGET=1; shift ;;
        --) shift; break ;;
        -*)
            echo "[framac-docker] ERROR: unknown wrapper option '$1'." \
                 "Valid options: --target, --run-dir, --new-run, --repo, --target-packages, --build-if-missing," \
                 "--build-image, --codeql, --scratch, --remove-scratch, --allow-run-dir-in-target, --engine, --class, --no-broker, --cpus, --memory, --pids-limit," \
                 "--cache-dir, --cache-rw, --script-file, -- <command...>" >&2
            exit 2 ;;
        *) break ;;
    esac
done

# ---- Container engine (docker or podman) ----
have() { command -v "$1" >/dev/null 2>&1; }
case "${ENGINE_PREF}" in
    docker|podman)
        have "${ENGINE_PREF}" || { echo "[framac-docker] container engine '${ENGINE_PREF}' not found on PATH" >&2; exit 2; }
        ENGINE="${ENGINE_PREF}" ;;
    auto|"")
        if have docker && { ! have podman || docker info >/dev/null 2>&1; }; then
            ENGINE=docker
        elif have podman; then
            ENGINE=podman
        else
            echo "[framac-docker] no container engine found (install docker or podman, or set FRAMAC_CONTAINER_ENGINE)" >&2; exit 2
        fi ;;
    *) echo "[framac-docker] invalid engine '${ENGINE_PREF}' (docker|podman|auto)" >&2; exit 2 ;;
esac
OUTER_SANDBOX="docker-hardened"
ENGINE_VERSION="$("${ENGINE}" --version 2>/dev/null || true)"
case "${ENGINE}:${ENGINE_VERSION}" in
    podman:*|*[Pp]odman*) OUTER_SANDBOX="podman-hardened" ;;
esac

# ---- Sizing path: host broker (default) or legacy static limits ----
PYTHON=""
find_python() {
    local cand
    for cand in "${FRAMAC_PYTHON:-}" python3; do
        [[ -n "${cand}" ]] || continue
        if have "${cand}" && "${cand}" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' >/dev/null 2>&1; then
            PYTHON="${cand}"
            return 0
        fi
    done
    return 1
}
if [[ ${NO_BROKER} -eq 0 ]] && ! find_python; then
    echo "[framac-docker] WARNING: no host python3 >= 3.10 found; using static per-container limits (as with --no-broker)" >&2
    NO_BROKER=1
fi
if [[ ${NO_BROKER} -eq 0 && -n "${AGENTS}" ]]; then
    echo "[framac-docker] WARNING: --agents / FRAMAC_CONCURRENT_AGENTS is deprecated and ignored: the host broker" \
         "sizes every container from the measured pool (use --no-broker for the legacy division)" >&2
fi

if [[ ${NO_BROKER} -eq 1 ]]; then
    AGENTS="${AGENTS:-1}"
    DEFAULT_CPUS="$(command -v nproc >/dev/null 2>&1 && nproc || echo 4)"
    DEFAULT_MEM="$(awk '/MemTotal:/ { g = int(($2 / 1048576) * 0.75); if (g < 8) g = 8; print g "g" }' /proc/meminfo 2>/dev/null || echo 8g)"
    [[ -z "${DEFAULT_MEM}" ]] && DEFAULT_MEM="8g"
    if [[ "${AGENTS}" =~ ^[0-9]+$ ]] && (( AGENTS > 1 )); then
        if [[ -z "${CPUS}" ]]; then
            DIV_CPUS=$(( DEFAULT_CPUS / AGENTS ))
            (( DIV_CPUS < 2 )) && DIV_CPUS=2
            CPUS="${DIV_CPUS}"
        fi
        if [[ -z "${MEMORY}" ]]; then
            MEM_NUM="${DEFAULT_MEM%g}"
            [[ "${MEM_NUM}" =~ ^[0-9]+$ ]] || MEM_NUM=8
            DIV_MEM=$(( MEM_NUM / AGENTS ))
            (( DIV_MEM < 2 )) && DIV_MEM=2
            MEMORY="${DIV_MEM}g"
        fi
        if [[ -z "${PIDS}" ]]; then
            DIV_PIDS=$(( 4096 / AGENTS ))
            (( DIV_PIDS < 512 )) && DIV_PIDS=512
            PIDS="${DIV_PIDS}"
        fi
    fi
    CPUS="${CPUS:-${DEFAULT_CPUS}}"
    MEMORY="${MEMORY:-${DEFAULT_MEM}}"
    PIDS="${PIDS:-4096}"
fi

RESOLVED_TARGET="$(cd "${TARGET_DIR}" && pwd)"
REPO="${REPO:-$(basename "${RESOLVED_TARGET}")}"
if [[ ! "${REPO}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; then
    echo "[framac-docker] invalid repo name '${REPO}' (use --repo)" >&2; exit 2
fi
# First 12 hex digits of the SHA-256 of a string (the scratch volume's run hash, the repo key's target hash).
short_hash() { printf '%s' "$1" | { sha256sum 2>/dev/null || shasum -a 256; } | cut -c1-12; }
# Repo key: the display name plus a hash of the resolved target path, so two targets with the same folder
# name never share a derived image tag or a cache partition. A Docker tag holds at most 128 characters:
# the name part is cut to fit, the hash is kept.
REPO_KEY="${REPO:0:115}-$(short_hash "${RESOLVED_TARGET}")"

if [[ ${NEW_RUN} -eq 1 ]]; then
    [[ -n "${RUN_DIR}" ]] && { echo "[framac-docker] use --run-dir or --new-run, not both" >&2; exit 2; }
    BASE="${HOME}/framac-pipeline/${REPO}"
    mkdir -p "${BASE}"
    # new-run allocation: start after the highest run-<N>, claim it with a mkdir that fails when the
    # directory exists (no -p), and on a lost race try the next number.
    MAX=0
    for d in "${BASE}"/run-*; do
        [[ -d "$d" ]] || continue
        n="${d##*/run-}"
        [[ "$n" =~ ^[0-9]+$ ]] && (( n > MAX )) && MAX=$n
    done
    N=$((MAX + 1))
    ATTEMPTS=0
    until mkdir "${BASE}/run-${N}" 2>/dev/null; do
        if [[ ! -e "${BASE}/run-${N}" ]]; then
            echo "[framac-docker] cannot create run dir ${BASE}/run-${N}" >&2; exit 2
        fi
        ATTEMPTS=$((ATTEMPTS + 1))
        if (( ATTEMPTS >= 1000 )); then
            echo "[framac-docker] no free run-<N> under ${BASE} after ${ATTEMPTS} attempts" >&2; exit 2
        fi
        N=$((N + 1))
    done
    RUN_DIR="${BASE}/run-${N}"
    # end new-run allocation
fi
[[ -z "${RUN_DIR}" ]] && { echo "[framac-docker] specify --run-dir DIR or --new-run" >&2; exit 2; }
mkdir -p "${RUN_DIR}"
RESOLVED_RUN="$(cd "${RUN_DIR}" && pwd)"

case "${RESOLVED_RUN}/" in
    "${RESOLVED_TARGET}/"*)
        if [[ ${ALLOW_IN_TARGET} -ne 1 ]] || ! git -C "${RESOLVED_TARGET}" check-ignore -q "${RESOLVED_RUN}"; then
            echo "[framac-docker] run dir is inside the target; use an outside path or a git-ignored path with --allow-run-dir-in-target" >&2
            exit 2
        fi ;;
esac
RUN_ID="$(basename "${RESOLVED_RUN}")"
RUN_HASH="$(short_hash "${RESOLVED_RUN}")"
RUN_TAG="${RUN_ID}-${RUN_HASH}"
echo "[framac-docker] run dir: ${RESOLVED_RUN}" >&2
echo "[framac-docker] run identity: ${REPO_KEY} / ${RUN_TAG}" >&2

# ---- SELinux: relabel pipeline-owned mounts; the target needs an explicit choice ----
Z=""
ZRW=""
ZT=""
SELINUX_ARGS=()
if [[ -r /sys/fs/selinux/enforce && "$(cat /sys/fs/selinux/enforce 2>/dev/null)" == "1" ]]; then
    Z=",z"
    ZRW=":z"
    case "${FRAMAC_SELINUX_TARGET:-}" in
        relabel) ZT=",z" ;;
        disable) SELINUX_ARGS=(--security-opt label=disable) ;;
        *)
            echo "[framac-docker] SELinux is enforcing: set FRAMAC_SELINUX_TARGET=relabel to relabel the target" \
                 "(shared container label, :z) or FRAMAC_SELINUX_TARGET=disable to run without SELinux confinement" \
                 "(--security-opt label=disable)." >&2
            exit 2 ;;
    esac
fi

# ---- Scratch volume: one named volume per run directory (repo, run id, and a hash of the run path) ----
SCRATCH_VOLUME=""
if [[ ${SCRATCH} -eq 1 || ${REMOVE_SCRATCH} -eq 1 ]]; then
    SCRATCH_VOLUME="framac-scratch-${REPO}-${RUN_ID}-${RUN_HASH}"
fi
if [[ ${REMOVE_SCRATCH} -eq 1 ]]; then
    "${ENGINE}" volume rm -f "${SCRATCH_VOLUME}" >/dev/null
    echo "[framac-docker] removed scratch volume ${SCRATCH_VOLUME}" >&2
    exit 0
fi

# Build steps (--build-image) run in the build image (Dockerfile stage framac-build); everything else in the
# analysis image (stage framac-analysis). FRAMAC_DOCKER_IMAGE only renames the image; it is built from the same stage.
IMAGE_TARGET=(--target framac-analysis)
if [[ ${BUILD_IMAGE} -eq 1 && ${CODEQL} -eq 1 ]]; then
    echo "[framac-docker] use either --build-image or --codeql" >&2; exit 2
fi
if [[ ${CODEQL} -eq 1 ]]; then
    # The CodeQL image extends the build image: the build image (or its derived image) is resolved first.
    IMAGE="framac-build:latest"
    IMAGE_TARGET=(--target framac-build)
elif [[ ${BUILD_IMAGE} -eq 1 ]]; then
    IMAGE="${FRAMAC_DOCKER_IMAGE:-framac-build:latest}"
    IMAGE_TARGET=(--target framac-build)
elif [[ -n "${TARGET_PACKAGES}" ]]; then
    echo "[framac-docker] --target-packages ignored: the analysis image reads the target's headers and libraries from the run's snapshot (pass them to the --build-image capture)" >&2
    TARGET_PACKAGES=""
fi
if [[ -z "$("${ENGINE}" images -q "${IMAGE}" 2>/dev/null)" ]]; then
    if [[ ${BUILD} -eq 1 ]]; then
        echo "[framac-docker] Building ${IMAGE}..." >&2
        "${ENGINE}" build ${IMAGE_TARGET[@]+"${IMAGE_TARGET[@]}"} -t "${IMAGE}" "${PIPELINE_ROOT}" >&2
    else
        echo "[framac-docker] image ${IMAGE} not found (use --build-if-missing)" >&2; exit 2
    fi
fi

if [[ -n "${TARGET_PACKAGES}" ]]; then
    DERIVED_IMAGE="framac-build:${REPO_KEY}"
    echo "[framac-docker] Building derived image ${DERIVED_IMAGE} with target packages: ${TARGET_PACKAGES}" >&2
    "${ENGINE}" build ${IMAGE_TARGET[@]+"${IMAGE_TARGET[@]}"} -t "${DERIVED_IMAGE}" \
        --build-arg "TARGET_APT_PACKAGES=${TARGET_PACKAGES}" "${PIPELINE_ROOT}" >&2
    IMAGE="${DERIVED_IMAGE}"
fi

if [[ ${CODEQL} -eq 1 ]]; then
    CODEQL_SOURCE="framac-codeql:latest"
    if [[ -z "$("${ENGINE}" images -q "${CODEQL_SOURCE}" 2>/dev/null)" ]]; then
        if [[ ${BUILD} -ne 1 ]]; then
            echo "[framac-docker] image ${CODEQL_SOURCE} not found (use --build-if-missing; it downloads the pinned CodeQL bundle)" >&2; exit 2
        fi
        echo "[framac-docker] Building ${CODEQL_SOURCE} from Dockerfile.codeql" >&2
        "${ENGINE}" build -f "${PIPELINE_ROOT}/Dockerfile.codeql" -t "${CODEQL_SOURCE}" "${PIPELINE_ROOT}" >&2
    fi
    if [[ "${IMAGE}" != "framac-build:latest" ]]; then
        # A target with packages: framac-codeql:<repo key> = its derived build image + /opt/codeql of framac-codeql:latest.
        CODEQL_IMAGE="framac-codeql:${REPO_KEY}"
        BASE_ID="$("${ENGINE}" image inspect -f '{{.Id}}' "${IMAGE}")"
        SOURCE_ID="$("${ENGINE}" image inspect -f '{{.Id}}' "${CODEQL_SOURCE}")"
        LABELS="$("${ENGINE}" image inspect -f '{{index .Config.Labels "framac.codeql.base"}} {{index .Config.Labels "framac.codeql.source"}}' "${CODEQL_IMAGE}" 2>/dev/null || true)"
        if [[ "${LABELS}" != "${BASE_ID} ${SOURCE_ID}" ]]; then
            echo "[framac-docker] Building ${CODEQL_IMAGE} from ${IMAGE} and ${CODEQL_SOURCE} (local only, never pushed)" >&2
            "${ENGINE}" build -t "${CODEQL_IMAGE}" --build-arg "BUILD_IMAGE=${IMAGE}" --build-arg "CODEQL_IMAGE=${CODEQL_SOURCE}" \
                --label "framac.codeql.base=${BASE_ID}" --label "framac.codeql.source=${SOURCE_ID}" \
                - < "${PIPELINE_ROOT}/wrappers/codeql-derived.Dockerfile" >&2
        fi
        IMAGE="${CODEQL_IMAGE}"
    else
        IMAGE="${CODEQL_SOURCE}"
    fi
fi

if [[ ${SCRATCH} -eq 1 ]]; then
    if ! "${ENGINE}" volume inspect "${SCRATCH_VOLUME}" >/dev/null 2>&1; then
        "${ENGINE}" volume create --label framac.scratch=1 --label "framac.repo=${REPO_KEY}" \
            --label "framac.run=${RUN_TAG}" "${SCRATCH_VOLUME}" >/dev/null
        # No chmod: both images create /framac-scratch with mode 1777, and the engine copies that mode to
        # the new, empty volume on its first mount, so the non-root job user can write it.
    fi
    echo "[framac-docker] scratch volume: ${SCRATCH_VOLUME} at /framac-scratch" >&2
fi
IMAGE_ID="$( ("${ENGINE}" image inspect -f '{{.Id}}' "${IMAGE}" 2>/dev/null | head -n 1) || true)"

TARGET_COMMIT="$(git -C "${RESOLVED_TARGET}" rev-parse HEAD 2>/dev/null || true)"
TARGET_DIRTY=""
if [[ -n "${TARGET_COMMIT}" ]]; then
    if [[ -n "$(git -C "${RESOLVED_TARGET}" status --porcelain --untracked-files=no 2>/dev/null || true)" ]]; then
        TARGET_DIRTY="1"
    else
        TARGET_DIRTY="0"
    fi
fi

HARDENING=(--rm -i --network none --cap-drop ALL --security-opt no-new-privileges)
if [[ "${OUTER_SANDBOX}" == "docker-hardened" ]]; then
    HARDENING+=(--user "$(id -u):$(id -g)")
fi
# Run identity labels on every container, on both paths (the broker adds only its own framac.lease label).
LABEL_ARGS=(--label "framac.repo=${REPO_KEY}" --label "framac.run=${RUN_TAG}")
ENV_ARGS=(-e PYTHONIOENCODING=utf-8 -e "S=/opt/framac-pipeline/scripts"
          -e "FRAMAC_OUTER_SANDBOX=${OUTER_SANDBOX}"
          -e "FRAMAC_TARGET_HOST=${RESOLVED_TARGET}"
          -e "FRAMAC_REFERENCES_HOST=${PIPELINE_ROOT}/docs/references"
          -e "FRAMAC_REPO=${REPO}" -e "FRAMAC_REPO_KEY=${REPO_KEY}" -e "FRAMAC_RUN_TAG=${RUN_TAG}"
          -e "FRAMAC_RUN_ID=${RUN_ID}" -e "FRAMAC_RUN_HOST=${RESOLVED_RUN}"
          -e "FRAMAC_TARGET_COMMIT=${TARGET_COMMIT}"
          -e "FRAMAC_TARGET_DIRTY=${TARGET_DIRTY}")
# Pipeline knobs that scripts read inside the container: forwarded when set on the host.
# Keep this list identical to framac-docker.ps1 and docker-compose.yml (tests/test_remediation_p2_container.py).
for knob in FRAMAC_CACHE FRAMAC_CACHE_MAX FRAMAC_MAX_AGENTS FRAMAC_SCHEDULER FRAMAC_LOCK_TIMEOUT \
            FRAMAC_LOCK_STALE FRAMAC_WP_WALL_TIMEOUT FRAMAC_PROVER_WALL_BUDGET_S FRAMAC_PROVER_CONTEXT \
            FRAMAC_FRAME_SKELETON FRAMAC_LOOP_TEMPLATES FRAMAC_SPEC_KB FRAMAC_RESOURCES_VERBOSE \
            FRAMAC_MUTATION_STUB; do
    [[ -n "${!knob:-}" ]] && ENV_ARGS+=(-e "${knob}=${!knob}")
done
MOUNT_ARGS=(-v "${RESOLVED_TARGET}:/target:ro${ZT}"
            -v "${RESOLVED_RUN}:/framac-run${ZRW}"
            -v "${PIPELINE_ROOT}/scripts:/opt/framac-pipeline/scripts:ro${Z}"
            -v "${PIPELINE_ROOT}/templates:/opt/framac-pipeline/templates:ro${Z}"
            -v "${PIPELINE_ROOT}/schemas:/opt/framac-pipeline/schemas:ro${Z}"
            -v "${PIPELINE_ROOT}/skills:/opt/framac-pipeline/skills:ro${Z}"
            -v "${PIPELINE_ROOT}/docs/references:/opt/framac-pipeline/docs/references:ro${Z}")
[[ ${SCRATCH} -eq 1 ]] && MOUNT_ARGS+=(-v "${SCRATCH_VOLUME}:/framac-scratch")

if [[ -n "${SCRIPT_FILE}" ]]; then
    if [[ ! -f "${SCRIPT_FILE}" ]]; then
        echo "[framac-docker] ERROR: script file '${SCRIPT_FILE}' does not exist" >&2
        exit 2
    fi
    CMD_STRING="$(cat "${SCRIPT_FILE}")"
else
    if [[ $# -eq 0 ]]; then
        echo "[framac-docker] ERROR: either a command or --script-file is required." >&2
        exit 2
    fi
    CMD_STRING="$*"
fi

if [[ ${NO_BROKER} -eq 1 ]]; then
    exec "${ENGINE}" run "${HARDENING[@]}" "${LABEL_ARGS[@]}" --cpus "${CPUS}" --memory "${MEMORY}" --pids-limit "${PIDS}" \
        ${SELINUX_ARGS[@]+"${SELINUX_ARGS[@]}"} "${ENV_ARGS[@]}" -e "FRAMAC_IMAGE_ID=${IMAGE_ID}" \
        "${MOUNT_ARGS[@]}" -w /framac-run "${IMAGE}" "${CMD_STRING}"
fi

# Broker path: resources.py exec leases CPUs/memory for the job class and inserts --name,
# --label, --init, the limits, the job/pool environment and the shared cache mount after `run`.
# The command string travels in FRAMAC_CONTAINER_CMD and becomes the entry shim's argument.
export FRAMAC_CONTAINER_CMD="${CMD_STRING}"
export FRAMAC_IMAGE_ID="${IMAGE_ID}"
export FRAMAC_REPO="${REPO}"   # display name of the repository
export FRAMAC_REPO_KEY="${REPO_KEY}"   # partitions the shared cache per target (name + path hash)
export FRAMAC_RUN_TAG="${RUN_TAG}"
EXEC_ARGS=(exec --run-dir "${RESOLVED_RUN}")
[[ -n "${JOB_CLASS}" ]] && EXEC_ARGS+=(--class "${JOB_CLASS}")
[[ -n "${CPUS}" ]] && EXEC_ARGS+=(--cpus "${CPUS}")
[[ -n "${MEMORY}" ]] && EXEC_ARGS+=(--memory "${MEMORY}")
[[ -n "${PIDS}" ]] && EXEC_ARGS+=(--pids-limit "${PIDS}")
[[ -n "${CACHE_DIR}" ]] && EXEC_ARGS+=(--cache-dir "${CACHE_DIR}")
[[ ${CACHE_RW} -eq 1 ]] && EXEC_ARGS+=(--cache-rw)
exec "${PYTHON}" "${PIPELINE_ROOT}/scripts/resources.py" "${EXEC_ARGS[@]}" -- \
    "${ENGINE}" run "${HARDENING[@]}" "${LABEL_ARGS[@]}" ${SELINUX_ARGS[@]+"${SELINUX_ARGS[@]}"} "${ENV_ARGS[@]}" "${MOUNT_ARGS[@]}" \
    -w /framac-run --entrypoint /bin/bash "${IMAGE}" /opt/framac-pipeline/scripts/container_entry.sh
