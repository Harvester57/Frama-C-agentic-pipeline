# syntax=docker/dockerfile:1
#
# Two images from one file (docs/phase0-implementation-plan.md, decision "Images"); the optional third
# image has its own Dockerfile:
#   docker build --target framac-analysis -t framac-analysis .     Frama-C, provers, instrumented builds
#   docker build --target framac-build -t framac-build .           the target's build and tests
# The build and analysis images share the Debian release, gcc and glibc (checked by
# scripts/image_toolchain.py), so flags captured in one mean the same in the other and binaries
# link against the same libc. The analysis image is the last stage, so a build without --target makes it.
#
# The "common base stage" of the plan's decision "Images" is kept by pinned digests, not by one shared
# stage (remediation plan step R8, decision D9): the analysis image starts from the Frama-C image
# (FRAMAC_BASE), which is built on Debian, and the build image from the same Debian release (DEBIAN_BASE),
# both pinned by digest. A shared stage cannot be had without rebuilding Frama-C and its opam switch on our
# own Debian stage. Bump the two digests together; CI's toolchain check (image_toolchain.py compare)
# fails when the release, gcc or glibc drift apart.
#
# Both images create /framac-scratch, mode 1777: a new named scratch volume mounted there copies that mode,
# so any non-root uid can write the capture's scratch tree without a chmod step.
ARG FRAMAC_BASE=framac/frama-c:dev@sha256:2296220f5d51cd9842db1d83f0c84390298100bc4efeb1bcab6bad557866f124
# MetAcsl, built from source: its 0.11 release does not compile against Frama-C 35 (Fileloc.t), the
# development branch does (feasibility test of 2026-11-07, plan step I0).
ARG METACSL_COMMIT=4d5d0e9179ae07f852ceb33fb5db58b04cab0801
# The Debian release the Frama-C base is built on (Debian 13.7, glibc 2.41-12+deb13u4, gcc 14.2.0-19).
ARG DEBIAN_BASE=debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2

# --- Build image: runs the target's own build and its tests ----------------------------------------
FROM ${DEBIAN_BASE} AS framac-build

LABEL description="Frama-C pipeline build image: the target's build (make, CMake, Meson, Ninja, autotools under bear) and its tests (strace), with common -dev libraries"

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONIOENCODING=utf-8
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8
ENV HOME=/home/framac
ENV S="/opt/framac-pipeline/scripts"

RUN apt-get update && apt-get install -y --no-install-recommends \
    autoconf \
    automake \
    bear \
    build-essential \
    ca-certificates \
    clang \
    cmake \
    curl \
    file \
    git \
    jq \
    libbsd-dev \
    libevent-dev \
    libjson-c-dev \
    libpcap-dev \
    libsnmp-dev \
    libsqlite3-dev \
    libssl-dev \
    libtool \
    libxml2-dev \
    m4 \
    meson \
    ninja-build \
    pkg-config \
    python3 \
    strace \
    time \
    zlib1g-dev \
    zstd \
    && rm -rf /var/lib/apt/lists/*

# Target packages (a derived image per target, framac-build:<repo>).
ARG TARGET_APT_PACKAGES=""
RUN if [ -n "${TARGET_APT_PACKAGES}" ]; then \
        apt-get update && \
        apt-get install -y --no-install-recommends ${TARGET_APT_PACKAGES} && \
        rm -rf /var/lib/apt/lists/*; \
    fi

COPY scripts/ /opt/framac-pipeline/scripts/
COPY templates/ /opt/framac-pipeline/templates/
COPY schemas/ /opt/framac-pipeline/schemas/
RUN chmod -R a+rX /opt/framac-pipeline \
    && chmod a+x /opt/framac-pipeline/scripts/*.py /opt/framac-pipeline/scripts/*.sh \
    && mkdir -p /home/framac/.cache /framac-run /framac-scratch \
    && chmod 1777 /home/framac /home/framac/.cache /framac-run /framac-scratch

WORKDIR /framac-run
ENTRYPOINT ["/bin/bash", "-lc"]

# --- Analysis image: Frama-C, provers, instrumented builds; no build systems, no target packages ------
FROM ${FRAMAC_BASE} AS framac-analysis

LABEL description="Frama-C pipeline analysis image: Frama-C (RTE, Eva, WP, E-ACSL), Alt-Ergo, Z3, CVC5, Clang/LibFuzzer, cvise; the target's headers and libraries come from the build image's snapshot"

USER root
ENV HOME=/home/opam
ENV DEBIAN_FRONTEND=noninteractive
ENV OPAMYES=1
ENV OPAMROOT=/home/opam/.opam
ENV PYTHONIOENCODING=utf-8
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8
ENV PATH="/home/opam/.opam/5.5/bin:${PATH}"
ENV FRAMAC_SHARE="/home/opam/.opam/5.5/share/frama-c"
ENV WHY3CONFIG="/home/opam/.why3.conf"
ENV S="/opt/framac-pipeline/scripts"

# build-essential stays: Frama-C preprocesses with gcc, E-ACSL compiles with it, and the pipeline's
# own Makefile needs make. GMP and MPFR serve E-ACSL's runtime.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    clang \
    cvc5 \
    cvise \
    git \
    graphviz \
    jq \
    libclang-rt-dev \
    libgmp-dev \
    libmpfr-dev \
    llvm \
    python3 \
    time \
    z3 \
    && rm -rf /var/lib/apt/lists/* \
    && chmod a+rx /home/opam /root \
    && chmod -R a+rX /home/opam/.opam \
    && printf 'export PATH="/home/opam/.opam/5.5/bin:${PATH}"\nexport FRAMAC_SHARE="/home/opam/.opam/5.5/share/frama-c"\nexport WHY3CONFIG="/home/opam/.why3.conf"\n' > /etc/profile.d/framac.sh \
    && chmod 644 /etc/profile.d/framac.sh \
    && python3 -c "from pathlib import Path; p = Path('/home/opam/.opam/5.5/share/why3/provers-detection-data.conf'); p.write_text(p.read_text().replace(')$', ')'))" \
    && why3 config detect -C /home/opam/.why3.conf \
    && cp -f /home/opam/.why3.conf /root/.why3.conf \
    && chmod 644 /home/opam/.why3.conf /root/.why3.conf

# MetAcsl (program-wide ACSL properties, Layers 4-6), pinned to a commit of its development branch.
ARG METACSL_COMMIT
RUN git init -q /tmp/metacsl \
    && git -C /tmp/metacsl fetch -q --depth 1 https://git.frama-c.com/pub/meta.git "${METACSL_COMMIT}" \
    && git -C /tmp/metacsl checkout -q FETCH_HEAD \
    && cd /tmp/metacsl && opam exec -- sh -c 'dune build @install && dune install' \
    && cd / && rm -rf /tmp/metacsl \
    && chmod -R a+rX /home/opam/.opam \
    && frama-c -plugins | grep -q MetAcsl

COPY scripts/ /opt/framac-pipeline/scripts/
COPY templates/ /opt/framac-pipeline/templates/
COPY schemas/ /opt/framac-pipeline/schemas/
COPY skills/ /opt/framac-pipeline/skills/
COPY docs/references/ /opt/framac-pipeline/docs/references/
# Jobs run as an arbitrary non-root uid (the wrappers pass --user <host uid>:<host gid>; compose uses
# FRAMAC_UID/FRAMAC_GID): everything they read must be world-readable, and HOME plus the default working
# directory must be writable by any uid (sticky, like /tmp), since that uid has no passwd entry or home.
RUN chmod -R a+rX /opt/framac-pipeline \
    && chmod a+x /opt/framac-pipeline/scripts/*.py /opt/framac-pipeline/scripts/*.sh \
    && mkdir -p /home/opam/.cache /framac-run /framac-scratch \
    && chmod 1777 /home/opam /home/opam/.cache /framac-run /framac-scratch
# The Phase 0 model's dump module must compile and load against this kernel.
RUN python3 /opt/framac-pipeline/scripts/phase0_model.py selftest

WORKDIR /framac-run
ENTRYPOINT ["/bin/bash", "-lc"]
