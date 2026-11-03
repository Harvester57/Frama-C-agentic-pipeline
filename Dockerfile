# syntax=docker/dockerfile:1
FROM ubuntu:24.04

LABEL maintainer="Frama-C Agentic Verification Pipeline"
LABEL description="Self-contained Frama-C (RTE, Eva, WP, E-ACSL, Mdr/SARIF) + SMT Solvers (Alt-Ergo, Z3, CVC5) + Clang/LibFuzzer + Bear container"

ENV DEBIAN_FRONTEND=noninteractive
ENV OPAMYES=1
ENV OPAMROOT=/opt/opam
ENV PYTHONIOENCODING=utf-8
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8

# Install system dependencies, Clang + LibFuzzer, Bear, SMT solvers, and OCaml/Opam build prerequisites
RUN apt-get update && apt-get install -y --no-install-recommends \
    autoconf \
    automake \
    bear \
    build-essential \
    ca-certificates \
    clang \
    cmake \
    curl \
    cvc5 \
    git \
    graphviz \
    jq \
    libbsd-dev \
    libclang-rt-dev \
    libevent-dev \
    libgmp-dev \
    libjson-c-dev \
    libmpfr-dev \
    libpcap-dev \
    libsnmp-dev \
    libsqlite3-dev \
    libssl-dev \
    libxml2-dev \
    llvm \
    m4 \
    ninja-build \
    ocaml \
    opam \
    pkg-config \
    python3 \
    python3-pip \
    python3-venv \
     time \
    unzip \
    wget \
    z3 \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

# Initialize Opam and install Frama-C with Alt-Ergo, Why3, E-ACSL, and SARIF (mdr) support
RUN opam init --bare --disable-sandboxing --root=/opt/opam && \
    opam switch create framac ocaml-base-compiler.5.1.1 && \
    eval $(opam env --root=/opt/opam --switch=framac) && \
    opam update && \
    opam install -y \
        conf-gmp \
        why3 \
        alt-ergo \
        frama-c \
    && eval $(opam env --root=/opt/opam --switch=framac) \
    && why3 config detect \
    && opam clean -a -c -s --logs

ENV PATH="/opt/opam/framac/bin:${PATH}"
ENV FRAMAC_SHARE="/opt/opam/framac/share/frama-c"
ENV S="/opt/framac-pipeline/scripts"

# Optional target-specific apt packages (built via --target-packages / -TargetPackages before dropping capabilities)
ARG TARGET_APT_PACKAGES=""
RUN if [ -n "${TARGET_APT_PACKAGES}" ]; then \
        apt-get update && \
        apt-get install -y --no-install-recommends ${TARGET_APT_PACKAGES} && \
        rm -rf /var/lib/apt/lists/*; \
    fi

# Copy pipeline scripts, templates, schemas, and skills into /opt/framac-pipeline for container-internal access
COPY scripts/ /opt/framac-pipeline/scripts/
COPY templates/ /opt/framac-pipeline/templates/
COPY schemas/ /opt/framac-pipeline/schemas/
COPY skills/ /opt/framac-pipeline/skills/
RUN chmod +x /opt/framac-pipeline/scripts/*.py

WORKDIR /framac-run

ENTRYPOINT ["/bin/bash", "-lc"]
