# syntax=docker/dockerfile:1
#
# Scratch image for the upstream Frama-C filing packages (docs/upstream/frama-c/): upstream
# `master` built from source with dune and kept as a git clone with its _build tree in
# /home/opam/frama-c, installed into /home/opam/.opam/5.5, plus what upstream's lint needs
# (ocp-indent, headache, clang-format). It is not a pipeline image.
#
# Build context: a directory that holds this file and `frama-c/.git`, a clone of pub/frama-c whose
# local branch `master` is the commit to build:
#
#   git clone https://git.frama-c.com/pub/frama-c.git <ctx>/frama-c
#   docker build -t framac-master-audit:<short sha> -f tools/upstream_audit/Dockerfile <ctx>
#
# Only the .git directory is copied, and the tree is checked out inside the image, so a Windows
# working tree (CRLF, lost executable bits) never reaches the build.
ARG OPAM_BASE=ocaml/opam:debian-13-ocaml-5.5@sha256:2f2870cc00eb7f66d39715193466107a3f1abd71fed09f078505b02bb21488dd
FROM ${OPAM_BASE}

USER root
ENV DEBIAN_FRONTEND=noninteractive
# The apt lists stay: opam installs the remaining system packages (depexts) itself.
RUN apt-get update && apt-get install -y --no-install-recommends \
    autoconf \
    automake \
    build-essential \
    ca-certificates \
    clang \
    clang-format \
    cvc5 \
    git \
    graphviz \
    libgmp-dev \
    libmpfr-dev \
    pkg-config \
    python3 \
    time \
    util-linux \
    z3 \
    zlib1g-dev

USER opam
ENV OPAMYES=1
ENV OPAMCONFIRMLEVEL=unsafe-yes
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8

# The identity is a placeholder: author each patch commit with `git -c user.name=... -c user.email=...`.
COPY --chown=opam:opam frama-c/.git /home/opam/frama-c-origin.git
RUN git clone --quiet --branch master /home/opam/frama-c-origin.git /home/opam/frama-c \
    && rm -rf /home/opam/frama-c-origin.git \
    && git -C /home/opam/frama-c remote remove origin \
    && git -C /home/opam/frama-c config user.name "audit" \
    && git -C /home/opam/frama-c config user.email "audit@example.invalid" \
    && git -C /home/opam/frama-c log -1 --format='%H %s'

WORKDIR /home/opam/frama-c

# No `opam update`: the repository is the checkout pinned by OPAM_BASE.
# The lint and prover versions are those of upstream's `with-dev-setup` dependencies
# (ocp-indent >= 1.10.0, alt-ergo 2.6.4), named here because the image's default opam does not
# know --with-dev-setup. alt-ergo-free 2.4.3 cannot be installed next to ocp-indent 1.10.0 on
# OCaml 5.5 (no cmdliner version in common): asking for both fails, and installing the
# dependencies without naming alt-ergo downgrades ocp-indent to 1.9.0.
RUN sudo apt-get update \
    && opam install alt-ergo.2.6.4 ocp-indent.1.10.0 headache why3.1.8.2 \
    && opam install --deps-only --with-test . \
    && opam list --installed --columns=name,version | grep -E "alt-ergo|why3|ocp-indent|headache|cmdliner|dune " \
    && opam clean --all-switches --download-cache --logs --repo-cache

RUN opam exec -- dune build @install \
    && opam exec -- dune install --release --prefix /home/opam/.opam/5.5

ENV PATH="/home/opam/.opam/5.5/bin:${PATH}"

RUN frama-c -version \
    && frama-c -plugins | grep -E "E-ACSL|Eva|WP" \
    && why3 config detect 2>&1 | tail -n 8 \
    && echo 'int main(void) { /*@ assert 1 + 2 == 2; */ return 0; }' > /tmp/t.c \
    && (cd /tmp && e-acsl-gcc -c t.c && (prlimit --core=1:1 ./a.out.e-acsl 2>&1 || true) | grep "Assertion failed") \
    && rm -f /tmp/t.c /tmp/a.out*
