# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
# check=skip=InvalidDefaultArgInFrom;error=true

# Phase 8.6-A — dedicated kubectl sandbox image.
#
# This image exists only to run the four operations in
# KubectlOperation. It carries no cloud CLI, no shell helpers, no
# credential plugins and nothing from the deployment service.
#
# The kubectl binary is NOT downloaded here: the build context receives
# a binary the caller has already fetched and verified against the
# checksum published by dl.k8s.io for the pinned version. The build
# therefore needs no network at all, and the exact bytes that land in
# the image are the bytes the caller checksummed.
#
# The runtime boundary (--pull never, --read-only, --cap-drop ALL,
# --security-opt no-new-privileges, non-root uid, pid/cpu/memory limits,
# read-only mounts, a dedicated egress-controlled network) is enforced
# by kubectl_sandbox.py, not by this file.
#
# Immutable build input: BASE_IMAGE must be a <name>@sha256:<64hex>
# reference from the committed pin file. No default, no fallback.
ARG BASE_IMAGE
FROM ${BASE_IMAGE}

# A plugin named kubectl-<x> anywhere on PATH is executable as
# `kubectl <x>`. The sandbox PATH is minimal and this image installs
# none, so there is nothing for a hostile manifest to reach.
COPY kubectl /usr/local/bin/kubectl

RUN set -eu; \
    chmod 0555 /usr/local/bin/kubectl; \
    kubectl version --client=true --output=yaml > /etc/kubectl-version.yaml; \
    # 65532 is the conventional "nonroot" uid; the sandbox spec pins the
    # same value, so a root-capable image cannot be substituted silently.
    if ! getent group 65532 >/dev/null; then groupadd -g 65532 nonroot; fi; \
    if ! getent passwd 65532 >/dev/null; then \
        useradd -u 65532 -g 65532 -M -s /usr/sbin/nologin nonroot; \
    fi; \
    mkdir -p /workspace /run/secrets/ares; \
    chown -R 65532:65532 /workspace

USER 65532:65532
WORKDIR /workspace
ENTRYPOINT ["kubectl"]
