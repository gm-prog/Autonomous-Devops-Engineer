# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
# check=skip=InvalidDefaultArgInFrom;error=true

# Phase 8.7-B.0 in-cluster sampler.
#
# The sampler must run INSIDE the cluster so the requests it sends
# traverse the real Envoy Gateway data plane instead of a tunnel from
# the runner. Immutable build input, same policy as the workload
# fixture: BASE_IMAGE is a <name>@sha256:<64hex> reference from the
# committed pin file, with no default and no fallback.
ARG BASE_IMAGE
FROM ${BASE_IMAGE}
WORKDIR /srv
COPY sampler.py /srv/sampler.py
RUN useradd -u 10001 -M appuser && chown -R appuser /srv
USER 10001:10001
CMD ["python", "/srv/sampler.py"]
