# E2E fixture workload: deterministic HTTP readiness for checkout-service.
# Immutable build input (§9): BASE_IMAGE must be name@sha256:<64hex>.
# No tag default is allowed — a missing/non-digest reference fails
# the build (tests/test_e2e_corrective.py static checks).
ARG BASE_IMAGE
FROM ${BASE_IMAGE:?BASE_IMAGE must be a name@sha256:<64hex> reference}
WORKDIR /srv
COPY server.py /srv/server.py
RUN useradd -u 10001 -M appuser && chown -R appuser /srv
USER 10001:10001
EXPOSE 8080
CMD ["python", "/srv/server.py"]
