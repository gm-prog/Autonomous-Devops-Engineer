"""Phase 8.7-D.1 runtime-composition guard (P0-5).

The canonical D1 compose stack must genuinely declare — and CI must
genuinely build and boot — the full authenticated analysis path:

* ``docker-compose.yml`` (canonical) declares ``api-gateway`` +
  ``agent-service`` + ``redis``;
* the gateway and agent each build from a Dockerfile that EXISTS;
* third-party / base images are pinned to immutable digests;
* no service publishes a host port except the gateway's public 8000;
* CI's runtime verification builds BOTH service images (removing either
  build from the verification must turn CI red — mutation M17).

Run standalone with the other guards:

    PYTHONPATH=devops-ai-platform python -m security_guards
"""

from __future__ import annotations

from pathlib import Path
from typing import List

import yaml

PLATFORM = "devops-ai-platform"
CANONICAL_COMPOSE = f"{PLATFORM}/docker-compose.yml"
LEGACY_COMPOSE = f"{PLATFORM}/docker-compose.legacy.yml"
CI_WORKFLOW = ".github/workflows/ci.yml"

_REQUIRED_SERVICES = ("api-gateway", "agent-service", "redis")
_BUILT_SERVICES = ("api-gateway", "agent-service")
_ONLY_HOST_PORT = ("api-gateway", "8000")


def _dockerfile_exists(repo_root: Path, build) -> bool:
    if not build:
        return False
    if isinstance(build, str):
        context, dockerfile = build, "Dockerfile"
    elif isinstance(build, dict):
        context = build.get("context", ".")
        dockerfile = build.get("dockerfile", "Dockerfile")
    else:
        return False
    return (repo_root / PLATFORM / context / dockerfile).is_file()


def check_runtime_contract(repo_root: Path) -> List[str]:
    """Structural contract for the canonical D1 runtime (violations list)."""
    violations: List[str] = []

    compose_path = repo_root / CANONICAL_COMPOSE
    if not compose_path.is_file():
        return [f"canonical compose file {CANONICAL_COMPOSE} is missing"]
    try:
        spec = yaml.safe_load(compose_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        return [f"canonical compose file is not valid YAML: {exc}"]
    if not isinstance(spec, dict):
        return ["canonical compose file has no top-level mapping"]

    services = spec.get("services") or {}
    for name in _REQUIRED_SERVICES:
        if name not in services:
            violations.append(
                f"canonical compose stack is missing required service '{name}'"
            )

    for name in _BUILT_SERVICES:
        svc = services.get(name)
        if not isinstance(svc, dict):
            continue
        if not _dockerfile_exists(repo_root, svc.get("build")):
            violations.append(
                f"service '{name}' must build from an existing Dockerfile "
                f"(missing build context or Dockerfile)"
            )

    # Third-party images must be immutable (digest-pinned).
    redis_svc = services.get("redis")
    if isinstance(redis_svc, dict):
        image = redis_svc.get("image", "")
        if "@" not in str(image):
            violations.append(
                "redis image must be pinned to an immutable digest "
                f"(got {image!r})"
            )

    # No host-exposed ports except the gateway's public API port.
    for name, svc in services.items():
        if not isinstance(svc, dict):
            continue
        for port in svc.get("ports") or []:
            host = str(port).split(":")[0].strip('"')
            if (name, host) != _ONLY_HOST_PORT:
                violations.append(
                    f"service '{name}' publishes host port {host!r} — only "
                    "api-gateway:8000 may be host-exposed"
                )

    # CI must genuinely verify the runtime: canonical config AND a build of
    # BOTH service images (mutation M17 removes one of them).
    ci_path = repo_root / CI_WORKFLOW
    ci_src = ci_path.read_text(encoding="utf-8") if ci_path.is_file() else ""
    if "docker compose config" not in ci_src:
        violations.append("CI does not run 'docker compose config' on the canonical stack")
    for svc in _BUILT_SERVICES:
        if f"dockerfile: ./{svc}/Dockerfile" not in compose_path.read_text(encoding="utf-8"):
            violations.append(
                f"canonical compose file does not reference ./{svc}/Dockerfile"
            )
        if f"docker compose build api-gateway agent-service" not in ci_src and \
           not (f"{svc}" in ci_src and "docker compose build" in ci_src):
            violations.append(
                f"CI runtime verification must build the '{svc}' image"
            )

    # The legacy stack, when present, must be quarantined: no hardcoded
    # database password may remain in it.
    legacy_path = repo_root / LEGACY_COMPOSE
    if legacy_path.is_file():
        legacy_src = legacy_path.read_text(encoding="utf-8")
        if "POSTGRES_PASSWORD: postgres" in legacy_src:
            violations.append(
                "quarantined legacy compose file still contains a hardcoded "
                "database password"
            )

    return violations


def check_runtime_contract_repo(repo_root: Path) -> List[str]:
    """Alias matching the ``check_repo`` convention of the other guards."""
    return check_runtime_contract(repo_root)
