"""Shared fixtures & import plumbing for the Phase 8.7-C security test-suite.

The platform service directories use hyphens (``api-gateway``,
``monitoring-service`` ...), which are not importable Python package names.
The production relative imports (e.g. ``from ....shared_kernel.domain.events
import ...`` inside ``monitoring-service/application/services``) assume the
services are nested one package level below a platform root.  This conftest
reproduces that structure with synthetic package names so the production
modules — and their relative imports — load unchanged:

    platform_pkg                 (synthetic platform root)
    platform_pkg.api_gateway     <- devops-ai-platform/api-gateway
    platform_pkg.monitoring      <- devops-ai-platform/monitoring-service
    platform_pkg.incident        <- devops-ai-platform/incident-service
    platform_pkg.shared_kernel   <- devops-ai-platform/shared-kernel

No production layout is modified by the tests.
"""

from __future__ import annotations

import os
import sys
import types
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
PLATFORM_ROOT = REPO_ROOT / "devops-ai-platform"

# Keep the gateway's import-time app creation from failing closed during
# test collection.  Individual tests build apps with explicit env mappings.
os.environ.setdefault("JWT_SECRET", "unit-test-process-jwt-secret-0123456789ab")

# The test PROCESS is a single-instance test deployment.  Phase 8.7-D.1-
# CORRECTION-2 (P1-B) treats an EMPTY/MISSING APP_ENV as non-development
# (fail closed: shared store required), so the process environment must
# EXPLICITLY declare the recognized test environment — development mode is
# enabled by an exact value, never inferred.  Tests that assert the
# fail-closed classification pass explicit env mappings and are unaffected
# by this process-level declaration.
os.environ.setdefault("APP_ENV", "test")

# Make the guard package importable in-process.
if str(PLATFORM_ROOT) not in sys.path:
    sys.path.insert(0, str(PLATFORM_ROOT))


def _register_service_package(base_dir: Path, package_name: str) -> None:
    if package_name in sys.modules:
        return
    package = types.ModuleType(package_name)
    package.__path__ = [str(base_dir)]
    sys.modules[package_name] = package


# Synthetic platform root (empty namespace container).
if "platform_pkg" not in sys.modules:
    _root = types.ModuleType("platform_pkg")
    _root.__path__ = []
    sys.modules["platform_pkg"] = _root

for _dir, _name in [
    ("api-gateway", "platform_pkg.api_gateway"),
    ("monitoring-service", "platform_pkg.monitoring"),
    ("incident-service", "platform_pkg.incident"),
    ("agent-service", "platform_pkg.agent"),
    ("shared-kernel", "platform_pkg.shared_kernel"),
]:
    _register_service_package(PLATFORM_ROOT / _dir, _name)


def _alias_shared_kernel(parent_name: str) -> None:
    """Make ``<parent>.shared_kernel`` resolve to the canonical
    ``platform_pkg.shared_kernel`` modules (same module objects, so domain
    class identity is preserved across services).

    Some production modules import the shared kernel with relative depths
    that assume it sits next to the service package (e.g.
    ``incident-service/domain/aggregates`` uses three dots).  This alias
    bridges those modules without modifying the production layout.
    """
    import importlib

    alias_name = f"{parent_name}.shared_kernel"
    if alias_name in sys.modules:
        return
    alias = types.ModuleType(alias_name)
    alias.__path__ = []
    sys.modules[alias_name] = alias
    setattr(sys.modules[parent_name], "shared_kernel", alias)
    for sub in ("domain", "domain.events", "domain.value_objects"):
        try:
            mod = importlib.import_module(f"platform_pkg.shared_kernel.{sub}")
        except ModuleNotFoundError:
            continue
        sys.modules[f"{alias_name}.{sub}"] = mod
        parts = sub.split(".")
        node = alias
        for part in parts[:-1]:
            node = getattr(node, part)
        setattr(node, parts[-1], mod)


_alias_shared_kernel("platform_pkg.incident")
_alias_shared_kernel("platform_pkg.monitoring")


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

TEST_GW_SECRET = "unit-test-gateway-secret-887c-0123456789"
TEST_TELEMETRY_SECRET = "unit-test-telemetry-hmac-secret-887c-0123"


def make_token(subject: str, roles: list, secret: str = TEST_GW_SECRET, ttl: int = 3600) -> str:
    from platform_pkg.api_gateway.core.auth import create_access_token

    return create_access_token(subject, roles, secret, ttl_seconds=ttl)


class RecordingPublisher:
    """Event-bus spy: records every published domain event (test 3)."""

    def __init__(self):
        self.events: list = []

    def publish(self, event):
        self.events.append(event)
        return True

    @property
    def threat_events(self):
        return [e for e in self.events if type(e).__name__ == "ThreatThresholdExceededEvent"]


class CountingThresholdValidator:
    """ThresholdValidator wrapper that records invocations (test 3)."""

    def __init__(self, inner):
        self.inner = inner
        self.calls = 0

    def evaluate_stream(self, stream):
        self.calls += 1
        return self.inner.evaluate_stream(stream)

    def __getattr__(self, name):
        return getattr(self.inner, name)


class RecordingIncidentRepo:
    """IncidentRepositoryPort spy for the incident ingestion side effect."""

    def __init__(self):
        self.saved: list = []

    def save_incident(self, incident):
        self.saved.append(incident)

    def get_incident_by_id(self, id):
        return next((i for i in self.saved if i.id == id), None)

    def get_active_incidents(self):
        return list(self.saved)


@pytest.fixture
def recording_publisher():
    return RecordingPublisher()


@pytest.fixture
def counting_validator():
    from platform_pkg.monitoring.application.services.threshold_validator import ThresholdValidator

    return CountingThresholdValidator(ThresholdValidator(danger_percentage=90.0))


@pytest.fixture
def recording_incident_repo():
    return RecordingIncidentRepo()


@pytest.fixture
def gateway_env():
    """A valid production-mode gateway environment for app factories.

    These tests exercise a SINGLE-REPLICA production-mode gateway (in-memory
    app, no Redis), so they opt in EXPLICITLY to the documented
    single-instance rate-limit mode — the exact-value flag that cannot be
    enabled by accident. A multi-replica gateway must use the shared store.
    """
    return {
        "JWT_SECRET": TEST_GW_SECRET,
        "APP_ENV": "production",
        "ANALYSIS_RATE_LIMIT_SINGLE_INSTANCE_PRODUCTION": "true",
    }


@pytest.fixture
def gateway_app(gateway_env):
    from platform_pkg.api_gateway.main import create_app

    return create_app(env=gateway_env)


@pytest.fixture
def gateway_client(gateway_app):
    from fastapi.testclient import TestClient

    with TestClient(gateway_app) as client:
        yield client
