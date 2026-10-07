"""Composition root for the monitoring bounded context (Phase 6.1).

Mirrors ``incident_service.application.dependencies``: configuration is
read from the environment (repository-wide ``os.getenv`` convention), the
real adapter (:class:`RedisStreamPublisher`) and the existing
:class:`ThresholdValidator` are constructed here, and presentation layers
depend on ``get_threshold_monitor`` only. Tests may inject a publisher
whose *client* is fake (adapter boundary) — the composition code path
itself is always the real one.
"""

import os
from functools import lru_cache
from typing import Optional

from monitoring_service.application.services.threshold_monitor import (
    ThresholdMonitor,
)
from monitoring_service.application.services.threshold_validator import (
    ThresholdValidator,
)
from shared_kernel.infrastructure.messaging.redis_stream_publisher import (
    RedisStreamPublisher,
)

#: Breach limit (%) evaluated by the validator — env-overridable like the
#: other service settings (``RepoServiceSettings`` / ``INFLUX_BUCKET`` …).
DANGER_LIMIT_ENV = "MONITORING_DANGER_LIMIT"
DEFAULT_DANGER_LIMIT = 90.0


def load_danger_limit() -> float:
    """Fail fast on malformed configuration (same style as int(os.getenv))."""
    raw = os.getenv(DANGER_LIMIT_ENV, "").strip()
    if not raw:
        return DEFAULT_DANGER_LIMIT
    limit = float(raw)
    if not 0.0 < limit < 1000.0:
        raise ValueError(f"{DANGER_LIMIT_ENV} must be a positive number")
    return limit


def build_threshold_monitor(
    publisher: Optional[RedisStreamPublisher] = None,
    danger_limit: Optional[float] = None,
) -> ThresholdMonitor:
    """Construct the real monitor: publisher adapter + existing validator."""
    resolved_publisher = publisher or RedisStreamPublisher()
    limit = load_danger_limit() if danger_limit is None else danger_limit
    validator = ThresholdValidator(
        danger_percentage=limit,
        publisher=resolved_publisher,
    )
    return ThresholdMonitor(validator)


@lru_cache(maxsize=1)
def get_threshold_monitor() -> ThresholdMonitor:
    """Singleton monitor for the running service (lazy, env-configured)."""
    return build_threshold_monitor()
