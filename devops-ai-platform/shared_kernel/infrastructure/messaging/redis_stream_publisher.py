"""Redis Streams event producer (Phase 6.1 step 1: monitoring → stream).

The incident consumer already reads ``devops:events`` and dispatches
``ThreatThresholdExceededEvent`` entries; this publisher is the missing
producer side. It serializes any ``DomainEvent`` via ``to_dict()`` and
``XADD``s it. The Redis client is constructed lazily (like the consumer)
and can be injected for deterministic tests.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Optional

logger = logging.getLogger("RedisStreamPublisher")


class RedisStreamPublisher:
    """Publishes domain events to the shared Redis event stream."""

    def __init__(
        self,
        redis_url: Optional[str] = None,
        stream_name: Optional[str] = None,
        client: Any = None,
    ):
        self.redis_url = (
            redis_url
            or os.getenv("EVENT_BUS_REDIS_URL")
            or "redis://redis:6379/0"
        )
        self.stream_name = (
            stream_name
            or os.getenv("EVENT_BUS_STREAM")
            or "devops:events"
        )
        self._client = client

    @property
    def client(self):
        if self._client is None:
            import redis

            self._client = redis.Redis.from_url(
                self.redis_url,
                decode_responses=True,
            )
        return self._client

    def publish(self, event: Any) -> str:
        """XADD the event's ``to_dict()`` payload; returns the stream id."""
        body = event.to_dict()
        stream_id = self.client.xadd(self.stream_name, {"data": json.dumps(body)})
        logger.info(
            "Published event_type=%s event_id=%s stream_id=%s",
            body.get("event_type"),
            body.get("event_id"),
            stream_id,
        )
        return stream_id
