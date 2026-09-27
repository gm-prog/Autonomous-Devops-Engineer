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
        """XADD the event using the consumer's field envelope.

        ``RedisIncidentEventConsumer._deserialize`` reads the stream
        fields ``event_id`` / ``event_type`` / ``aggregate_id`` /
        ``timestamp`` / ``payload`` (payload as a JSON string) — the
        producer must speak exactly that convention or messages are
        acknowledged without ever reaching a handler.
        """
        body = event.to_dict()
        fields = {
            "event_id": str(body.get("event_id") or ""),
            "event_type": str(body.get("event_type") or ""),
            "aggregate_id": str(body.get("aggregate_id") or ""),
            "timestamp": str(body.get("timestamp") or ""),
            "payload": json.dumps(body.get("payload") or {}),
        }
        stream_id = self.client.xadd(self.stream_name, fields)
        logger.info(
            "Published event_type=%s event_id=%s stream_id=%s",
            fields["event_type"],
            fields["event_id"],
            stream_id,
        )
        return stream_id
