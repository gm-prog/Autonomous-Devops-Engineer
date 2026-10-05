import json
import os
from typing import Any, Protocol


class EventLike(Protocol):
    def to_dict(self) -> dict[str, Any]:
        ...


class RedisStreamEventPublisher:
    """Publishes serialized domain events to a durable Redis Stream."""

    def __init__(
        self,
        redis_url: str | None = None,
        stream_name: str | None = None,
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

    def publish(self, event: EventLike) -> str:
        payload = event.to_dict()
        event_id = str(payload.get("event_id", "")).strip()
        event_type = str(payload.get("event_type", "")).strip()
        aggregate_id = str(payload.get("aggregate_id", "")).strip()

        if not event_id or not event_type or not aggregate_id:
            raise ValueError("event_id, event_type, and aggregate_id are required")

        message = {
            "event_id": event_id,
            "event_type": event_type,
            "aggregate_id": aggregate_id,
            "timestamp": str(payload.get("timestamp", "")),
            "payload": json.dumps(payload.get("payload", {}), separators=(",", ":")),
        }

        message_id = self.client.xadd(
            self.stream_name,
            message,
            maxlen=10000,
            approximate=True,
        )
        return str(message_id)
