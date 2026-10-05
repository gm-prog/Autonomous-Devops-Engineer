import json
import logging
import os
import socket
import time
from typing import Any, Mapping

from application.event_handlers.on_metric_threshold_failed import (
    OnMetricThresholdFailedHandler,
)

logger = logging.getLogger("IncidentEventConsumer")


class RedisIncidentEventConsumer:
    """Consumes monitoring events from Redis Streams with acknowledged delivery."""

    def __init__(
        self,
        handler: OnMetricThresholdFailedHandler,
        redis_url: str | None = None,
        stream_name: str | None = None,
        group_name: str | None = None,
        consumer_name: str | None = None,
        client: Any = None,
    ):
        self.handler = handler
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
        self.group_name = (
            group_name
            or os.getenv("INCIDENT_EVENT_GROUP")
            or "incident-service"
        )
        self.consumer_name = (
            consumer_name
            or os.getenv("INCIDENT_EVENT_CONSUMER")
            or f"{socket.gethostname()}-{os.getpid()}"
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

    def ensure_group(self) -> None:
        try:
            self.client.xgroup_create(
                name=self.stream_name,
                groupname=self.group_name,
                id="0-0",
                mkstream=True,
            )
        except Exception as exc:
            if "BUSYGROUP" not in str(exc):
                raise

    def _process_messages(self, messages) -> int:
        processed = 0
        for _, entries in messages or []:
            for message_id, fields in entries:
                try:
                    event = self._deserialize(fields)
                    if event.get("event_type") == "ThreatThresholdExceededEvent":
                        self.handler.handle(event)
                    self.client.xack(self.stream_name, self.group_name, message_id)
                    processed += 1
                except Exception:
                    logger.exception(
                        "Failed processing event message_id=%s; leaving it pending for retry",
                        message_id,
                    )
        return processed

    def consume_once(self, block_ms: int = 1000, count: int = 10) -> int:
        self.ensure_group()

        pending = self.client.xreadgroup(
            groupname=self.group_name,
            consumername=self.consumer_name,
            streams={self.stream_name: "0"},
            count=count,
            block=0,
        )
        processed = self._process_messages(pending)
        if processed:
            return processed

        fresh = self.client.xreadgroup(
            groupname=self.group_name,
            consumername=self.consumer_name,
            streams={self.stream_name: ">"},
            count=count,
            block=block_ms,
        )
        return processed + self._process_messages(fresh)
    def run_forever(self) -> None:
        while True:
            try:
                self.consume_once()
            except Exception:
                logger.exception("Incident event consumer loop failed")
                time.sleep(2)

    @staticmethod
    def _deserialize(fields: Mapping[str, str]) -> dict[str, Any]:
        payload_raw = fields.get("payload", "{}")
        payload = json.loads(payload_raw)

        if not isinstance(payload, dict):
            raise ValueError("event payload must be an object")

        return {
            "event_id": fields.get("event_id", ""),
            "event_type": fields.get("event_type", ""),
            "aggregate_id": fields.get("aggregate_id", ""),
            "timestamp": fields.get("timestamp", ""),
            "payload": payload,
        }
