"""Phase 6.1 step 1: monitoring → event-stream producer wiring.

Proves the missing producer side of the incident pipeline: a threshold
breach published by ``ThresholdValidator`` serializes to the exact event
shape ``RedisIncidentEventConsumer`` dispatches
(``event_type == "ThreatThresholdExceededEvent"`` on the shared stream),
without requiring a live Redis.
"""

import json
import unittest

from monitoring_service.application.services.threshold_validator import (
    ThresholdValidator,
)
from monitoring_service.domain.aggregates.metric_stream import MetricStreamAggregate
from monitoring_service.domain.value_objects.metric_unit import MetricUnit
from shared_kernel.domain.events import ThreatThresholdExceededEvent
from shared_kernel.infrastructure.messaging.redis_stream_publisher import (
    RedisStreamPublisher,
)


class RecordingPublisher:
    def __init__(self):
        self.events = []

    def publish(self, event):
        self.events.append(event)
        return "1-0"


class FakeRedisClient:
    def __init__(self):
        self.added = []

    def xadd(self, stream_name, fields):
        self.added.append((stream_name, fields))
        return f"{len(self.added)}-0"


def loaded_stream(service_id="gateway", value=97.0):
    stream = MetricStreamAggregate(
        service_id=service_id,
        metric_name="cpu_percent",
        unit=MetricUnit(symbol="%", description="percent"),
    )
    stream.record_value(value)
    return stream


class ThresholdValidatorPublisherTests(unittest.TestCase):
    def test_breach_publishes_consumable_threshold_event(self):
        publisher = RecordingPublisher()
        validator = ThresholdValidator(danger_percentage=90.0, publisher=publisher)

        breached = validator.evaluate_stream(loaded_stream())

        self.assertTrue(breached)
        self.assertEqual(len(publisher.events), 1)
        event = publisher.events[0]
        self.assertIsInstance(event, ThreatThresholdExceededEvent)
        body = event.to_dict()
        # contract consumed by RedisIncidentEventConsumer._process_messages
        self.assertEqual(body["event_type"], "ThreatThresholdExceededEvent")
        self.assertEqual(body["aggregate_id"], "gateway")
        breaches = body["payload"]["breaches"]
        self.assertEqual(breaches[0]["metric"], "cpu_percent")
        self.assertEqual(breaches[0]["value"], 97.0)

    def test_no_breach_publishes_nothing(self):
        publisher = RecordingPublisher()
        validator = ThresholdValidator(danger_percentage=90.0, publisher=publisher)
        self.assertFalse(validator.evaluate_stream(loaded_stream(value=50.0)))
        self.assertEqual(publisher.events, [])

    def test_without_publisher_behaviour_is_unchanged(self):
        validator = ThresholdValidator(danger_percentage=90.0)
        self.assertTrue(validator.evaluate_stream(loaded_stream()))


class RedisStreamPublisherTests(unittest.TestCase):
    def test_publish_xadds_consumer_field_envelope(self):
        client = FakeRedisClient()
        publisher = RedisStreamPublisher(
            redis_url="redis://unused:6379/0",
            stream_name="devops:events",
            client=client,
        )
        event = ThreatThresholdExceededEvent(
            aggregate_id="gateway", payload={"average": 97.0}
        )

        stream_id = publisher.publish(event)

        self.assertEqual(stream_id, "1-0")
        self.assertEqual(len(client.added), 1)
        stream_name, fields = client.added[0]
        self.assertEqual(stream_name, "devops:events")
        # exact envelope RedisIncidentEventConsumer._deserialize reads
        self.assertEqual(
            sorted(fields),
            ["aggregate_id", "event_id", "event_type", "payload", "timestamp"],
        )
        self.assertEqual(fields["event_id"], event.event_id)
        self.assertEqual(fields["event_type"], "ThreatThresholdExceededEvent")
        self.assertEqual(fields["aggregate_id"], "gateway")
        payload = json.loads(fields["payload"])
        self.assertEqual(payload, {"average": 97.0})
        # round-trip through the real consumer deserializer
        from incident_service.infrastructure.messaging.redis_incident_consumer import (
            RedisIncidentEventConsumer,
        )

        decoded = RedisIncidentEventConsumer._deserialize(fields)
        self.assertEqual(decoded["event_type"], "ThreatThresholdExceededEvent")
        self.assertEqual(decoded["payload"]["average"], 97.0)
        self.assertEqual(decoded["event_id"], event.event_id)

    def test_env_overrides_default_stream(self):
        import os
        from unittest.mock import patch

        client = FakeRedisClient()
        with patch.dict(
            os.environ,
            {"EVENT_BUS_STREAM": "custom:stream", "EVENT_BUS_REDIS_URL": "redis://x:1/0"},
        ):
            publisher = RedisStreamPublisher(client=client)
        publisher.publish(
            ThreatThresholdExceededEvent(aggregate_id="api", payload={})
        )
        self.assertEqual(client.added[0][0], "custom:stream")
        self.assertEqual(publisher.redis_url, "redis://x:1/0")


if __name__ == "__main__":
    unittest.main()
