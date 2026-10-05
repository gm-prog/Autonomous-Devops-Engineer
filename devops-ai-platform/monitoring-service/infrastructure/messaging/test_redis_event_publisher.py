import unittest

from infrastructure.messaging.redis_event_publisher import RedisStreamEventPublisher


class FakeRedis:
    def __init__(self):
        self.calls = []

    def xadd(self, stream_name, message, maxlen=None, approximate=False):
        self.calls.append((stream_name, message, maxlen, approximate))
        return "1710000000000-0"


class FakeEvent:
    def to_dict(self):
        return {
            "event_id": "evt-1",
            "event_type": "ThreatThresholdExceededEvent",
            "aggregate_id": "gateway",
            "timestamp": "2026-09-23T00:00:00+00:00",
            "payload": {
                "severity": "critical",
                "breach_count": 1,
                "breaches": [{"metric": "cpu_percent", "value": 95.0}],
            },
        }


class RedisStreamEventPublisherTests(unittest.TestCase):
    def test_publish_serializes_event_without_logging_payload(self):
        redis = FakeRedis()
        publisher = RedisStreamEventPublisher(
            redis_url="redis://unused",
            stream_name="test:events",
            client=redis,
        )

        message_id = publisher.publish(FakeEvent())

        self.assertEqual(message_id, "1710000000000-0")
        self.assertEqual(len(redis.calls), 1)

        stream, message, maxlen, approximate = redis.calls[0]
        self.assertEqual(stream, "test:events")
        self.assertEqual(maxlen, 10000)
        self.assertTrue(approximate)
        self.assertEqual(message["event_id"], "evt-1")
        self.assertEqual(message["event_type"], "ThreatThresholdExceededEvent")
        self.assertEqual(message["aggregate_id"], "gateway")
        self.assertIn('"cpu_percent"', message["payload"])

    def test_publish_rejects_incomplete_event(self):
        class InvalidEvent:
            def to_dict(self):
                return {"event_type": "ThreatThresholdExceededEvent"}

        publisher = RedisStreamEventPublisher(client=FakeRedis())

        with self.assertRaises(ValueError):
            publisher.publish(InvalidEvent())


if __name__ == "__main__":
    unittest.main()
