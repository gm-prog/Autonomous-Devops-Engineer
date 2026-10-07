import unittest

from incident_service.infrastructure.messaging.redis_incident_consumer import RedisIncidentEventConsumer


class FakeRedis:
    def __init__(self):
        self.acked = []
        self.groups = []

    def xgroup_create(self, name, groupname, id, mkstream):
        self.groups.append((name, groupname, id, mkstream))

    def xreadgroup(self, groupname, consumername, streams, count, block):
        return [[
            "test:events",
            [
                (
                    "1-0",
                    {
                        "event_id": "evt-1",
                        "event_type": "ThreatThresholdExceededEvent",
                        "aggregate_id": "gateway",
                        "timestamp": "2026-09-23T00:00:00+00:00",
                        "payload": '{"severity":"critical","breach_count":1,"breaches":[{"metric":"cpu_percent","value":95.0}]}',
                    },
                )
            ],
        ]]

    def xack(self, stream, group, message_id):
        self.acked.append((stream, group, message_id))


class FakeHandler:
    def __init__(self):
        self.events = []

    def handle(self, event):
        self.events.append(event)
        return "incident-1"


class RedisIncidentEventConsumerTests(unittest.TestCase):
    def test_consume_once_handles_and_acks_threshold_event(self):
        redis = FakeRedis()
        handler = FakeHandler()
        consumer = RedisIncidentEventConsumer(
            handler=handler,
            stream_name="test:events",
            group_name="incident-service",
            consumer_name="consumer-1",
            client=redis,
        )

        processed = consumer.consume_once(block_ms=0)

        self.assertEqual(processed, 1)
        self.assertEqual(len(handler.events), 1)
        self.assertEqual(handler.events[0]["aggregate_id"], "gateway")
        self.assertEqual(
            handler.events[0]["payload"]["breaches"][0]["metric"],
            "cpu_percent",
        )
        self.assertEqual(redis.acked, [("test:events", "incident-service", "1-0")])
        self.assertEqual(
            redis.groups,
            [("test:events", "incident-service", "0-0", True)],
        )

    def test_consume_once_leaves_failed_message_pending(self):
        class FailingHandler:
            def handle(self, event):
                raise RuntimeError("triage failed")

        redis = FakeRedis()
        consumer = RedisIncidentEventConsumer(
            handler=FailingHandler(),
            client=redis,
        )

        processed = consumer.consume_once(block_ms=0)

        self.assertEqual(processed, 0)
        self.assertEqual(redis.acked, [])


if __name__ == "__main__":
    unittest.main()
