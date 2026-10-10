from datetime import datetime, timedelta, timezone
import unittest

from core.events import Event, EventValidationError
from core.lists import EnforcementLists, ListEntry
from core.rate import RateEngine


class CoreTests(unittest.TestCase):
    def test_event_redacts_sensitive_metadata(self):
        event = Event.from_request_metadata(
            {
                "src_ip": "203.0.113.10",
                "path": "/login",
                "query": "user=alice&token=secret",
                "headers": {"Authorization": "secret", "User-Agent": "test"},
            },
            node_id="node-1",
            mode="gateway",
        )
        self.assertEqual(event.query_redacted, "user=alice&token=%5BREDACTED%5D")
        self.assertEqual(event.user_agent, "test")
        self.assertNotIn("secret", event.to_json())

    def test_event_requires_52_flow_features(self):
        with self.assertRaises(EventValidationError):
            Event(
                node_id="node",
                mode="gateway",
                direction="inbound",
                src_ip="1.2.3.4",
                flow_features=[1.0],
            ).validate()

    def test_enforcement_lists_match_cidr_and_expiry(self):
        lists = EnforcementLists()
        lists.replace(
            allowlist=[],
            blocklist=[
                ListEntry("cidr", "203.0.113.0/24"),
                ListEntry(
                    "ip",
                    "198.51.100.4",
                    datetime.now(timezone.utc) - timedelta(seconds=1),
                ),
            ],
            version=1,
        )
        self.assertTrue(lists.is_blocked("203.0.113.8"))
        self.assertFalse(lists.is_blocked("198.51.100.4"))

    def test_rate_engine_escalates_and_excludes_safe_sources(self):
        engine = RateEngine(
            requests_limit=1,
            connections_limit=50,
            own_networks=("10.0.0.0/8",),
        )
        self.assertTrue(engine.check("10.1.1.1").allowed)
        self.assertTrue(engine.check("203.0.113.10").allowed)
        first = engine.check("203.0.113.10")
        second = engine.check("203.0.113.10")
        self.assertEqual((first.offence, first.block_minutes), (1, 10))
        self.assertEqual((second.offence, second.block_minutes), (2, 60))


if __name__ == "__main__":
    unittest.main()
