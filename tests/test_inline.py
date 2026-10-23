import unittest

from core.inline import InlineDecision, InlinePolicy, InlineRequest
from core.lists import EnforcementLists, ListEntry
from core.rate import RateEngine


class InlinePolicyTests(unittest.TestCase):
    def policy(self, **kwargs):
        return InlinePolicy(
            lists=EnforcementLists(),
            rate_engine=RateEngine(
                requests_limit=1,
                connections_limit=10,
                own_networks=(),
            ),
            **kwargs,
        )

    def test_intel_signal_is_allowed_for_expert_review(self):
        policy = self.policy(intel_matcher=lambda request: ("local_ioc",))

        result = policy.evaluate(InlineRequest(source_ip="203.0.113.10"))

        self.assertEqual(result.decision, InlineDecision.REVIEW)
        self.assertTrue(result.allowed)
        self.assertFalse(result.automatically_blocked)

    def test_rate_excess_is_automatically_blocked(self):
        policy = self.policy()
        request = InlineRequest(source_ip="203.0.113.10")

        self.assertEqual(policy.evaluate(request).decision, InlineDecision.ALLOWED)
        result = policy.evaluate(request)

        self.assertEqual(result.decision, InlineDecision.BLOCKED)
        self.assertFalse(result.allowed)
        self.assertTrue(result.rate.exceeded)

    def test_shadow_model_result_does_not_enter_review(self):
        policy = self.policy(model_scorer=lambda request: {
            "mode": "shadow",
            "prediction": "DDoS",
        })

        result = policy.evaluate(InlineRequest(source_ip="203.0.113.11"))

        self.assertEqual(result.decision, InlineDecision.ALLOWED)
        self.assertEqual(result.model["mode"], "shadow")

    def test_advisory_model_result_enters_review_without_blocking(self):
        policy = self.policy(model_scorer=lambda request: {
            "mode": "advisory",
            "prediction": "DDoS",
        })

        result = policy.evaluate(InlineRequest(source_ip="203.0.113.12"))

        self.assertEqual(result.decision, InlineDecision.REVIEW)
        self.assertTrue(result.allowed)

    def test_blocklist_matches_url_and_allowlist_wins_for_rate(self):
        lists = EnforcementLists()
        lists.replace(
            allowlist=[ListEntry("domain", "trusted.example")],
            blocklist=[ListEntry("url_prefix", "https://bad.example/")],
            version=1,
        )
        policy = InlinePolicy(
            lists=lists,
            rate_engine=RateEngine(requests_limit=1, own_networks=()),
        )

        blocked = policy.evaluate(
            InlineRequest(source_ip="203.0.113.10", url="https://bad.example/login")
        )
        trusted = policy.evaluate(
            InlineRequest(source_ip="203.0.113.10", host="trusted.example")
        )

        self.assertEqual(blocked.decision, InlineDecision.BLOCKED)
        self.assertEqual(trusted.decision, InlineDecision.ALLOWED)


if __name__ == "__main__":
    unittest.main()
