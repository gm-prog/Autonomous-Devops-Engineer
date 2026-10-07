"""Deterministic Compose network-boundary tests (production topology).

The real boundary is: external client -> API gateway (JWT) -> private
compose network. These tests fail the build if the base Compose file ever
re-publishes an internal service to the host again, or silently weakens the
gateway's required-secret fail-fast.

No host networking is exercised - the assertions parse the declared topology.
"""

import os
import re
import unittest

import yaml

PLATFORM_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE_COMPOSE = os.path.join(PLATFORM_DIR, "docker-compose.yml")
DEV_OVERRIDE = os.path.join(PLATFORM_DIR, "docker-compose.dev.yml")

# Services that must NEVER publish a host port in the production topology.
INTERNAL_SERVICES = {
    "postgres",
    "redis",
    "qdrant",
    "repo-service",
    "agent-service",
    "deployment-service",
    "monitoring-service",
    "incident-service",
    "incident-event-worker",
}
GATEWAY_SERVICE = "api-gateway"


def _load(path):
    with open(path, "r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


class ComposeNetworkBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = _load(BASE_COMPOSE)
        cls.dev = _load(DEV_OVERRIDE)

    def test_only_gateway_publishes_a_host_port(self):
        published = {
            name: svc["ports"]
            for name, svc in self.base["services"].items()
            if svc.get("ports")
        }
        self.assertEqual(set(published), {GATEWAY_SERVICE})
        self.assertEqual(published[GATEWAY_SERVICE], ["8000:8000"])

    def test_internal_services_define_no_host_ports(self):
        for name in INTERNAL_SERVICES:
            with self.subTest(service=name):
                self.assertNotIn(
                    "ports",
                    self.base["services"].get(name, {}),
                    f"{name} must not publish a host port in production topology",
                )

    def test_internal_services_still_exist_for_private_network(self):
        """Removing host ports must not remove the services themselves -
        gateway forwarding and service-to-service calls use service DNS."""
        for name in INTERNAL_SERVICES:
            with self.subTest(service=name):
                self.assertIn(name, self.base["services"])

    def test_gateway_dispatch_targets_exist_in_compose(self):
        """Every service the gateway forwards to must be a compose service."""
        router_path = os.path.join(
            PLATFORM_DIR, "api_gateway", "routers", "gateway_router.py"
        )
        source = open(router_path, encoding="utf-8").read()
        targets = set(re.findall(r'"http://([a-z0-9-]+):\d+"', source))
        self.assertTrue(targets, "no dispatch targets found")
        for target in targets:
            with self.subTest(target=target):
                self.assertIn(target, self.base["services"])

    def test_gateway_requires_jwt_secret_fail_fast(self):
        env = self.base["services"][GATEWAY_SERVICE].get("environment") or []
        jwt_lines = [e for e in env if str(e).startswith("JWT_SECRET=")]
        self.assertTrue(jwt_lines, "gateway must configure JWT_SECRET")
        self.assertIn(
            ":?",
            jwt_lines[0],
            "gateway JWT_SECRET must fail fast when unset/empty",
        )

    def test_dev_override_republishes_internal_ports(self):
        """Development experience: explicit opt-in override restores ports."""
        for name in INTERNAL_SERVICES - {"incident-event-worker"}:
            with self.subTest(service=name):
                self.assertTrue(
                    self.dev["services"].get(name, {}).get("ports"),
                    f"dev override must republish {name} for local development",
                )

    def test_no_hardcoded_secrets_in_compose(self):
        raw = open(BASE_COMPOSE, encoding="utf-8").read()
        for pattern in (r"ghp_[A-Za-z0-9]{10}", r"github_pat_", r"BEGIN OPENSSH"):
            self.assertIsNone(re.search(pattern, raw))


if __name__ == "__main__":
    unittest.main()
