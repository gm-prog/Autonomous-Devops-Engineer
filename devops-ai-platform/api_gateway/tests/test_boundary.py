"""Gateway authentication boundary tests (OWASP API1/API5).

The API gateway is the only externally reachable service; these tests prove
the authentication layer rejects unauthenticated, malformed, expired and
wrong-key tokens before any dispatch occurs. Internal services stay on the
private network (asserted by tests/test_compose_network_boundary.py), so a
guessed `/api/internal/*` path is unreachable from outside even though the
path prefix itself grants nothing.
"""

import time
import unittest

from fastapi.testclient import TestClient

from api_gateway.core.auth import GatewaySettings, mint_token
from api_gateway.main import app

client = TestClient(app)
METRICS = "/v1/gateway/metrics"


def _authed(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


class GatewayAuthenticationBoundaryTests(unittest.TestCase):
    def test_unauthenticated_request_rejected(self):
        resp = client.get(METRICS)
        self.assertIn(resp.status_code, (401, 403))

    def test_malformed_bearer_token_rejected(self):
        resp = client.get(METRICS, headers={"Authorization": "Bearer not-a-jwt"})
        self.assertIn(resp.status_code, (401, 403))

    def test_invalid_signature_rejected_over_http(self):
        token = mint_token("attacker", secret="some-other-key")
        resp = client.get(METRICS, headers=_authed(token))
        self.assertIn(resp.status_code, (401, 403))

    def test_expired_token_rejected_over_http(self):
        token = mint_token(
            "expired-user",
            secret=GatewaySettings.JWT_SECRET,
            ttl_seconds=-1,
        )
        resp = client.get(METRICS, headers=_authed(token))
        self.assertIn(resp.status_code, (401, 403))

    def test_valid_token_allowed(self):
        token = mint_token(
            "operator",
            roles=["operator"],
            secret=GatewaySettings.JWT_SECRET,
        )
        resp = client.get(METRICS, headers=_authed(token))
        self.assertEqual(resp.status_code, 200, resp.text)

    def test_guessed_internal_prefix_is_not_a_gateway_route(self):
        """Knowing an internal path name grants nothing at the gateway: the
        gateway only exposes its own authenticated routes, and internal
        services are not published to the host (compose boundary test)."""
        resp = client.post(
            "/api/internal/deployments/dry-run",
            json={"anything": 1},
            headers=_authed(mint_token("operator", secret=GatewaySettings.JWT_SECRET)),
        )
        self.assertEqual(resp.status_code, 404)


if __name__ == "__main__":
    unittest.main()
