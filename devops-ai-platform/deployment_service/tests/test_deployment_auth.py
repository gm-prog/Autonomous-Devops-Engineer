"""Phase 8.8A Correction-1 (F2) — deployment API authentication tests.

Every sensitive route must authenticate and authorize:

* 401 without credentials / with an invalid, expired or wrong-signed
  token / with a malformed internal token;
* 403 for an authenticated caller without the role;
* the approver identity is the VERIFIED JWT subject — a caller-supplied
  ``approved_by`` body field is ignored, never trusted;
* the internal service token authenticates as the fixed service
  principal (constant-time comparison; too-short tokens are refused);
* fail-closed configuration: absent JWT_SECRET / AGENT_INTERNAL_TOKEN
  ⇒ 503 on sensitive routes, never a bundled secret;
* execution-enabled mode without the required auth configuration
  refuses to start (application factory).

Each test builds a FRESH app via ``create_app()`` with a controlled
environment, so the shared module-level app (used by the HTTP contract
suite) is never disturbed.
"""
import base64
import json
import os
import time
import unittest
from unittest import mock

import jwt as pyjwt
from fastapi.testclient import TestClient

from deployment_service.application.services import deployment_auth
from deployment_service.application.services.deployment_auth import (
    DeploymentAuthenticationConfigError,
    SERVICE_PRINCIPAL,
)

TEST_SECRET = "auth-test-jwt-secret-0123456789abcdef0123"
TEST_INTERNAL = "auth-test-internal-token-0123456789abcdef"
OPERATOR_SUB = "auth-test-operator"
PLAIN_SUB = "auth-test-developer"


def _mint(sub, roles, secret=TEST_SECRET, ttl=3600, **extra):
    payload = {
        "sub": sub,
        "roles": roles,
        "iat": int(time.time()),
        "exp": int(time.time()) + ttl,
    }
    payload.update(extra)
    return pyjwt.encode(payload, secret, algorithm="HS256")


_AUTH_ENV_KEYS = ("JWT_SECRET", "AGENT_INTERNAL_TOKEN",
                  "DEPLOYMENT_EXECUTION_ENABLED")


def _apply_env(env):
    """Install a fully controlled auth environment and build the app.

    The three auth variables are RESET (not just updated) so a leaked
    CI value can never mask a fail-closed assertion. The environment
    must stay in place for the whole request (verification reads it at
    request time) — return a restore snapshot.
    """
    snapshot = dict(os.environ)
    for key in _AUTH_ENV_KEYS:
        os.environ.pop(key, None)
    os.environ.update(env)
    from deployment_service.main import create_app

    return create_app(), snapshot


def _restore_env(snapshot):
    os.environ.clear()
    os.environ.update(snapshot)


def _headers(token):
    return {"Authorization": f"Bearer {token}"}


class _FakeStore:
    """In-memory stand-in for the durable run store.

    Authentication is verified against a DETERMINISTIC store: a CI
    job that does not run a live Redis (the focused security suites)
    must still exercise the authenticated success paths — the tests
    assert authn/authz behaviour, not broker behaviour (the broker
    contract is covered by the real-Redis jobs and the health tests
    below, which deliberately point at an unreachable store).
    """

    def __init__(self):
        self._runs = {}

    def ping(self) -> bool:
        return True

    def save(self, run) -> None:
        self._runs[run.id] = run.to_dict()

    def get(self, run_id):
        return self._runs.get(run_id)

    def delete(self, run_id) -> None:
        self._runs.pop(run_id, None)


DRY_RUN_BODY = {
    "repository_id": 1,
    "repository_name": "acme/checkout",
    "dockerfile": "FROM python:3.11-slim\n",
    "k8s_yaml": "",
    "terraform_tf": "",
    "pipeline_yaml": "name: ci\n",
    "source_revision": {"head_sha": "a" * 40},
}


class _AuthedAppTestCase(unittest.TestCase):
    def setUp(self):
        self.app, self._env_snapshot = _apply_env(
            {
                "JWT_SECRET": TEST_SECRET,
                "AGENT_INTERNAL_TOKEN": TEST_INTERNAL,
                "DEPLOYMENT_EXECUTION_ENABLED": "false",
            }
        )
        self.addCleanup(_restore_env, self._env_snapshot)
        # Deterministic store: the authenticated success paths must be
        # testable without a live Redis (see _FakeStore).
        self.app.state.engine.store = _FakeStore()
        self.client = TestClient(self.app)

    def _jwt(self, sub=OPERATOR_SUB, roles=("operator",), secret=TEST_SECRET,
             ttl=3600, **extra):
        return _mint(sub, list(roles), secret, ttl, **extra)

    def _internal(self, token=TEST_INTERNAL):
        return {"X-Internal-Token": token}


class SensitiveRouteAuthenticationTests(_AuthedAppTestCase):
    """401/403 matrix over every sensitive route."""

    def test_dry_run_without_credentials_is_401(self):
        resp = self.client.post(
            "/api/internal/deployments/dry-run", json=DRY_RUN_BODY)
        self.assertEqual(resp.status_code, 401, resp.text)

    def test_run_inspection_without_credentials_is_401(self):
        resp = self.client.get("/api/internal/deployments/run-1")
        self.assertEqual(resp.status_code, 401, resp.text)

    def test_approve_without_credentials_is_401(self):
        resp = self.client.post(
            "/api/internal/deployments/run-1/approve",
            json={"artifact_hash": "a" * 64, "plan_hash": "p" * 64},
        )
        self.assertEqual(resp.status_code, 401, resp.text)

    def test_execute_without_credentials_is_401(self):
        resp = self.client.post(
            "/api/internal/deployments/run-1/execute",
            json={
                "artifact_hash": "a" * 64,
                "plan_hash": "p" * 64,
                "dockerfile": "",
                "k8s_yaml": "",
                "terraform_tf": "",
                "pipeline_yaml": "",
            },
        )
        self.assertEqual(resp.status_code, 401, resp.text)

    def test_garbage_token_is_401(self):
        resp = self.client.post(
            "/api/internal/deployments/dry-run",
            json=DRY_RUN_BODY,
            headers=_headers("not-a-jwt"),
        )
        self.assertEqual(resp.status_code, 401, resp.text)

    def test_wrong_secret_signature_is_401(self):
        other = "other-secret-0123456789abcdef0123456789abcdef0123456789abcdef"
        resp = self.client.post(
            "/api/internal/deployments/dry-run",
            json=DRY_RUN_BODY,
            headers=_headers(_mint(OPERATOR_SUB, ["operator"], other)),
        )
        self.assertEqual(resp.status_code, 401, resp.text)

    def test_expired_token_is_401(self):
        resp = self.client.post(
            "/api/internal/deployments/dry-run",
            json=DRY_RUN_BODY,
            headers=_headers(_mint(OPERATOR_SUB, ["operator"], ttl=-10)),
        )
        self.assertEqual(resp.status_code, 401, resp.text)

    def test_alg_none_token_is_401(self):
        # alg confusion must never be accepted (HS256 only).
        token = self._jwt()
        header, payload, _ = token.split(".")
        forged_header = base64.urlsafe_b64encode(
            json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(b"=")
        resp = self.client.post(
            "/api/internal/deployments/dry-run",
            json=DRY_RUN_BODY,
            headers=_headers(f"{forged_header.decode()}.{payload}."),
        )
        self.assertEqual(resp.status_code, 401, resp.text)

    def test_token_missing_roles_claim_is_401(self):
        token = pyjwt.encode(
            {"sub": OPERATOR_SUB, "exp": int(time.time()) + 60},
            TEST_SECRET, algorithm="HS256")
        resp = self.client.post(
            "/api/internal/deployments/dry-run",
            json=DRY_RUN_BODY,
            headers=_headers(token),
        )
        self.assertEqual(resp.status_code, 401, resp.text)

    def test_plain_developer_role_is_403_not_401(self):
        resp = self.client.post(
            "/api/internal/deployments/dry-run",
            json=DRY_RUN_BODY,
            headers=_headers(self._jwt(PLAIN_SUB, ("Developer",))),
        )
        self.assertEqual(resp.status_code, 403, resp.text)

    def test_service_token_may_dry_run(self):
        resp = self.client.post(
            "/api/internal/deployments/dry-run",
            json=DRY_RUN_BODY,
            headers=self._internal(),
        )
        # authenticated + authorized (source verification may still
        # refuse the fixture revision — but NEVER 401/403)
        self.assertIn(resp.status_code, (200, 422, 503), resp.text)

    def test_service_token_cannot_approve(self):
        resp = self.client.post(
            "/api/internal/deployments/run-1/approve",
            json={"artifact_hash": "a" * 64, "plan_hash": "p" * 64},
            headers=self._internal(),
        )
        self.assertEqual(resp.status_code, 403, resp.text)

    def test_internal_token_too_short_is_401_not_503(self):
        # A short header value must be a rejected credential (401), not
        # a configuration failure (503): the configured token is intact.
        resp = self.client.get(
            "/api/internal/deployments/run-1",
            headers={"X-Internal-Token": "short"},
        )
        self.assertEqual(resp.status_code, 401, resp.text)

    def test_service_token_cannot_read_a_foreign_run(self):
        store = self.app.state.engine.store
        original = store.get
        store.get = lambda run_id: {
            "id": run_id, "repository_id": 1, "repository_name": "acme/x",
            "requested_by": None, "created_by": "other-principal",
            "source_revision": {}, "state": "AWAITING_APPROVAL",
        }
        try:
            resp = self.client.get(
                "/api/internal/deployments/run-1", headers=self._internal())
        finally:
            store.get = original
        self.assertEqual(resp.status_code, 403, resp.text)

    def test_operator_can_read_any_run(self):
        store = self.app.state.engine.store
        original = store.get
        store.get = lambda run_id: {
            "id": run_id, "repository_id": 1, "repository_name": "acme/x",
            "requested_by": None, "created_by": "someone-else",
            "source_revision": {}, "state": "AWAITING_APPROVAL",
        }
        try:
            resp = self.client.get(
                "/api/internal/deployments/run-1",
                headers=_headers(self._jwt()),
            )
        finally:
            store.get = original
        self.assertEqual(resp.status_code, 200, resp.text)


class ApproverIdentityTests(_AuthedAppTestCase):
    """The approver is the verified subject; body text is ignored."""

    def _approved_run(self, sub, spoofed_body_field):
        from deployment_service.tests.test_deployment_engine import (
            FakeHealth,
            FakeKubectl,
            FakeSourceVerifier,
            FakeTerraform,
            FakeValidator,
        )

        engine = self.app.state.engine
        engine.source_verifier = FakeSourceVerifier()
        engine.validator = FakeValidator()
        engine.terraform = FakeTerraform()
        engine.kubectl = FakeKubectl()
        engine.health_checker = FakeHealth()
        body = {
            "repository_id": 1,
            "repository_name": "acme/checkout",
            "dockerfile": "FROM python:3.11-slim\nUSER 10001\n",
            "k8s_yaml": ("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n"
                         "  name: d\nspec:\n  template:\n    spec:\n"
                         "      containers:\n        - name: d\n"
                         "          image: d:latest\n"),
            "terraform_tf": 'terraform { required_version = ">= 1.5.0" }\n',
            "pipeline_yaml": "name: ci\n",
            "source_revision": {"head_sha": "a" * 40},
            "created_by": sub,
        }
        run = engine.create_dry_run(body)
        approval_body = {
            "approved_by": spoofed_body_field,  # must be IGNORED
            "artifact_hash": run.artifact_hash,
            "plan_hash": run.plan_hash,
        }
        resp = self.client.post(
            f"/api/internal/deployments/{run.id}/approve",
            json=approval_body,
            headers=_headers(self._jwt(sub, ("operator",))),
        )
        self.assertEqual(resp.status_code, 200, resp.text)
        return run, resp.json()

    def test_approver_is_the_verified_subject_not_the_body_field(self):
        _, approved = self._approved_run(OPERATOR_SUB, "spoofed-attacker")
        self.assertEqual(approved["approval"]["approved_by"], OPERATOR_SUB)

    def test_body_spoof_cannot_change_the_recorded_approver(self):
        _, approved = self._approved_run(OPERATOR_SUB, "root")
        self.assertEqual(approved["approval"]["approved_by"], OPERATOR_SUB)


class InternalTokenTests(unittest.TestCase):
    def test_too_short_internal_token_is_refused_at_config(self):
        with mock.patch.dict("os.environ",
                             {"AGENT_INTERNAL_TOKEN": "short"}):
            with self.assertRaises(DeploymentAuthenticationConfigError):
                deployment_auth.verify_service_token("short")

    def test_missing_internal_token_fails_closed(self):
        env = dict(os.environ)
        env.pop("AGENT_INTERNAL_TOKEN", None)
        with mock.patch.dict("os.environ", env, clear=True):
            with self.assertRaises(DeploymentAuthenticationConfigError):
                deployment_auth.verify_service_token("whatever")

    def test_service_identity_is_fixed_never_caller_chosen(self):
        with mock.patch.dict("os.environ",
                             {"AGENT_INTERNAL_TOKEN": TEST_INTERNAL}):
            identity = deployment_auth.verify_service_token(TEST_INTERNAL)
        self.assertEqual(identity.subject, SERVICE_PRINCIPAL)
        self.assertEqual(identity.kind, "service")


class FailClosedConfigTests(unittest.TestCase):
    def test_missing_jwt_secret_fails_sensitive_routes_with_503(self):
        # Credentials ARE presented, but the verifier cannot be
        # constructed (no JWT_SECRET): the route must fail closed with
        # 503 — never 200, never a silent bypass.
        app, snap = _apply_env({"AGENT_INTERNAL_TOKEN": TEST_INTERNAL})
        self.addCleanup(_restore_env, snap)
        client = TestClient(app)
        resp = client.get(
            "/api/internal/deployments/run-1",
            headers=_headers(_mint(OPERATOR_SUB, ["operator"])),
        )
        self.assertEqual(resp.status_code, 503, resp.text)

    def test_missing_jwt_secret_without_credentials_is_401(self):
        # No credentials at all: the credential-missing answer (401)
        # precedes verification, but it must NOT be a 200/503 leak of
        # run data.
        app, snap = _apply_env({"AGENT_INTERNAL_TOKEN": TEST_INTERNAL})
        self.addCleanup(_restore_env, snap)
        client = TestClient(app)
        resp = client.get("/api/internal/deployments/run-1")
        self.assertEqual(resp.status_code, 401, resp.text)

    def test_missing_internal_token_still_allows_human_jwt(self):
        app, snap = _apply_env({"JWT_SECRET": TEST_SECRET})
        self.addCleanup(_restore_env, snap)
        # Authentication succeeds here, so the route reaches the store:
        # a deterministic fake keeps the assertion about AUTH (404,
        # never 401/503) independent of whether CI runs a live Redis.
        app.state.engine.store = _FakeStore()
        client = TestClient(app)
        resp = client.get(
            "/api/internal/deployments/run-1",
            headers=_headers(_mint(OPERATOR_SUB, ["operator"])),
        )
        # authenticated fine; run unknown ⇒ 404, never 401/503
        self.assertEqual(resp.status_code, 404, resp.text)

    def test_execution_mode_without_auth_config_refuses_to_start(self):
        env = dict(os.environ)
        env.pop("JWT_SECRET", None)
        env.pop("AGENT_INTERNAL_TOKEN", None)
        env["DEPLOYMENT_EXECUTION_ENABLED"] = "true"
        with mock.patch.dict("os.environ", env, clear=True):
            with self.assertRaises(DeploymentAuthenticationConfigError):
                deployment_auth.validate_execution_config()

    def test_execution_mode_with_full_auth_config_starts(self):
        with mock.patch.dict(
            "os.environ",
            {
                "DEPLOYMENT_EXECUTION_ENABLED": "true",
                "JWT_SECRET": TEST_SECRET,
                "AGENT_INTERNAL_TOKEN": TEST_INTERNAL,
            },
        ):
            deployment_auth.validate_execution_config()  # no raise


class HealthContractTests(unittest.TestCase):
    """F1: /health measures the declared contract, not mere existence."""

    def test_health_reports_execution_flag_and_broker(self):
        app, snap = _apply_env(
            {
                "DEPLOYMENT_EXECUTION_ENABLED": "false",
                "REDIS_HOST": "127.0.0.1",
                "REDIS_PORT": "1",
            }
        )
        self.addCleanup(_restore_env, snap)
        client = TestClient(app)
        resp = client.get("/health")
        # broker unreachable ⇒ degraded 503 (never a success-shaped 200)
        self.assertEqual(resp.status_code, 503)
        self.assertEqual(resp.json()["redis"], "unreachable")
        self.assertEqual(resp.json()["execution_enabled"], False)


if __name__ == "__main__":
    unittest.main()
