"""Phase 8.7-C — Defect C acceptance tests: JWT fallback must fail closed.

Acceptance criteria covered:

1. Production configuration without JWT_SECRET fails closed.
2. Production configuration cannot use the old fallback secret.
3. Explicit development mode may use a development fallback (and only then).
4. A production configuration with a configured JWT_SECRET signs and
   verifies tokens normally.
5. Changing JWT_SECRET invalidates tokens created under the old secret.
6. Logs must not expose the actual secret.
7. The environment contract is documented.
"""

from __future__ import annotations

import logging
from pathlib import Path

import jwt as pyjwt
import pytest

from platform_pkg.api_gateway.config import (
    DEVELOPMENT_ENV_VALUE,
    DEV_FALLBACK_JWT_SECRET,
    LEGACY_PREDICTABLE_JWT_SECRET,
    GatewayConfigurationError,
    load_gateway_settings,
    resolve_jwt_secret,
)
from platform_pkg.api_gateway.core.auth import decode_and_validate_token, create_access_token


# ---------------------------------------------------------------------------
# Test 1 — production without JWT_SECRET fails closed
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "env",
    [
        {},                                          # nothing set (bare process)
        {"APP_ENV": "production"},
        {"APP_ENV": "staging"},
        {"APP_ENV": "Production"},                   # wrong case: not explicit
        {"APP_ENV": "dev"},                          # not the exact switch
        {"APP_ENV": "development-ish"},              # not the exact switch
        {"APP_ENV": " development"},                 # not the exact switch
        {"JWT_SECRET": "   "},                       # whitespace-only is absent
    ],
)
def test_production_configuration_without_secret_fails_closed(env):
    with pytest.raises(GatewayConfigurationError):
        resolve_jwt_secret(env)
    with pytest.raises(GatewayConfigurationError):
        load_gateway_settings(env)


def test_failing_config_error_message_does_not_contain_a_secret():
    # The error must tell the operator what to do, without offering a secret.
    with pytest.raises(GatewayConfigurationError) as excinfo:
        resolve_jwt_secret({"APP_ENV": "production"})
    assert "JWT_SECRET" in str(excinfo.value)
    assert DEV_FALLBACK_JWT_SECRET not in str(excinfo.value)
    assert LEGACY_PREDICTABLE_JWT_SECRET not in str(excinfo.value)


# ---------------------------------------------------------------------------
# Test 2 — production cannot use the old (legacy) fallback secret
# ---------------------------------------------------------------------------


def test_production_never_resolves_the_legacy_secret():
    # Even an empty env never yields the legacy value.
    for env in ({}, {"APP_ENV": "production"}, {"APP_ENV": "staging"}):
        with pytest.raises(GatewayConfigurationError):
            resolve_jwt_secret(env)

    # And a production token signed with the legacy secret must not verify.
    config = load_gateway_settings({"JWT_SECRET": "prod-secret-a", "APP_ENV": "production"})
    legacy_token = create_access_token("attacker", ["operator"], LEGACY_PREDICTABLE_JWT_SECRET)
    with pytest.raises(Exception):
        decode_and_validate_token(legacy_token, config)


def test_legacy_secret_value_is_not_usable_anywhere_in_the_gateway():
    # The legacy value may only exist as a quarantined test reference.  It
    # must never be returned by the resolver, in any mode.
    secret, origin = resolve_jwt_secret({"APP_ENV": DEVELOPMENT_ENV_VALUE})
    assert secret != LEGACY_PREDICTABLE_JWT_SECRET
    secret, origin = resolve_jwt_secret({"JWT_SECRET": "x" * 32, "APP_ENV": "production"})
    assert secret != LEGACY_PREDICTABLE_JWT_SECRET


# ---------------------------------------------------------------------------
# Test 3 — explicit development mode: fallback allowed, and only there
# ---------------------------------------------------------------------------


def test_explicit_development_mode_may_use_development_fallback():
    secret, origin = resolve_jwt_secret({"APP_ENV": DEVELOPMENT_ENV_VALUE})
    assert origin == "development-fallback"
    assert secret == DEV_FALLBACK_JWT_SECRET
    # The fallback is usable for signing/verification in that mode.
    config = load_gateway_settings({"APP_ENV": DEVELOPMENT_ENV_VALUE})
    token = create_access_token("dev-user", ["Developer"], config.jwt_secret)
    claims = decode_and_validate_token(token, config)
    assert claims["sub"] == "dev-user"


def test_development_fallback_does_not_accept_legacy_signed_tokens():
    # A token minted under the old predictable secret is invalid under the
    # development fallback too — the fallback is a different value.
    config = load_gateway_settings({"APP_ENV": DEVELOPMENT_ENV_VALUE})
    legacy_token = create_access_token("attacker", ["ClusterAdmin"], LEGACY_PREDICTABLE_JWT_SECRET)
    with pytest.raises(Exception):
        decode_and_validate_token(legacy_token, config)


def test_explicit_development_switch_must_be_exact():
    # The switch is never inferred: only the exact value works.
    assert resolve_jwt_secret({"APP_ENV": DEVELOPMENT_ENV_VALUE})[1] == "development-fallback"
    for env in ({"APP_ENV": "Development"}, {"APP_ENV": "development "},
                {"APP_ENV": "local"}, {}):
        with pytest.raises(GatewayConfigurationError):
            resolve_jwt_secret(env)


def test_environment_secret_wins_over_development_fallback():
    secret, origin = resolve_jwt_secret(
        {"JWT_SECRET": "explicit-dev-secret", "APP_ENV": DEVELOPMENT_ENV_VALUE}
    )
    assert origin == "environment"
    assert secret == "explicit-dev-secret"


# ---------------------------------------------------------------------------
# Test 4 — production with configured JWT_SECRET signs and verifies normally
# ---------------------------------------------------------------------------


def test_production_configured_secret_signs_and_verifies():
    config = load_gateway_settings({"JWT_SECRET": "prod-secret-a", "APP_ENV": "production"})
    assert config.jwt_secret_origin == "environment"
    token = create_access_token("ops-1", ["operator", "DevOpsLead"], config.jwt_secret)
    claims = decode_and_validate_token(token, config)
    assert claims == {"sub": "ops-1", "roles": ["operator", "DevOpsLead"]}


def test_token_with_wrong_algorithm_is_rejected():
    config = load_gateway_settings({"JWT_SECRET": "prod-secret-a", "APP_ENV": "production"})
    # Hand-roll an HS512 token: algorithm confusion must be rejected.
    payload = {"sub": "attacker", "roles": ["ClusterAdmin"],
               "iat": 0, "exp": 9999999999}
    token = pyjwt.encode(payload, config.jwt_secret, algorithm="HS512")
    with pytest.raises(Exception):
        decode_and_validate_token(token, config)


def test_expired_token_is_rejected():
    config = load_gateway_settings({"JWT_SECRET": "prod-secret-a", "APP_ENV": "production"})
    token = create_access_token("ops-1", ["operator"], config.jwt_secret, ttl_seconds=-10)
    with pytest.raises(Exception):
        decode_and_validate_token(token, config)


# ---------------------------------------------------------------------------
# Test 5 — changing JWT_SECRET invalidates tokens under the old secret
# ---------------------------------------------------------------------------


def test_secret_rotation_invalidates_prior_tokens():
    old = load_gateway_settings({"JWT_SECRET": "rotation-old", "APP_ENV": "production"})
    new = load_gateway_settings({"JWT_SECRET": "rotation-new", "APP_ENV": "production"})
    token = create_access_token("ops-1", ["operator"], old.jwt_secret)
    claims = decode_and_validate_token(token, old)  # valid under old
    assert claims["sub"] == "ops-1"
    with pytest.raises(Exception):  # invalid under new
        decode_and_validate_token(token, new)


# ---------------------------------------------------------------------------
# Test 6 — logs must not expose the actual secret
# ---------------------------------------------------------------------------


def test_configuration_logs_never_expose_secret(caplog):
    secret = "highly-sensitive-jwt-secret-value-9f3a"
    with caplog.at_level(logging.DEBUG, logger="GatewayConfig"):
        config = load_gateway_settings({"APP_ENV": DEVELOPMENT_ENV_VALUE})
    assert DEV_FALLBACK_JWT_SECRET not in caplog.text
    # And with an environment secret:
    with caplog.at_level(logging.DEBUG, logger="GatewayConfig"):
        load_gateway_settings({"JWT_SECRET": secret, "APP_ENV": "production"})
    assert secret not in caplog.text


def test_authentication_logs_never_expose_secret(caplog):
    from fastapi import HTTPException

    config = load_gateway_settings({"JWT_SECRET": "logcheck-secret-77ab", "APP_ENV": "production"})
    good = create_access_token("ops-1", ["operator"], config.jwt_secret)
    bad = create_access_token("ops-1", ["operator"], "other-secret-22cc")
    with caplog.at_level(logging.DEBUG, logger="GatewayAuth"):
        decode_and_validate_token(good, config)   # success path
        with pytest.raises(HTTPException):
            decode_and_validate_token(bad, config)  # rejection path
    assert "logcheck-secret-77ab" not in caplog.text
    assert "other-secret-22cc" not in caplog.text
    assert good not in caplog.text  # token material is not logged either


# ---------------------------------------------------------------------------
# Test 7 — the environment contract is documented
# ---------------------------------------------------------------------------


def test_environment_contract_is_documented():
    repo_root = Path(__file__).resolve().parents[2]
    security_md = (repo_root / "devops-ai-platform" / "SECURITY.md").read_text()
    read_md = (repo_root / "README.md").read_text()
    for doc in (security_md, read_md):
        assert "JWT_SECRET" in doc
        assert "fail closed" in doc.lower() or "fails closed" in doc.lower()
        assert "APP_ENV" in doc
    assert "development" in security_md
