"""Phase 6.5.1 — release identity provider: validation + exposition.

Proves, without starting any external service: exact acceptance of a
valid deployment id + lowercase 40-hex SHA; fail-closed rejection of
missing/blank/uppercase/short/prefixed/whitespace/control-character
inputs (never fabricated, never normalized); deterministic repeated
evaluation; exactly-one carrier series with value 1 on valid identity;
zero attributable identity series on invalid identity; and that the
existing request counter keeps its method/path dimensions with no
release labels on unrelated application metrics.
"""

from prometheus_client import REGISTRY, CollectorRegistry, Gauge, generate_latest

from app.main import RELEASE_IDENTITY_APPLIED  # conftest pops identity env first
from app.release_identity import (
    MAX_DEPLOYMENT_ID_LENGTH,
    apply_release_identity,
    resolve_release_identity,
    validate_deployment_id,
    validate_source_sha,
)

VALID_ID = "run-phase-6-5-1-proof"
VALID_SHA = "0123456789abcdef0123456789abcdef01234567"
CARRIER_NAME = "devops_release_identity_info"


def _fresh_carrier():
    """Isolated registry + identical-shape gauge (no default-registry pollution)."""
    registry = CollectorRegistry()
    gauge = Gauge(
        CARRIER_NAME,
        "Authoritative release identity for this runtime instance.",
        ["deployment_id", "source_sha"],
        registry=registry,
    )
    return registry, gauge


# --- identity provider ----------------------------------------------------- #

def test_valid_identity_accepted_exactly():
    assert resolve_release_identity(VALID_ID, VALID_SHA) == (VALID_ID, VALID_SHA)
    # deployment id preserves exact string (no case normalization)
    mixed = "Run-Phase-651-Proof"
    assert resolve_release_identity(mixed, VALID_SHA) == (mixed, VALID_SHA)


def test_missing_or_blank_identity_is_unavailable_never_fabricated():
    assert validate_deployment_id(None) is None
    assert validate_deployment_id("") is None
    assert validate_deployment_id("   ") is None
    assert validate_source_sha(None) is None
    assert validate_source_sha("") is None
    assert resolve_release_identity(None, VALID_SHA) is None
    assert resolve_release_identity(VALID_ID, None) is None
    assert resolve_release_identity(VALID_ID, "") is None
    assert resolve_release_identity("", VALID_SHA) is None


def test_uppercase_sha_rejected():
    assert validate_source_sha(VALID_SHA.upper()) is None
    # uppercase a lettered hex position (index 10 is 'a'), not a digit
    mutated = VALID_SHA[:10] + VALID_SHA[10].upper() + VALID_SHA[11:]
    assert validate_source_sha(mutated) is None
    assert mutated != VALID_SHA


def test_short_long_and_prefixed_sha_rejected():
    assert validate_source_sha(VALID_SHA[:39]) is None  # 39 hex
    assert validate_source_sha(VALID_SHA + "a") is None  # 41 hex
    assert validate_source_sha("sha:" + VALID_SHA) is None
    assert validate_source_sha("0x" + VALID_SHA) is None
    assert validate_source_sha("g" * 40) is None  # non-hex alphabet
    assert validate_source_sha(VALID_SHA[:-1]) is None


def test_whitespace_padded_sha_rejected():
    assert validate_source_sha(" " + VALID_SHA) is None
    assert validate_source_sha(VALID_SHA + " ") is None
    assert validate_source_sha(VALID_SHA + "\n") is None
    assert validate_source_sha("\t" + VALID_SHA) is None


def test_control_and_newline_deployment_id_rejected():
    assert validate_deployment_id("run\n1") is None
    assert validate_deployment_id("run\r\n1") is None
    assert validate_deployment_id("run\x00x") is None
    assert validate_deployment_id("run\t1") is None
    assert validate_deployment_id("run\x7f") is None
    assert validate_deployment_id("a" * (MAX_DEPLOYMENT_ID_LENGTH + 1)) is None
    assert validate_deployment_id("a" * MAX_DEPLOYMENT_ID_LENGTH) == "a" * MAX_DEPLOYMENT_ID_LENGTH


def test_deterministic_repeated_evaluation():
    results = {
        resolve_release_identity(VALID_ID, VALID_SHA),
        resolve_release_identity(VALID_ID, VALID_SHA),
        resolve_release_identity(VALID_ID, VALID_SHA),
    }
    assert results == {(VALID_ID, VALID_SHA)}
    bad = {
        resolve_release_identity(VALID_ID, VALID_SHA.upper()),
        resolve_release_identity(VALID_ID, VALID_SHA.upper()),
    }
    assert bad == {None}


# --- metric exposition ----------------------------------------------------- #

def test_valid_identity_emits_exactly_one_series_value_one():
    registry, gauge = _fresh_carrier()
    assert apply_release_identity(VALID_ID, VALID_SHA, gauge=gauge) is True
    samples = [
        sample
        for family in registry.collect()
        for sample in family.samples
        if family.name == CARRIER_NAME
    ]
    assert len(samples) == 1
    sample = samples[0]
    assert sample.labels == {"deployment_id": VALID_ID, "source_sha": VALID_SHA}
    assert sample.value == 1.0
    assert registry.get_sample_value(
        CARRIER_NAME, {"deployment_id": VALID_ID, "source_sha": VALID_SHA}
    ) == 1.0
    text = generate_latest(registry).decode("utf-8")
    assert f'{CARRIER_NAME}{{deployment_id="{VALID_ID}"' in text
    assert f'source_sha="{VALID_SHA}"' in text


def test_invalid_identity_emits_no_attributable_series():
    for bad_id, bad_sha in (
        (VALID_ID, VALID_SHA.upper()),  # uppercase sha
        (VALID_ID, ""),  # missing sha
        ("", VALID_SHA),  # missing id
        (VALID_ID, VALID_SHA[:-1]),  # short sha
        ("run\n1", VALID_SHA),  # control id
    ):
        registry, gauge = _fresh_carrier()
        assert apply_release_identity(bad_id, bad_sha, gauge=gauge) is False
        text = generate_latest(registry).decode("utf-8")
        assert "deployment_id=" not in text
        assert "source_sha=" not in text
        assert registry.get_sample_value(
            CARRIER_NAME, {"deployment_id": bad_id, "source_sha": bad_sha}
        ) is None


def test_request_metric_keeps_method_path_dimensions_no_release_labels(client):
    client.get("/health")  # produce request-counter samples
    response = client.get("/metrics")
    assert response.status_code == 200
    body = response.text

    # environment is absent in tests -> no carrier *series* at startup
    # (HELP/TYPE metadata for the registered gauge may still appear)
    assert RELEASE_IDENTITY_APPLIED is False
    assert f"{CARRIER_NAME}{{" not in body
    assert "deployment_id=" not in body

    # existing request metric intact with its original dimensions only
    assert "devops_api_requests_total" in body
    for line in body.splitlines():
        if line.startswith("devops_api_requests_total{"):
            labels = line.split("{", 1)[1].rsplit("}", 1)[0]
            keys = {pair.split("=", 1)[0] for pair in labels.split(",")}
            assert keys <= {"method", "path"}, keys

    # no release identity labels leak onto any application metric
    assert "deployment_id=" not in body
    assert "source_sha=" not in body


def test_app_metric_family_has_no_release_identity_labels():
    """No metric in the default registry carries release-identity labels
    when identity is unavailable (and only the carrier ever could)."""
    for family in REGISTRY.collect():
        for sample in family.samples:
            assert "deployment_id" not in sample.labels
            assert "source_sha" not in sample.labels

