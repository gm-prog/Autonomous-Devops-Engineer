"""Provenance contract: canonical hash, sensitivity matrix, honest claims.

Stage 5 §6 requirements proven here:

* ``provenance_hash`` is canonical-JSON SHA-256 — deterministic across key
  order and construction order (no ambiguous representation);
* the hash changes when ANY identity field changes: repository, source
  SHA, artifact, plan, deployment run id, state, verification method —
  each distinct in isolation;
* tampering, missing fields, unknown fields, wrong schema, malformed hex,
  an ``unverified`` source, and over-claimed artifact derivation all fail
  verification (fail closed);
* the platform refuses to build a record claiming artifact-to-source
  derivation it cannot establish.
"""

from shared_kernel.domain.provenance import (
    ARTIFACT_SOURCE_DERIVATION_NOT_ESTABLISHED,
    PROVENANCE_SCHEMA,
    VERIFICATION_METHOD_UNVERIFIED,
    ProvenanceError,
    build_provenance_record,
    compute_provenance_hash,
    verify_provenance_record,
)

REPO = "acme/checkout"
SHA = "a" * 40
ARTIFACT = "c" * 64
PLAN = "d" * 64
RUN_ID = "run-stage5"
STATE = "DEPLOYED"
METHOD = "github-commit-lookup"


def _build(**overrides):
    kwargs = dict(
        repository_name=REPO,
        source_sha=SHA,
        artifact_hash=ARTIFACT,
        plan_hash=PLAN,
        deployment_run_id=RUN_ID,
        state=STATE,
        verification_method=METHOD,
    )
    kwargs.update(overrides)
    return build_provenance_record(**kwargs)


def _expect_rejected(record, why):
    try:
        verify_provenance_record(record)
    except ProvenanceError:
        return
    raise AssertionError(f"provenance verification must reject: {why}")


def test_valid_record_verifies_and_has_stable_hash():
    record = _build()
    verify_provenance_record(record)  # no raise
    assert record["schema"] == PROVENANCE_SCHEMA
    assert record["artifact_source_derivation"] == (
        ARTIFACT_SOURCE_DERIVATION_NOT_ESTABLISHED
    )
    # identical inputs rebuild the identical hash (canonical JSON)
    assert _build()["provenance_hash"] == record["provenance_hash"]
    # insertion order is irrelevant to the hash
    reordered = dict(reversed(list(record.items())))
    assert compute_provenance_hash(reordered) == record["provenance_hash"]


def test_identity_field_sensitivity_matrix():
    """Every security-relevant identity field changes the provenance hash in
    isolation (§6: repo / SHA / artifact / plan / state each distinct)."""
    base = _build()["provenance_hash"]
    variants = {
        "repository": _build(repository_name="acme/payments"),
        "source_sha": _build(source_sha="b" * 40),
        "artifact": _build(artifact_hash="e" * 64),
        "plan": _build(plan_hash="f" * 64),
        "run_id": _build(deployment_run_id="run-other"),
        "state": _build(state="AWAITING_APPROVAL"),
        "verification_method": _build(verification_method="test-source-verifier"),
    }
    hashes = {name: rec["provenance_hash"] for name, rec in variants.items()}
    assert all(h != base for h in hashes.values()), hashes
    # every variant hash is itself distinct from every other
    assert len(set(hashes.values())) == len(hashes)


def test_tampering_with_any_field_fails_verification():
    base = _build()
    for field, forged in (
        ("repository_name", "evil/checkout"),
        ("source_sha", "b" * 40),
        ("artifact_hash", "e" * 64),
        ("plan_hash", "f" * 64),
        ("deployment_run_id", "run-forged"),
        ("state", "AWAITING_APPROVAL"),
        ("verification_method", "something-else"),
        ("schema", "devops.deployment-provenance/0"),
    ):
        tampered = dict(base, **{field: forged})
        _expect_rejected(tampered, f"field {field} altered without rehash")


def test_tampering_with_the_hash_itself_fails():
    base = _build()
    _expect_rejected(dict(base, provenance_hash="0" * 64), "hash replaced")
    _expect_rejected(dict(base, provenance_hash="short"), "hash malformed")


def test_missing_and_unknown_fields_fail():
    base = _build()
    missing = {k: v for k, v in base.items() if k != "plan_hash"}
    _expect_rejected(missing, "missing field")
    _expect_rejected(dict(base, extra_field=1), "unknown field")
    _expect_rejected("not-a-dict", "non-object")
    _expect_rejected(None, "null")


def test_malformed_identity_fields_fail():
    """A hand-crafted record with malformed stored values never verifies —
    even when the attacker recomputes the unkeyed hash (structural checks
    reject before the hash is even compared)."""
    base = _build()
    for field, forged in (
        ("source_sha", SHA.upper()),
        ("source_sha", "a" * 39),
        ("source_sha", "main"),
        ("repository_name", "checkout"),
        ("repository_name", "a/b/c"),
        ("artifact_hash", "c" * 63),
        ("artifact_hash", ""),
        ("deployment_run_id", "  "),
        ("state", "  "),
    ):
        rec = dict(base, **{field: forged})
        rec["provenance_hash"] = compute_provenance_hash(rec)
        _expect_rejected(rec, f"malformed {field}={forged!r} with valid hash")
    # builder refuses non-canonical inputs up front too
    for overrides, why in (
        (dict(repository_name="checkout"), "builder bare repo"),
        (dict(source_sha="main"), "builder branch name as sha"),
        (dict(artifact_hash="xyz"), "builder non-hex artifact"),
        (dict(verification_method=""), "builder empty method"),
        (dict(state=""), "builder empty state"),
    ):
        try:
            _build(**overrides)
        except ProvenanceError:
            continue
        raise AssertionError(f"builder must refuse: {why}")
    # builder canonicalizes source SHA case at construction
    assert _build(source_sha=SHA.upper())["source_sha"] == SHA


def test_unverified_method_never_verifies_even_with_a_valid_hash():
    """An attacker who can recompute the (unkeyed) hash still cannot launder
    an unverified record: the method claim is checked structurally."""
    record = _build(verification_method=VERIFICATION_METHOD_UNVERIFIED)
    # builder recorded the honest claim and hashed it consistently
    assert record["provenance_hash"] == compute_provenance_hash(record)
    _expect_rejected(record, "unverified method with valid hash")


def test_over_claimed_artifact_derivation_is_impossible():
    # builder refuses to fabricate a derivation claim
    try:
        _build(artifact_source_derivation="sha256-source-tree")
    except ProvenanceError:
        pass
    else:
        raise AssertionError("builder must refuse over-claimed derivation")
    # verifier rejects a hand-crafted over-claim (with recomputed hash)
    forged = _build()
    forged["artifact_source_derivation"] = "sha256-source-tree"
    forged["provenance_hash"] = compute_provenance_hash(forged)
    _expect_rejected(forged, "over-claimed derivation with valid hash")
