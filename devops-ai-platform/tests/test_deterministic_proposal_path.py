"""Deterministic RCA → canonical proposal closure (Phase 8.4.1 §20–§26).

Suites B/C/D/F/H prove the exact bridge the Phase 8.4 report listed as
missing: a real-shaped evidence pack validating the checkout-service
breach, the deterministic adapter producing a schema-valid RCA with the
fixture-owned remediation draft, the incident service's REAL
``parse_rca_result`` accepting it, and the REAL
``ProposalGenerationService.generate()`` reaching ``PROPOSED`` — with
repository/source-SHA still bound exclusively to authoritative
deployment evidence, deterministic canonical hashing, and no request
surface able to steer repository/SHA/commands.

No proposal-pipeline stage is mocked away: the analyzer port is
dependency-injected with the actual deterministic adapter function
(the production HTTP adapter is covered by test_agent_rca_boundary).
"""

import json
import os
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

from agent_service.application.deterministic_rca import (
    DETERMINISTIC_PATCH,
    DETERMINISTIC_ROOT_CAUSE,
    DETERMINISTIC_VALIDATION_PLAN,
    E2E_PATCHED_SERVICE_NAME,
    E2E_TARGET_FILE,
    deterministic_analyze,
)
from incident_service.application.services.proposal_generation_service import (
    ProposalGenerationService,
    compute_proposal_hash,
)
from incident_service.application.services.rca_analyzer import (
    DRAFT_KEYS,
    RcaAnalyzerPort,
    parse_rca_result,
)
from incident_service.application.services.test_proposal_generation_service import (
    SOURCE_SHA,
    FakeRepo,
    deployment_evidence,
)
from incident_service.domain.aggregates.incident import IncidentAggregate
from incident_service.domain.entities.hotfix_proposal import HotfixProposal
from incident_service.domain.entities.incident_evidence import IncidentEvidence

THRESHOLD_ID = "ev-threshold-1"
DEPLOY_ID = "deploy-1"
INCIDENT_ID = "inc-e2e-1"
AUTHORITATIVE_REPO = "acme/checkout"

VALID_EVIDENCE_IDS = {THRESHOLD_ID, DEPLOY_ID}


def threshold_evidence() -> IncidentEvidence:
    """Full real-shaped monitoring evidence (as OnMetricThresholdFailed
    persists it): service, metric, numeric value, configured threshold."""
    return IncidentEvidence(
        id=THRESHOLD_ID,
        kind="threshold_breach",
        source="monitoring-service",
        observed_at=datetime(2026, 10, 6, 0, 0, 1, tzinfo=timezone.utc),
        payload={
            "event_id": "evt-e2e-1",
            "event_type": "ThreatThresholdExceededEvent",
            "service": "checkout-service",
            "metric": "cpu_percent",
            "value": 97.0,
            "threshold": 90.0,
            "operator": ">",
            "severity": "HIGH",
            "breach_count": 1,
            "breaches": [
                {
                    "metric": "cpu_percent",
                    "value": 97.0,
                    "threshold": 90.0,
                    "operator": ">",
                    "severity": "high",
                }
            ],
            "metrics": {"cpu_percent": 97.0},
        },
    )


def make_staging_incident() -> IncidentAggregate:
    incident = IncidentAggregate(
        id=INCIDENT_ID,
        title="checkout-service cpu breach",
        severity="HIGH",
        context_details="e2e synthetic threshold breach",
    )
    incident.move_to_triage()
    incident.attach_evidence(threshold_evidence())
    incident.attach_evidence(
        deployment_evidence(
            evidence_id=DEPLOY_ID,
            name=AUTHORITATIVE_REPO,
            head_sha=SOURCE_SHA,
            run_id="run-e2e-1",
            observed_at=datetime(2026, 10, 6, 0, 0, 2, tzinfo=timezone.utc),
        )
    )
    return incident


class DeterministicAdapterPort(RcaAnalyzerPort):
    """DI of the REAL deterministic adapter (not a mock of the pipeline)."""

    def __init__(self):
        self.packs = []

    def analyze(self, evidence_pack):
        self.packs.append(evidence_pack)
        return deterministic_analyze(evidence_pack)


def build_service(incident=None):
    repo = FakeRepo(incident=incident if incident is not None else make_staging_incident())
    analyzer = DeterministicAdapterPort()
    return ProposalGenerationService(repository=repo, analyzer=analyzer), repo, analyzer


def _pack():
    """Real-shaped pack exactly as RcaEvidencePackBuilder emits it."""
    from incident_service.application.services.rca_evidence_pack import (
        RcaEvidencePackBuilder,
    )

    repo = FakeRepo(incident=make_staging_incident())
    return RcaEvidencePackBuilder(repo).build(INCIDENT_ID)


class ParserIntegrationTests(unittest.TestCase):
    """Suite B (§20): parser-level proof, not dictionary comparison."""

    def test_deterministic_result_is_accepted_by_real_parser(self):
        result = deterministic_analyze(_pack())
        rca, draft = parse_rca_result(
            result,
            incident_id=INCIDENT_ID,
            valid_evidence_ids=VALID_EVIDENCE_IDS,
        )
        self.assertEqual(rca.root_cause, DETERMINISTIC_ROOT_CAUSE)
        self.assertEqual(rca.evidence_refs, [THRESHOLD_ID, DEPLOY_ID])
        self.assertIsNotNone(draft)
        self.assertEqual(draft["target_file"], E2E_TARGET_FILE)
        self.assertEqual(draft["risk_class"], "LOW")
        self.assertTrue(draft["validation_plan"])
        self.assertTrue(draft["patch"].strip())

        # draft patch accepted as a single-file unified diff by the
        # authoritative verification gate
        proposal = HotfixProposal(
            id="proposal-probe",
            incident_id=INCIDENT_ID,
            target_filepath=draft["target_file"],
            diff_patch_payload=draft["patch"],
            source_sha=SOURCE_SHA,
            repository=AUTHORITATIVE_REPO,
            evidence_refs=list(rca.evidence_refs),
            validation_plan=list(draft["validation_plan"]),
        )
        self.assertTrue(proposal.apply_verification_pass())

    def test_foreign_evidence_ids_rejected_by_parser(self):
        from incident_service.application.failures import InvalidRcaResult

        result = deterministic_analyze(_pack())
        with self.assertRaises(InvalidRcaResult):
            parse_rca_result(
                result,
                incident_id=INCIDENT_ID,
                valid_evidence_ids={"ev-from-somewhere-else"},
            )


class CanonicalProposalPathTests(unittest.TestCase):
    """Suite C (§21): authoritative target + deterministic RCA + draft →
    the REAL ProposalGenerationService → PROPOSED."""

    def test_generate_reaches_proposed_bound_to_authoritative_evidence(self):
        incident = make_staging_incident()
        service, repo, analyzer = build_service(incident)

        result = service.generate(INCIDENT_ID)

        proposal = result["proposal"]
        self.assertEqual(proposal["status"], "PROPOSED")
        self.assertTrue(proposal["is_verified"])
        self.assertEqual(incident.status, "RemediationProposed")

        # repository + source SHA exclusively from deployment evidence
        self.assertEqual(proposal["repository"], AUTHORITATIVE_REPO)
        self.assertEqual(proposal["source_sha"], SOURCE_SHA)
        self.assertEqual(result["target"]["repository_name"], AUTHORITATIVE_REPO)
        self.assertEqual(result["target"]["source_sha"], SOURCE_SHA)
        self.assertEqual(result["target"]["evidence_id"], DEPLOY_ID)

        # fixture target + canonical hash shape
        self.assertEqual(proposal["target_filepath"], E2E_TARGET_FILE)
        self.assertEqual(proposal["validation_plan"], DETERMINISTIC_VALIDATION_PLAN)
        self.assertRegex(proposal["proposal_hash"], r"^[0-9a-f]{64}$")
        # deterministic classifier: contributing_factors floor → MEDIUM
        # (draft risk_class LOW only floors, never forces the score)
        self.assertEqual(proposal["risk_class"], "MEDIUM")

        # RCA persisted as typed evidence; citations ⊆ incident evidence
        rca_evidence = [
            item for item in incident.evidence if item.kind == "rca_result"
        ]
        self.assertEqual(len(rca_evidence), 1)
        self.assertTrue(set(result["rca"]["evidence_refs"]) <= {e.id for e in incident.evidence})
        self.assertIn(THRESHOLD_ID, result["rca"]["evidence_refs"])

        # the pack handed to the provider really carried the breach
        received = analyzer.packs[0]
        self.assertEqual(
            received["signals"]["threshold_breaches"][0]["service"],
            "checkout-service",
        )

        # draft cannot alter authoritative identity: neither the RCA
        # payload nor the adapter output ever contains the repository/SHA
        rca_json = json.dumps(result["rca"])
        adapter_json = json.dumps(deterministic_analyze(received))
        for sensitive in (AUTHORITATIVE_REPO, SOURCE_SHA):
            self.assertNotIn(sensitive, rca_json)
            self.assertNotIn(sensitive, adapter_json)

    def test_same_equivalent_evidence_yields_identical_hash(self):
        first = build_service(make_staging_incident())
        second = build_service(make_staging_incident())
        hash_one = first[0].generate(INCIDENT_ID)["proposal"]["proposal_hash"]
        hash_two = second[0].generate(INCIDENT_ID)["proposal"]["proposal_hash"]
        self.assertEqual(hash_one, hash_two)

    def test_rca_evidence_is_persisted_and_regeneration_stays_executable(self):
        incident = make_staging_incident()
        service, repo, _ = build_service(incident)
        result = service.generate(INCIDENT_ID)
        self.assertEqual(result["incident_status"], "RemediationProposed")

        # regeneration over the persisted incident stays executable
        again = service.generate(INCIDENT_ID)
        self.assertEqual(again["proposal"]["status"], "PROPOSED")
        self.assertIs(repo.incident, incident)


class ProposalHashTests(unittest.TestCase):
    """Suite D (§22): canonical hash stability + mutation sensitivity."""

    BASE = {
        "incident_id": INCIDENT_ID,
        "root_cause": DETERMINISTIC_ROOT_CAUSE,
        "evidence_refs": [THRESHOLD_ID, DEPLOY_ID],
        "repository": AUTHORITATIVE_REPO,
        "source_sha": SOURCE_SHA,
        "file_paths": [E2E_TARGET_FILE],
        "patch": DETERMINISTIC_PATCH,
        "validation_plan": DETERMINISTIC_VALIDATION_PLAN,
        "risk_class": "MEDIUM",
    }

    def test_hash_is_stable_for_equivalent_inputs(self):
        self.assertEqual(
            compute_proposal_hash(**self.BASE),
            compute_proposal_hash(**dict(self.BASE)),
        )

    def test_every_meaningful_field_mutation_changes_the_hash(self):
        baseline = compute_proposal_hash(**self.BASE)
        mutations = {
            "patch": {**self.BASE, "patch": self.BASE["patch"] + "\n"},
            "file_paths": {**self.BASE, "file_paths": ["src/other.py"]},
            "repository": {**self.BASE, "repository": "evil/repo"},
            "source_sha": {**self.BASE, "source_sha": "f" * 40},
            "risk_class": {**self.BASE, "risk_class": "LOW"},
            "validation_plan": {**self.BASE, "validation_plan": ["something else"]},
            "evidence_refs": {**self.BASE, "evidence_refs": [DEPLOY_ID, THRESHOLD_ID]},
            "root_cause": {**self.BASE, "root_cause": "some other conclusion"},
            "incident_id": {**self.BASE, "incident_id": "inc-other"},
        }
        for field, mutated in mutations.items():
            with self.subTest(field=field):
                self.assertNotEqual(compute_proposal_hash(**mutated), baseline)


class SecurityRegressionTests(unittest.TestCase):
    """Suite F/H (§24/§26): request data cannot steer remediation or leak
    secrets through deterministic output."""

    EXTRA_FIELDS = {
        "repository": "evil/repo",
        "source_sha": "f" * 40,
        "command": "rm -rf /",
        "argv": ["bash", "-c", "whoami"],
        "branch": "pwned-branch",
        "github_url": "https://evil.example/repo",
    }

    def test_request_body_cannot_control_authoritative_fields(self):
        from fastapi.testclient import TestClient

        from agent_service.main import app

        client = TestClient(app)
        with patch.dict(os.environ, {"E2E_DETERMINISTIC_RCA": "true"}):
            baseline = client.post(
                "/api/internal/analyze-rca", json={"evidence_pack": _pack()}
            )
            tampered = client.post(
                "/api/internal/analyze-rca",
                json={"evidence_pack": _pack(), **self.EXTRA_FIELDS},
            )
        self.assertEqual(baseline.status_code, 200, baseline.text)
        self.assertEqual(tampered.status_code, 200, tampered.text)
        self.assertEqual(baseline.json(), tampered.json())
        body = tampered.text
        for value in self.EXTRA_FIELDS.values():
            needle = value if isinstance(value, str) else json.dumps(value)
            self.assertNotIn(needle, body)

    def test_result_contains_no_identity_or_command_surface(self):
        result = deterministic_analyze(_pack())
        self.assertTrue(set(result) <= {
            "root_cause", "confidence", "evidence_refs",
            "supporting_evidence_ids", "contributing_factors",
            "uncertainty", "methodology", "remediation_draft",
        })
        self.assertEqual(set(result["remediation_draft"]), set(DRAFT_KEYS))
        for banned in ("repository", "source_sha", "branch", "github", "command", "argv"):
            self.assertNotIn(banned, result["remediation_draft"])

    def test_deterministic_outputs_contain_no_secret_material(self):
        incident = make_staging_incident()
        service, _, _ = build_service(incident)
        result = service.generate(INCIDENT_ID)
        bundle = json.dumps(result, default=str) + json.dumps(
            deterministic_analyze(_pack())
        )
        for marker in (
            "JWT_SECRET",
            "GITHUB_OAUTH_TOKEN",
            "GEMINI_API_KEY",
            "Bearer ",
            "ghp_",
            "PRIVATE KEY",
            "Authorization",
        ):
            self.assertNotIn(marker, bundle)


if __name__ == "__main__":
    unittest.main()
