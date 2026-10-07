"""Phase 6.1 proposal pipeline unit tests (§8–§26).

Covers: trusted target binding, blocked outcomes, schema fail-closed,
deterministic validation/risk/hash, idempotency, typed failures and the
mandatory no-side-effect guarantee (§22).
"""

import hashlib
import json
import unittest
from unittest.mock import MagicMock, patch

from shared_kernel.domain.provenance import build_provenance_record

from incident_service.application.failures import (
    IncidentNotFound,
    InvalidRcaResult,
    ProposalPersistenceFailed,
    RcaGenerationFailed,
)
from incident_service.application.services.proposal_generation_service import (
    BLOCKED_MISSING_TARGET,
    BLOCKED_NO_DRAFT,
    BLOCKED_PATH_REJECTED,
    BLOCKED_VALIDATION_FAILED,
    ProposalGenerationService,
    classify_proposal_risk,
    compute_proposal_hash,
)
from incident_service.application.services.rca_analyzer import RcaAnalyzerPort
from incident_service.domain.aggregates.incident import IncidentAggregate
from incident_service.domain.entities.incident_evidence import IncidentEvidence
from incident_service.infrastructure.source_provider.github_pr_client import (
    GitHubPRClient,
)
from incident_service.application.services.remediation_orchestration_service import (
    RemediationOrchestrationService,
)

SOURCE_SHA = "a" * 40
OTHER_SHA = "b" * 40

GOOD_PATCH = (
    "--- a/app/pool.py\n"
    "+++ b/app/pool.py\n"
    "@@ -1 +1 @@\n"
    "-close_pool()\n"
    "+close_pool_gracefully()\n"
)

GOOD_RESULT = {
    "root_cause": "connection pool leak introduced by deployment run-1",
    "confidence": 0.95,
    "contributing_factors": [],
    "evidence_refs": ["evt-1", "deploy-1"],
    "uncertainty": [],
    "methodology": "deterministic-test",
    "remediation_draft": {
        "target_file": "app/pool.py",
        "patch": GOOD_PATCH,
        "validation_plan": ["run unit tests", "run linters"],
        "risk_class": None,
    },
}


class FakeRepo:
    def __init__(self, incident=None, fail_save=False):
        self.incident = incident
        self.saved = []
        self.fail_save = fail_save

    def save_incident(self, incident):
        if self.fail_save:
            raise RuntimeError("database gone")
        self.incident = incident
        self.saved.append(incident)

    def get_incident_by_id(self, incident_id):
        if self.incident and self.incident.id == incident_id:
            return self.incident
        return None

    def get_active_incidents(self):
        return [self.incident] if self.incident else []


class FakeAnalyzer(RcaAnalyzerPort):
    def __init__(self, result):
        self.result = result
        self.calls = 0
        self.received_pack = None

    def analyze(self, evidence_pack):
        self.calls += 1
        self.received_pack = evidence_pack
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def deployment_evidence(
    evidence_id="deploy-1",
    name="acme/checkout",
    head_sha=SOURCE_SHA,
    run_id="run-1",
    state="DEPLOYED",
    observed_at=None,
):
    payload = {
        "deployment_run_id": run_id,
        "repository_id": 42,
        "repository_name": name,
        "source_revision": {"head_sha": head_sha, "commits": []},
        "state": state,
        "artifact_hash": "c" * 64,
        "plan_hash": "d" * 64,
    }
    payload["provenance"] = build_provenance_record(
        repository_name=name,
        source_sha=head_sha,
        artifact_hash=payload["artifact_hash"],
        plan_hash=payload["plan_hash"],
        deployment_run_id=run_id,
        state=state,
        verification_method="test-source-verifier",
    )
    evidence = IncidentEvidence(
        id=evidence_id,
        kind="deployment_run",
        source="deployment-service",
        payload=payload,
    )
    if observed_at is not None:
        evidence.observed_at = observed_at
    return evidence


def threshold_evidence(evidence_id="evt-1"):
    return IncidentEvidence(
        id=evidence_id,
        kind="threshold_breach",
        source="monitoring-service",
        payload={"metric": "cpu_percent", "value": 97.0, "threshold": 90.0},
    )


def make_incident(incident_id="inc-1", severity="HIGH", deployment=True):
    incident = IncidentAggregate(
        id=incident_id,
        title="cpu breach",
        severity=severity,
        context_details="gateway cpu",
    )
    incident.move_to_triage()
    incident.attach_evidence(threshold_evidence())
    if deployment:
        incident.attach_evidence(deployment_evidence())
    return incident


def build_service(incident, result=GOOD_RESULT, **repo_kwargs):
    repo = FakeRepo(incident=incident, **repo_kwargs)
    analyzer = FakeAnalyzer(result)
    service = ProposalGenerationService(repository=repo, analyzer=analyzer)
    return service, repo, analyzer


class RiskClassifierTests(unittest.TestCase):
    def test_deterministic_matrix(self):
        base = dict(
            confidence=0.95,
            uncertainty=(),
            contributing_factors=(),
            incident_severity="HIGH",
            ai_suggested=None,
            validation_ok=True,
        )
        self.assertEqual(classify_proposal_risk(**base), "LOW")
        self.assertEqual(
            classify_proposal_risk(**{**base, "confidence": 0.85}), "MEDIUM"
        )
        self.assertEqual(
            classify_proposal_risk(**{**base, "uncertainty": ["t"]}), "MEDIUM"
        )
        self.assertEqual(
            classify_proposal_risk(**{**base, "incident_severity": "CRITICAL"}),
            "HIGH",
        )
        self.assertEqual(
            classify_proposal_risk(**{**base, "ai_suggested": "high"}), "HIGH"
        )
        self.assertEqual(
            classify_proposal_risk(**{**base, "validation_ok": False}), "BLOCKED"
        )
        self.assertEqual(
            classify_proposal_risk(
                **{**base, "validation_ok": True, "violations": ["x"]}
            ),
            "BLOCKED",
        )

    def test_ai_cannot_downgrade_deterministic_risk(self):
        risk = classify_proposal_risk(
            confidence=0.80,
            uncertainty=(),
            contributing_factors=(),
            incident_severity="CRITICAL",
            ai_suggested="LOW",
            validation_ok=True,
        )
        self.assertEqual(risk, "HIGH")

    def test_hash_is_canonical_and_sensitive(self):
        fields = dict(
            incident_id="inc-1",
            root_cause="rc",
            evidence_refs=["e1", "e2"],
            repository="acme/checkout",
            source_sha=SOURCE_SHA,
            file_paths=["app/pool.py"],
            patch=GOOD_PATCH,
            validation_plan=["step"],
            risk_class="LOW",
        )
        reordered = dict(reversed(list(fields.items())))
        self.assertEqual(
            compute_proposal_hash(**fields), compute_proposal_hash(**reordered)
        )
        self.assertEqual(
            compute_proposal_hash(**fields),
            hashlib.sha256(
                json.dumps(
                    fields, sort_keys=True, separators=(",", ":"), ensure_ascii=True
                ).encode("utf-8")
            ).hexdigest(),
        )
        mutated = dict(fields, patch=GOOD_PATCH + "\n# tampered")
        self.assertNotEqual(
            compute_proposal_hash(**fields), compute_proposal_hash(**mutated)
        )


class ProposalGenerationTests(unittest.TestCase):
    def test_happy_path_produces_proposal_bound_to_trusted_record(self):
        incident = make_incident()
        service, repo, analyzer = build_service(incident)

        result = service.generate("inc-1")

        proposal = result["proposal"]
        self.assertEqual(proposal["status"], "PROPOSED")
        self.assertEqual(incident.status, "RemediationProposed")
        # target identity comes verbatim from the trusted evidence record
        self.assertEqual(proposal["repository"], "acme/checkout")
        self.assertEqual(proposal["source_sha"], SOURCE_SHA)
        self.assertEqual(result["target"]["repository_name"], "acme/checkout")
        self.assertEqual(result["target"]["source_sha"], SOURCE_SHA)
        self.assertEqual(result["target"]["evidence_id"], "deploy-1")
        self.assertEqual(proposal["risk_class"], "LOW")
        self.assertRegex(proposal["proposal_hash"], r"^[0-9a-f]{64}$")
        self.assertEqual(proposal["validation_plan"], ["run unit tests", "run linters"])
        self.assertEqual(proposal["evidence_refs"], ["evt-1", "deploy-1"])
        self.assertTrue(proposal["is_verified"])
        # evidence pack reached the provider with the timeline groups
        self.assertIn("threshold_breaches", str(analyzer.received_pack))
        self.assertIn("deployment_runs", str(analyzer.received_pack))
        # RCA persisted as typed evidence
        rca_evidence = [
            item for item in incident.evidence if item.kind == "rca_result"
        ]
        self.assertEqual(len(rca_evidence), 1)
        self.assertEqual(result["rca"]["evidence_refs"], ["evt-1", "deploy-1"])

    def test_target_uses_most_recent_trusted_record_single_pair(self):
        from datetime import datetime, timedelta, timezone

        older = deployment_evidence(
            evidence_id="deploy-old",
            name="acme/checkout",
            head_sha=SOURCE_SHA,
            run_id="run-old",
        )
        older.observed_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
        newer = deployment_evidence(
            evidence_id="deploy-new",
            name="acme/billing",
            head_sha=OTHER_SHA,
            run_id="run-new",
        )
        newer.observed_at = datetime(2026, 6, 1, tzinfo=timezone.utc)
        incident = make_incident(deployment=False)
        incident.attach_evidence(older)
        incident.attach_evidence(newer)
        service, _, _ = build_service(
            incident,
            result={**GOOD_RESULT, "evidence_refs": ["evt-1", "deploy-new"]},
        )

        result = service.generate("inc-1")

        # one record's pair — never repo of A with sha of B
        self.assertEqual(result["proposal"]["repository"], "acme/billing")
        self.assertEqual(result["proposal"]["source_sha"], OTHER_SHA)
        self.assertEqual(result["target"]["evidence_id"], "deploy-new")

    def test_missing_target_blocks_without_calling_provider(self):
        incident = make_incident(deployment=False)
        service, repo, analyzer = build_service(incident)

        result = service.generate("inc-1")

        proposal = result["proposal"]
        self.assertEqual(proposal["status"], "BLOCKED")
        self.assertEqual(proposal["blocked_reason"], BLOCKED_MISSING_TARGET)
        self.assertEqual(proposal["risk_class"], "BLOCKED")
        self.assertEqual(proposal["repository"], "")
        self.assertEqual(proposal["source_sha"], "")
        self.assertFalse(proposal["is_verified"])
        self.assertEqual(analyzer.calls, 0)
        self.assertNotIn(incident.status, {"RemediationProposed"})
        # blocked proposal persisted exactly once
        self.assertEqual(len(incident.patch_proposals), 1)
        self.assertEqual(len(repo.saved), 1)

    def test_non_deployed_state_is_not_actionable(self):
        incident = make_incident(deployment=False)
        incident.attach_evidence(deployment_evidence(state="AWAITING_APPROVAL"))
        service, _, analyzer = build_service(incident)

        result = service.generate("inc-1")

        self.assertEqual(result["proposal"]["status"], "BLOCKED")
        self.assertEqual(
            result["proposal"]["blocked_reason"], BLOCKED_MISSING_TARGET
        )
        self.assertEqual(analyzer.calls, 0)

    def test_missing_draft_blocks_after_rca(self):
        result_no_draft = {
            k: v for k, v in GOOD_RESULT.items() if k != "remediation_draft"
        }
        incident = make_incident()
        service, _, analyzer = build_service(incident, result=result_no_draft)

        result = service.generate("inc-1")

        self.assertEqual(result["proposal"]["status"], "BLOCKED")
        self.assertEqual(result["proposal"]["blocked_reason"], BLOCKED_NO_DRAFT)
        self.assertEqual(analyzer.calls, 1)
        self.assertIsNotNone(result["rca"])
        self.assertEqual(incident.status, "RootCauseFound")
        rca_evidence = [
            item for item in incident.evidence if item.kind == "rca_result"
        ]
        self.assertEqual(len(rca_evidence), 1)

    def test_dangerous_paths_are_rejected(self):
        for index, bad_path in enumerate(
            ("../etc/passwd", "/etc/cron.d/evil", "..\\win\\sys")
        ):
            with self.subTest(path=bad_path):
                incident = make_incident(incident_id=f"inc-bad-path-{index}")
                service, _, _ = build_service(
                    incident,
                    result={
                        **GOOD_RESULT,
                        "remediation_draft": {
                            **GOOD_RESULT["remediation_draft"],
                            "target_file": bad_path,
                        },
                    },
                )
                result = service.generate(incident.id)
                self.assertEqual(result["proposal"]["status"], "BLOCKED")
                self.assertEqual(
                    result["proposal"]["blocked_reason"], BLOCKED_PATH_REJECTED
                )
                self.assertFalse(result["proposal"]["is_verified"])

    def test_multi_file_patch_is_rejected(self):
        multi = (
            "--- a/app/pool.py\n"
            "+++ b/app/pool.py\n"
            "@@ -1 +1 @@\n"
            "-a\n"
            "+b\n"
            "--- a/app/other.py\n"
            "+++ b/app/other.py\n"
            "@@ -1 +1 @@\n"
            "-c\n"
            "+d\n"
        )
        incident = make_incident()
        service, _, _ = build_service(
            incident,
            result={
                **GOOD_RESULT,
                "remediation_draft": {
                    **GOOD_RESULT["remediation_draft"],
                    "patch": multi,
                },
            },
        )

        result = service.generate("inc-1")

        self.assertEqual(result["proposal"]["status"], "BLOCKED")
        self.assertEqual(
            result["proposal"]["blocked_reason"], BLOCKED_VALIDATION_FAILED
        )
        self.assertFalse(result["proposal"]["is_verified"])
        self.assertTrue(result.get("validation_violations"))

    def test_low_confidence_fails_validation(self):
        incident = make_incident()
        service, _, _ = build_service(
            incident, result={**GOOD_RESULT, "confidence": 0.70}
        )

        result = service.generate("inc-1")

        self.assertEqual(result["proposal"]["status"], "BLOCKED")
        self.assertEqual(
            result["proposal"]["blocked_reason"], BLOCKED_VALIDATION_FAILED
        )
        self.assertFalse(result["proposal"]["is_verified"])

    def test_malformed_ai_fails_closed_without_persisting(self):
        bad_results = [
            "garbage",
            {**GOOD_RESULT, "confidence": 42},
            {**GOOD_RESULT, "evidence_refs": ["ghost-ref"]},
            {**GOOD_RESULT, "root_cause": ""},
        ]
        for bad in bad_results:
            with self.subTest(bad=str(bad)[:60]):
                incident = make_incident(incident_id=f"inc-{id(bad)}")
                service, repo, _ = build_service(incident, result=bad)
                with self.assertRaises(InvalidRcaResult):
                    service.generate(incident.id)
                self.assertEqual(incident.patch_proposals, [])
                self.assertEqual(repo.saved, [])

    def test_provider_failure_is_typed(self):
        incident = make_incident()
        service, repo, _ = build_service(
            incident, result=RuntimeError("agent down")
        )
        with self.assertRaises(RcaGenerationFailed):
            service.generate("inc-1")
        self.assertEqual(repo.saved, [])

    def test_unknown_incident_is_typed(self):
        service, _, _ = build_service(make_incident())
        with self.assertRaises(IncidentNotFound):
            service.generate("missing-inc")

    def test_persistence_failure_is_typed(self):
        incident = make_incident()
        service, _, _ = build_service(incident, fail_save=True)
        with self.assertRaises(ProposalPersistenceFailed):
            service.generate("inc-1")

    def test_regeneration_is_idempotent(self):
        incident = make_incident()
        service, repo, analyzer = build_service(incident)

        first = service.generate("inc-1")
        second = service.generate("inc-1")

        self.assertEqual(first["proposal"]["proposal_hash"],
                         second["proposal"]["proposal_hash"])
        self.assertEqual(len(incident.patch_proposals), 1)
        rca_evidence = [
            item for item in incident.evidence if item.kind == "rca_result"
        ]
        self.assertEqual(len(rca_evidence), 1)
        threshold = [
            item for item in incident.evidence if item.kind == "threshold_breach"
        ]
        self.assertEqual(len(threshold), 1)
        self.assertEqual(analyzer.calls, 2)

    def test_proposal_mutation_breaks_hash(self):
        incident = make_incident()
        service, _, _ = build_service(incident)
        result = service.generate("inc-1")
        stored_hash = result["proposal"]["proposal_hash"]

        proposal = incident.patch_proposals[0]
        proposal.diff_patch_payload += "\n+evil()"
        recomputed = compute_proposal_hash(
            incident_id=proposal.incident_id,
            root_cause=GOOD_RESULT["root_cause"],
            evidence_refs=proposal.evidence_refs,
            repository=proposal.repository,
            source_sha=proposal.source_sha,
            file_paths=[proposal.target_filepath],
            patch=proposal.diff_patch_payload,
            validation_plan=proposal.validation_plan,
            risk_class=proposal.risk_class,
        )
        self.assertNotEqual(stored_hash, recomputed)

    def test_no_execution_side_effects(self):
        """§22: proposal produced + persisted while every execution path
        (GitHub client, git/branch/PR, remediation engine) is proven
        untouched via spies."""
        incident = make_incident()
        service, repo, _ = build_service(incident)

        with patch.object(
            RemediationOrchestrationService, "execute"
        ) as orchestrator_spy, patch(
            "incident_service.infrastructure.source_provider."
            "github_pr_client.GitHubPRClient.__init__"
        ) as github_spy, patch(
            "subprocess.run"
        ) as subprocess_run, patch(
            "subprocess.Popen"
        ) as subprocess_popen, patch(
            "os.system"
        ) as os_system:
            result = service.generate("inc-1")

        self.assertEqual(result["proposal"]["status"], "PROPOSED")
        self.assertEqual(len(repo.saved), 1)
        orchestrator_spy.assert_not_called()
        github_spy.assert_not_called()
        subprocess_run.assert_not_called()
        subprocess_popen.assert_not_called()
        os_system.assert_not_called()

    def test_risk_class_from_severity_and_ai_floor(self):
        incident = make_incident(severity="CRITICAL")
        service, _, _ = build_service(incident)
        result = service.generate("inc-1")
        self.assertEqual(result["proposal"]["risk_class"], "HIGH")

        incident2 = make_incident(incident_id="inc-2", severity="HIGH")
        service2, _, _ = build_service(
            incident2,
            result={
                **GOOD_RESULT,
                "evidence_refs": ["evt-1", "deploy-1"],
                "remediation_draft": {
                    **GOOD_RESULT["remediation_draft"],
                    "risk_class": "MEDIUM",
                },
            },
        )
        result2 = service2.generate("inc-2")
        self.assertEqual(result2["proposal"]["risk_class"], "MEDIUM")


if __name__ == "__main__":
    unittest.main()
