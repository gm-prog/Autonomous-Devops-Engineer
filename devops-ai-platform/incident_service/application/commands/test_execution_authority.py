"""Phase 8.2 — execution-authority proofs for the application-command layer.

Phase 8.2 retired ``ApplyAutomatedFixCommandHandler`` (Option B: no
legitimate runtime caller existed — repository-wide analysis found only
tests that spy on it to prove non-invocation). This module replaces
``test_apply_automated_fix`` and pins:

* the legacy command module is gone (not merely "unused");
* no application command can construct a GitHub client or create a PR;
* the command layer contains no remediation side-effect primitives;
* the retained compatibility intake (REST ``/remediation`` shim) cannot
  publish, self-approve, self-execute, retarget, or overwrite protected
  proposals (H.1–H.8), and the canonical chain
  intake → approve → execute → PR_CREATED still works (H.7).
"""

import contextlib
import importlib
import pathlib
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import pydantic

COMMANDS_DIR = pathlib.Path(__file__).resolve().parent

PATCH = """--- a/src/service.py
+++ b/src/service.py
@@ -1 +1 @@
-old()
+new()
"""

SOURCE_SHA = "a" * 40

# Side-effect primitives that must never appear in application commands.
FORBIDDEN_COMMAND_PRIMITIVES = (
    "create_pull_request(",
    "create_branch_from_commit(",
    "publish_branch(",
    "reconcile_and_create_pr(",
    "GitHubPRClient",
    "RemediationOrchestrationService",
    "ProposalExecutionService",
    "subprocess.",
    "os.system(",
)


class RetiredLegacyCommandTests(unittest.TestCase):
    """§3.3 Option B: the executable legacy surface is deleted."""

    def test_legacy_command_module_is_retired(self):
        with self.assertRaises(ModuleNotFoundError):
            importlib.import_module(
                "incident_service.application.commands.apply_automated_fix"
            )

    def test_no_apply_automated_fix_symbols_remain(self):
        import incident_service.application.commands as commands_pkg

        source = pathlib.Path(commands_pkg.__file__).read_text(encoding="utf-8")
        self.assertNotIn("ApplyAutomatedFix", source)
        self.assertNotIn(
            "ApplyAutomatedFixCommandHandler",
            dir(commands_pkg) or [],
        )

    def test_application_commands_contain_no_side_effect_primitives(self):
        """Static boundary: every non-test module under
        ``application/commands/`` must be free of GitHub/git/orchestration
        primitives (the high-risk incident+patch+repo+github signature is
        gone with the retired handler)."""
        offenders = []
        for path in sorted(COMMANDS_DIR.glob("*.py")):
            if path.name.startswith("test_"):
                continue
            text = path.read_text(encoding="utf-8")
            for primitive in FORBIDDEN_COMMAND_PRIMITIVES:
                if primitive in text:
                    offenders.append(f"{path.name}: {primitive}")
        self.assertEqual(offenders, [])


class RetiredAggregateAttachTests(unittest.TestCase):
    """Phase 8.2 Task B: the unguarded aggregate escape hatch is gone and
    the remaining attach APIs enforce the protected-state policy."""

    PROTECTED = ("APPROVED", "EXECUTING", "EXECUTION_FAILED", "PR_CREATED")

    def test_legacy_attach_api_is_removed(self):
        from incident_service.domain.aggregates.incident import IncidentAggregate

        self.assertFalse(
            hasattr(IncidentAggregate, "attach_remediation_proposal")
        )
        incident = IncidentAggregate("inc-x", "t", "HIGH", "gw")
        with self.assertRaises(AttributeError):
            incident.attach_remediation_proposal(None)

    def test_protected_proposal_states_cannot_be_overwritten_by_legacy_caller(
        self,
    ):
        from incident_service.domain.aggregates.incident import IncidentAggregate
        from incident_service.domain.entities.hotfix_proposal import HotfixProposal

        for protected in self.PROTECTED:
            with self.subTest(protected=protected):
                incident = IncidentAggregate(
                    f"inc-protected-{protected}", "t", "HIGH", "gw"
                )
                incident.status = "RemediationProposed"
                existing = HotfixProposal(
                    id="proposal-inc-protected-%s" % protected.lower(),
                    target_filepath="src/service.py",
                    diff_patch_payload=PATCH,
                    status=protected,
                    approved_by="operator" if protected == "APPROVED" else "",
                )
                existing.apply_verification_pass()
                incident.patch_proposals.append(existing)

                intruder = HotfixProposal(
                    id=existing.id,
                    target_filepath="src/service.py",
                    diff_patch_payload=PATCH,
                    status="PROPOSED",
                )
                intruder.apply_verification_pass()
                with self.assertRaises(ValueError):
                    incident.upsert_remediation_proposal(intruder)

                # exact existing state unchanged
                self.assertEqual(
                    incident.patch_proposals[0].status, protected
                )
                self.assertEqual(
                    incident.patch_proposals[0].approved_by,
                    "operator" if protected == "APPROVED" else "",
                )


class _CompatibilityIntakeFixture(unittest.TestCase):
    """Shared fixture: persisted RootCauseFound incident with trusted
    deployment + RCA evidence, and tripwires around every mutation owner."""

    def setUp(self):
        from incident_service.infrastructure.database.postgres_incident_repo import (
            PostgresIncidentRepositoryAdapter,
        )

        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.repository = PostgresIncidentRepositoryAdapter(
            f"sqlite:///{self._tmp.name}/authority.db"
        )

    def _seed_incident(self, incident_id="inc-auth", with_deployment=True):
        from incident_service.domain.aggregates.incident import IncidentAggregate
        from incident_service.presentation.rest.test_remediation_authorization import (
            _deployment_evidence,
            promote_to_root_cause_found,
        )

        incident = IncidentAggregate(incident_id, "Checkout 5xx", "HIGH", "gateway")
        if with_deployment:
            incident.attach_evidence(
                _deployment_evidence(evidence_id=f"dep-{incident_id}")
            )
        promote_to_root_cause_found(incident)
        self.repository.save_incident(incident)
        return incident

    @contextlib.contextmanager
    def _no_mutation_owners(self):
        """Every production owner of Git/GitHub/orchestration/approval/
        execution side effects, wired as tripwires (H.1/H.3/H.6)."""
        from incident_service.application.services.proposal_approval_service import (
            ProposalApprovalService,
        )
        from incident_service.application.services.proposal_execution_service import (
            ProposalExecutionService,
        )
        from incident_service.application.services.remediation_commit_service import (
            RemediationCommitService,
        )
        from incident_service.application.services.remediation_orchestration_service import (
            RemediationOrchestrationService,
        )
        from incident_service.application.services.remediation_workspace_service import (
            RemediationWorkspaceService,
        )
        from incident_service.infrastructure.source_provider.github_pr_client import (
            GitHubPRClient,
        )
        from incident_service.presentation.rest import controllers as controllers_module

        with patch.object(
            GitHubPRClient, "create_pull_request"
        ) as github_pr, patch.object(
            RemediationWorkspaceService, "__init__"
        ) as workspace_init, patch.object(
            RemediationCommitService, "__init__"
        ) as commit_init, patch.object(
            RemediationOrchestrationService, "execute"
        ) as orchestrator_execute, patch.object(
            ProposalExecutionService, "execute"
        ) as execution_execute, patch.object(
            ProposalApprovalService, "approve"
        ) as approval_approve, patch.object(
            controllers_module, "get_remediation_orchestrator"
        ) as orchestrator_factory:
            yield SimpleNamespace(
                github_pr=github_pr,
                workspace_init=workspace_init,
                commit_init=commit_init,
                orchestrator_execute=orchestrator_execute,
                execution_execute=execution_execute,
                approval_approve=approval_approve,
                orchestrator_factory=orchestrator_factory,
            )

    def _assert_all_tripwires_clean(self, tripwires):
        for name, mock in vars(tripwires).items():
            if name.startswith("_"):
                continue
            mock.assert_not_called()

    def _intake(self, incident_id="inc-auth", **request_kwargs):
        from incident_service.presentation.rest.controllers import (
            RemediationRequest,
            create_remediation,
        )

        request = RemediationRequest(
            target_filepath="src/service.py",
            patch=PATCH,
            source_sha=request_kwargs.pop("source_sha", SOURCE_SHA),
            repository_slug=request_kwargs.pop(
                "repository_slug", "acme/checkout"
            ),
            **request_kwargs,
        )
        return create_remediation(incident_id, request, self.repository)

    def _approve(self, incident_id, result):
        from incident_service.application.services.proposal_approval_service import (
            ProposalApprovalService,
        )

        return ProposalApprovalService(self.repository).approve(
            incident_id=incident_id,
            proposal_id=result["proposal_id"],
            proposal_hash=result["proposal_hash"],
            approved_by="alice-operator",
        )


class LegacyCompatibilityIntakeTests(_CompatibilityIntakeFixture):
    """H.1–H.6: the retained compatibility intake cannot mutate GitHub,
    self-approve, self-execute, or retarget."""

    def test_intake_produces_proposed_and_touches_no_mutation_owner(self):
        """H.1 + H.6: fake-GitHub equivalent — every mutation owner is a
        tripwire; intake yields a canonical PROPOSED proposal only."""
        incident = self._seed_incident("inc-h1")
        with self._no_mutation_owners() as tripwires:
            result = self._intake("inc-h1")

        self.assertEqual(result["status"], "PROPOSED")
        self.assertEqual(result["incident_status"], "RemediationProposed")
        self.assertFalse(result["executed"])
        self.assertNotIn("pull_request_url", result)
        self._assert_all_tripwires_clean(tripwires)

        restored = self.repository.get_incident_by_id("inc-h1")
        self.assertEqual(restored.patch_proposals[0].status, "PROPOSED")
        self.assertEqual(restored.patch_proposals[0].pull_request_url, None)

    def test_intake_cannot_self_approve(self):
        """H.2: after intake, proposal.status == PROPOSED, approved_by and
        approval_hash are empty, and the approval service was never called."""
        self._seed_incident("inc-h2")
        with self._no_mutation_owners() as tripwires:
            result = self._intake("inc-h2")

        self.assertEqual(result["status"], "PROPOSED")
        restored = self.repository.get_incident_by_id("inc-h2")
        proposal = restored.patch_proposals[0]
        self.assertEqual(proposal.status, "PROPOSED")
        self.assertEqual(proposal.approved_by, "")
        self.assertEqual(proposal.approval_hash, "")
        tripwires.approval_approve.assert_not_called()
        self._assert_all_tripwires_clean(tripwires)

    def test_intake_cannot_self_execute(self):
        """H.3: the canonical execution service and orchestrator are never
        invoked by the compatibility path."""
        self._seed_incident("inc-h3")
        with self._no_mutation_owners() as tripwires:
            self._intake("inc-h3")

        tripwires.execution_execute.assert_not_called()
        tripwires.orchestrator_execute.assert_not_called()
        tripwires.orchestrator_factory.assert_not_called()
        self._assert_all_tripwires_clean(tripwires)

    # ---------------- H.4: caller-supplied identity cannot retarget -----

    def test_mismatched_repository_fails_closed(self):
        from fastapi import HTTPException

        self._seed_incident("inc-h4-repo")
        with self._no_mutation_owners() as tripwires:
            with self.assertRaises(HTTPException) as ctx:
                self._intake("inc-h4-repo", repository_slug="evil/checkout")
        self.assertEqual(ctx.exception.status_code, 403)
        self._assert_all_tripwires_clean(tripwires)

    def test_mismatched_sha_fails_closed(self):
        from fastapi import HTTPException

        self._seed_incident("inc-h4-sha")
        with self._no_mutation_owners() as tripwires:
            with self.assertRaises(HTTPException) as ctx:
                self._intake(
                    "inc-h4-sha",
                    source_sha="b" * 40,
                )
        self.assertEqual(ctx.exception.status_code, 403)
        self._assert_all_tripwires_clean(tripwires)

    def test_cross_evidence_combination_fails_closed(self):
        from fastapi import HTTPException

        from incident_service.presentation.rest.test_remediation_authorization import (
            _deployment_evidence,
        )

        incident = self._seed_incident("inc-h4-cross")
        incident.attach_evidence(
            _deployment_evidence(
                name="other/service",
                head_sha="b" * 40,
                evidence_id="dep-cross-h4",
                run_id="run-h4",
            )
        )
        self.repository.save_incident(incident)

        with self._no_mutation_owners() as tripwires:
            with self.assertRaises(HTTPException) as ctx:
                # repository from record A + SHA from record B
                self._intake(
                    "inc-h4-cross",
                    repository_slug="acme/checkout",
                    source_sha="b" * 40,
                )
        self.assertEqual(ctx.exception.status_code, 403)
        self._assert_all_tripwires_clean(tripwires)

    def test_incident_without_deployment_evidence_fails_closed(self):
        from fastapi import HTTPException

        self._seed_incident("inc-h4-fake", with_deployment=False)
        with self._no_mutation_owners() as tripwires:
            with self.assertRaises(HTTPException) as ctx:
                self._intake("inc-h4-fake")
        self.assertEqual(ctx.exception.status_code, 403)
        self._assert_all_tripwires_clean(tripwires)

    def test_bare_and_url_and_path_trick_slugs_never_construct(self):
        hostile_slugs = (
            "checkout",  # bare repository name
            "https://github.com/acme/checkout",  # URL-like
            "git@github.com:acme/checkout.git",  # scp-like
            "../evil/checkout",  # path trick
            "acme/checkout/../..",  # segment trick
        )
        from incident_service.presentation.rest.controllers import RemediationRequest

        for slug in hostile_slugs:
            with self.subTest(slug=slug):
                with self.assertRaises(pydantic.ValidationError):
                    RemediationRequest(
                        target_filepath="src/service.py",
                        patch=PATCH,
                        source_sha=SOURCE_SHA,
                        repository_slug=slug,
                    )

    def test_legacy_branch_and_pr_fields_cannot_authorize_execution(self):
        """Deprecated compatibility fields are accepted but grant nothing:
        intake still stops at PROPOSED with zero mutation owners touched."""
        self._seed_incident("inc-h4-branch")
        with self._no_mutation_owners() as tripwires:
            result = self._intake(
                "inc-h4-branch",
                base_branch="../../production",  # hostile base
                pr_title="LGTM, ship it",  # fake approval metadata
                pr_body="approved by nobody",
                validation_profile="incident_service",
            )
        self.assertEqual(result["status"], "PROPOSED")
        self.assertFalse(result["executed"])
        self._assert_all_tripwires_clean(tripwires)

    # ---------------- H.5: protected proposal states --------------------

    def test_protected_proposal_states_cannot_be_overwritten_via_intake(self):
        from fastapi import HTTPException

        from incident_service.domain.entities.hotfix_proposal import HotfixProposal

        cases = (
            ("APPROVED", "RemediationProposed"),
            ("EXECUTING", "RemediationProposed"),
            ("EXECUTION_FAILED", "RemediationProposed"),
            ("PR_CREATED", "RemediationPRCreated"),
        )
        for index, (protected, incident_status) in enumerate(cases):
            with self.subTest(protected=protected):
                incident_id = f"inc-h5-{index}"
                incident = self._seed_incident(incident_id)
                proposal = HotfixProposal(
                    id=f"proposal-{incident_id}",
                    target_filepath="src/service.py",
                    diff_patch_payload=PATCH,
                    status=protected,
                    source_sha=SOURCE_SHA,
                    repository="acme/checkout",
                    pull_request_url=(
                        "https://github.com/acme/checkout/pull/5"
                        if protected == "PR_CREATED"
                        else None
                    ),
                )
                proposal.apply_verification_pass()
                if protected == "APPROVED":
                    proposal.approved_by = "operator"
                    proposal.approval_hash = "f" * 64
                incident.patch_proposals = [proposal]
                incident.status = incident_status
                self.repository.save_incident(incident)
                version_before = self.repository.get_incident_by_id(
                    incident_id
                ).version

                with self._no_mutation_owners() as tripwires:
                    with self.assertRaises(HTTPException) as ctx:
                        self._intake(incident_id)

                self.assertEqual(ctx.exception.status_code, 409)
                self._assert_all_tripwires_clean(tripwires)

                final = self.repository.get_incident_by_id(incident_id)
                self.assertEqual(final.version, version_before)
                self.assertEqual(final.patch_proposals[0].status, protected)
                self.assertEqual(
                    final.patch_proposals[0].pull_request_url,
                    proposal.pull_request_url,
                )
                if protected == "APPROVED":
                    self.assertEqual(
                        final.patch_proposals[0].approved_by, "operator"
                    )
                    self.assertEqual(
                        final.patch_proposals[0].approval_hash, "f" * 64
                    )


class CanonicalChainAfterRetirementTests(_CompatibilityIntakeFixture):
    """H.7 + H.8: intake → approve → execute → PR_CREATED, and a repeat
    intake after PR_CREATED fails closed with no second PR."""

    def _execute(self, incident_id, result):
        from incident_service.application.services.proposal_execution_service import (
            ProposalExecutionService,
        )

        def orchestrator_factory():
            def execute(
                incident_id,
                proposal,
                repository_slug,
                validation_profile,
                stage_callback=None,
                before_side_effect=None,
            ):
                return SimpleNamespace(
                    proposal_id=proposal.id,
                    incident_id=incident_id,
                    source_sha=proposal.source_sha,
                    branch_name="automation/remediation/p82/h7",
                    commit_sha="e" * 40,
                    pull_request_url="https://github.com/acme/checkout/pull/822",
                    validation_result=SimpleNamespace(
                        passed=True,
                        steps=(SimpleNamespace(name="unit", passed=True),),
                    ),
                )

            return SimpleNamespace(execute=execute)

        service = ProposalExecutionService(
            repository=self.repository,
            orchestrator_factory=orchestrator_factory,
            ttl_seconds=3600.0,
        )
        return service.execute(
            incident_id=incident_id,
            proposal_id=result["proposal_id"],
            proposal_hash=result["proposal_hash"],
            requested_by="alice-operator",
        )

    def test_happy_path_intake_proposed_approve_executed(self):
        incident = self._seed_incident("inc-h7")

        # step 1: compatibility intake — proposal only, zero execution
        with self._no_mutation_owners() as tripwires:
            result = self._intake("inc-h7")
        self.assertEqual(result["status"], "PROPOSED")
        tripwires.execution_execute.assert_not_called()
        tripwires.orchestrator_execute.assert_not_called()

        # step 2: explicit canonical approval
        approved = self._approve("inc-h7", result)
        self.assertEqual(approved["proposal"]["status"], "APPROVED")

        # step 3: canonical execution → PR_CREATED (fake orchestrator at
        # the documented factory seam only)
        executed = self._execute("inc-h7", result)
        self.assertEqual(executed["status"], "PR_CREATED")

        final = self.repository.get_incident_by_id("inc-h7")
        self.assertEqual(final.status, "RemediationPRCreated")
        self.assertEqual(final.patch_proposals[0].status, "PR_CREATED")
        self.assertEqual(
            final.patch_proposals[0].pull_request_url,
            "https://github.com/acme/checkout/pull/822",
        )

    def test_repeat_intake_after_pr_created_is_409_no_second_pr(self):
        incident = self._seed_incident("inc-h8")
        result = self._intake("inc-h8")
        self._approve("inc-h8", result)
        executed = self._execute("inc-h8", result)
        self.assertEqual(executed["status"], "PR_CREATED")
        pr_url = self.repository.get_incident_by_id(
            "inc-h8"
        ).patch_proposals[0].pull_request_url

        from fastapi import HTTPException

        with self._no_mutation_owners() as tripwires:
            with self.assertRaises(HTTPException) as ctx:
                self._intake("inc-h8")
        self.assertEqual(ctx.exception.status_code, 409)
        self._assert_all_tripwires_clean(tripwires)

        final = self.repository.get_incident_by_id("inc-h8")
        self.assertEqual(len(final.patch_proposals), 1)
        self.assertEqual(final.patch_proposals[0].status, "PR_CREATED")
        self.assertEqual(final.patch_proposals[0].pull_request_url, pr_url)


if __name__ == "__main__":
    unittest.main()
