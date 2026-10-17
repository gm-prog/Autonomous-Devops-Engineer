"""Deployment gRPC service implementation — honest boundary (Phase 8.8A).

This class is the gRPC-shaped seam for cross-module provisioning requests.
The forward-ported slice contains NO ``.proto`` file and no gRPC server
bootstrap, so this surface is NOT exposed over the wire in this phase; the
HTTP boundary (``deployment_service.main``, port 8030) is the real service.
When a proto contract is added, THIS implementation is the wiring:

  * the request contract is validated FIRST (typed failure, never SUCCESS);
  * a REAL dry run is created through the DeploymentEngine — source
    revision verification, IaC validation, sandboxed Terraform plan and
    Kubernetes dry run, artifact/plan hash binding — and persisted in the
    engine's store;
  * the response carries the REAL persisted run identifier and state;
  * a fabricated placeholder run ID or an unconditional success
    dispatch status is forbidden here and is asserted absent by
    tests/test_deployment_dispatch_truth.py.

A dry run is NOT a deployment: ``dispatch_status`` therefore reports
``DRY_RUN_PERSISTED`` (awaiting approval) on the success path and a typed
failure code otherwise. Execution happens only after an explicit,
hash-bound approval and is gated by DEPLOYMENT_EXECUTION_ENABLED.
"""

import logging
import re
from typing import Any, Dict, List, Optional

from deployment_service.application.services.deployment_engine import (
    DeploymentActionError,
    DeploymentEngine,
)
from deployment_service.application.services.source_verification import (
    SourceVerificationError,
)

logger = logging.getLogger("DeploymentServiceGRPCServer")

_SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
_SLUG_PATTERN = re.compile(
    r"^(?=[A-Za-z0-9_.-]*[A-Za-z0-9])[A-Za-z0-9_.-]+/"
    r"(?=[A-Za-z0-9_.-]*[A-Za-z0-9])[A-Za-z0-9_.-]+$"
)

_DEFAULT_COMPONENTS = ["dockerfile", "kubernetes", "terraform", "pipeline"]


class _GRPCDeployResponse:
    """Response-shaped object (the slice ships no generated proto stubs)."""

    def __init__(self, fields: Dict[str, Any]):
        for key, value in fields.items():
            setattr(self, key, value)
        self.pipeline_run_id = fields.get("pipeline_run_id")
        self.dispatch_status = fields.get("dispatch_status")
        self.error = fields.get("error")


def _response(status: str, run_id: Optional[str] = None, state: Optional[str] = None,
              artifact_hash: str = "", plan_hash: str = "",
              error_code: str = "", error: str = "") -> _GRPCDeployResponse:
    return _GRPCDeployResponse({
        "pipeline_run_id": run_id,
        "dispatch_status": status,
        "state": state,
        "artifact_hash": artifact_hash,
        "plan_hash": plan_hash,
        "error_code": error_code,
        "error": error,
    })


class DeploymentServiceGRPCImpl:
    """gRPC service implementation facilitating direct cross-module provisioning requests."""

    def __init__(self, engine: Optional[DeploymentEngine] = None):
        self._engine = engine or DeploymentEngine()

    @staticmethod
    def _validated_payload(request) -> Dict[str, Any]:
        repository_id = int(getattr(request, "repository_id", 0) or 0)
        repository_name = str(getattr(request, "repository_name", "") or "")
        head_sha = str(getattr(request, "head_sha", "") or "").strip().lower()
        if repository_id <= 0:
            raise ValueError("repository_id must be a positive integer")
        if not _SLUG_PATTERN.fullmatch(repository_name):
            raise ValueError(
                "repository_name must be canonical owner/repository"
            )
        if not _SHA_PATTERN.fullmatch(head_sha):
            raise ValueError("head_sha must be a 40-character lowercase hex commit")
        components = list(
            getattr(request, "components", None) or _DEFAULT_COMPONENTS
        )
        return {
            "repository_id": repository_id,
            "repository_name": repository_name,
            "requested_by": str(getattr(request, "requested_by", "") or ""),
            "dockerfile": str(getattr(request, "dockerfile", "") or ""),
            "k8s_yaml": str(getattr(request, "k8s_yaml", "") or ""),
            "terraform_tf": str(getattr(request, "terraform_tf", "") or ""),
            "pipeline_yaml": str(getattr(request, "pipeline_yaml", "") or ""),
            "source_revision": {
                "head_sha": head_sha,
                "commits": [],
                "summary": {"commit_count": 0, "files_changed": 0,
                            "additions": 0, "deletions": 0},
            },
            "components": components,
        }

    def TriggerContinuousDeployment(self, request, context) -> _GRPCDeployResponse:
        logger.info(
            "Received internal gRPC request to deploy Repo ID: %s",
            getattr(request, "repo_id", None)
            or getattr(request, "repository_id", None),
        )

        # 1) Contract validation — typed failure, never a fabricated SUCCESS.
        try:
            payload = self._validated_payload(request)
        except (TypeError, ValueError) as exc:
            return _response(
                "FAILED", error_code="INVALID_REQUEST", error=str(exc)
            )

        # 2) REAL dry run: source verification, validation, sandboxed
        #    plan/dry-run, hash binding — persisted in the engine's store.
        try:
            run = self._engine.create_dry_run(payload)
        except SourceVerificationError as exc:
            return _response(
                "FAILED",
                error_code="SOURCE_VERIFICATION_FAILED",
                error=exc.public_message,
            )
        except DeploymentActionError as exc:
            return _response(
                "FAILED", error_code="DRY_RUN_REFUSED", error=str(exc)
            )
        except Exception as exc:  # noqa: BLE001 — honest typed failure, no SUCCESS
            logger.exception("dry run failed for repository %s",
                              payload["repository_name"])
            return _response(
                "FAILED", error_code="DRY_RUN_FAILED", error=type(exc).__name__
            )

        state = run.state.value if hasattr(run.state, "value") else str(run.state)
        return _response(
            "DRY_RUN_PERSISTED",
            run_id=run.id,
            state=state,
            artifact_hash=run.artifact_hash or "",
            plan_hash=run.plan_hash or "",
        )
