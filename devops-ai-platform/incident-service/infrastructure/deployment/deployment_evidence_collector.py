from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin
from urllib.request import Request, urlopen

from domain.entities.incident_evidence import IncidentEvidence


class DeploymentEvidenceCollectorError(RuntimeError):
    pass


class DeploymentEvidenceCollector:
    """Collects bounded deployment metadata for incident RCA."""

    def __init__(self, base_url: str | None = None, timeout_seconds: float = 5.0):
        self.base_url = (
            base_url
            or os.getenv("DEPLOYMENT_SERVICE_URL")
            or "http://deployment-service:8030"
        ).rstrip("/")
        if not self.base_url:
            raise ValueError("deployment service URL must not be empty")
        if timeout_seconds <= 0:
            raise ValueError("deployment timeout must be greater than zero")
        self.timeout_seconds = timeout_seconds

    def collect(self, deployment_run_id: str) -> IncidentEvidence:
        run_id = deployment_run_id.strip()
        if not run_id:
            raise ValueError("deployment_run_id must not be empty")

        url = urljoin(self.base_url + "/", f"api/internal/deployments/{run_id}")
        request = Request(url, headers={"Accept": "application/json"}, method="GET")

        try:
            with urlopen(request, timeout=self.timeout_seconds) as response:
                if response.getcode() < 200 or response.getcode() >= 300:
                    raise DeploymentEvidenceCollectorError(
                        f"deployment service returned HTTP {response.getcode()}"
                    )
                raw = response.read()
        except HTTPError as exc:
            if exc.code == 404:
                raise DeploymentEvidenceCollectorError(
                    f"deployment run {run_id} was not found"
                ) from exc
            raise DeploymentEvidenceCollectorError(
                f"deployment service request failed with status {exc.code}"
            ) from exc
        except (URLError, TimeoutError, OSError) as exc:
            raise DeploymentEvidenceCollectorError(
                "unable to reach deployment service"
            ) from exc

        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise DeploymentEvidenceCollectorError(
                "deployment service returned invalid JSON"
            ) from exc

        if not isinstance(payload, dict):
            raise DeploymentEvidenceCollectorError(
                "deployment run response must be a JSON object"
            )

        return IncidentEvidence(
            kind="deployment_run",
            source="deployment-service",
            observed_at=_parse_timestamp(payload.get("updated_at") or payload.get("created_at")),
            payload={
                "deployment_run_id": str(payload.get("id", run_id)),
                "repository_id": payload.get("repository_id"),
                "repository_name": payload.get("repository_name"),
                "state": payload.get("state"),
                "created_at": payload.get("created_at"),
                "updated_at": payload.get("updated_at"),
                "artifact_hash": payload.get("artifact_hash"),
                "plan_hash": payload.get("plan_hash"),
                "approval": {
                    "approved_by": (payload.get("approval") or {}).get("approved_by"),
                    "approved_at": (payload.get("approval") or {}).get("approved_at"),
                },
                "health_check_status": (payload.get("health_check") or {}).get("status"),
                "rollback_status": (payload.get("rollback") or {}).get("status"),
                "error": payload.get("error"),
            },
        )


def _parse_timestamp(value: Any) -> datetime:
    raw = str(value or "").strip()
    if raw:
        try:
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return datetime.now(timezone.utc)