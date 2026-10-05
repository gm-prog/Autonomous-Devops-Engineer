import json
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from sqlalchemy import Column, DateTime, ForeignKey, Integer, MetaData, String, Table, Text, create_engine, delete, select, update
from sqlalchemy.exc import IntegrityError

from incident_service.domain.aggregates.incident import IncidentAggregate
from incident_service.domain.entities.hotfix_proposal import HotfixProposal
from incident_service.domain.entities.incident_evidence import IncidentEvidence
from incident_service.domain.repository_interface import IncidentRepositoryPort


metadata = MetaData()

incidents_table = Table(
    "devops_incidents",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("title", String(255), nullable=False),
    Column("severity", String(32), nullable=False),
    Column("context", Text, nullable=False),
    Column("status", String(64), nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("patch_proposals", Text, nullable=False, default="[]"),
)

evidence_table = Table(
    "devops_incident_evidence",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("incident_id", String(64), ForeignKey("devops_incidents.id"), nullable=False, index=True),
    Column("kind", String(64), nullable=False),
    Column("source", String(128), nullable=False),
    Column("observed_at", DateTime(timezone=True), nullable=False),
    Column("payload", Text, nullable=False),
)

progressive_release_gate_evaluations_table = Table(
    "devops_progressive_release_gate_evaluations",
    metadata,
    Column("evaluation_id", String(128), primary_key=True),
    Column("deployment_run_id", String(64), nullable=False, index=True),
    Column("source_sha", String(40), nullable=False),
    Column("repository_name", String(255), nullable=False),
    Column("target_percentage", Integer, nullable=False),
    Column("observation_start", DateTime(timezone=True), nullable=False),
    Column("observation_end", DateTime(timezone=True), nullable=False),
    Column("baseline_deployment_run_id", String(64)),
    Column("baseline_source_sha", String(40)),
    Column("health_decision", String(32), nullable=False),
    Column("gate_decision", String(32), nullable=False),
    Column("reasons", Text, nullable=False),
    Column("live_assessment", Text, nullable=False),
    Column("policy_version", String(32), nullable=False),
    Column("request_fingerprint", String(64), nullable=False),
    Column("assessment_fingerprint", String(64), nullable=False),
    Column("observed_at", DateTime(timezone=True), nullable=False),
    Column("expires_at", DateTime(timezone=True), nullable=False),
)

# Phase 6.6.2 — one durable rollout stage row per deployment (control
# state only; never a second source of truth for identity/artifacts/
# telemetry — it references the gate evaluation instead of copying it).
progressive_rollout_stages_table = Table(
    "devops_progressive_rollout_stages",
    metadata,
    Column("deployment_run_id", String(64), primary_key=True),
    Column("stage_state_id", String(128), nullable=False),
    Column("source_sha", String(40), nullable=False),
    Column("repository", String(255), nullable=False),
    Column("current_percentage", Integer, nullable=False),
    Column("previous_percentage", Integer, nullable=False),
    Column("state", String(32), nullable=False),
    Column("last_gate_evaluation_id", String(128), nullable=False),
    Column("last_gate_decision", String(32), nullable=False),
    Column("observation_start", DateTime(timezone=True), nullable=False),
    Column("observation_end", DateTime(timezone=True), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
)

class PostgresIncidentRepositoryAdapter(IncidentRepositoryPort):
    """Persists incident aggregates without leaking database concerns into the domain."""

    def __init__(self, database_url: str):
        if not database_url.strip():
            raise ValueError("database_url must not be empty")

        normalized_url = database_url.strip()
        if normalized_url.startswith("postgres://"):
            normalized_url = "postgresql+psycopg://" + normalized_url[len("postgres://"):]
        elif normalized_url.startswith("postgresql://"):
            normalized_url = "postgresql+psycopg://" + normalized_url[len("postgresql://"):]

        self.engine = create_engine(normalized_url, pool_pre_ping=True)
        metadata.create_all(self.engine)

    def save_incident(self, incident: IncidentAggregate) -> None:
        values = self._to_row(incident)
        with self.engine.begin() as connection:
            existing = connection.execute(
                select(incidents_table.c.id).where(incidents_table.c.id == incident.id)
            ).first()

            if existing:
                connection.execute(
                    update(incidents_table)
                    .where(incidents_table.c.id == incident.id)
                    .values(**values)
                )
            else:
                connection.execute(incidents_table.insert().values(**values))

            connection.execute(
                delete(evidence_table).where(evidence_table.c.incident_id == incident.id)
            )
            if incident.evidence:
                connection.execute(
                    evidence_table.insert(),
                    [self._evidence_row(incident.id, item) for item in incident.evidence],
                )

    def get_incident_by_id(self, id: str) -> Optional[IncidentAggregate]:
        with self.engine.connect() as connection:
            row = connection.execute(
                select(incidents_table).where(incidents_table.c.id == id)
            ).mappings().first()

        if not row:
            return None

        evidence = self._get_evidence(id)
        incident = self._from_row(row, evidence)
        self._apply_claim_overlay(incident)
        return incident

    def get_active_incidents(self) -> List[IncidentAggregate]:
        with self.engine.connect() as connection:
            rows = connection.execute(
                select(incidents_table)
                .where(incidents_table.c.status.not_in(["Fixed", "Resolved"]))
                .order_by(incidents_table.c.created_at.desc())
            ).mappings().all()

        incidents: List[IncidentAggregate] = []
        for row in rows:
            incident = self._from_row(row, self._get_evidence(row["id"]))
            # Phase 6.2.1B: list/read path projects durable claim state
            # with the SAME per-proposal mapping as get_incident_by_id()
            self._apply_claim_overlay(incident)
            incidents.append(incident)
        return incidents

    def list_incidents_in_window(
        self, start: datetime, end: datetime
    ) -> List[IncidentAggregate]:
        """Phase 6.3 analytics read: incidents with created_at in [start, end).

        Half-open interval, deterministic ordering (created_at ASC, id ASC),
        and a single bulk evidence query (ordered by incident_id, observed_at,
        id) so the aggregation over these records is reproducible: exactly
        TWO statements regardless of how many incidents match — never one
        query per incident. Read-only: no schema change, no writes,
        parameterized predicates only.

        The claim overlay is deliberately NOT applied here (unlike
        get_incident_by_id/get_active_incidents): analytics does not need
        live execution-lease/claim state, and overlaying would issue one
        execution_claims query per incident (N+1). Analytics reads the
        durable proposal JSON mirrors persisted alongside claim updates.
        Normal read semantics and claim/CAS behavior are untouched.
        """
        with self.engine.connect() as connection:
            rows = connection.execute(
                select(incidents_table)
                .where(
                    incidents_table.c.created_at >= start,
                    incidents_table.c.created_at < end,
                )
                .order_by(
                    incidents_table.c.created_at.asc(),
                    incidents_table.c.id.asc(),
                )
            ).mappings().all()

            evidence_by_incident: dict = {}
            incident_ids = [row["id"] for row in rows]
            if incident_ids:
                evidence_rows = connection.execute(
                    select(evidence_table)
                    .where(evidence_table.c.incident_id.in_(incident_ids))
                    .order_by(
                        evidence_table.c.incident_id.asc(),
                        evidence_table.c.observed_at.asc(),
                        evidence_table.c.id.asc(),
                    )
                ).mappings().all()
                for item in evidence_rows:
                    evidence_by_incident.setdefault(item["incident_id"], []).append(
                        IncidentEvidence(
                            id=item["id"],
                            kind=item["kind"],
                            source=item["source"],
                            observed_at=item["observed_at"],
                            payload=json.loads(item["payload"]),
                        )
                    )

            return [
                self._from_row(row, evidence_by_incident.get(row["id"], []))
                for row in rows
            ]

    # ------------------------------------------------------------------ #
    # Phase 6.2.1: durable execution coordination (source of truth for
    # lease ownership + persisted stage cursor; short transactions only —
    # never held across external Git/GitHub operations).
    # ------------------------------------------------------------------ #
    def claim_execution_lease(
        self,
        incident_id: str,
        proposal_id: str,
        proposal_hash: str,
        *,
        owner: str,
        now: datetime,
        lease_seconds: float,
    ) -> tuple[str, Optional[IncidentAggregate]]:
        """Atomically acquire (or reclaim an expired) execution lease.

        Returns ``(reason, incident)`` where reason is one of
        ``claimed | no_incident | proposal_missing | hash_mismatch |
        status_not_executable | lease_active | raced``. On ``claimed`` the
        returned incident reflects the EXECUTING transition written in the
        same transaction as the claim row.
        """
        from incident_service.application.services.proposal_execution_policy import (
            RESUMABLE_STAGES,
            execution_id_for,
        )

        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive")
        now = _aware_utc(now)
        expires = now + timedelta(seconds=lease_seconds)
        observed_json = None

        for _ in range(3):
            try:
                with self.engine.begin() as connection:
                    row = connection.execute(
                        select(incidents_table).where(
                            incidents_table.c.id == incident_id
                        )
                    ).mappings().first()
                    if row is None:
                        return ("no_incident", None)
                    observed_json = row["patch_proposals"]
                    incident = self._from_row(
                        row,
                        self._evidence_rows(connection, incident_id),
                    )
                    proposal = next(
                        (
                            item
                            for item in incident.patch_proposals
                            if item.id == proposal_id
                        ),
                        None,
                    )
                    if proposal is None:
                        return ("proposal_missing", None)
                    if not proposal_hash or (
                        (proposal.proposal_hash or "").strip().lower()
                        != proposal_hash.strip().lower()
                    ):
                        return ("hash_mismatch", None)
                    if proposal.status not in {
                        "APPROVED",
                        "EXECUTION_FAILED",
                        "EXECUTING",
                    }:
                        return ("status_not_executable", None)

                    claim = connection.execute(
                        select(execution_claims_table).where(
                            execution_claims_table.c.incident_id == incident_id,
                            execution_claims_table.c.proposal_id == proposal_id,
                        )
                    ).mappings().first()

                    if claim is not None:
                        state = str(claim["state"])
                        lease_expires = _aware_utc(claim["lease_expires_at"])
                        if state == "LEASED" and lease_expires and lease_expires > now:
                            return ("lease_active", None)
                        prev_attempt = int(claim["attempt"] or 0)
                        prev_stage = str(claim["stage"] or "")
                        prev_commit = claim["commit_sha"] or None
                        prev_branch = claim["branch_name"] or None
                    else:
                        prev_attempt = 0
                        prev_stage = ""
                        prev_commit = None
                        prev_branch = None

                    resume = (
                        prev_stage in RESUMABLE_STAGES
                        and bool(prev_commit)
                        and proposal.status in {"EXECUTING", "EXECUTION_FAILED"}
                    )
                    new_stage = prev_stage if resume else "CLAIMED"
                    new_attempt = prev_attempt + 1

                    proposal.status = "EXECUTING"
                    proposal.execution_attempts = new_attempt
                    proposal.execution_stage = new_stage
                    proposal.lease_owner = owner
                    proposal.lease_acquired_at = now
                    proposal.lease_expires_at = expires
                    proposal.last_heartbeat_at = now
                    proposal.last_failure_stage = ""
                    proposal.last_failure_reason = ""
                    execution_id = execution_id_for(proposal_id, proposal_hash)

                    if claim is None:
                        connection.execute(
                            execution_claims_table.insert().values(
                                incident_id=incident_id,
                                proposal_id=proposal_id,
                                proposal_hash=proposal_hash,
                                execution_id=execution_id,
                                attempt=new_attempt,
                                state="LEASED",
                                lease_owner=owner,
                                lease_acquired_at=now,
                                lease_expires_at=expires,
                                last_heartbeat_at=now,
                                stage=new_stage,
                                commit_sha=prev_commit,
                                branch_name=prev_branch,
                            )
                        )
                    else:
                        result = connection.execute(
                            update(execution_claims_table)
                            .where(
                                execution_claims_table.c.incident_id
                                == incident_id,
                                execution_claims_table.c.proposal_id
                                == proposal_id,
                                execution_claims_table.c.state
                                == str(claim["state"]),
                                execution_claims_table.c.lease_owner
                                == claim["lease_owner"],
                                execution_claims_table.c.attempt
                                == int(claim["attempt"] or 0),
                            )
                            .values(
                                proposal_hash=proposal_hash,
                                execution_id=execution_id,
                                attempt=new_attempt,
                                state="LEASED",
                                lease_owner=owner,
                                lease_acquired_at=now,
                                lease_expires_at=expires,
                                last_heartbeat_at=now,
                                completed_at=None,
                                stage=new_stage,
                                last_failure_stage=None,
                                last_failure_reason=None,
                            )
                        )
                        if result.rowcount != 1:
                            raise _CoordinationRace("claim row changed")

                    proposals_update = connection.execute(
                        update(incidents_table)
                        .where(
                            incidents_table.c.id == incident_id,
                            incidents_table.c.patch_proposals == observed_json,
                        )
                        .values(patch_proposals=self._to_row(incident)["patch_proposals"])
                    )
                    if proposals_update.rowcount != 1:
                        raise _CoordinationRace("proposals changed during claim")

                return ("claimed", self.get_incident_by_id(incident_id))
            except IntegrityError:
                # concurrent first-claim insert → re-read and re-evaluate
                continue
            except _CoordinationRace:
                continue
        return ("raced", None)

    def persist_execution_progress(
        self,
        incident_id: str,
        proposal_id: str,
        owner: str,
        *,
        stage: str,
        now: datetime,
        lease_seconds: float,
        commit_sha: Optional[str] = None,
        branch_name: Optional[str] = None,
    ) -> bool:
        """Owner-gated durable stage write + lease renewal (heartbeat)."""
        from incident_service.application.services.proposal_execution_policy import (
            validate_stage_transition,
        )

        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive")
        now = _aware_utc(now)
        with self.engine.begin() as connection:
            claim = connection.execute(
                select(execution_claims_table).where(
                    execution_claims_table.c.incident_id == incident_id,
                    execution_claims_table.c.proposal_id == proposal_id,
                )
            ).mappings().first()
            if (
                claim is None
                or str(claim["state"]) != "LEASED"
                or str(claim["lease_owner"] or "") != owner
                or not _lease_is_live(claim, now)
            ):
                # an expired lease is not authoritative even when state
                # and owner still match — never renew progress from an
                # expired owner
                return False
            validate_stage_transition(str(claim["stage"] or ""), stage)
            result = connection.execute(
                update(execution_claims_table)
                .where(
                    execution_claims_table.c.incident_id == incident_id,
                    execution_claims_table.c.proposal_id == proposal_id,
                    execution_claims_table.c.state == "LEASED",
                    execution_claims_table.c.lease_owner == owner,
                    execution_claims_table.c.lease_expires_at.isnot(None),
                    execution_claims_table.c.lease_expires_at > now,
                )
                .values(
                    stage=stage,
                    commit_sha=commit_sha
                    if commit_sha is not None
                    else claim["commit_sha"],
                    branch_name=branch_name
                    if branch_name is not None
                    else claim["branch_name"],
                    last_heartbeat_at=now,
                    lease_expires_at=now + timedelta(seconds=lease_seconds),
                )
            )
            return result.rowcount == 1

    def finish_execution_lease(
        self,
        incident_id: str,
        proposal_id: str,
        owner: str,
        *,
        status: str,
        stage: str,
        now: datetime,
        updates: Optional[dict] = None,
        evidence: Optional[IncidentEvidence] = None,
        promote_incident_pr_created: bool = False,
    ) -> bool:
        """Atomically release the lease and persist the attempt outcome
        (proposal status + claim cursor + evidence) in one transaction.

        Phase 8 §4/§28: with ``promote_incident_pr_created`` the incident
        lifecycle row advances RemediationProposed → RemediationPRCreated
        inside the SAME compare-and-set transaction as the proposal's
        PR_CREATED write — the two can never diverge, and a racing writer
        fails the CAS instead of double-writing.
        """
        from incident_service.application.services.proposal_execution_policy import (
            validate_stage_transition,
        )

        now = _aware_utc(now)
        updates = dict(updates or {})
        with self.engine.begin() as connection:
            row = connection.execute(
                select(incidents_table).where(
                    incidents_table.c.id == incident_id
                )
            ).mappings().first()
            if row is None:
                return False
            observed_json = row["patch_proposals"]
            incident = self._from_row(
                row, self._evidence_rows(connection, incident_id)
            )
            proposal = next(
                (
                    item
                    for item in incident.patch_proposals
                    if item.id == proposal_id
                ),
                None,
            )
            claim = connection.execute(
                select(execution_claims_table).where(
                    execution_claims_table.c.incident_id == incident_id,
                    execution_claims_table.c.proposal_id == proposal_id,
                )
            ).mappings().first()
            if (
                proposal is None
                or claim is None
                or str(claim["state"]) != "LEASED"
                or str(claim["lease_owner"] or "") != owner
                or not _lease_is_live(claim, now)
            ):
                # a stale (expired) owner must not write terminal state,
                # release the claim, or attach evidence
                return False
            validate_stage_transition(str(claim["stage"] or ""), stage)

            proposal.status = status
            proposal.execution_stage = stage
            proposal.lease_owner = ""
            proposal.lease_acquired_at = None
            proposal.lease_expires_at = None
            proposal.last_heartbeat_at = None
            for key in (
                "commit_sha",
                "branch_name",
                "pull_request_url",
                "last_failure_stage",
                "last_failure_reason",
                "executed_at",
            ):
                if key in updates:
                    setattr(proposal, key, updates[key])

            if promote_incident_pr_created and status == "PR_CREATED":
                # Guarded domain transition (strict in the aggregate).
                # Anything other than RemediationProposed/RemediationPRCreated
                # raises → transaction rolls back → no partial write.
                incident.mark_remediation_pr_created()

            proposals_update = connection.execute(
                update(incidents_table)
                .where(
                    incidents_table.c.id == incident_id,
                    incidents_table.c.patch_proposals == observed_json,
                )
                .values(
                    patch_proposals=self._to_row(incident)["patch_proposals"],
                    status=self._to_row(incident)["status"],
                )
            )
            if proposals_update.rowcount != 1:
                return False

            claim_values = {
                "state": "FREE",
                "lease_owner": None,
                "lease_expires_at": None,
                "last_heartbeat_at": None,
                "completed_at": now,
                "stage": stage,
                "pull_request_url": updates.get(
                    "pull_request_url", claim["pull_request_url"]
                ),
                "commit_sha": updates.get("commit_sha", claim["commit_sha"]),
                "branch_name": updates.get(
                    "branch_name", claim["branch_name"]
                ),
                "last_failure_stage": updates.get("last_failure_stage"),
                "last_failure_reason": updates.get("last_failure_reason"),
            }
            claim_update = connection.execute(
                update(execution_claims_table)
                .where(
                    execution_claims_table.c.incident_id == incident_id,
                    execution_claims_table.c.proposal_id == proposal_id,
                    execution_claims_table.c.state == "LEASED",
                    execution_claims_table.c.lease_owner == owner,
                    execution_claims_table.c.lease_expires_at.isnot(None),
                    execution_claims_table.c.lease_expires_at > now,
                )
                .values(**claim_values)
            )
            if claim_update.rowcount != 1:
                # The proposals mutation above is already staged in THIS
                # transaction. Returning normally here would commit stale
                # terminal state (status/stage/commit/branch/PR/failure)
                # after another worker replaced the lease — raise so the
                # whole transaction rolls back (stale-writer isolation;
                # not exactly-once: external effects are unchanged).
                raise _CoordinationRace(
                    "claim row changed during finish; rolling back "
                    "terminal write"
                )

            if evidence is not None:
                connection.execute(
                    delete(evidence_table).where(
                        evidence_table.c.id == evidence.id
                    )
                )
                connection.execute(
                    evidence_table.insert(),
                    [self._evidence_row(incident_id, evidence)],
                )
        return True

    def renew_execution_lease(
        self,
        incident_id: str,
        proposal_id: str,
        owner: str,
        *,
        now: datetime,
        lease_seconds: float,
    ) -> bool:
        """Owner-gated heartbeat: extend THIS lease only.

        CAS on (state == LEASED AND lease_owner == owner AND
        lease_expires_at > now): a different owner, a released claim, a
        completed/reclaimed claim, or an EXPIRED lease all return False —
        renewal never resurrects or steals a lease, never extends an
        expired owner's authority, and never changes the durable stage.
        """
        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive")
        now = _aware_utc(now)
        with self.engine.begin() as connection:
            result = connection.execute(
                update(execution_claims_table)
                .where(
                    execution_claims_table.c.incident_id == incident_id,
                    execution_claims_table.c.proposal_id == proposal_id,
                    execution_claims_table.c.state == "LEASED",
                    execution_claims_table.c.lease_owner == owner,
                    execution_claims_table.c.lease_expires_at.isnot(None),
                    execution_claims_table.c.lease_expires_at > now,
                )
                .values(
                    last_heartbeat_at=now,
                    lease_expires_at=now + timedelta(seconds=lease_seconds),
                )
            )
            return result.rowcount == 1

    def get_execution_claim(
        self, incident_id: str, proposal_id: str
    ) -> Optional[dict]:
        with self.engine.connect() as connection:
            row = connection.execute(
                select(execution_claims_table).where(
                    execution_claims_table.c.incident_id == incident_id,
                    execution_claims_table.c.proposal_id == proposal_id,
                )
            ).mappings().first()
        return dict(row) if row else None

    def get_execution_claims_for_incident(self, incident_id: str) -> List[dict]:
        """All claim rows for an incident (one per proposal, ordered)."""
        with self.engine.connect() as connection:
            rows = connection.execute(
                select(execution_claims_table)
                .where(execution_claims_table.c.incident_id == incident_id)
                .order_by(execution_claims_table.c.proposal_id.asc())
            ).mappings().all()
        return [dict(row) for row in rows]

    def save_progressive_release_gate_evaluation(self, evaluation: dict) -> dict:
        """Insert an immutable gate analysis record or return the identical row.

        The evaluation id is content/slot-derived by the application service.
        If the same id is presented with different durable evidence, fail closed
        rather than silently overwriting an audit record.
        """
        required = {
            "evaluation_id",
            "deployment_run_id",
            "source_sha",
            "repository_name",
            "target_percentage",
            "observation_start",
            "observation_end",
            "health_decision",
            "gate_decision",
            "reasons",
            "live_assessment",
            "policy_version",
            "request_fingerprint",
            "assessment_fingerprint",
            "observed_at",
            "expires_at",
        }
        missing = sorted(required.difference(evaluation))
        if missing:
            raise ValueError(
                "progressive release evaluation missing fields: "
                + ", ".join(missing)
            )

        values = {
            "evaluation_id": str(evaluation["evaluation_id"]),
            "deployment_run_id": str(evaluation["deployment_run_id"]),
            "source_sha": str(evaluation["source_sha"]).lower(),
            "repository_name": str(evaluation.get("repository_name") or ""),
            "target_percentage": int(evaluation["target_percentage"]),
            "observation_start": _aware_utc(evaluation["observation_start"]),
            "observation_end": _aware_utc(evaluation["observation_end"]),
            "baseline_deployment_run_id": (
                str(evaluation["baseline_deployment_run_id"])
                if evaluation.get("baseline_deployment_run_id") is not None
                else None
            ),
            "baseline_source_sha": (
                str(evaluation["baseline_source_sha"]).lower()
                if evaluation.get("baseline_source_sha") is not None
                else None
            ),
            "health_decision": str(evaluation["health_decision"]),
            "gate_decision": str(evaluation["gate_decision"]),
            "reasons": json.dumps(
                list(evaluation["reasons"]), separators=(",", ":")
            ),
            "live_assessment": json.dumps(
                evaluation["live_assessment"], sort_keys=True, separators=(",", ":")
            ),
            "policy_version": str(evaluation["policy_version"]),
            "request_fingerprint": str(evaluation["request_fingerprint"]),
            "assessment_fingerprint": str(evaluation["assessment_fingerprint"]),
            "observed_at": _aware_utc(evaluation["observed_at"]),
            "expires_at": _aware_utc(evaluation["expires_at"]),
        }
        immutable_keys = tuple(
            key for key in values if key not in {"observed_at", "expires_at"}
        )

        with self.engine.begin() as connection:
            existing = connection.execute(
                select(progressive_release_gate_evaluations_table).where(
                    progressive_release_gate_evaluations_table.c.evaluation_id
                    == values["evaluation_id"]
                )
            ).mappings().first()
            if existing is None:
                connection.execute(
                    progressive_release_gate_evaluations_table.insert().values(**values)
                )
                row = values
            else:
                row = dict(existing)
                for key in immutable_keys:
                    existing_value = row.get(key)
                    incoming_value = values.get(key)
                    if isinstance(existing_value, datetime) or isinstance(
                        incoming_value, datetime
                    ):
                        existing_value = _aware_utc(existing_value)
                        incoming_value = _aware_utc(incoming_value)
                    if existing_value != incoming_value:
                        raise ValueError(
                            "progressive release evaluation identity conflict"
                        )

        return self._gate_evaluation_from_row(row)

    def get_progressive_release_gate_evaluations(
        self, deployment_run_id: str, limit: int = 50
    ) -> List[dict]:
        if (
            not isinstance(limit, int)
            or isinstance(limit, bool)
            or not 1 <= limit <= 100
        ):
            raise ValueError("limit must be an integer between 1 and 100")
        with self.engine.connect() as connection:
            rows = connection.execute(
                select(progressive_release_gate_evaluations_table)
                .where(
                    progressive_release_gate_evaluations_table.c.deployment_run_id
                    == deployment_run_id
                )
                .order_by(
                    progressive_release_gate_evaluations_table.c.observed_at.desc(),
                    progressive_release_gate_evaluations_table.c.evaluation_id.desc(),
                )
                .limit(limit)
            ).mappings().all()
        return [self._gate_evaluation_from_row(dict(row)) for row in rows]

    def get_progressive_release_gate_evaluation(
        self, evaluation_id: str
    ) -> Optional[dict]:
        """Bounded single-row lookup of the exact presented evaluation."""
        if not isinstance(evaluation_id, str) or not evaluation_id.strip():
            return None
        with self.engine.connect() as connection:
            row = connection.execute(
                select(progressive_release_gate_evaluations_table).where(
                    progressive_release_gate_evaluations_table.c.evaluation_id
                    == evaluation_id
                )
            ).mappings().first()
        return self._gate_evaluation_from_row(dict(row)) if row else None

    # ------------------------------------------------------------ rollout stage

    @staticmethod
    def _rollout_stage_from_row(row: dict) -> dict:
        return {
            "stage_state_id": str(row["stage_state_id"]),
            "deployment_run_id": str(row["deployment_run_id"]),
            "source_sha": str(row["source_sha"]),
            "repository": str(row.get("repository") or ""),
            "current_percentage": int(row["current_percentage"]),
            "previous_percentage": int(row["previous_percentage"]),
            "state": str(row["state"]),
            "last_gate_evaluation_id": str(row["last_gate_evaluation_id"]),
            "last_gate_decision": str(row["last_gate_decision"]),
            "observation_start": _aware_utc(row["observation_start"]),
            "observation_end": _aware_utc(row["observation_end"]),
            "updated_at": _aware_utc(row["updated_at"]),
        }

    @staticmethod
    def _rollout_stage_values(stage: dict) -> dict:
        required = {
            "stage_state_id",
            "deployment_run_id",
            "source_sha",
            "repository",
            "current_percentage",
            "previous_percentage",
            "state",
            "last_gate_evaluation_id",
            "last_gate_decision",
            "observation_start",
            "observation_end",
            "updated_at",
        }
        missing = sorted(required.difference(stage))
        if missing:
            raise ValueError(
                "progressive rollout stage missing fields: " + ", ".join(missing)
            )
        return {
            "stage_state_id": str(stage["stage_state_id"]),
            "deployment_run_id": str(stage["deployment_run_id"]),
            "source_sha": str(stage["source_sha"]).lower(),
            "repository": str(stage.get("repository") or ""),
            "current_percentage": int(stage["current_percentage"]),
            "previous_percentage": int(stage["previous_percentage"]),
            "state": str(stage["state"]),
            "last_gate_evaluation_id": str(stage["last_gate_evaluation_id"]),
            "last_gate_decision": str(stage["last_gate_decision"]),
            "observation_start": _aware_utc(stage["observation_start"]),
            "observation_end": _aware_utc(stage["observation_end"]),
            "updated_at": _aware_utc(stage["updated_at"]),
        }

    def get_progressive_rollout_stage(
        self, deployment_run_id: str
    ) -> Optional[dict]:
        """Bounded durable lookup; no inference when state is missing."""
        if not isinstance(deployment_run_id, str) or not deployment_run_id.strip():
            return None
        with self.engine.connect() as connection:
            row = connection.execute(
                select(progressive_rollout_stages_table).where(
                    progressive_rollout_stages_table.c.deployment_run_id
                    == deployment_run_id
                )
            ).mappings().first()
        return self._rollout_stage_from_row(dict(row)) if row else None

    def insert_progressive_rollout_stage(self, stage: dict) -> dict:
        """Atomic create of the single durable stage row (CAS bootstrap).

        Raises ``ValueError`` when the row already exists — the caller
        decides whether that converges as an idempotent replay or a
        conflict; nothing is ever silently overwritten.
        """
        values = self._rollout_stage_values(stage)
        with self.engine.begin() as connection:
            existing = connection.execute(
                select(progressive_rollout_stages_table).where(
                    progressive_rollout_stages_table.c.deployment_run_id
                    == values["deployment_run_id"]
                )
            ).mappings().first()
            if existing is not None:
                raise ValueError("progressive rollout stage already exists")
            connection.execute(
                progressive_rollout_stages_table.insert().values(**values)
            )
        return self._rollout_stage_from_row(values)

    def update_progressive_rollout_stage(
        self,
        deployment_run_id: str,
        *,
        expected_current_percentage: int,
        expected_state: str,
        changes: dict,
    ) -> Optional[dict]:
        """Atomic compare-and-set transition of the durable stage.

        The UPDATE is conditioned on the exact percentage and state the
        caller validated against; a miss returns ``None`` (no row was
        touched) so two racing workers deterministically converge: one
        wins, the other replays or fails closed. Single short
        transaction; no external locks.
        """
        allowed_changes = {
            "state",
            "current_percentage",
            "previous_percentage",
            "last_gate_evaluation_id",
            "last_gate_decision",
            "observation_start",
            "observation_end",
            "updated_at",
        }
        missing = sorted(set(changes).difference(allowed_changes))
        if missing:
            raise ValueError(
                "progressive rollout stage change has unsupported fields: "
                + ", ".join(missing)
            )
        values = {key: value for key, value in changes.items()}
        for key in ("observation_start", "observation_end", "updated_at"):
            if key in values:
                values[key] = _aware_utc(values[key])
        with self.engine.begin() as connection:
            result = connection.execute(
                progressive_rollout_stages_table.update()
                .where(
                    progressive_rollout_stages_table.c.deployment_run_id
                    == deployment_run_id,
                    progressive_rollout_stages_table.c.current_percentage
                    == int(expected_current_percentage),
                    progressive_rollout_stages_table.c.state == expected_state,
                )
                .values(**values)
            )
            if result.rowcount != 1:
                return None
            row = connection.execute(
                select(progressive_rollout_stages_table).where(
                    progressive_rollout_stages_table.c.deployment_run_id
                    == deployment_run_id
                )
            ).mappings().first()
        return self._rollout_stage_from_row(dict(row))

    @staticmethod
    def _gate_evaluation_from_row(row: dict) -> dict:
        return {
            "evaluation_id": str(row["evaluation_id"]),
            "deployment_run_id": str(row["deployment_run_id"]),
            "source_sha": str(row["source_sha"]),
            "repository_name": str(row.get("repository_name") or ""),
            "target_percentage": int(row["target_percentage"]),
            "observation_start": _aware_utc(row["observation_start"]),
            "observation_end": _aware_utc(row["observation_end"]),
            "baseline_deployment_run_id": row.get("baseline_deployment_run_id"),
            "baseline_source_sha": row.get("baseline_source_sha"),
            "health_decision": str(row["health_decision"]),
            "gate_decision": str(row["gate_decision"]),
            "reasons": list(json.loads(row["reasons"] or "[]")),
            "live_assessment": json.loads(row["live_assessment"] or "{}"),
            "policy_version": str(row["policy_version"]),
            "request_fingerprint": str(row["request_fingerprint"]),
            "assessment_fingerprint": str(row["assessment_fingerprint"]),
            "observed_at": _aware_utc(row["observed_at"]),
            "expires_at": _aware_utc(row["expires_at"]),
        }

    def _apply_claim_overlay(self, incident) -> None:
        """Project authoritative claim-row state onto each proposal view.

        The claim primary key is (incident_id, proposal_id): an incident
        may carry several independent proposal claims, so every row for
        the incident is fetched and mapped BY PROPOSAL ID — a proposal
        never inherits another proposal's coordination state, and a
        proposal without a claim row keeps its persisted JSON view.
        """
        if not incident.patch_proposals:
            return
        with self.engine.connect() as connection:
            rows = connection.execute(
                select(execution_claims_table).where(
                    execution_claims_table.c.incident_id == incident.id
                )
            ).mappings().all()
        if not rows:
            return
        claims_by_proposal = {str(row["proposal_id"]): row for row in rows}
        for proposal in incident.patch_proposals:
            row = claims_by_proposal.get(proposal.id)
            if row is None:
                continue
            proposal.execution_stage = str(row["stage"] or "")
            proposal.execution_attempts = int(row["attempt"] or 0)
            proposal.execution_id = str(row["execution_id"] or "")
            proposal.lease_owner = str(row["lease_owner"] or "")
            proposal.lease_acquired_at = _aware_utc(row["lease_acquired_at"])
            proposal.lease_expires_at = _aware_utc(row["lease_expires_at"])
            proposal.last_heartbeat_at = _aware_utc(row["last_heartbeat_at"])
            # claim row is authoritative for the durable remote identity
            if row["commit_sha"]:
                proposal.commit_sha = str(row["commit_sha"])
            if row["branch_name"]:
                proposal.branch_name = str(row["branch_name"])
            if row["pull_request_url"]:
                proposal.pull_request_url = str(row["pull_request_url"])

    @staticmethod
    def _evidence_rows(connection, incident_id: str) -> List[IncidentEvidence]:
        rows = connection.execute(
            select(evidence_table)
            .where(evidence_table.c.incident_id == incident_id)
            .order_by(evidence_table.c.observed_at.asc(), evidence_table.c.id.asc())
        ).mappings().all()
        return [
            IncidentEvidence(
                id=item["id"],
                kind=item["kind"],
                source=item["source"],
                observed_at=item["observed_at"],
                payload=json.loads(item["payload"]),
            )
            for item in rows
        ]

    @staticmethod
    def _to_row(incident: IncidentAggregate) -> dict:
        # to_dict() carries every §12 field (incident_id, repository,
        # evidence_refs, validation_plan, risk_class, proposal_hash,
        # status, blocked_reason) — all survive reload (§19).
        proposals = [
            proposal.to_dict()
            for proposal in incident.patch_proposals
        ]

        return {
            "id": incident.id,
            "title": incident.title,
            "severity": incident.severity,
            "context": incident.context,
            "status": incident.status,
            "created_at": incident.created_at,
            "patch_proposals": json.dumps(proposals),
        }

    def _get_evidence(self, incident_id: str) -> List[IncidentEvidence]:
        with self.engine.connect() as connection:
            rows = connection.execute(
                select(evidence_table)
                .where(evidence_table.c.incident_id == incident_id)
                .order_by(evidence_table.c.observed_at.asc(), evidence_table.c.id.asc())
            ).mappings().all()

        return [
            IncidentEvidence(
                id=item["id"],
                kind=item["kind"],
                source=item["source"],
                observed_at=_normalize_created_at(item["observed_at"]),
                payload=json.loads(item["payload"] or "{}"),
            )
            for item in rows
        ]

    @staticmethod
    def _evidence_row(incident_id: str, evidence: IncidentEvidence) -> dict:
        return {
            "id": evidence.id,
            "incident_id": incident_id,
            "kind": evidence.kind,
            "source": evidence.source,
            "observed_at": evidence.observed_at,
            "payload": json.dumps(dict(evidence.payload)),
        }

    def _from_row(self, row, evidence: Optional[List[IncidentEvidence]] = None) -> IncidentAggregate:
        incident = IncidentAggregate(
            id=row["id"],
            title=row["title"],
            severity=row["severity"],
            context_details=row["context"],
        )
        incident.created_at = _normalize_created_at(row["created_at"])
        incident.status = row["status"]
        incident.domain_events = []
        incident.evidence = list(evidence or [])

        proposals = json.loads(row["patch_proposals"] or "[]")
        incident.patch_proposals = [
            HotfixProposal(
                id=item["id"],
                target_filepath=item["target_filepath"],
                diff_patch_payload=item["diff_patch_payload"],
                is_verified=bool(item.get("is_verified", False)),
                generated_at=datetime.fromisoformat(item["generated_at"]),
                pull_request_url=item.get("pull_request_url"),
                source_sha=item.get("source_sha"),
                # Phase 6.1 fields (missing on legacy rows → defaults)
                incident_id=str(item.get("incident_id") or ""),
                repository=str(item.get("repository") or ""),
                evidence_refs=[
                    str(ref) for ref in item.get("evidence_refs") or []
                ],
                validation_plan=[
                    str(step) for step in item.get("validation_plan") or []
                ],
                risk_class=str(item.get("risk_class") or "UNSPECIFIED"),
                proposal_hash=str(item.get("proposal_hash") or ""),
                status=str(item.get("status") or "PROPOSED"),
                blocked_reason=str(item.get("blocked_reason") or ""),
                # Phase 6.2 lifecycle (missing on older rows → defaults)
                approved_by=str(item.get("approved_by") or ""),
                approved_at=_parse_optional_datetime(item.get("approved_at")),
                approval_hash=str(item.get("approval_hash") or ""),
                execution_id=str(item.get("execution_id") or ""),
                executed_at=_parse_optional_datetime(item.get("executed_at")),
                commit_sha=str(item.get("commit_sha") or ""),
                branch_name=str(item.get("branch_name") or ""),
                execution_attempts=int(item.get("execution_attempts") or 0),
                last_failure_stage=str(item.get("last_failure_stage") or ""),
                last_failure_reason=str(item.get("last_failure_reason") or ""),
            )
            for item in proposals
        ]

        return incident


def _parse_optional_datetime(value):
    if isinstance(value, str) and value:
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            return None
    return None


def _normalize_created_at(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


# ---------------------------------------------------------------------- #
# Phase 6.2.1: durable execution claims (lease + persisted stage cursor)
# ---------------------------------------------------------------------- #
# One row per (incident, proposal). This table is the AUTHORITATIVE home of
# execution ownership and stage progress; save_incident() never touches it,
# so unrelated aggregate writes can never clobber a live lease. Proposal
# lifecycle (status/attempt mirrors) is updated in the SAME transaction as
# the claim/finish CAS so JSON and claim row never diverge within a
# completed transaction.
execution_claims_table = Table(
    "devops_execution_claims",
    metadata,
    Column("incident_id", String(64), primary_key=True),
    Column("proposal_id", String(200), primary_key=True),
    Column("proposal_hash", String(64), nullable=False),
    Column("execution_id", String(64), nullable=False),
    Column("attempt", Integer, nullable=False, default=0),
    Column("state", String(16), nullable=False, default="FREE"),
    Column("lease_owner", String(160)),
    Column("lease_acquired_at", DateTime(timezone=True)),
    Column("lease_expires_at", DateTime(timezone=True)),
    Column("last_heartbeat_at", DateTime(timezone=True)),
    Column("completed_at", DateTime(timezone=True)),
    Column("stage", String(32), nullable=False, default=""),
    Column("commit_sha", String(40)),
    Column("branch_name", String(255)),
    Column("pull_request_url", Text),
    Column("last_failure_stage", String(32)),
    Column("last_failure_reason", Text),
)


class _CoordinationRace(Exception):
    """Concurrent writer changed coordination state between read and CAS."""


def _lease_is_live(claim_row, now: datetime) -> bool:
    """A lease is authoritative only while expiry is present and strictly
    after `now` (state/owner are checked separately by callers).
    Expired-but-LEASED is NOT live."""
    expires = claim_row["lease_expires_at"]
    if expires is None:
        return False
    return _aware_utc(expires) > _aware_utc(now)


def _aware_utc(value):
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value
