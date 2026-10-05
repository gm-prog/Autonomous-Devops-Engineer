import json
from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy import Column, DateTime, ForeignKey, MetaData, String, Table, Text, create_engine, delete, select, update

from domain.aggregates.incident import IncidentAggregate
from domain.entities.hotfix_proposal import HotfixProposal
from domain.entities.incident_evidence import IncidentEvidence
from domain.repository_interface import IncidentRepositoryPort


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
        return self._from_row(row, evidence)

    def get_active_incidents(self) -> List[IncidentAggregate]:
        with self.engine.connect() as connection:
            rows = connection.execute(
                select(incidents_table)
                .where(incidents_table.c.status.not_in(["Fixed", "Resolved"]))
                .order_by(incidents_table.c.created_at.desc())
            ).mappings().all()

        return [self._from_row(row, self._get_evidence(row["id"])) for row in rows]

    @staticmethod
    def _to_row(incident: IncidentAggregate) -> dict:
        proposals = [
            {
                "id": proposal.id,
                "target_filepath": proposal.target_filepath,
                "diff_patch_payload": proposal.diff_patch_payload,
                "is_verified": proposal.is_verified,
                "generated_at": proposal.generated_at.isoformat(),
            }
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
            )
            for item in proposals
        ]

        return incident


def _normalize_created_at(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value
