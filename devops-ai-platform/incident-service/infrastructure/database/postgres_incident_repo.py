import json
from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy import Column, DateTime, MetaData, String, Table, Text, create_engine, select, update

from domain.aggregates.incident import IncidentAggregate
from domain.entities.hotfix_proposal import HotfixProposal
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

    def get_incident_by_id(self, id: str) -> Optional[IncidentAggregate]:
        with self.engine.connect() as connection:
            row = connection.execute(
                select(incidents_table).where(incidents_table.c.id == id)
            ).mappings().first()

        return self._from_row(row) if row else None

    def get_active_incidents(self) -> List[IncidentAggregate]:
        with self.engine.connect() as connection:
            rows = connection.execute(
                select(incidents_table)
                .where(incidents_table.c.status.not_in(["Fixed", "Resolved"]))
                .order_by(incidents_table.c.created_at.desc())
            ).mappings().all()

        return [self._from_row(row) for row in rows]

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

    @staticmethod
    def _from_row(row) -> IncidentAggregate:
        incident = IncidentAggregate(
            id=row["id"],
            title=row["title"],
            severity=row["severity"],
            context_details=row["context"],
        )
        incident.created_at = _normalize_created_at(row["created_at"])
        incident.status = row["status"]
        incident.domain_events = []

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
