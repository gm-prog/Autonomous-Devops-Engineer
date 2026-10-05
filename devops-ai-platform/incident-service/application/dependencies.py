import os
from functools import lru_cache

from infrastructure.database.postgres_incident_repo import PostgresIncidentRepositoryAdapter


@lru_cache(maxsize=1)
def get_incident_repository() -> PostgresIncidentRepositoryAdapter:
    database_url = (
        os.getenv("INCIDENT_DATABASE_URL")
        or os.getenv("DATABASE_URL")
        or ""
    )
    if not database_url.strip():
        raise RuntimeError(
            "INCIDENT_DATABASE_URL or DATABASE_URL must be configured for incident persistence"
        )

    return PostgresIncidentRepositoryAdapter(database_url)
