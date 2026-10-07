import os
from functools import lru_cache

from incident_service.infrastructure.database.postgres_incident_repo import PostgresIncidentRepositoryAdapter


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


@lru_cache(maxsize=1)
def get_live_prometheus_client():
    """Singleton Prometheus client for Phase 6.5 live release verification.

    Reuses the existing monitoring scraper client and its configuration
    (endpoint default ``prometheus:9090``). Imported lazily so this
    module keeps loading in environments where only the incident package
    is present; the composed image ships the full package tree.
    """
    from monitoring_service.infrastructure.prometheus.scraper_client import (
        PrometheusScraperClient,
    )

    return PrometheusScraperClient()
