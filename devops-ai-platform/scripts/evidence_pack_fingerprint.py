#!/usr/bin/env python3
"""Print the pack hash of the Phase 8.4.2-G.1 §53 acceptance fixture.

Determinism has to hold *across processes*, not only inside one pytest
session: dict iteration, set ordering and string hashing are all per
process. Running this script under different ``PYTHONHASHSEED`` values and
comparing the output proves the canonical form — not the interpreter's
incidental ordering — decides the hash.

Deterministic and offline by construction: every input is a literal in
this file, and the evidence layer is stdlib-only.

    cd devops-ai-platform
    for seed in 0 1 12345; do PYTHONHASHSEED=$seed python scripts/evidence_pack_fingerprint.py; done
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared_kernel.evidence import (  # noqa: E402
    DEFAULT_POLICY,
    ObservationType,
    OperationalCorrelationEngine,
    capture_inputs,
    replay_capture,
)
from shared_kernel.evidence.adapters import (  # noqa: E402
    DeploymentEvidenceSource,
    IncidentEvidenceSource,
    MonitoringEvidenceSource,
)

#: Fixed instant. Nothing in this fixture reads the wall clock.
T0 = datetime(2026, 10, 6, 12, 0, 0, tzinfo=timezone.utc)
GENERATED_AT = T0 + timedelta(minutes=10)
SHA_A = "a" * 40
SHA_B = "b" * 40
REPOSITORY = "gm-prog/Autonomous-Devops-Engineer"


def build_fixture(include_conflict: bool = False):
    """deployment -> metric -> trace -> log -> incident, in hostile order."""
    collected = T0 + timedelta(minutes=10)
    deployment = DeploymentEvidenceSource().collect(
        deployment_id="dep-42", service_name="checkout", environment="production",
        observed_at=T0, collected_at=collected, source_sha=SHA_A,
        status="succeeded", repository=REPOSITORY,
    )[0]
    metric = MonitoringEvidenceSource().collect(
        observation_type=ObservationType.METRIC, service_name="checkout",
        environment="production", observed_at=T0 + timedelta(minutes=3),
        collected_at=collected, metric_name="avg_latency_ms", metric_value=850.0,
        metric_unit="ms", deployment_id="dep-42",
    )[0]
    trace = MonitoringEvidenceSource().collect(
        observation_type=ObservationType.TRACE, service_name="checkout",
        environment="production", observed_at=T0 + timedelta(minutes=4),
        collected_at=collected, trace_id="trace-99", deployment_id="dep-42",
    )[0]
    log = MonitoringEvidenceSource().collect(
        observation_type=ObservationType.LOG, service_name="checkout",
        environment="production", observed_at=T0 + timedelta(minutes=4, seconds=30),
        collected_at=collected, log_level="ERROR", log_message="upstream timeout",
        trace_id="trace-99",
    )[0]
    incident = IncidentEvidenceSource().collect(
        incident_id="inc-501", service_name="checkout", environment="production",
        observed_at=T0 + timedelta(minutes=5), collected_at=collected,
        title="latency regression", severity="high", trace_id="trace-99",
        deployment_id="dep-42",
    )[0]

    # the §53 hostile order, including a duplicate deployment
    items = [log, deployment, incident, trace, metric, deployment]
    if include_conflict:
        items.append(
            DeploymentEvidenceSource().collect(
                deployment_id="dep-42", service_name="checkout",
                environment="production", observed_at=T0, collected_at=collected,
                source_sha=SHA_B, status="succeeded", repository=REPOSITORY,
            )[0]
        )
    return items


def fingerprint(include_conflict: bool = False):
    items = build_fixture(include_conflict=include_conflict)
    pack = OperationalCorrelationEngine().correlate(
        incident_id="inc-501", evidence_items=items, generated_at=GENERATED_AT,
    )
    replayed = replay_capture(
        capture_inputs(
            incident_id="inc-501", evidence_items=items, policy=DEFAULT_POLICY,
            generated_at=GENERATED_AT,
        )
    )
    return {
        "evidence_pack_id": pack.evidence_pack_id,
        "pack_hash": pack.pack_hash,
        "replay_pack_hash": replayed.pack_hash,
        "replay_matches": replayed.pack_hash == pack.pack_hash,
        "item_count": len(pack.evidence_items),
        "relationship_count": len(pack.relationships),
        "pack_status": pack.summary["pack_status"],
        "evidence_ids": [item.evidence_id for item in pack.evidence_items],
        "schema_version": pack.schema_version,
        "correlation_policy_version": pack.correlation_policy_version,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--conflict", action="store_true",
        help="add the contradictory second deployment SHA",
    )
    parser.add_argument(
        "--json", action="store_true", help="emit the full fingerprint as JSON",
    )
    args = parser.parse_args(argv)

    result = fingerprint(include_conflict=args.conflict)
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(result["pack_hash"])
    return 0 if result["replay_matches"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
