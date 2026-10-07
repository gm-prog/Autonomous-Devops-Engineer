import logging

# We declare robust stats logging fallback structures or prometheus core counters
# to remain lightweight and highly compilable across all host instances.
try:
    from prometheus_client import Counter, Histogram, Gauge
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False

logger = logging.getLogger("DevOpsMetrics")

if PROMETHEUS_AVAILABLE:
    # Counters (cumulative)
    incidents_ingested = Counter(
        'incidents_ingested_total',
        'Total incident alerts received by ingestion layers',
        ['source']  # sentry, prometheus_alert
    )

    hotfixes_generated = Counter(
        'hotfixes_generated_total',
        'AI Hotfixes computed by agent',
        ['status']  # success, validation_failed, rejected
    )

    hotfixes_applied = Counter(
        'hotfixes_applied_total',
        'Successful hotfixes applied or merged to VCS main branch',
        ['service']
    )

    # Phase 8.4.2-G.1: operational evidence substrate self-observability.
    # Bounded label vocabularies only - never per-incident or per-evidence
    # ids, which would make cardinality grow with traffic.
    evidence_ingested = Counter(
        'evidence_ingested_total',
        'Normalized operational evidence items accepted by the evidence layer',
        ['source_type', 'observation_type']
    )

    evidence_rejected = Counter(
        'evidence_rejected_total',
        'Observations rejected at the evidence boundary',
        ['source_type', 'error_code']
    )

    evidence_conflict = Counter(
        'evidence_conflict_total',
        'Contradictory observations detected during correlation',
        ['conflict_kind']
    )

    evidence_correlation = Counter(
        'evidence_correlation_total',
        'Relationships emitted by the deterministic correlation engine',
        ['rule_id']
    )

    evidence_pack_generation = Counter(
        'evidence_pack_generation_total',
        'Evidence packs generated',
        ['pack_status']
    )

    evidence_replay = Counter(
        'evidence_replay_total',
        'Evidence pack replays executed from captured input',
        ['outcome']
    )

    # Phase 6.3: operational analytics self-observability only — bounded
    # outcome vocabulary (ok | window_rejected); never per-incident labels.
    analytics_summary_requests = Counter(
        'analytics_summary_requests_total',
        'Operational analytics summary queries served by the incident service',
        ['outcome']
    )

    # Histograms
    incident_resolution_time = Histogram(
        'incident_resolution_seconds',
        'Time elapsed from inbound alert webhook to target automated deployment',
        buckets=(60, 300, 900, 1800, 3600),
        labelnames=['service']
    )

    gemini_api_latency = Histogram(
        'gemini_api_latency_ms',
        'Google Gemini REST handshake execution delay',
        buckets=(100, 500, 1000, 3000, 5000, 10000),
        labelnames=['operation']
    )

    # Gauges
    agent_active_tasks = Gauge(
        'agent_active_tasks_count',
        'Ongoing swarm tasks active inside the Celery workers queue'
    )

    gemini_monthly_spend = Gauge(
        'gemini_monthly_spend_usd',
        'Telemetry tracking current accumulated API billing rates across the enterprise'
    )
else:
    # Compile-friendly mock wrappers for environments without prometheus_client installed.
    class MockMetric:
        def __init__(self, *args, **kwargs): pass
        def labels(self, *args, **kwargs): return self
        def inc(self, *args, **kwargs): pass
        def dec(self, *args, **kwargs): pass
        def set(self, *args, **kwargs): pass
        def observe(self, *args, **kwargs): pass

    incidents_ingested = MockMetric()
    hotfixes_generated = MockMetric()
    hotfixes_applied = MockMetric()
    analytics_summary_requests = MockMetric()
    incident_resolution_time = MockMetric()
    gemini_api_latency = MockMetric()
    agent_active_tasks = MockMetric()
    gemini_monthly_spend = MockMetric()
    logger.info("Prometheus client libraries missing. Operational metrics falling back to passive logger models.")
