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
    incident_resolution_time = MockMetric()
    gemini_api_latency = MockMetric()
    agent_active_tasks = MockMetric()
    gemini_monthly_spend = MockMetric()
    logger.info("Prometheus client libraries missing. Operational metrics falling back to passive logger models.")
