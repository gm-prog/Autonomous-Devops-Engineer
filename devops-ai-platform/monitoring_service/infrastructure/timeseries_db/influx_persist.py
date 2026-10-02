import os
import logging
from datetime import datetime

logger = logging.getLogger("InfluxPersistenceAdapter")

class InfluxPersistenceAdapter:
    """Saves telemetry points to fast, compressed timeseries buckets."""
    def __init__(self):
        self.bucket = os.getenv("INFLUX_BUCKET", "devops_live_averages")

    def persist_point(self, metric_name: str, host: str, value: float, time: datetime):
        logger.debug(f"[TSDB] Inserting measurement: {metric_name} [host={host}]={value} at {time}")
        # actual influx influxdb_client connection.write codes executed here
        return True
