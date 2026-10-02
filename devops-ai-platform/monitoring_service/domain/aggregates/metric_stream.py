from dataclasses import dataclass
from typing import List, Tuple
from datetime import datetime
from ..value_objects.metric_unit import MetricUnit

@dataclass
class MetricDatapoint:
    timestamp: datetime
    value: float

class MetricStreamAggregate:
    """
    MetricStream Aggregate Root.
    Tracks timeseries numerical indicators like CPU cycles, 
    memory consumption rates, and active transaction counts.
    """
    def __init__(self, service_id: str, metric_name: str, unit: MetricUnit):
        self.service_id = service_id
        self.metric_name = metric_name
        self.unit = unit
        self.datapoints: List[MetricDatapoint] = []

    def record_value(self, value: float):
        point = MetricDatapoint(timestamp=datetime.utcnow(), value=value)
        self.datapoints.append(point)
        # Limit in-memory cache to the last 120 points
        if len(self.datapoints) > 120:
            self.datapoints.pop(0)

    def current_load_average(self) -> float:
        if not self.datapoints:
            return 0.0
        tot = sum(point.value for point in self.datapoints)
        return tot / len(self.datapoints)
