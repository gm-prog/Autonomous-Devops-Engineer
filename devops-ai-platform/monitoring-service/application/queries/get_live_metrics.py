from typing import Dict, Any, List
import random
import math
from datetime import datetime

class GetLiveMetricsQuery:
    def __init__(self, target_service: str):
        self.target_service = target_service

class GetLiveMetricsQueryHandler:
    """Computes mathematical load models and metrics data to feed our dynamic front-end graphs."""
    def handle(self, q: GetLiveMetricsQuery) -> Dict[str, Any]:
        # Generate clean sine-based data representing network oscillations
        now = datetime.utcnow()
        timeline = []
        for i in range(10):
            val = 45.0 + 15.0 * math.sin(i * 0.5) + random.uniform(-2.0, 2.0)
            timeline.append({
                "index": i,
                "value": val,
                "timestamp": now.isoformat()
            })
            
        return {
            "service_id": q.target_service,
            "latency_ms": random.randint(12, 45),
            "cpu_percent": random.randint(35, 78),
            "memory_usage_mib": 512 + random.randint(-15, 20),
            "timeline_data": timeline
        }
