from datetime import datetime
from typing import List
from ..value_objects.regulatory_compliance import RegulatoryCompliance

class AuditReportAggregate:
    """
    AuditReport Aggregate Root.
    Assembles summaries of weekly deploys, alert incidents, remediation rates, 
    and verifies standard platform compliance checklists.
    """
    def __init__(self, id: str, timeframe: str):
        self.id = id
        self.timeframe = timeframe
        self.created_at = datetime.utcnow()
        self.total_deploys = 0
        self.remediation_percentage = 100.0
        self.compliance_checks: List[RegulatoryCompliance] = []

    def set_stats(self, deploys: int, remediation_rate: float):
        self.total_deploys = deploys
        self.remediation_percentage = remediation_rate

    def append_standard_badge(self, compliance: RegulatoryCompliance):
        if compliance not in self.compliance_checks:
            self.compliance_checks.append(compliance)
