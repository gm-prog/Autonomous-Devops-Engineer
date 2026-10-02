"""Phase 6.6.1 durable progressive-release gate state tests."""
import os,tempfile,unittest
from datetime import datetime,timedelta,timezone
from incident_service.application.services.progressive_release_gate_service import GATE_EVALUATION_TTL_SECONDS,InvalidProgressiveReleaseGateRequest,ProgressiveReleaseGateService
from incident_service.domain.aggregates.incident import IncidentAggregate
from incident_service.infrastructure.database.postgres_incident_repo import PostgresIncidentRepositoryAdapter
from incident_service.presentation.rest.test_remediation_authorization import _deployment_evidence
from monitoring_service.infrastructure.prometheus.scraper_client import RangeQueryResult,RangeSample,RangeSeries
U=timezone.utc; S=datetime(2026,9,1,tzinfo=U); E=datetime(2026,9,8,tzinfo=U)
class P:
 def __init__(self,c=.3): self.c=c
 def query_range_metric(self,t,s,e):
  v=10 if t=="request_rate" else self.c
  return RangeQueryResult(template=t,query="q",start=s.timestamp(),end=e.timestamp(),step_seconds=60,series=(RangeSeries(labels={"deployment_id":"run-state-1"},samples=tuple(RangeSample(timestamp=S.timestamp()+3600+i*600,value=v) for i in range(6))),))
class T(unittest.TestCase):
 def r(self):
  d=tempfile.TemporaryDirectory();self.addCleanup(d.cleanup);r=PostgresIncidentRepositoryAdapter(f"sqlite:///{os.path.join(d.name,'g.db')}")
  i=IncidentAggregate("i","release","HIGH","gate");i.created_at=S+timedelta(hours=1);i.status="Fixed";i.evidence.append(_deployment_evidence(run_id="run-state-1",evidence_id="e",kind_extra={"health_check_status":"PASS","source_sha":"a"*40}));r.save_incident(i);return r
 def s(self,r,n,c=.3): return ProgressiveReleaseGateService(r,P(c),now_factory=lambda:n)
 def test_round_trip(self):
  r=self.r();n=datetime(2026,9,8,12,tzinfo=U);o=self.s(r,n).evaluate("run-state-1",S,E,5);x=r.get_progressive_release_gate_evaluations("run-state-1");self.assertEqual(x[0]["evaluation_id"],o["evaluation_id"])
 def test_idempotent_bucket(self):
  r=self.r();n=datetime(2026,9,8,12,tzinfo=U);a=self.s(r,n).evaluate("run-state-1",S,E,5);b=self.s(r,n+timedelta(seconds=30)).evaluate("run-state-1",S,E,5);self.assertEqual(a["evaluation_id"],b["evaluation_id"]);self.assertEqual(len(r.get_progressive_release_gate_evaluations("run-state-1")),1)
 def test_new_bucket(self):
  r=self.r();n=datetime(2026,9,8,12,tzinfo=U);a=self.s(r,n).evaluate("run-state-1",S,E,5);b=self.s(r,n+timedelta(seconds=GATE_EVALUATION_TTL_SECONDS)).evaluate("run-state-1",S,E,5);self.assertNotEqual(a["evaluation_id"],b["evaluation_id"])
 def test_stale_history(self):
  r=self.r();n=datetime(2026,9,8,12,tzinfo=U);self.s(r,n).evaluate("run-state-1",S,E,5);h=self.s(r,n+timedelta(seconds=GATE_EVALUATION_TTL_SECONDS+1)).history("run-state-1");self.assertFalse(h["evaluations"][0]["fresh"])
 def test_failed_aborts(self):
  r=self.r();o=self.s(r,datetime(2026,9,8,12,tzinfo=U),.95).evaluate("run-state-1",S,E,5);self.assertEqual(o["gate_decision"],"ABORT")
 def test_baseline_required(self):
  with self.assertRaises(InvalidProgressiveReleaseGateRequest): self.s(self.r(),datetime(2026,9,8,tzinfo=U)).evaluate("run-state-1",S,E,25)
