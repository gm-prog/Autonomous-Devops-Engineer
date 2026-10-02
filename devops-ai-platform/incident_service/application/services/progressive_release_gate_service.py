"""Phase 6.6.1 — durable progressive-release gate analysis state."""
from __future__ import annotations
import hashlib,json
from dataclasses import dataclass
from datetime import datetime,timedelta,timezone
from typing import Any,Dict,Optional,Tuple
from incident_service.application.services.live_release_verification_service import LiveReleaseVerificationService
ALLOWED_EXPOSURE_PERCENTAGES:Tuple[int,...]=(5,25,50,100); BASELINE_REQUIRED_AFTER_PERCENT=5; GATE_POLICY_VERSION="6.6.1"; GATE_EVALUATION_TTL_SECONDS=900
class InvalidProgressiveReleaseGateRequest(ValueError): pass
@dataclass(frozen=True)
class ProgressiveReleaseGateAssessment:
    evaluation_id:str; deployment_run_id:str; source_sha:str; target_percentage:int; gate_decision:str; health_decision:str; reasons:Tuple[str,...]; live_assessment:Dict[str,Any]; baseline_deployment_run_id:Optional[str]; baseline_source_sha:Optional[str]; observed_at:datetime; expires_at:datetime; fresh:bool; reused:bool=False
    def to_dict(self): return {"evaluation_id":self.evaluation_id,"deployment_run_id":self.deployment_run_id,"source_sha":self.source_sha,"target_percentage":self.target_percentage,"gate_decision":self.gate_decision,"health_decision":self.health_decision,"reasons":list(self.reasons),"live_assessment":dict(self.live_assessment),"baseline_deployment_run_id":self.baseline_deployment_run_id,"baseline_source_sha":self.baseline_source_sha,"observed_at":self.observed_at.isoformat(),"expires_at":self.expires_at.isoformat(),"fresh":self.fresh,"reused":self.reused,"policy_version":GATE_POLICY_VERSION}
def _v_target(v):
    if not isinstance(v,int) or isinstance(v,bool) or v not in ALLOWED_EXPOSURE_PERCENTAGES: raise InvalidProgressiveReleaseGateRequest("target_percentage must be one of: 5, 25, 50, 100")
    return v
def _v_base(v):
    if v is not None and not isinstance(v,str): raise InvalidProgressiveReleaseGateRequest("baseline_deployment_run_id must be a string or null")
    return v
def _utc(v): return v.replace(tzinfo=timezone.utc) if v.tzinfo is None else v.astimezone(timezone.utc)
def _sha(v): return hashlib.sha256(v.encode()).hexdigest()
def _canon(v): return json.dumps(v,sort_keys=True,separators=(",",":"),default=str)
class ProgressiveReleaseGateService:
    def __init__(self,repository,prometheus,*,now_factory=None): self.repository=repository;self.prometheus=prometheus;self.now_factory=now_factory or (lambda:datetime.now(timezone.utc))
    @staticmethod
    def _gate_decision(h): return {"HEALTHY":"PROMOTE","DEGRADED":"PAUSE","FAILED":"ABORT","INCONCLUSIVE":"INCONCLUSIVE"}.get(h,"INCONCLUSIVE")
    def evaluate(self,deployment_run_id,start,end,target_percentage,baseline_deployment_run_id=None):
        target_percentage=_v_target(target_percentage); baseline_deployment_run_id=_v_base(baseline_deployment_run_id)
        if target_percentage>5 and not baseline_deployment_run_id: raise InvalidProgressiveReleaseGateRequest("an explicit baseline deployment is required for exposure above 5%")
        result=LiveReleaseVerificationService(self.repository,self.prometheus).verify(deployment_run_id=deployment_run_id,start=start,end=end,baseline_deployment_run_id=baseline_deployment_run_id)
        durable=result["durable_assessment"]; live=result["live_assessment"]; health=str(live.get("decision") or "INCONCLUSIVE"); gate=self._gate_decision(health); ident=dict(live.get("release_identity") or {})
        if str(ident.get("deployment_run_id") or "")!=deployment_run_id: raise InvalidProgressiveReleaseGateRequest("live evidence deployment identity does not match requested deployment")
        source_sha=str(ident.get("source_sha") or "")
        if len(source_sha)!=40: raise InvalidProgressiveReleaseGateRequest("authoritative source SHA is unavailable")
        base=live.get("baseline_identity") or {}; base_sha=str(base["source_sha"]) if base.get("source_sha") else None; now=_utc(self.now_factory())
        req=_sha(_canon({"deployment_run_id":deployment_run_id,"source_sha":source_sha,"target_percentage":target_percentage,"start":_utc(start).isoformat(),"end":_utc(end).isoformat(),"baseline_deployment_run_id":baseline_deployment_run_id,"baseline_source_sha":base_sha,"policy_version":GATE_POLICY_VERSION})); assess=_sha(_canon(live)); eid=_sha(f"{req}:{assess}:{int(now.timestamp())//GATE_EVALUATION_TTL_SECONDS}"); exp=now+timedelta(seconds=GATE_EVALUATION_TTL_SECONDS)
        record={"evaluation_id":eid,"deployment_run_id":deployment_run_id,"source_sha":source_sha,"repository_name":str(ident.get("repository_name") or ""),"target_percentage":target_percentage,"observation_start":_utc(start),"observation_end":_utc(end),"baseline_deployment_run_id":baseline_deployment_run_id,"baseline_source_sha":base_sha,"health_decision":health,"gate_decision":gate,"reasons":list(live.get("reasons") or []),"live_assessment":live,"policy_version":GATE_POLICY_VERSION,"request_fingerprint":req,"assessment_fingerprint":assess,"observed_at":now,"expires_at":exp}
        saved=self.repository.save_progressive_release_gate_evaluation(record); reused=saved["observed_at"]!=now
        out=ProgressiveReleaseGateAssessment(saved["evaluation_id"],saved["deployment_run_id"],saved["source_sha"],saved["target_percentage"],saved["gate_decision"],saved["health_decision"],tuple(saved["reasons"]),saved["live_assessment"],saved["baseline_deployment_run_id"],saved["baseline_source_sha"],saved["observed_at"],saved["expires_at"],_utc(saved["expires_at"])>now,reused).to_dict(); out["durable_assessment"]=durable; return out
    def history(self,deployment_run_id,limit=50):
        if not isinstance(deployment_run_id,str) or not deployment_run_id.strip(): raise InvalidProgressiveReleaseGateRequest("deployment_run_id must be a non-empty string")
        if not isinstance(limit,int) or isinstance(limit,bool) or not 1<=limit<=100: raise InvalidProgressiveReleaseGateRequest("limit must be an integer between 1 and 100")
        now=_utc(self.now_factory()); items=[]
        for row in self.repository.get_progressive_release_gate_evaluations(deployment_run_id,limit):
            item=dict(row); item["observed_at"]=_utc(row["observed_at"]).isoformat(); item["expires_at"]=_utc(row["expires_at"]).isoformat(); item["fresh"]=_utc(row["expires_at"])>now; items.append(item)
        return {"deployment_run_id":deployment_run_id,"count":len(items),"evaluations":items,"policy_version":GATE_POLICY_VERSION}
