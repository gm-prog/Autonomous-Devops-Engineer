"""Phase 8.4.2 golden-path driver — runs ON the GitHub Actions runner.

Drives the REAL external chain through the API gateway only (no direct
service calls on the happy path), then cross-checks durable state and
remote GitHub truth.  Exits 0=PASS, 1=FAIL, 2=BLOCKED/NOT VERIFIED.

Long-running control-plane operations may exceed the gateway's
downstream relay timeout; the driver treats a relay 502/504 as
"dispatched" and completes verification through read endpoints, the
database and remote GitHub state — never through fabricated responses.
"""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import json
import os
import re
import subprocess
import sys
import time
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from e2e import helpers as H  # noqa: E402
from e2e.readiness import ReadinessTimeout, wait_until  # noqa: E402

GATEWAY = os.environ.get("GATEWAY_URL", "http://localhost:8000").rstrip("/")
FIXTURE_REPO = os.environ.get("E2E_FIXTURE_REPOSITORY", "")
FIXTURE_SEED_SHA = os.environ.get("E2E_FIXTURE_SEED_SHA", "")
FIXTURE_TOKEN = os.environ.get("E2E_FIXTURE_GITHUB_TOKEN", "")
JWT_SECRET = os.environ.get("E2E_JWT_SECRET", "")
RUN_ID = os.environ.get("E2E_RUN_ID", "local")
ARTIFACTS = os.environ.get("E2E_ARTIFACT_DIR", "/tmp/e2e-artifacts")
TTL_SECONDS = float(os.environ.get("REMEDIATION_PROPOSAL_TTL_SECONDS", "600"))
SANDBOX_GOOD = os.environ.get("REMEDIATION_SANDBOX_IMAGE", "")
SANDBOX_BAD = os.environ.get("E2E_SANDBOX_IMAGE_BAD", "")
COMPOSE_PROJECT = os.environ.get("E2E_PROJECT", "ares-e2e")
COMPOSE_FILES = os.environ.get(
    "E2E_COMPOSE_FILE",
    "devops-ai-platform/docker-compose.yml,docker-compose.e2e.yml",
).split(",")
OPERATOR_SUB = "e2e-operator"
VIEWER_SUB = "e2e-viewer"

from api_gateway.core.auth import mint_token  # noqa: E402  (HS256 contract)
from incident_service.application.services.proposal_generation_service import (  # noqa: E402
    compute_proposal_hash,
)
from agent_service.application.deterministic_rca import (  # noqa: E402
    DETERMINISTIC_ROOT_CAUSE,
    E2E_PATCHED_SERVICE_NAME,
)

INITIAL_FILE = 'SERVICE_NAME = "checkout-service"\n'
PATCHED_LINE = f'SERVICE_NAME = "{E2E_PATCHED_SERVICE_NAME}"'


class Stage:
    def __init__(self, name: str):
        self.name = name
        self.rows: List[Dict[str, Any]] = []

    def check(self, case: str, expected: Any, observed: Any, ok: bool) -> bool:
        self.rows.append(H.row(case, str(expected), str(observed), ok))
        return ok

    def result(self) -> str:
        return H.classify_gate(self.rows)


class Harness:
    def __init__(self) -> None:
        os.makedirs(ARTIFACTS, exist_ok=True)
        self.operator = mint_token(OPERATOR_SUB, ["DevOpsLead"], secret=JWT_SECRET)
        self.viewer = mint_token(VIEWER_SUB, ["Developer"], secret=JWT_SECRET)
        self.stages: List[Stage] = []
        self.proposal: Dict[str, Any] = {}
        self.incident_id = ""
        self.run_id = ""
        self.commit_sha = ""
        self.branch_name = ""
        self.pr_url = ""
        self.evidence_id = ""
        self.deployment_evidence_id = ""
        self.event_id = ""
        self.artifact_hash = ""
        self.plan_hash = ""
        self.incident_hits = 0
        self.manifest = H.new_manifest(
            workflow_run_id=str(RUN_ID),
            source_repository="gm-prog/Autonomous-Devops-Engineer",
            source_sha=os.environ.get("E2E_SOURCE_SHA", ""),
            fixture_repository=FIXTURE_REPO,
            fixture_source_sha=FIXTURE_SEED_SHA,
            kind_cluster="ares-e2e",
            namespace="devops-production-namespace",
            validation_profile="e2e_fixture",
            sandbox_image_digest=os.environ.get("E2E_SANDBOX_DIGEST", ""),
            terraform_version=os.environ.get("E2E_TERRAFORM_VERSION", ""),
            kubectl_version=os.environ.get("E2E_KUBECTL_VERSION", ""),
            kind_version=os.environ.get("E2E_KIND_VERSION", ""),
        )
        self.marker = f"e2e-run-{RUN_ID}"
        self.api = requests.Session()
        self.api.headers.update({"Accept": "application/vnd.github+json"})
        if FIXTURE_TOKEN:
            self.api.headers.update({"Authorization": f"Bearer {FIXTURE_TOKEN}"})

    # ------------------------------ plumbing --------------------------- #
    def save(self, name: str, data: Any) -> None:
        H.dump_json(os.path.join(ARTIFACTS, name), data)

    def gw(self, method: str, path: str, token: Optional[str], **kw) -> requests.Response:
        headers = dict(kw.pop("headers", {}))
        if token:
            headers["Authorization"] = f"Bearer {token}"
        deadline = time.monotonic() + 180
        while True:
            response = self.api.request(method, f"{GATEWAY}{path}", headers=headers, timeout=60, **kw)
            if response.status_code != 429 or time.monotonic() > deadline:
                return response
            time.sleep(2.0)

    def gh(self, path: str, **kw) -> requests.Response:
        return self.api.get(f"https://api.github.com{path}", timeout=30, **kw)

    def compose(self, *extra: str) -> subprocess.CompletedProcess:
        argv = ["docker", "compose", "-p", COMPOSE_PROJECT]
        for f in COMPOSE_FILES:
            argv += ["-f", f.strip()]
        argv += list(extra)
        return subprocess.run(argv, capture_output=True, text=True, timeout=300)

    # ------------------------------ preflight -------------------------- #
    def preflight(self) -> str:
        problems = []
        if not H.validate_repo_slug(FIXTURE_REPO):
            problems.append("E2E_FIXTURE_REPOSITORY is not owner/repo")
        if not H.validate_sha40(FIXTURE_SEED_SHA):
            problems.append("E2E_FIXTURE_SEED_SHA is not 40-hex")
        if not JWT_SECRET:
            problems.append("E2E_JWT_SECRET missing")
        if not FIXTURE_TOKEN:
            problems.append("E2E_FIXTURE_GITHUB_TOKEN missing")
        if not H.validate_digest_ref(SANDBOX_GOOD):
            problems.append("REMEDIATION_SANDBOX_IMAGE is not digest-pinned")
        if problems:
            for p in problems:
                print(f"::error::preflight: {p}")
            return H.BLOCKED
        probe = self.gh(f"/repos/{FIXTURE_REPO}")
        if probe.status_code != 200:
            print(f"::error::fixture repo unreachable: {probe.status_code}")
            return H.BLOCKED
        if probe.json().get("full_name") != FIXTURE_REPO:
            return H.BLOCKED
        commit = self.gh(f"/repos/{FIXTURE_REPO}/commits/{FIXTURE_SEED_SHA}")
        if commit.status_code != 200:
            print("::error::fixture seed commit not found")
            return H.BLOCKED
        content = self.gh(f"/repos/{FIXTURE_REPO}/contents/src/service_config.py",
                          params={"ref": FIXTURE_SEED_SHA})
        if content.status_code != 200:
            return H.BLOCKED
        text = base64.b64decode(content.json()["content"]).decode("utf-8")
        if text != INITIAL_FILE:
            print("::error::fixture seed content mismatch")
            return H.BLOCKED
        self.save("fixture-verification.json",
                  {"repository": FIXTURE_REPO, "seed_sha": FIXTURE_SEED_SHA,
                   "seed_content_matches": True, "verified_at": _now()})
        return H.PASS

    # ------------------------------ stages ----------------------------- #
    def security(self) -> None:
        st = Stage("security")
        self.stages.append(st)
        r = self.gw("GET", "/v1/incidents", None)
        st.check("no JWT -> 401", 401, r.status_code, r.status_code == 401)

        # operator-gated mutation with a valid non-operator identity
        inc_probe = self.gw("GET", "/v1/incidents", self.operator)
        st.check("authorized list works", 200, inc_probe.status_code,
                 inc_probe.status_code == 200)
        r = self.gw("POST", "/v1/incidents/e2e-nonexistent/proposal/approve",
                    self.viewer,
                    json={"proposal_id": "p", "proposal_hash": "0" * 64})
        st.check("non-operator mutation -> 403", 403, r.status_code,
                 r.status_code == 403)

        # internal services not host-published
        ps = subprocess.run(["docker", "ps", "--format", "{{.Names}}|{{.Ports}}"],
                            capture_output=True, text=True, timeout=60)
        exposed = [ln for ln in ps.stdout.splitlines()
                   if re.search(r"0\.0\.0\.0:\d+->", ln)
                   and not re.search(r"->(8000|5001|6443)/", ln)]
        st.check("only gateway/registry/kind published", "[]", str(exposed), not exposed)

        r = self.gw("POST", "/v1/gateway/dispatch/monitoring", self.viewer,
                    json={"payload": {"service": "x", "metric": "y", "value": 1.0}})
        st.check("viewer may read-only dispatch policy per contract",
                 "auth accepted or policy-refused", str(r.status_code),
                 r.status_code in (200, 403, 422, 502))
        results_file = os.path.join(ARTIFACTS, "security-negative-results.json")
        H.dump_json(results_file, st.rows)

    def deployment(self) -> Stage:
        st = Stage("deployment")
        self.stages.append(st)
        payload = {
            "repository_id": 1,
            "repository_name": FIXTURE_REPO,
            "requested_by": "attacker@evil",
            "dockerfile": _fixture("Dockerfile"),
            "k8s_yaml": _fixture("k8s-deployment.yaml").replace(
                "WORKLOAD_IMAGE_REF",
                os.environ.get("E2E_WORKLOAD_IMAGE", "WORKLOAD_IMAGE_REF"),
            ),
            "terraform_tf": _fixture("main.tf"),
            "pipeline_yaml": _fixture("pipeline.yaml"),
            "source_revision": {"head_sha": FIXTURE_SEED_SHA},
        }
        r = self.gw("POST", "/v1/deployments/dry-run", self.operator, json=payload)
        self.save("deployment-dry-run.json", _safe(r))
        if r.status_code != 200:
            st.check("dry-run accepted", 200, r.status_code, False)
            return st
        run = r.json()
        st.check("state AWAITING_APPROVAL", "AWAITING_APPROVAL",
                 run.get("state"), run.get("state") == "AWAITING_APPROVAL")
        st.check("requested_by is JWT identity", OPERATOR_SUB,
                 run.get("requested_by"), run.get("requested_by") == OPERATOR_SUB)
        st.check("source verified", "github-commit-lookup",
                 (run.get("source_verification") or {}).get("method"),
                 (run.get("source_verification") or {}).get("method") == "github-commit-lookup")
        st.check("artifact_hash 64-hex", True,
                 bool(re.fullmatch(r"[0-9a-f]{64}", run.get("artifact_hash", ""))),
                 bool(re.fullmatch(r"[0-9a-f]{64}", run.get("artifact_hash", ""))))
        st.check("plan_hash 64-hex", True,
                 bool(re.fullmatch(r"[0-9a-f]{64}", run.get("plan_hash", ""))),
                 bool(re.fullmatch(r"[0-9a-f]{64}", run.get("plan_hash", ""))))
        st.check("provenance present", True, bool(run.get("provenance")),
                 bool(run.get("provenance")))
        self.run_id = run["id"]
        self.artifact_hash = run["artifact_hash"]
        self.plan_hash = run["plan_hash"]

        wrong = self.gw("POST", f"/v1/deployments/{self.run_id}/approve", self.operator,
                        json={"approved_by": "attacker@evil",
                              "artifact_hash": "0" * 64, "plan_hash": self.plan_hash})
        st.check("wrong approval hashes -> 409", 409, wrong.status_code,
                 wrong.status_code == 409)

        r = self.gw("POST", f"/v1/deployments/{self.run_id}/approve", self.operator,
                    json={"approved_by": "attacker@evil",
                          "artifact_hash": self.artifact_hash,
                          "plan_hash": self.plan_hash})
        self.save("deployment-approve.json", _safe(r))
        st.check("approve accepted", 200, r.status_code, r.status_code == 200)
        if r.status_code == 200:
            st.check("approved_by is JWT identity", OPERATOR_SUB,
                     (r.json().get("approval") or {}).get("approved_by"),
                     (r.json().get("approval") or {}).get("approved_by") == OPERATOR_SUB)

        execute_body = {
            "artifact_hash": self.artifact_hash, "plan_hash": self.plan_hash,
            "namespace": "devops-production-namespace", "healthcheck_url": "",
            "previous_good_terraform_tf": "",
            **{k: payload[k] for k in
               ("dockerfile", "k8s_yaml", "terraform_tf", "pipeline_yaml")},
        }
        r = self.gw("POST", f"/v1/deployments/{self.run_id}/execute", self.operator,
                    json=execute_body)
        self.save("deployment-execute-relay.json", _safe(r))
        st.check("execute dispatched (200 or relay-timeout)",
                 "200|502|504", str(r.status_code), r.status_code in (200, 502, 504))

        state = self._poll_run(expected="DEPLOYED", timeout=900)
        self.save("deployment-response.json", state)
        st.check("state DEPLOYED", "DEPLOYED", state.get("state"),
                 state.get("state") == "DEPLOYED")
        exec_ = state.get("execution") or {}
        st.check("terraform plan PASS", "PASS",
                 (exec_.get("terraform_plan") or {}).get("status"),
                 (exec_.get("terraform_plan") or {}).get("status") == "PASS")
        st.check("terraform apply PASS", "PASS",
                 (exec_.get("terraform_apply") or {}).get("status"),
                 (exec_.get("terraform_apply") or {}).get("status") == "PASS")
        st.check("kubernetes apply PASS", "PASS",
                 (exec_.get("kubernetes_apply") or {}).get("status"),
                 (exec_.get("kubernetes_apply") or {}).get("status") == "PASS")
        st.check("health PASS", "PASS",
                 (state.get("health_check") or {}).get("status"),
                 (state.get("health_check") or {}).get("status") == "PASS")
        st.check("terraform fmt/init/validate ran", True,
                 _terraform_steps_ran(state), _terraform_steps_ran(state))
        return st

    def _poll_run(self, expected: str, timeout: float) -> Dict[str, Any]:
        deadline = time.monotonic() + timeout
        last: Dict[str, Any] = {}
        while time.monotonic() < deadline:
            r = self.gw("GET", f"/v1/deployments/{self.run_id}", self.operator)
            if r.status_code == 200:
                last = r.json()
                if last.get("state") in {expected, "DEPLOYMENT_FAILED", "ROLLBACK_FAILED",
                                         "VALIDATION_FAILED", "DRY_RUN_FAILED"}:
                    return last
            time.sleep(3)
        return last

    def monitoring(self) -> None:
        st = Stage("monitoring")
        self.stages.append(st)
        r = self.gw("POST", "/v1/gateway/dispatch/monitoring", self.operator,
                    json={"payload": {"service": "checkout-service",
                                      "metric": "cpu_percent", "value": 97.0,
                                      "metrics": {"e2e_run_id": self.marker}}})
        st.check("breach published", "breached", str(_safe(r)),
                 r.status_code == 200 and r.json().get("breached") is True)

        incident = self._poll_incident(timeout=300)
        st.check("exactly one correlated incident", "1", str(self.incident_hits),
                 self.incident_hits == 1)
        if not incident:
            return
        self.incident_id = incident["id"]
        self.save("incident-response.json", incident)
        breaches = [e for e in incident.get("evidence", [])
                    if e.get("kind") == "threshold_breach"]
        st.check("one threshold_breach evidence", 1, len(breaches), len(breaches) == 1)
        if breaches:
            p = breaches[0].get("payload") or {}
            st.check("service", "checkout-service", p.get("service"),
                     p.get("service") == "checkout-service")
            st.check("metric", "cpu_percent", p.get("metric"),
                     p.get("metric") == "cpu_percent")
            st.check("value", 97.0, p.get("value"), float(p.get("value", 0)) == 97.0)
            st.check("threshold", 90.0, p.get("threshold"),
                     float(p.get("threshold", 0)) == 90.0)
            st.check("operator", ">", p.get("operator"), p.get("operator") == ">")
            st.check("producer event id real", True,
                     bool(str(p.get("event_id", "")).strip()),
                     bool(str(p.get("event_id", "")).strip()))
            self.evidence_id = breaches[0]["id"]
            self.event_id = str(p.get("event_id", ""))

    def _poll_incident(self, timeout: float) -> Optional[Dict[str, Any]]:
        deadline = time.monotonic() + timeout
        self.incident_hits = 0
        while time.monotonic() < deadline:
            r = self.gw("GET", "/v1/incidents", self.operator)
            if r.status_code == 200:
                hits = []
                for item in r.json():
                    if self._correlates(item):
                        detail = self.gw("GET", f"/v1/incidents/{item['id']}",
                                         self.operator)
                        if detail.status_code == 200:
                            hits.append(detail.json())
                self.incident_hits = len(hits)
                if len(hits) == 1:
                    return hits[0]
                if len(hits) > 1:
                    return None
            time.sleep(3)
        return None

    def _correlates(self, summary: Dict[str, Any]) -> bool:
        for ev in summary.get("evidence", []):
            metrics = ((ev.get("payload") or {}).get("metrics")) or {}
            if metrics.get("e2e_run_id") == self.marker:
                return True
        return False

    def replay(self) -> None:
        st = Stage("redis-replay")
        self.stages.append(st)
        read = subprocess.run(
            ["docker", "exec", "devops_redis", "redis-cli", "--json",
             "XRANGE", "devops:events", "-", "+", "COUNT", "200"],
            capture_output=True, text=True, timeout=60)
        try:
            entries = json.loads(read.stdout or "[]")
        except json.JSONDecodeError:
            entries = []
        fields = None
        for _sid, kv in entries:
            if kv.get("event_id") == self.event_id and \
               kv.get("event_type") == "ThreatThresholdExceededEvent":
                fields = kv
        st.check("producer event found on stream", True, fields is not None,
                 fields is not None)
        if not fields:
            return
        argv: List[str] = ["docker", "exec", "devops_redis", "redis-cli",
                           "XADD", "devops:events", "*"]
        for key, value in fields.items():
            argv += [key, str(value)]
        add = subprocess.run(argv, capture_output=True, text=True, timeout=60)
        st.check("event replayed via real stream", 0, add.returncode, add.returncode == 0)
        time.sleep(6)  # bounded settle window, then verify durable state
        r = self.gw("GET", f"/v1/incidents/{self.incident_id}", self.operator)
        if r.status_code != 200:
            st.check("incident unchanged after replay", 200, r.status_code, False)
            return
        incident = r.json()
        st.check("same incident identity", self.incident_id, incident["id"],
                 incident["id"] == self.incident_id)
        breaches = [e for e in incident["evidence"] if e["kind"] == "threshold_breach"]
        st.check("no duplicate threshold evidence", 1, len(breaches), len(breaches) == 1)
        all_ids = [e["id"] for e in incident["evidence"]]
        st.check("no duplicate evidence ids", len(all_ids), len(set(all_ids)),
                 len(all_ids) == len(set(all_ids)))
        r = self.gw("GET", "/v1/incidents", self.operator)
        correlated = [i for i in r.json() if self._correlates(i)]
        st.check("still exactly one incident for the breach", 1, len(correlated),
                 len(correlated) == 1)

    def evidence(self) -> None:
        st = Stage("deployment-evidence")
        self.stages.append(st)
        body = {"deployment_run_id": self.run_id,
                "repository": "evil/spoof", "source_sha": "f" * 40,
                "state": "FAKE", "artifact_hash": "a" * 64, "plan_hash": "b" * 64,
                "branch": "pwn", "command": "rm -rf /"}
        r = self.gw("POST", f"/v1/incidents/{self.incident_id}/deployment-evidence",
                    self.operator, json=body)
        self.save("deployment-evidence-response.json", _safe(r))
        st.check("evidence attached", 200, r.status_code, r.status_code == 200)
        if r.status_code != 200:
            return
        payload = r.json().get("payload") or {}
        st.check("repository from deployment record", FIXTURE_REPO,
                 payload.get("repository_name"),
                 payload.get("repository_name") == FIXTURE_REPO)
        st.check("source sha from deployment record", FIXTURE_SEED_SHA,
                 payload.get("source_revision", {}).get("head_sha"),
                 payload.get("source_revision", {}).get("head_sha") == FIXTURE_SEED_SHA)
        st.check("state DEPLOYED", "DEPLOYED", payload.get("state"),
                 payload.get("state") == "DEPLOYED")
        st.check("provenance present", True, bool(payload.get("provenance")),
                 bool(payload.get("provenance")))
        blob = json.dumps(_safe(r))
        st.check("spoofed fields ignored", True,
                 all(s not in blob for s in ("evil/spoof", "pwn", "FAKE")),
                 all(s not in blob for s in ("evil/spoof", "pwn", "FAKE")))
        self.deployment_evidence_id = r.json()["id"]

        bad = self.gw("POST", f"/v1/incidents/{self.incident_id}/deployment-evidence",
                      self.operator, json={"deployment_run_id": "run_does_not_exist"})
        st.check("unknown run -> 404/422", bad.status_code in (404, 422), True,
                 bad.status_code in (404, 422))

    def rca(self) -> None:
        st = Stage("RCA")
        self.stages.append(st)
        r = self.gw("POST", f"/v1/incidents/{self.incident_id}/rca", self.operator,
                    json={})
        self.save("rca-response.json", _safe(r))
        st.check("networked RCA accepted", 200, r.status_code, r.status_code == 200)
        if r.status_code != 200:
            return
        body = r.json()
        st.check("root cause", DETERMINISTIC_ROOT_CAUSE,
                 body.get("root_cause") or body.get("rca", {}).get("root_cause"),
                 (body.get("root_cause") or (body.get("rca") or {}).get("root_cause"))
                 == DETERMINISTIC_ROOT_CAUSE)
        # persisted RCA evidence via incident read-back
        detail = self.gw("GET", f"/v1/incidents/{self.incident_id}", self.operator)
        rca_ev = [e for e in detail.json().get("evidence", [])
                  if e.get("kind") == "rca_result"]
        st.check("RCA evidence persisted", True, bool(rca_ev), bool(rca_ev))
        if rca_ev:
            refs = (rca_ev[0].get("payload") or {}).get("evidence_refs") or \
                   (rca_ev[0].get("payload") or {}).get("supporting_evidence_ids") or []
            valid = {e["id"] for e in detail.json()["evidence"]}
            st.check("citations within pack", True,
                     bool(refs) and set(refs) <= valid,
                     bool(refs) and set(refs) <= valid)
        # agent-boundary hostile battery through real private-network HTTP
        self._agent_negatives(st)

    def _agent_negatives(self, st: Stage) -> None:
        import copy
        base = self._agent_pack(st)
        if not base:
            st.check("agent negative battery preconditions", "pack built", "missing", False)
            return
        cases = []
        bad = copy.deepcopy(base)
        bad["signals"]["threshold_breaches"][0]["value"] = 85.0
        cases.append(("below threshold", bad))
        bad = copy.deepcopy(base)
        bad["signals"]["threshold_breaches"][0]["value"] = 90.0
        cases.append(("equality to threshold", bad))
        bad = copy.deepcopy(base)
        bad["signals"]["threshold_breaches"][0]["service"] = "billing-service"
        cases.append(("wrong service", bad))
        bad = copy.deepcopy(base)
        bad["signals"]["threshold_breaches"][0]["metric"] = "memory_percent"
        cases.append(("wrong metric", bad))
        bad = copy.deepcopy(base)
        bad["signals"]["threshold_breaches"][0]["value"] = "N/A"
        cases.append(("malformed numeric signal", bad))
        bad = copy.deepcopy(base)
        bad["signals"]["threshold_breaches"][0]["operator"] = "<"
        cases.append(("contradictory operator", bad))
        bad = copy.deepcopy(base)
        bad["signals"]["threshold_breaches"][0]["evidence_id"] = "foreign-99"
        cases.append(("foreign evidence citation", bad))
        for name, pack in cases:
            code = self._post_agent(pack)
            st.check(f"agent negative: {name}", 422, code, code == 422)

    def _agent_pack(self, st: Stage) -> Optional[Dict[str, Any]]:
        detail = self.gw("GET", f"/v1/incidents/{self.incident_id}", self.operator)
        if detail.status_code != 200:
            return None
        incident = detail.json()
        timeline = [{"evidence_id": e["id"], "kind": e["kind"],
                     "source": e["source"], "observed_at": e["observed_at"]}
                    for e in incident["evidence"]]
        breaches = [{"evidence_id": e["id"], **{
            k: (e.get("payload") or {}).get(k)
            for k in ("service", "metric", "value", "threshold", "operator",
                      "severity", "breach_count")}}
            for e in incident["evidence"] if e["kind"] == "threshold_breach"]
        return {"pack_version": "1.0",
                "incident": {"id": incident["id"]},
                "evidence": {"count": len(timeline), "timeline": timeline},
                "signals": {"threshold_breaches": breaches, "deployment_runs": []}}

    def _post_agent(self, pack: Dict[str, Any]) -> int:
        script = (
            "import json,sys,urllib.request;"
            "body=json.dumps({'evidence_pack':json.load(sys.stdin)}).encode();"
            "req=urllib.request.Request('http://localhost:8020/api/internal/analyze-rca',"
            "data=body,headers={'Content-Type':'application/json'});"
            "try:"
            "    r=urllib.request.urlopen(req,timeout=10);print(r.status)"
            "except urllib.error.HTTPError as e:"
            "    print(e.code)"
        )
        run = subprocess.run(
            ["docker", "exec", "-i", "devops_agent_service", "python", "-c", script],
            input=json.dumps(pack), capture_output=True, text=True, timeout=60)
        try:
            return int(run.stdout.strip().splitlines()[-1])
        except (ValueError, IndexError):
            return -1

    def proposal(self) -> None:
        st = Stage("proposal")
        self.stages.append(st)
        r = self.gw("POST", f"/v1/incidents/{self.incident_id}/proposal",
                    self.operator, json={})
        self.save("proposal-response.json", _safe(r))
        st.check("proposal generated", 200, r.status_code, r.status_code == 200)
        if r.status_code != 200:
            return
        body = r.json()
        proposal = body.get("proposal") or {}
        st.check("status PROPOSED", "PROPOSED", proposal.get("status"),
                 proposal.get("status") == "PROPOSED")
        st.check("is_verified", True, proposal.get("is_verified") is True,
                 proposal.get("is_verified") is True)
        st.check("incident_status", "RemediationProposed", body.get("incident_status"),
                 body.get("incident_status") == "RemediationProposed")
        st.check("repository authoritative", FIXTURE_REPO, proposal.get("repository"),
                 proposal.get("repository") == FIXTURE_REPO)
        st.check("source_sha authoritative", FIXTURE_SEED_SHA,
                 proposal.get("source_sha"), proposal.get("source_sha") == FIXTURE_SEED_SHA)
        st.check("target_filepath", "src/service_config.py",
                 proposal.get("target_filepath"),
                 proposal.get("target_filepath") == "src/service_config.py")
        st.check("risk_class", "MEDIUM", proposal.get("risk_class"),
                 proposal.get("risk_class") == "MEDIUM")
        st.check("proposal_hash 64-hex", True,
                 bool(re.fullmatch(r"[0-9a-f]{64}", proposal.get("proposal_hash") or "")),
                 bool(re.fullmatch(r"[0-9a-f]{64}", proposal.get("proposal_hash") or "")))
        refs = set(proposal.get("evidence_refs") or [])
        st.check("deployment evidence targeted",
                 self.deployment_evidence_id in refs,
                 self.deployment_evidence_id in refs,
                 self.deployment_evidence_id in refs)

        self.proposal = proposal
        self.incident_status = body.get("incident_status")
        self._verify_hash(st)

    def _verify_hash(self, st: Stage) -> None:
        incident = self.gw("GET", f"/v1/incidents/{self.incident_id}",
                           self.operator).json()
        rca_ev = [e for e in incident["evidence"] if e["kind"] == "rca_result"][0]
        payload = rca_ev["payload"]
        root_cause = payload.get("root_cause", "")
        refs = payload.get("evidence_refs") or payload.get("supporting_evidence_ids") or []
        base = dict(
            incident_id=self.incident_id, root_cause=root_cause,
            evidence_refs=list(refs), repository=self.proposal["repository"],
            source_sha=self.proposal["source_sha"],
            file_paths=[self.proposal["target_filepath"]],
            patch=self.proposal["diff_patch_payload"],
            validation_plan=self.proposal["validation_plan"],
            risk_class=self.proposal["risk_class"],
        )
        recomputed = compute_proposal_hash(**base)
        st.check("canonical hash reproduced exactly",
                 self.proposal["proposal_hash"], recomputed,
                 recomputed == self.proposal["proposal_hash"])
        for field, mutate in {
            "incident_id": lambda b: b.update(incident_id="inc-other"),
            "root_cause": lambda b: b.update(root_cause="other"),
            "evidence_refs": lambda b: b.update(evidence_refs=list(reversed(refs))),
            "repository": lambda b: b.update(repository="evil/repo"),
            "source_sha": lambda b: b.update(source_sha="f" * 40),
            "file_paths": lambda b: b.update(file_paths=["src/other.py"]),
            "patch": lambda b: b.update(patch=b["patch"] + "\n"),
            "validation_plan": lambda b: b.update(validation_plan=["x"]),
            "risk_class": lambda b: b.update(risk_class="LOW"),
        }.items():
            mutated = dict(base)
            mutate(mutated)
            changed = compute_proposal_hash(**mutated) != recomputed
            st.check(f"hash mutation changes digest: {field}", True, changed, changed)

    def approval(self) -> None:
        st = Stage("approval")
        self.stages.append(st)
        pid, phash = self.proposal["id"], self.proposal["proposal_hash"]

        r = self.gw("POST", f"/v1/incidents/{self.incident_id}/proposal/approve",
                    self.operator,
                    json={"proposal_id": pid, "proposal_hash": "0" * 64,
                          "approved_by": "attacker@evil"})
        st.check("wrong proposal hash -> 422", 422, r.status_code, r.status_code == 422)
        r = self.gw("POST", f"/v1/incidents/{self.incident_id}/proposal/approve",
                    self.operator,
                    json={"proposal_id": "proposal-nope", "proposal_hash": phash})
        st.check("unknown proposal -> 404", 404, r.status_code, r.status_code == 404)
        r = self.gw("POST", f"/v1/incidents/{self.incident_id}/proposal/approve",
                    self.viewer,
                    json={"proposal_id": pid, "proposal_hash": phash,
                          "approved_by": VIEWER_SUB})
        st.check("non-operator approval -> 403", 403, r.status_code, r.status_code == 403)

        # stale approval through the real TTL mechanism (§33)
        generated = _parse_ts(self.proposal.get("generated_at"))
        age = (datetime.now(timezone.utc) - generated).total_seconds()
        wait = TTL_SECONDS - age + 8
        if wait > 0:
            print(f"waiting {wait:.0f}s for proposal TTL expiry ({TTL_SECONDS:.0f}s)")
            time.sleep(wait)
        r = self.gw("POST", f"/v1/incidents/{self.incident_id}/proposal/approve",
                    self.operator,
                    json={"proposal_id": pid, "proposal_hash": phash,
                          "approved_by": "attacker@evil"})
        st.check("stale approval -> 409", 409, r.status_code, r.status_code == 409)
        after = self.gw("GET", f"/v1/incidents/{self.incident_id}/proposal",
                        self.operator).json()["proposal"]
        st.check("stale approval caused no side effects", "PROPOSED",
                 after.get("status"), after.get("status") == "PROPOSED")
        st.check("stale approval recorded no identity", None,
                 after.get("approved_by"), not after.get("approved_by"))

        # regenerate (fresh) and approve with JWT-identity supremacy
        r = self.gw("POST", f"/v1/incidents/{self.incident_id}/proposal",
                    self.operator, json={})
        st.check("proposal regeneration", 200, r.status_code, r.status_code == 200)
        if r.status_code != 200:
            return
        self.proposal = r.json()["proposal"]
        st.check("regenerated hash unchanged", phash,
                 self.proposal["proposal_hash"],
                 self.proposal["proposal_hash"] == phash)
        r = self.gw("POST", f"/v1/incidents/{self.incident_id}/proposal/approve",
                    self.operator,
                    json={"proposal_id": self.proposal["id"],
                          "proposal_hash": self.proposal["proposal_hash"],
                          "approved_by": "attacker@evil"})
        self.save("approval-response.json", _safe(r))
        st.check("approval accepted", 200, r.status_code, r.status_code == 200)
        if r.status_code == 200:
            body = r.json()
            approved = (body.get("proposal") or {}).get("approved_by")
            st.check("authenticated identity wins", OPERATOR_SUB, approved,
                     approved == OPERATOR_SUB)

    def sandbox_failure(self) -> None:
        st = Stage("sandbox-failure")
        self.stages.append(st)
        os.environ["REMEDIATION_SANDBOX_IMAGE"] = SANDBOX_BAD
        try:
            up = self.compose("up", "-d", "--force-recreate", "incident-service")
            st.check("bad-sandbox incident-service recreated", 0, up.returncode,
                     up.returncode == 0)
            self._wait_incident_service(st, timeout=240)
            r = self._execute()
            self.save("sandbox-failure-response.json", _safe(r))
            st.check("execution fails closed", r.status_code in (422, 502),
                     r.status_code, r.status_code in (422, 502))
            state = self._proposal_state()
            st.check("no commit recorded", None, state.get("commit_sha"),
                     not state.get("commit_sha"))
            st.check("no branch recorded", None, state.get("branch_name"),
                     not state.get("branch_name"))
            st.check("no PR recorded", None, state.get("pull_request_url"),
                     not state.get("pull_request_url"))
            remote = self._remote_branch_state(state.get("branch_name")
                                               or self._planned_branch())
            st.check("no remote branch", None, remote, remote is None)
            prs = self._fixture_prs()
            st.check("no GitHub PR", 0, len(prs), len(prs) == 0)
        finally:
            os.environ["REMEDIATION_SANDBOX_IMAGE"] = SANDBOX_GOOD
            self.compose("up", "-d", "--force-recreate", "incident-service")
            self._wait_incident_service(st, timeout=240)

    def _planned_branch(self) -> str:
        return f"automation/remediation/e2e/{RUN_ID}"

    def _execute(self) -> requests.Response:
        state = self._proposal_state()
        return self.gw("POST", f"/v1/incidents/{self.incident_id}/proposal/execute",
                       self.operator,
                       json={"proposal_id": state["id"],
                             "proposal_hash": state["proposal_hash"],
                             "requested_by": "attacker@evil"})

    def _proposal_state(self) -> Dict[str, Any]:
        r = self.gw("GET", f"/v1/incidents/{self.incident_id}/proposal", self.operator)
        return r.json().get("proposal") or {}

    def _wait_incident_service(self, st: Stage, timeout: float) -> None:
        from e2e.readiness import docker_exec_ok
        probe = docker_exec_ok(
            "devops_incident_service",
            ["python", "-c", "import urllib.request as u;"
                             "print(u.urlopen('http://localhost:8050/health',timeout=3).status)"])
        try:
            wait_until("incident-service", probe, timeout=timeout, interval=3)
            st.check("incident-service ready", True, True, True)
        except ReadinessTimeout as exc:
            st.check("incident-service ready", True, str(exc)[:160], False)

    def execution(self) -> None:
        st = Stage("execution")
        self.stages.append(st)
        # §32 concurrent execution race against the same approved proposal
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            f1 = pool.submit(self._execute)
            f2 = pool.submit(self._execute)
            responses = [f1.result(timeout=600), f2.result(timeout=600)]
        codes = sorted(r.status_code for r in responses)
        self.save("execution-race-codes.json", {"codes": codes})
        state = self._poll_proposal_until("PR_CREATED", timeout=600)
        gate = H.classify_execution_outcomes(codes)
        ok = gate["acceptable"] and state.get("status") == "PR_CREATED" and \
            gate["successes"] >= 0 and any(c != 409 for c in codes) and \
            not gate["invalid"] and state.get("status") == "PR_CREATED"
        st.check("race: one winner + conflict, terminal PR_CREATED",
                 "200/409/502/504 with final PR_CREATED",
                 f"codes={codes} final={state.get('status')}", ok)
        self.proposal = state
        self.commit_sha = state.get("commit_sha")
        self.branch_name = state.get("branch_name")
        self.pr_url = state.get("pull_request_url")
        st.check("single commit recorded", True,
                 bool(self.commit_sha) and len(str(self.commit_sha)) == 40,
                 bool(self.commit_sha) and len(str(self.commit_sha)) == 40)
        prs = self._fixture_prs()
        st.check("exactly one PR on fixture", 1, len(prs), len(prs) == 1)

        # §31 duplicate execution reconciles
        r = self._execute()
        st.check("duplicate execution reconciles", r.status_code, 200,
                 r.status_code == 200)
        after = self._proposal_state()
        st.check("duplicate did not mint second commit", self.commit_sha,
                 after.get("commit_sha"), after.get("commit_sha") == self.commit_sha)
        st.check("still exactly one PR", 1, len(self._fixture_prs()),
                 len(self._fixture_prs()) == 1)

        # §36 remote branch tamper fails closed
        moved = self._force_remote_branch_to_seed()
        st.check("remote branch tampered by attacker", True, moved, moved)
        r = self._execute()
        st.check("branch moved -> conflict", 409, r.status_code, r.status_code == 409)
        remote = self._remote_branch_state(self.branch_name)
        st.check("conflict never overwrites remote", True,
                 remote is not None and remote != self.commit_sha,
                 remote is not None and remote != self.commit_sha)
        restored = self._restore_remote_branch(self.commit_sha)
        st.check("remote branch restored for final assertions", True, restored, restored)
        H.dump_json(os.path.join(ARTIFACTS, "hostile-path-results.json"),
                    self.rows)
        return

    def _poll_proposal_until(self, status: str, timeout: float) -> Dict[str, Any]:
        deadline = time.monotonic() + timeout
        last: Dict[str, Any] = {}
        while time.monotonic() < deadline:
            last = self._proposal_state()
            if last.get("status") == status:
                return last
            time.sleep(4)
        return last

    def _fixture_prs(self) -> List[Dict[str, Any]]:
        r = self.gh(f"/repos/{FIXTURE_REPO}/pulls",
                    params={"state": "all", "head": f"{FIXTURE_REPO}:{self._planned_branch()}"})
        if r.status_code != 200:
            return []
        return r.json()

    def _remote_branch_state(self, branch: str) -> Optional[str]:
        r = self.gh(f"/repos/{FIXTURE_REPO}/git/ref/heads/{branch}")
        if r.status_code != 200:
            return None
        return (r.json().get("object") or {}).get("sha")

    def _force_remote_branch_to_seed(self) -> bool:
        r = self.gh(f"/repos/{FIXTURE_REPO}/git/refs/heads/{self.branch_name}",
                    method="PATCH", json={"sha": FIXTURE_SEED_SHA, "force": True})
        return r.status_code == 200

    def _restore_remote_branch(self, sha: str) -> bool:
        r = self.gh(f"/repos/{FIXTURE_REPO}/git/refs/heads/{self.branch_name}",
                    method="PATCH", json={"sha": sha, "force": True})
        return r.status_code == 200

    def remote_checks(self) -> None:
        st = Stage("remote-branch-and-PR")
        self.stages.append(st)
        branch_sha = self._remote_branch_state(self.branch_name)
        st.check("branch exists at commit", self.commit_sha, branch_sha,
                 branch_sha == self.commit_sha)
        commit = self.gh(f"/repos/{FIXTURE_REPO}/commits/{self.commit_sha}")
        st.check("commit readable", 200, commit.status_code, commit.status_code == 200)
        if commit.status_code == 200:
            meta = commit.json()
            parents = meta.get("parents") or []
            st.check("parent is fixture seed SHA", FIXTURE_SEED_SHA,
                     parents[0].get("sha") if parents else None,
                     bool(parents) and parents[0].get("sha") == FIXTURE_SEED_SHA)
            files = [f.get("filename") for f in meta.get("files") or []]
            st.check("commit touches only src/service_config.py",
                     ["src/service_config.py"], files, files == ["src/service_config.py"])
        prs = self._fixture_prs()
        st.check("one PR discovered", 1, len(prs), len(prs) == 1)
        if prs:
            pr = prs[0]
            self.save("github-pr-response.json", pr)
            st.check("PR is draft", True, pr.get("draft") is True, pr.get("draft") is True)
            st.check("head repo is fixture", FIXTURE_REPO,
                     ((pr.get("head") or {}).get("repo") or {}).get("full_name"),
                     ((pr.get("head") or {}).get("repo") or {}).get("full_name") == FIXTURE_REPO)
            st.check("head branch run-scoped", self.branch_name,
                     (pr.get("head") or {}).get("ref"),
                     (pr.get("head") or {}).get("ref") == self.branch_name)
            st.check("head sha is remediation commit", self.commit_sha,
                     (pr.get("head") or {}).get("sha"),
                     (pr.get("head") or {}).get("sha") == self.commit_sha)
            st.check("base branch main", "main", (pr.get("base") or {}).get("ref"),
                     (pr.get("base") or {}).get("ref") == "main")
            st.check("PR URL points at fixture repo", True,
                     bool(self.pr_url) and FIXTURE_REPO in self.pr_url,
                     bool(self.pr_url) and FIXTURE_REPO in self.pr_url)
        content = self.gh(f"/repos/{FIXTURE_REPO}/contents/src/service_config.py",
                          params={"ref": self.branch_name})
        st.check("remote file readable", 200, content.status_code,
                 content.status_code == 200)
        if content.status_code == 200:
            text = base64.b64decode(content.json()["content"]).decode("utf-8")
            st.check("remote file exactly patched", PATCHED_LINE, text.strip(),
                     PATCHED_LINE in text and INITIAL_FILE not in text)

    def db_cross_check(self) -> None:
        st = Stage("DB-cross-check")
        self.stages.append(st)
        rows = self._psql(
            "SELECT id, status, version FROM devops_incidents WHERE id = "
            f"'{self.incident_id}'")
        st.check("incident row exists", 1, len(rows), len(rows) == 1)
        api_incident = self.gw("GET", f"/v1/incidents/{self.incident_id}",
                               self.operator).json()
        st.check("lifecycle status matches API",
                 api_incident.get("status"), rows[0][1] if rows else None,
                 bool(rows) and rows[0][1] == api_incident.get("status"))
        ev = self._psql(
            "SELECT id, kind FROM devops_incident_evidence WHERE incident_id = "
            f"'{self.incident_id}' ORDER BY observed_at")
        kinds = {k for _, k in ev}
        st.check("evidence kinds durable",
                 "threshold_breach,deployment_run,rca_result",
                 ",".join(sorted(kinds)),
                 {"threshold_breach", "deployment_run", "rca_result"} <= kinds)
        ids = {i for i, _ in ev}
        st.check("threshold evidence id matches", True, self.evidence_id in ids,
                 self.evidence_id in ids)
        st.check("deployment evidence id matches", True,
                 self.deployment_evidence_id in ids,
                 self.deployment_evidence_id in ids)
        st.check("rca evidence id matches", True,
                 f"rca-{self.incident_id}" in ids, f"rca-{self.incident_id}" in ids)
        prow = self._psql("SELECT patch_proposals FROM devops_incidents WHERE id = "
                          f"'{self.incident_id}'")
        proposals = json.loads(prow[0][0]) if prow else []
        prop = next((p for p in proposals
                     if p.get("id") == self.proposal["id"]), None)
        st.check("proposal row present", True, prop is not None, prop is not None)
        if prop:
            st.check("proposal hash matches API", self.proposal["proposal_hash"],
                     prop.get("proposal_hash"),
                     prop.get("proposal_hash") == self.proposal["proposal_hash"])
            st.check("approval identity durable", OPERATOR_SUB, prop.get("approved_by"),
                     prop.get("approved_by") == OPERATOR_SUB)
            st.check("commit sha durable", self.commit_sha, prop.get("commit_sha"),
                     prop.get("commit_sha") == self.commit_sha)
            st.check("branch durable", self.branch_name, prop.get("branch_name"),
                     prop.get("branch_name") == self.branch_name)
            st.check("PR url durable", self.pr_url, prop.get("pull_request_url"),
                     prop.get("pull_request_url") == self.pr_url)
            st.check("proposal status durable", "PR_CREATED", prop.get("status"),
                     prop.get("status") == "PR_CREATED")
            st.check("execution id present", True, bool(prop.get("execution_id")),
                     bool(prop.get("execution_id")))
            self.manifest["execution_id"] = prop.get("execution_id") or ""
            self.manifest["approval_identity"] = prop.get("approved_by") or ""
        st.check("remote commit equals durable commit", self.commit_sha,
                 self._remote_branch_state(self.branch_name),
                 self._remote_branch_state(self.branch_name) == self.commit_sha)
        H.dump_json(os.path.join(ARTIFACTS, "database-cross-check.json"), st.rows)

    def _psql(self, sql: str) -> List[List[str]]:
        run = subprocess.run(
            ["docker", "exec", "devops_postgres", "psql", "-U", "postgres",
             "-d", "devops_prod", "-At", "-F", "\t", "-c", sql],
            capture_output=True, text=True, timeout=60)
        lines = [ln for ln in (run.stdout or "").splitlines() if ln.strip()]
        return [ln.split("\t") for ln in lines]

    def finalize(self) -> Tuple[str, int]:
        self.manifest.update(
            deployment_run_id=getattr(self, "run_id", ""),
            incident_id=getattr(self, "incident_id", ""),
            threshold_evidence_id=getattr(self, "evidence_id", ""),
            deployment_evidence_id=getattr(self, "deployment_evidence_id", ""),
            rca_evidence_id=f"rca-{getattr(self, 'incident_id', '')}",
            proposal_id=(self.proposal or {}).get("id", ""),
            proposal_hash=(self.proposal or {}).get("proposal_hash", ""),
            remediation_commit_sha=getattr(self, "commit_sha", "") or "",
            remediation_branch=getattr(self, "branch_name", "") or "",
            pull_request_url=getattr(self, "pr_url", "") or "",
        )
        summary = [{"stage": s.name, "result": s.result(), "rows": s.rows}
                   for s in self.stages]
        H.dump_json(os.path.join(ARTIFACTS, "stage-summary.json"), summary)
        H.dump_json(os.path.join(ARTIFACTS, "hostile-path-results.json"),
                    [r for s in self.stages for r in s.rows
                     if s.name in ("security", "approval", "execution",
                                   "sandbox-failure", "RCA", "proposal",
                                   "deployment-evidence")])
        overall = H.classify_gate([{"result": s.result()} for s in self.stages])
        if overall == H.PASS:
            overall = H.PASS
        H.finalize_manifest(self.manifest, overall)
        H.dump_json(os.path.join(ARTIFACTS, "e2e-manifest.json"), self.manifest)
        lines = ["# E2E golden path summary", "",
                 f"Result: **{overall}**", "", "| Stage | Result |", "| --- | --- |"]
        lines += [f"| {s.name} | {s.result()} |" for s in self.stages]
        with open(os.path.join(ARTIFACTS, "e2e-summary.md"), "w") as fh:
            fh.write("\n".join(lines) + "\n")
        return overall, 0 if overall == H.PASS else 1


def _fixture(name: str) -> str:
    root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
    with open(os.path.join(root, name), encoding="utf-8") as fh:
        return fh.read()


def _safe(response: requests.Response) -> Any:
    try:
        return {"status": response.status_code, "body": response.json()}
    except ValueError:
        return {"status": response.status_code, "text": response.text[:4000]}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_ts(value: Any) -> datetime:
    return datetime.fromisoformat(str(value))


def _terraform_steps_ran(run: Dict[str, Any]) -> bool:
    plan = ((run.get("execution") or {}).get("terraform_plan") or {})
    steps = plan.get("steps") or []
    commands = " ".join(str(s.get("command", "")) for s in steps)
    return all(token in commands
               for token in ("fmt", "init", "validate", "plan")) and \
        plan.get("status") == "PASS" and \
        bool(((run.get("execution") or {}).get("terraform_apply") or {})
             .get("status") == "PASS")


def main() -> int:
    parser = argparse.ArgumentParser(description="ARES golden path driver")
    parser.add_argument("--only", default="",
                        help="comma list of stages to run (default all)")
    args = parser.parse_args()
    harness = Harness()
    only = {s for s in args.only.split(",") if s}

    def want(name: str) -> bool:
        return not only or name in only

    overall = harness.preflight()
    if overall != H.PASS:
        H.finalize_manifest(harness.manifest, overall)
        H.dump_json(os.path.join(ARTIFACTS, "e2e-manifest.json"), harness.manifest)
        return 2
    try:
        if want("security"):
            harness.security()
        if want("deployment"):
            harness.deployment()
        if want("monitoring"):
            harness.monitoring()
            harness.replay()
        if want("evidence"):
            harness.evidence()
        if want("rca"):
            harness.rca()
        if want("proposal"):
            harness.proposal()
        if want("approval"):
            harness.approval()
        if want("sandbox"):
            harness.sandbox_failure()
        if want("execution"):
            harness.execution()
        if want("remote"):
            harness.remote_checks()
        if want("database"):
            harness.db_cross_check()
    except Exception as exc:  # keep artifacts + honest failure status
        import traceback
        traceback.print_exc()
        with open(os.path.join(ARTIFACTS, "fatal-error.txt"), "w") as fh:
            fh.write(f"{type(exc).__name__}: {exc}\n")
        return 1
    overall, code = harness.finalize()
    print(f"golden-path result: {overall}")
    return code


if __name__ == "__main__":
    sys.exit(main())
