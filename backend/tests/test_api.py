"""API-level tests for the operator gateway (SQLite-backed, no external deps)."""
from app.main import Incident, SessionLocal


ARTIFACT_FIELDS = ("dockerfile", "k8s_yaml", "terraform_tf", "pipeline_yaml", "analysis_report")


def _assert_artifacts(payload):
    for field in ARTIFACT_FIELDS:
        assert payload[field], f"artifact '{field}' is empty"


# --- liveness & observability ---------------------------------------------

def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "healthy"
    assert "api_gateway" in body["components"]


def test_v1_health(client):
    r = client.get("/api/v1/health")
    assert r.status_code == 200
    assert r.json()["status"] == "healthy"


def test_metrics_endpoint(client):
    client.get("/health")
    r = client.get("/metrics")
    assert r.status_code == 200
    assert "text/plain" in r.headers["content-type"]
    body = r.text
    assert "devops_api_requests_total" in body
    assert 'path="/health"' in body


def test_cors_wildcard_allows_any_origin(client):
    r = client.get("/health", headers={"Origin": "https://random.example"})
    assert r.headers.get("access-control-allow-origin") in ("*", "https://random.example")


# --- repository catalog ------------------------------------------------------

def test_import_repository(client, sample_repo_payload):
    r = client.post("/api/repositories", json=sample_repo_payload)
    assert r.status_code == 201
    body = r.json()
    assert body["name"] == sample_repo_payload["name"]
    assert body["status"] == "Idle"


def test_import_duplicate_name_rejected(client):
    payload = {
        "name": "dup-reject-svc",
        "url": "https://github.com/example/dup",
        "framework": "Flask",
        "technology": "Python 3.12",
    }
    assert client.post("/api/repositories", json=payload).status_code == 201
    r = client.post("/api/repositories", json=payload)
    assert r.status_code == 400


def test_list_repositories(client, sample_repo_payload):
    client.post("/api/repositories", json=sample_repo_payload)
    r = client.get("/api/repositories")
    assert r.status_code == 200
    names = [row["name"] for row in r.json()]
    assert sample_repo_payload["name"] in names


def test_v1_list_repositories_alias(client, sample_repo_payload):
    client.post("/api/repositories", json=sample_repo_payload)
    assert client.get("/api/v1/repositories").status_code == 200


# --- the Android remote contract ---------------------------------------------

def test_v1_repository_analyze_end_to_end(client):
    payload = {
        "name": "remote-demo-svc",
        "url": "https://github.com/example/remote-demo",
        "framework": "FastAPI",
        "technology": "Python 3.12 / FastAPI Rest",
    }
    r = client.post("/api/v1/repository/analyze", json=payload)
    assert r.status_code == 200
    body = r.json()
    _assert_artifacts(body)
    assert body["status"] == "Generated"
    assert body["engine"] == "template"   # no key in the test env
    assert body["id"] > 0

    # the row is persisted and visible through both catalog views
    rows = client.get("/api/repositories").json()
    row = next(x for x in rows if x["name"] == "remote-demo-svc")
    assert row["status"] == "Generated"


def test_v1_repository_analyze_upserts_same_name(client):
    base = {"name": "upsert-svc", "url": "u1", "framework": "FastAPI", "technology": "Python 3.12"}
    assert client.post("/api/v1/repository/analyze", json=base).status_code == 200
    r = client.post("/api/v1/repository/analyze", json={**base, "framework": "Django"})
    assert r.status_code == 200
    rows = [x for x in client.get("/api/repositories").json() if x["name"] == "upsert-svc"]
    assert len(rows) == 1  # upsert, not a duplicate row


def test_v1_repository_analyze_validation(client):
    r = client.post("/api/v1/repository/analyze", json={"name": "x"})
    assert r.status_code == 422


# --- async (Celery) endpoints: broker is down in tests -> inline fallback ----

def _create_repo(client, name):
    r = client.post(
        "/api/repositories",
        json={"name": name, "url": "u", "framework": "FastAPI", "technology": "Python"},
    )
    assert r.status_code == 201
    return r.json()["id"]


def test_async_analyze_inline_fallback(client):
    repo_id = _create_repo(client, "async-analyze-svc")
    r = client.post(f"/api/repositories/{repo_id}/analyze")
    assert r.status_code == 200
    rows = client.get("/api/repositories").json()
    row = next(x for x in rows if x["id"] == repo_id)
    assert row["status"] == "Generated"


def test_async_deploy_inline_fallback(client):
    repo_id = _create_repo(client, "async-deploy-svc")
    r = client.post(f"/api/repositories/{repo_id}/deploy")
    assert r.status_code == 200
    rows = client.get("/api/repositories").json()
    row = next(x for x in rows if x["id"] == repo_id)
    assert row["status"] == "Deployed"


def test_async_analyze_unknown_repo_404(client):
    assert client.post("/api/repositories/999999/analyze").status_code == 404


def test_investigate_unknown_incident_404(client):
    assert client.post("/api/incidents/999999/investigate").status_code == 404


def test_investigate_inline_fallback(client):
    db = SessionLocal()
    incident = Incident(title="DB pool saturation", description="pool full", severity="High")
    db.add(incident)
    db.commit()
    incident_id = incident.id
    db.close()

    r = client.post(f"/api/incidents/{incident_id}/investigate")
    assert r.status_code == 200
    r2 = client.get("/api/incidents")
    assert r2.status_code == 200
    row = next(x for x in r2.json() if x["id"] == incident_id)
    assert row["status"] == "RootCauseFound"
