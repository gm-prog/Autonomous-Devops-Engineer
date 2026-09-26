"""Unit tests for the analysis engine (no HTTP, no DB)."""
from types import SimpleNamespace

import pytest

from app.services.analysis import (
    analyze_repository,
    call_gemini,
    generate_templates,
    parse_gemini_response,
    parse_tag,
)


# --- parse_tag: the 5-tag output protocol -------------------------------

def test_parse_tag_extracts_content():
    text = "preamble <DOCKERFILE>FROM python:3.12</DOCKERFILE> trailing"
    assert parse_tag(text, "DOCKERFILE") == "FROM python:3.12"


def test_parse_tag_missing_returns_empty():
    assert parse_tag("no tags here", "DOCKERFILE") == ""


def test_parse_tag_malformed_returns_empty():
    assert parse_tag("<DOCKERFILE>unterminated", "DOCKERFILE") == ""
    assert parse_tag("</DOCKERFILE>FROM python", "DOCKERFILE") == ""


def test_parse_tag_strips_code_fences():
    text = "<KUBERNETES>```yaml\napiVersion: v1\n```</KUBERNETES>"
    assert parse_tag(text, "KUBERNETES") == "apiVersion: v1"


def test_parse_gemini_response_full_protocol():
    text = (
        "<DOCKERFILE>FROM alpine</DOCKERFILE>"
        "<KUBERNETES>kind: Deployment</KUBERNETES>"
        "<TERRAFORM>provider \"aws\" {}</TERRAFORM>"
        "<CICD>name: ci</CICD>"
        "<REPORT>It works.</REPORT>"
    )
    arts = parse_gemini_response(text)
    assert arts["dockerfile"] == "FROM alpine"
    assert arts["k8s_yaml"] == "kind: Deployment"
    assert arts["terraform_tf"] == 'provider "aws" {}'
    assert arts["pipeline_yaml"] == "name: ci"
    assert arts["analysis_report"] == "It works."


def test_parse_gemini_response_defaults_report():
    arts = parse_gemini_response("<DOCKERFILE>x</DOCKERFILE>")
    assert arts["analysis_report"]  # non-empty default


# --- offline templates ----------------------------------------------------

@pytest.mark.parametrize("tech", ["Python 3.12 / FastAPI Rest", "Django 5", "python"])
def test_templates_python_branch(tech):
    arts = generate_templates("My Service", "FastAPI", tech)
    assert "python:3.12" in arts["dockerfile"]
    assert "my-service" in arts["k8s_yaml"]
    assert "terraform-aws-modules/vpc/aws" in arts["terraform_tf"]
    assert "bandit" in arts["pipeline_yaml"]
    assert arts["analysis_report"]


def test_templates_node_branch():
    arts = generate_templates("Next Dashboard", "Next.js 14", "NodeJS / TypeScript")
    assert "node:20-alpine" in arts["dockerfile"]
    assert "aws_cloudfront_distribution" in arts["terraform_tf"]
    assert "npm audit" in arts["pipeline_yaml"]


def test_templates_jvm_branch_fallback():
    arts = generate_templates("Spring Gatekeeper", "Spring Boot 3.2", "Java 21 / JVM")
    assert "eclipse-temurin:21" in arts["dockerfile"]
    assert "terraform-aws-modules/eks/aws" in arts["terraform_tf"]
    assert "gradlew" in arts["pipeline_yaml"]


def test_all_template_branches_produce_full_artifacts():
    for tech in ("Python 3.12", "NodeJS", "Java 21"):
        arts = generate_templates("Svc", "FW", tech)
        for key in ("dockerfile", "k8s_yaml", "terraform_tf", "pipeline_yaml", "analysis_report"):
            assert arts[key].strip(), f"{tech}: empty {key}"


# --- orchestrator ----------------------------------------------------------

def test_analyze_repository_without_key_uses_templates():
    res = analyze_repository("Svc", "url", "FastAPI", "Python 3.12", api_key=None)
    assert res["engine"] == "template"
    assert res["note"]
    assert res["dockerfile"].strip()


def test_analyze_repository_placeholder_key_uses_templates():
    res = analyze_repository("Svc", "url", "FastAPI", "Python 3.12", api_key="MY_GEMINI_API_KEY")
    assert res["engine"] == "template"


def test_analyze_repository_fallback_when_gemini_fails(monkeypatch):
    import app.services.analysis as mod

    def boom(*a, **k):
        raise mod.requests.RequestException("connection refused")

    monkeypatch.setattr(mod.requests, "post", boom)
    res = analyze_repository("Svc", "url", "FastAPI", "Python 3.12", api_key="real-key-123")
    assert res["engine"] == "template"


def test_analyze_repository_fallback_when_gemini_404(monkeypatch):
    import app.services.analysis as mod

    monkeypatch.setattr(
        mod.requests, "post",
        lambda *a, **k: SimpleNamespace(status_code=404, json=lambda: {}),
    )
    res = analyze_repository("Svc", "url", "FastAPI", "Python 3.12", api_key="real-key-123")
    assert res["engine"] == "template"


def test_analyze_repository_live_gemini(monkeypatch):
    import app.services.analysis as mod

    fake_text = (
        "<DOCKERFILE>FROM custom-live</DOCKERFILE>"
        "<KUBERNETES>kind: Service</KUBERNETES>"
        "<TERRAFORM>resource \"x\" \"y\" {}</TERRAFORM>"
        "<CICD>name: live-ci</CICD>"
        "<REPORT>Live output.</REPORT>"
    )
    captured = {}

    def fake_post(url, json=None, headers=None, timeout=None):
        captured["url"] = url
        captured["headers"] = headers
        captured["json"] = json
        return SimpleNamespace(
            status_code=200,
            json=lambda: {"candidates": [{"content": {"parts": [{"text": fake_text}]}}]},
        )

    monkeypatch.setattr(mod.requests, "post", fake_post)
    res = analyze_repository("Live Svc", "url", "FastAPI", "Python 3.12", api_key="real-key-123")
    assert res["engine"] == "gemini"
    assert res["dockerfile"] == "FROM custom-live"
    assert res["analysis_report"] == "Live output."
    # security: key travels in the header, never in the URL
    assert "key=" not in captured["url"]
    assert captured["headers"]["x-goog-api-key"] == "real-key-123"
    assert "DevOpsAI" in captured["json"]["contents"][0]["parts"][0]["text"]
