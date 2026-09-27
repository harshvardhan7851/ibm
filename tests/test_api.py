"""
HTTP API tests via FastAPI's TestClient. No running server required.

Includes the honesty checks: /api/health must not claim a model connection it
does not have, and /api/analyze must reflect the submitted source.
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from backend.app import app

client = TestClient(app)

WEAK_PYTHON = "import md5\nAPI_SENTINEL = md5.new('x').hexdigest()\n"


# ── Health ───────────────────────────────────────────────────────────────────

def test_health_is_ok():
    body = client.get("/api/health").json()
    assert body["status"] == "healthy"
    assert body["version"]


def test_health_reports_rule_counts_from_the_registry():
    from backend import rules

    body = client.get("/api/health").json()
    assert body["rules"]["total"] == rules.rule_count()
    for language in rules.SUPPORTED_LANGUAGES:
        assert body["rules"]["by_language"][language] == len(rules.rules_for(language))


def test_health_does_not_claim_an_unconfigured_model_is_online():
    """Regression: the old endpoint hardcoded `ibm_bob_status: ONLINE (Connected)`."""
    body = client.get("/api/health").json()
    synthesis = body["synthesis"]
    assert synthesis["configured"] is False
    assert synthesis["mode"] == "rule-engine"
    assert synthesis["api_key_present"] is False

    serialised = json.dumps(body).upper()
    assert "ONLINE" not in serialised
    assert "CONNECTED" not in serialised


def test_health_reports_the_execution_gate():
    body = client.get("/api/health").json()
    assert body["verification"]["code_execution_enabled"] is False
    assert "BOBPULSE_ALLOW_EXEC" in body["verification"]["code_execution_note"]


def test_health_lists_the_pipeline_stages():
    body = client.get("/api/health").json()
    assert [stage["number"] for stage in body["pipeline"]["stages"]] == [1, 2, 3, 4, 5]


# ── Rules ────────────────────────────────────────────────────────────────────

def test_rules_endpoint_lists_everything():
    from backend import rules

    body = client.get("/api/rules").json()
    assert body["count"] == rules.rule_count()
    assert all({"id", "severity", "title", "remediation"} <= set(r) for r in body["rules"])


def test_rules_endpoint_filters_by_language():
    body = client.get("/api/rules", params={"language": "go"}).json()
    assert body["count"] > 0
    assert all("go" in rule["languages"] for rule in body["rules"])


def test_rules_endpoint_rejects_an_unknown_language():
    assert client.get("/api/rules", params={"language": "cobol"}).status_code == 422


# ── Examples ─────────────────────────────────────────────────────────────────

def test_examples_are_served_without_stored_answers():
    body = client.get("/api/examples").json()
    assert body["examples"]
    for example in body["examples"]:
        assert {"id", "name", "language", "filename", "original_code"} <= set(example)
        assert "modernized_code" not in example
        assert "tests" not in example


def test_legacy_presets_alias_still_works():
    body = client.get("/api/presets").json()
    assert body["presets"] == body["examples"]


# ── Scan ─────────────────────────────────────────────────────────────────────

def test_scan_returns_findings_with_locations():
    body = client.post("/api/scan", json={"code": WEAK_PYTHON, "language": "python"}).json()
    assert body["findings"]
    assert body["debt_score"] > 0
    assert body["rules_evaluated"] > 0
    assert all(finding["lines"] for finding in body["findings"])


def test_scan_breakdown_accounts_for_the_score():
    body = client.post("/api/scan", json={"code": WEAK_PYTHON, "language": "python"}).json()
    assert sum(item["points"] for item in body["debt_breakdown"]) == body["debt_points"]


def test_legacy_scan_only_alias_still_works():
    response = client.post("/api/scan-only", json={"code": WEAK_PYTHON, "language": "python"})
    assert response.status_code == 200
    assert response.json()["findings"]


def test_scan_rejects_empty_code():
    assert client.post("/api/scan", json={"code": "", "language": "python"}).status_code == 422


# ── Plan ─────────────────────────────────────────────────────────────────────

def test_plan_returns_ordered_steps():
    body = client.post("/api/plan", json={"code": WEAK_PYTHON, "language": "python"}).json()
    assert body["total_steps"] == len(body["plan"])
    assert body["plan"][0]["priority"] == 1


# ── Analyze ──────────────────────────────────────────────────────────────────

@pytest.mark.slow
def test_analyze_reflects_the_submitted_source():
    """The regression that mattered most: no substituted stored result."""
    body = client.post(
        "/api/analyze", json={"code": WEAK_PYTHON, "language": "python", "filename": "probe.py"}
    ).json()
    assert "API_SENTINEL" in body["modernized_code"]
    assert "hashlib.sha256" in body["modernized_code"]
    assert body["filename"] == "probe.py"


@pytest.mark.slow
def test_analyze_reports_measured_metrics():
    body = client.post("/api/analyze", json={"code": WEAK_PYTHON, "language": "python"}).json()
    metrics = body["metrics"]
    assert metrics["residual_debt_score"] < metrics["initial_debt_score"]
    assert metrics["debt_reduction_percent"] > 0
    assert metrics["comparison_reliable"] is True


def test_analyze_rejects_an_unsupported_language():
    response = client.post("/api/analyze", json={"code": "x = 1", "language": "cobol"})
    assert response.status_code == 422
    assert "Unsupported language" in response.json()["detail"]


def test_analyze_rejects_empty_code():
    assert client.post("/api/analyze", json={"code": "", "language": "python"}).status_code == 422


def test_analyze_requires_code():
    assert client.post("/api/analyze", json={"language": "python"}).status_code == 422


# ── Streaming ────────────────────────────────────────────────────────────────

@pytest.mark.slow
def test_stream_emits_every_stage_then_a_result():
    with client.stream(
        "POST",
        "/api/analyze/stream",
        json={"code": WEAK_PYTHON, "language": "python", "use_cache": False},
    ) as response:
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/event-stream")

        events = []
        for line in response.iter_lines():
            if line.startswith("data: "):
                events.append(json.loads(line[6:]))

    kinds = [event["type"] for event in events]
    assert kinds[0] == "start"
    assert kinds[-1] == "result"
    assert [e["stage"] for e in events if e["type"] == "progress"] == [1, 2, 3, 4, 5]

    payload = events[-1]["payload"]
    assert "API_SENTINEL" in payload["modernized_code"]


@pytest.mark.slow
def test_stream_and_blocking_endpoints_agree():
    """Both routes must run the same pipeline — they used to be separate code."""
    blocking = client.post(
        "/api/analyze", json={"code": WEAK_PYTHON, "language": "python", "use_cache": False}
    ).json()

    with client.stream(
        "POST",
        "/api/analyze/stream",
        json={"code": WEAK_PYTHON, "language": "python", "use_cache": False},
    ) as response:
        streamed = None
        for line in response.iter_lines():
            if line.startswith("data: "):
                event = json.loads(line[6:])
                if event["type"] == "result":
                    streamed = event["payload"]

    assert streamed is not None
    assert streamed["modernized_code"] == blocking["modernized_code"]
    assert streamed["metrics"]["initial_debt_score"] == blocking["metrics"]["initial_debt_score"]
    assert streamed["metrics"]["residual_debt_score"] == blocking["metrics"]["residual_debt_score"]
    assert streamed["verification"]["verdict"] == blocking["verification"]["verdict"]


def test_stream_reports_validation_errors():
    assert (
        client.post("/api/analyze/stream", json={"code": "x", "language": "cobol"}).status_code
        == 422
    )


# ── Export ───────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def completed_run():
    return client.post(
        "/api/analyze", json={"code": WEAK_PYTHON, "language": "python", "filename": "probe.py"}
    ).json()


def export_body(run):
    return {
        "filename": run["filename"],
        "diff_unified": run["diff_unified"],
        "metrics": run["metrics"],
        "findings": run["findings"],
        "verification": run["verification"],
        "synthesis": run["synthesis"],
        "language": run["language"],
    }


@pytest.mark.slow
def test_export_pr_uses_the_measured_numbers(completed_run):
    payload = client.post("/api/export-pr", json=export_body(completed_run)).json()
    metrics = completed_run["metrics"]

    assert payload["title"]
    assert len(payload["title"]) <= 70
    assert payload["branch_from"].startswith("bobpulse/")
    body = payload["body_markdown"]
    assert f"{metrics['initial_debt_score']} → {metrics['residual_debt_score']}" in body
    assert f"{metrics['checks_passed']}/{metrics['checks_total']}" in body
    # Regression: the body used to hardcode a passing test count.
    assert "100% Passed (4/4 assertions)" not in body


@pytest.mark.slow
def test_export_pr_marks_a_clean_run_ready(completed_run):
    payload = client.post("/api/export-pr", json=export_body(completed_run)).json()
    assert payload["ready_to_merge"] == (
        completed_run["verification"]["verdict"] == "clean"
        and not completed_run["findings"]["introduced"]
    )


def test_export_pr_warns_when_the_comparison_is_unreliable():
    payload = client.post(
        "/api/export-pr",
        json={
            "filename": "x.py",
            "diff_unified": "--- a\n+++ b\n",
            "metrics": {"comparison_reliable": False},
            "findings": {"resolved": [], "remaining": [], "introduced": []},
            "verification": {"verdict": "rejected", "test_cases": []},
            "synthesis": {"engine": "none"},
            "language": "python",
        },
    ).json()
    assert "not reliable" in payload["body_markdown"]
    assert payload["ready_to_merge"] is False


@pytest.mark.slow
def test_download_patch_returns_a_diff_attachment(completed_run):
    response = client.post("/api/download-patch", json=export_body(completed_run))
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/x-diff")
    assert ".patch" in response.headers["content-disposition"]
    assert response.text == completed_run["diff_unified"]


def test_download_patch_refuses_an_empty_diff():
    response = client.post(
        "/api/download-patch",
        json={
            "filename": "x.py",
            "diff_unified": "",
            "metrics": {},
            "findings": {},
            "language": "python",
        },
    )
    assert response.status_code == 409


# ── Static frontend ──────────────────────────────────────────────────────────

def test_frontend_is_served_at_the_root():
    response = client.get("/")
    assert response.status_code == 200
    assert "BobPulse" in response.text


def test_static_mount_does_not_shadow_the_api():
    assert client.get("/api/health").status_code == 200
