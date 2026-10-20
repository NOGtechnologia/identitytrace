import json
import os

import pytest
from fastapi.testclient import TestClient

from api.main import create_app
from api.storage import Store
from tests.conftest import rec, user


@pytest.fixture()
def client():
    url = os.environ.get("TEST_DATABASE_URL", "sqlite://")
    return TestClient(create_app(Store(url)))


@pytest.fixture()
def demo(client):
    summary = client.post("/api/datasets/demo").json()
    return client, summary["dataset_id"]


def test_health_reports_no_cloud_write_access(client):
    body = client.get("/api/health").json()
    assert body["cloud_write_access"] is False


def test_demo_import(demo):
    client, ds = demo
    incidents = client.get(f"/api/datasets/{ds}/incidents").json()
    assert len(incidents) == 9
    assert incidents[0]["severity"] == "critical"
    quality = client.get(f"/api/datasets/{ds}/quality").json()
    assert quality["unusable_events"] == 4
    assert len(client.get(f"/api/datasets/{ds}/findings", params={"rule_id": "IT-004"}).json()) == 4
    assert client.get(f"/api/datasets/{ds}/events", params={"only_issues": True}).json()


def test_upload_and_investigation_flow(client):
    records = {"Records": [rec("StopLogging", user("x"), source="cloudtrail.amazonaws.com", params={"name": "t"})]}
    up = client.post("/api/datasets", files={"file": ("trail.json", json.dumps(records), "application/json")}).json()
    ds = up["dataset_id"]
    assert up["incidents"] == 1
    inc_id = client.get(f"/api/datasets/{ds}/incidents").json()[0]["incident_id"]
    base = f"/api/datasets/{ds}/incidents/{inc_id}"

    assert client.post(f"{base}/log", json={"analyst": "anna", "note": "Trail-Status geprüft"}).status_code == 200
    assert client.post(f"{base}/status", json={"analyst": "anna", "status": "investigating", "note": "los"}).status_code == 200
    assert client.post(f"{base}/status", json={"analyst": "anna", "status": "closed", "note": "x"}).status_code == 409
    rec_id = client.get(base).json()["recommendations"][0]["rec_id"]
    assert client.post(f"{base}/approvals", json={"analyst": "lead", "recommendation_id": rec_id, "note": "ok"}).status_code == 200
    ai = client.post(f"{base}/analysis", json={"analyst": "anna"}).json()
    assert ai["provider"] == "offline-template" and ai["advisory_only"]
    client.post(f"{base}/status", json={"analyst": "anna", "status": "remediated", "note": "Logging läuft"})
    client.post(f"{base}/remediation", json={"analyst": "anna", "summary": "start-logging ausgeführt",
                                             "verification": "get-trail-status: IsLogging=true"})
    assert client.post(f"{base}/status", json={"analyst": "lead", "status": "closed", "note": "fertig"}).status_code == 200

    detail = client.get(base).json()
    actions = [e["action"] for e in detail["investigation_log"]]
    assert actions == ["note", "status_change", "approval", "ai_analysis", "status_change",
                       "remediation_documented", "status_change"]
    assert detail["status"] == "closed"

    report = client.get(f"{base}/report.json").json()
    assert report["remediation"]["verification"].startswith("get-trail-status")
    assert report["ai_analysis"]["provider"] == "offline-template"
    html = client.get(f"{base}/report.html")
    assert html.status_code == 200 and "default-src 'none'" in html.headers["content-security-policy"]
    # Export itself is logged.
    assert client.get(base).json()["investigation_log"][-1]["action"] == "report_exported"


def test_invalid_input_is_rejected(demo):
    client, ds = demo
    inc_id = client.get(f"/api/datasets/{ds}/incidents").json()[0]["incident_id"]
    base = f"/api/datasets/{ds}/incidents/{inc_id}"
    assert client.post(f"{base}/status", json={"analyst": "a", "status": "deleted"}).status_code == 422
    assert client.post(f"{base}/log", json={"analyst": "", "note": "x"}).status_code == 422
    assert client.get(f"/api/datasets/{ds}/incidents/INC-nope").status_code == 404


def test_cases_survive_a_restart(tmp_path):
    url = f"sqlite:///{tmp_path / 'it.db'}"
    c1 = TestClient(create_app(Store(url)))
    ds = c1.post("/api/datasets/demo").json()["dataset_id"]
    inc_id = c1.get(f"/api/datasets/{ds}/incidents").json()[0]["incident_id"]
    c1.post(f"/api/datasets/{ds}/incidents/{inc_id}/status", json={"analyst": "a", "status": "investigating", "note": "x"})
    c2 = TestClient(create_app(Store(url)))
    detail = c2.get(f"/api/datasets/{ds}/incidents/{inc_id}").json()
    assert detail["status"] == "investigating" and len(detail["investigation_log"]) == 1
