import json
from datetime import datetime, timezone

import pytest

from incident_reports.case import Case, CaseError
from incident_reports.report import build_report, render_html, render_json


def _chain(result):
    return next(i for i in result.incidents if "IT-006" in i.rule_ids)


def test_json_report_contains_timeline_evidence_and_severity(demo_result):
    inc = _chain(demo_result)
    report = json.loads(render_json(build_report(demo_result, inc.incident_id, dataset_name="demo")))
    assert report["incident"]["severity"] == "critical"
    assert len(report["timeline"]) == len(inc.timeline)
    assert report["evidence_events"] and all(e["event_id"] for e in report["evidence_events"])
    assert {"facts", "inferences", "gaps", "recommendations", "investigation_log", "data_quality"} <= set(report)
    assert "keine Änderungen an Cloud-Ressourcen" in report["disclaimer"]


def test_recommendations_are_safe(demo_result):
    inc = _chain(demo_result)
    recs = build_report(demo_result, inc.incident_id)["recommendations"]
    ids = {r["rec_id"] for r in recs}
    assert "review-key:AKIA5BACKUPOPNEW077" in ids
    assert any(r["rec_id"].startswith("revert-permissions:user:backup-operator") for r in recs)
    for r in recs:
        assert r["verify_steps"], "every recommendation starts with read-only verification"
        if r["change_steps"]:
            assert r["requires_approval"]
        assert r["approval"] is None


def test_case_workflow_logs_every_step_with_timestamp():
    case = Case("INC-1")
    case.record("anna", "note", "Schlüssel-Nutzung geprüft")
    case.transition("investigating", "anna", "Übernommen")
    case.approve("review-key:AKIA1", "lead", "Deaktivierung freigegeben")
    with pytest.raises(CaseError):
        case.transition("closed", "anna", "zu früh")
    case.transition("contained", "anna", "Schlüssel deaktiviert")
    case.transition("remediated", "anna", "Policy entfernt")
    with pytest.raises(CaseError):
        case.transition("closed", "anna", "ohne Doku")
    case.document_remediation("anna", "Schlüssel gelöscht, Policy entfernt", "list-access-keys zeigt nur alten Schlüssel")
    case.transition("closed", "lead", "abgeschlossen")
    assert case.status == "closed"
    assert [e.action for e in case.log] == ["note", "status_change", "approval", "status_change", "status_change",
                                            "remediation_documented", "status_change"]
    assert all(isinstance(e.timestamp, datetime) and e.timestamp.tzinfo for e in case.log)
    assert case.approvals["review-key:AKIA1"]["executed_by_tool"] is False


def test_false_positive_requires_reason():
    case = Case("INC-1")
    with pytest.raises(CaseError):
        case.transition("false_positive", "anna", "  ")
    case.transition("false_positive", "anna", "Genehmigter Change CHG-2231")
    assert case.status == "false_positive"


def test_report_includes_case_state(demo_result):
    inc = _chain(demo_result)
    case = Case(inc.incident_id)
    t = datetime(2026, 9, 15, 14, 0, tzinfo=timezone.utc)
    case.transition("investigating", "anna", "Start", at=t)
    case.approve("review-key:AKIA5BACKUPOPNEW077", "lead", "ok", at=t)
    report = build_report(demo_result, inc.incident_id, case)
    assert report["incident"]["status"] == "investigating"
    assert report["investigation_log"][0]["timestamp"] == "2026-09-15T14:00:00Z"
    rec = next(r for r in report["recommendations"] if r["rec_id"] == "review-key:AKIA5BACKUPOPNEW077")
    assert rec["approval"]["approved_by"] == "lead"
    html = render_html(report)
    assert "Freigegeben von lead" in html and "Zeitleiste" in html
