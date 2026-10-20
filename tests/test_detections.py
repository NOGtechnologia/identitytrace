import json

from detections import DetectionConfig, Severity, run_detections
from parser.cloudtrail import parse_cloudtrail
from tests.conftest import policy, rec, user

ADMIN = "arn:aws:iam::aws:policy/AdministratorAccess"


def detect(records, config=None):
    return run_detections(parse_cloudtrail(json.dumps(records)).events, config)


def rule_ids(findings):
    return sorted(f.rule_id for f in findings)


def test_new_privileged_role_links_both_events():
    create = rec("CreateRole", user("alice"), params={"roleName": "r1", "assumeRolePolicyDocument": json.dumps(
        {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::111122223333:root"}, "Action": "sts:AssumeRole"}]})})
    attach = rec("AttachRolePolicy", user("alice"), time="2026-09-15T12:01:00Z", params={"roleName": "r1", "policyArn": ADMIN})
    findings = detect([create, attach])
    assert rule_ids(findings) == ["IT-001"]
    f = findings[0]
    assert f.event_ids == [create["eventID"], attach["eventID"]]
    assert "Neue privilegierte Rolle r1" in f.title
    assert any(ev.value == ADMIN for ev in f.evidence)


def test_trust_policy_for_foreign_account():
    r = rec("UpdateAssumeRolePolicy", user("alice"), params={"roleName": "r1", "policyDocument": json.dumps(
        {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::999988887777:root"}, "Action": "sts:AssumeRole"}]})})
    findings = detect([r])
    assert rule_ids(findings) == ["IT-001"]
    assert "999988887777" in findings[0].rationale


def test_non_privileged_attach_is_quiet():
    r = rec("AttachRolePolicy", user("alice"), params={"roleName": "r1", "policyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"})
    assert detect([r]) == []


def test_broad_inline_policy():
    r = rec("PutRolePolicy", user("bob"), params={"roleName": "app", "policyName": "x", "policyDocument": policy(["s3:GetObject", "iam:*"])})
    findings = detect([r])
    assert rule_ids(findings) == ["IT-002"]
    assert findings[0].targets == ["role:app"]
    assert findings[0].severity == Severity.HIGH


def test_full_wildcard_is_critical_and_url_encoded_documents_parse():
    from urllib.parse import quote
    r = rec("PutUserPolicy", user("bob"), params={"userName": "carol", "policyName": "x", "policyDocument": quote(policy("*"))})
    findings = detect([r])
    assert findings[0].severity == Severity.CRITICAL


def test_scoped_policy_is_quiet():
    r = rec("PutRolePolicy", user("bob"), params={"roleName": "app", "policyName": "x",
                                                  "policyDocument": policy("s3:GetObject", "arn:aws:s3:::bucket/*")})
    assert detect([r]) == []


def test_access_key_for_sensitive_account_by_name_and_by_history():
    by_name = rec("CreateAccessKey", user("helpdesk"), params={"userName": "break-glass-admin"},
                  response={"accessKey": {"accessKeyId": "AKIANEW"}})
    grant = rec("AttachUserPolicy", user("x"), time="2026-09-15T11:00:00Z", params={"userName": "ops", "policyArn": ADMIN})
    by_history = rec("CreateAccessKey", user("x"), params={"userName": "ops"})
    findings = [f for f in detect([by_name, grant, by_history]) if f.rule_id == "IT-003"]
    assert {f.targets[0] for f in findings} == {"user:break-glass-admin", "user:ops"}


def test_access_key_for_normal_user_is_quiet():
    assert detect([rec("CreateAccessKey", user("dev"))]) == []


def test_configured_sensitive_principal():
    cfg = DetectionConfig(sensitive_principals={"user:payroll"})
    findings = detect([rec("CreateAccessKey", user("hr"), params={"userName": "payroll"})], cfg)
    assert rule_ids(findings) == ["IT-003"]


def test_audit_logging_tampering():
    stop = rec("StopLogging", user("x"), source="cloudtrail.amazonaws.com", params={"name": "arn:aws:cloudtrail:eu-central-1:1:trail/main"})
    gd = rec("UpdateDetector", user("x"), source="guardduty.amazonaws.com", params={"detectorId": "d1", "enable": False})
    findings = detect([stop, gd])
    assert rule_ids(findings) == ["IT-004", "IT-004"]
    stop_f = next(f for f in findings if "gestoppt" in f.title)
    assert stop_f.severity == Severity.CRITICAL
    assert stop_f.title.endswith("main")
    assert any(ev.field == "eventTime" and ev.value for ev in stop_f.evidence)


def test_failed_attempt_is_lowered_and_labeled():
    r = rec("StopLogging", user("intern"), source="cloudtrail.amazonaws.com", params={"name": "t"}, error="AccessDenied")
    f = detect([r])[0]
    assert f.attempt_failed
    assert f.severity == Severity.HIGH
    assert f.title.startswith("Versuch:")


def test_self_privilege_modification():
    r = rec("AttachUserPolicy", user("mallory"), params={"userName": "mallory", "policyArn": ADMIN})
    findings = detect([r])
    assert rule_ids(findings) == ["IT-001", "IT-005"]
    assert next(f for f in findings if f.rule_id == "IT-005").severity == Severity.CRITICAL


def test_changing_someone_else_is_not_self_modification():
    r = rec("PutUserPolicy", user("admin"), params={"userName": "dev", "policyName": "p", "policyDocument": policy("s3:*")})
    assert "IT-005" not in rule_ids(detect([r]))


def test_burst_requires_multiple_rules_within_window():
    actor = user("ci")
    events = [
        rec("AttachUserPolicy", actor, time="2026-09-15T12:00:00Z", params={"userName": "b", "policyArn": ADMIN}),
        rec("PutUserPolicy", actor, time="2026-09-15T12:05:00Z", params={"userName": "b", "policyName": "p", "policyDocument": policy("*")}),
        rec("CreateAccessKey", actor, time="2026-09-15T12:10:00Z", params={"userName": "b"}),
    ]
    burst = [f for f in detect(events) if f.rule_id == "IT-006"]
    assert len(burst) == 1
    assert len(burst[0].event_ids) == 3

    spread = [dict(e, eventTime=f"2026-09-15T{10 + 2 * i:02d}:00:00Z") for i, e in enumerate(events)]
    assert not [f for f in detect(spread) if f.rule_id == "IT-006"]


def test_every_finding_explains_itself(demo_result):
    events = {e.event_id for e in demo_result.events}
    for f in demo_result.findings:
        assert f.event_ids and set(f.event_ids) <= events
        assert f.rationale and f.rule_name and f.evidence


def test_unusable_events_never_trigger_rules():
    r = rec("StopLogging", user("x"), source="cloudtrail.amazonaws.com", params={"name": "t"})
    del r["eventTime"]
    assert detect([r]) == []
