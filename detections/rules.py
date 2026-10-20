"""Explainable detection rules.

Every rule is a small, readable function over normalized events. A finding
always lists the triggering event IDs, the concrete field values (evidence)
and a rationale that says *why* the rule fired. See docs/detection-rules.md.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Callable

from detections.config import DetectionConfig
from detections.models import Evidence, Finding, Severity
from detections.policy import broad_grants, has_full_admin, load_policy, untrusted_principals
from parser.models import Event

PERMISSION_CHANGE_EVENTS = {
    "AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy",
    "PutUserPolicy", "PutRolePolicy", "PutGroupPolicy",
    "AddUserToGroup", "UpdateAssumeRolePolicy", "CreatePolicyVersion",
}
INLINE_POLICY_EVENTS = {"PutUserPolicy", "PutRolePolicy", "PutGroupPolicy", "CreatePolicy", "CreatePolicyVersion"}
ATTACH_EVENTS = {"AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy"}

AUDIT_TAMPERING = {
    ("cloudtrail.amazonaws.com", "StopLogging"): (Severity.CRITICAL, "CloudTrail-Protokollierung gestoppt"),
    ("cloudtrail.amazonaws.com", "DeleteTrail"): (Severity.CRITICAL, "CloudTrail-Trail gelöscht"),
    ("cloudtrail.amazonaws.com", "UpdateTrail"): (Severity.HIGH, "CloudTrail-Trail-Konfiguration geändert"),
    ("cloudtrail.amazonaws.com", "PutEventSelectors"): (Severity.HIGH, "CloudTrail-Event-Selektoren geändert"),
    ("cloudtrail.amazonaws.com", "PutInsightSelectors"): (Severity.MEDIUM, "CloudTrail-Insights geändert"),
    ("config.amazonaws.com", "StopConfigurationRecorder"): (Severity.HIGH, "AWS-Config-Recorder gestoppt"),
    ("config.amazonaws.com", "DeleteConfigurationRecorder"): (Severity.HIGH, "AWS-Config-Recorder gelöscht"),
    ("config.amazonaws.com", "DeleteDeliveryChannel"): (Severity.HIGH, "AWS-Config-Delivery-Channel gelöscht"),
    ("guardduty.amazonaws.com", "DeleteDetector"): (Severity.HIGH, "GuardDuty-Detector gelöscht"),
    ("ec2.amazonaws.com", "DeleteFlowLogs"): (Severity.MEDIUM, "VPC-Flow-Logs gelöscht"),
    ("logs.amazonaws.com", "DeleteLogGroup"): (Severity.MEDIUM, "CloudWatch-Log-Gruppe gelöscht"),
}


@dataclass
class RuleContext:
    config: DetectionConfig
    # entity -> earliest time it received privileged or broad permissions in this dataset
    privileged_since: dict[str, datetime]

    def is_sensitive(self, entity: str, at: datetime | None) -> tuple[bool, str]:
        if entity == "root":
            return True, "Root-Konto"
        if entity in self.config.sensitive_principals:
            return True, "in der Konfiguration als sensibel hinterlegt"
        name = entity.split(":", 1)[-1].lower()
        for pattern in self.config.sensitive_name_patterns:
            if pattern.lower() in name:
                return True, f"Name enthält \"{pattern}\""
        since = self.privileged_since.get(entity)
        if since is not None and (at is None or since <= at):
            return True, f"hat seit {since.isoformat()} privilegierte Berechtigungen (laut Log)"
        return False, ""


def targets_of(event: Event) -> list[str]:
    targets = []
    user = event.param("userName")
    role = event.param("roleName")
    group = event.param("groupName")
    if user:
        targets.append(f"user:{user}")
    if role:
        targets.append(f"role:{role}")
    if group:
        targets.append(f"group:{group}")
    return targets


def _span(events: list[Event]) -> tuple[datetime | None, datetime | None]:
    times = [e.timestamp for e in events if e.timestamp]
    return (min(times), max(times)) if times else (None, None)


def _finding(rule: "Rule", severity: Severity, title: str, description: str, rationale: str,
             events: list[Event], targets: list[str], evidence: list[Evidence]) -> Finding:
    trigger = events[-1]
    failed = all(not e.succeeded for e in events)
    if failed:
        severity = severity.lowered()
        title = f"Versuch: {title}"
        rationale += f" Die Anfrage schlug fehl ({trigger.error_code}); es wurde keine Änderung wirksam, der Versuch selbst ist aber auffällig."
    first, last = _span(events)
    ids = [e.event_id for e in events]
    return Finding(
        finding_id=Finding.make_id(rule.rule_id, ids),
        rule_id=rule.rule_id,
        rule_name=rule.name,
        severity=severity,
        title=title,
        description=description,
        rationale=rationale,
        event_ids=ids,
        actor=trigger.actor,
        targets=targets,
        first_seen=first,
        last_seen=last,
        evidence=evidence,
        attempt_failed=failed,
        mitre_attack=list(rule.mitre),
    )


@dataclass
class Rule:
    rule_id: str
    name: str
    summary: str
    mitre: tuple[str, ...]
    evaluate: Callable[["Rule", list[Event], RuleContext], list[Finding]]


# ---------------------------------------------------------------- IT-001
def _privileged_role_change(rule: Rule, events: list[Event], ctx: RuleContext) -> list[Finding]:
    findings = []
    created_roles: dict[str, Event] = {}
    for e in events:
        if e.event_name == "CreateRole" and e.succeeded and e.param("roleName"):
            created_roles[e.param("roleName")] = e
            trust = load_policy(e.param("assumeRolePolicyDocument"))
            outsiders = untrusted_principals(trust, ctx.config.trusted_account_ids or {e.account_id or ""})
            if outsiders:
                findings.append(_finding(
                    rule, Severity.HIGH,
                    f"Neue Rolle {e.param('roleName')} vertraut externen Prinzipalen",
                    "Eine neu angelegte Rolle kann von einem fremden Konto oder öffentlich übernommen werden.",
                    f"Die Trust-Policy erlaubt sts:AssumeRole für {', '.join(outsiders)}.",
                    [e], [f"role:{e.param('roleName')}"],
                    [Evidence(e.event_id, "requestParameters.assumeRolePolicyDocument", outsiders)],
                ))
        elif e.event_name in ATTACH_EVENTS and e.param("policyArn") in ctx.config.privileged_managed_policies:
            policy = e.param("policyArn")
            targets = targets_of(e)
            role = e.param("roleName")
            chain = [e]
            title = f"Privilegierte Policy an {', '.join(targets) or 'unbekanntes Ziel'} angehängt"
            description = "Eine Identität erhielt eine verwaltete Policy mit administrativen Rechten."
            if role and role in created_roles and e.timestamp and created_roles[role].timestamp \
                    and e.timestamp - created_roles[role].timestamp <= timedelta(hours=24):
                chain = [created_roles[role], e]
                title = f"Neue privilegierte Rolle {role} angelegt"
                description = "Eine Rolle wurde neu angelegt und kurz darauf mit administrativen Rechten ausgestattet."
            findings.append(_finding(
                rule, Severity.HIGH, title, description,
                f"{e.event_name} mit policyArn {policy}, die in der Liste privilegierter Policies steht.",
                chain, targets,
                [Evidence(e.event_id, "requestParameters.policyArn", policy)]
                + [Evidence(c.event_id, "eventName", c.event_name) for c in chain if c is not e],
            ))
        elif e.event_name == "UpdateAssumeRolePolicy":
            trust = load_policy(e.param("policyDocument"))
            outsiders = untrusted_principals(trust, ctx.config.trusted_account_ids or {e.account_id or ""})
            if outsiders:
                findings.append(_finding(
                    rule, Severity.HIGH,
                    f"Trust-Policy von {e.param('roleName')} für externe Prinzipale geöffnet",
                    "Die Vertrauensbeziehung einer bestehenden Rolle wurde erweitert.",
                    f"Die neue Trust-Policy erlaubt sts:AssumeRole für {', '.join(outsiders)}.",
                    [e], targets_of(e),
                    [Evidence(e.event_id, "requestParameters.policyDocument", outsiders)],
                ))
    return findings


# ---------------------------------------------------------------- IT-002
def _overly_broad_permissions(rule: Rule, events: list[Event], ctx: RuleContext) -> list[Finding]:
    findings = []
    for e in events:
        if e.event_name not in INLINE_POLICY_EVENTS:
            continue
        if e.event_name == "CreatePolicyVersion" and str(e.param("setAsDefault")).lower() != "true":
            continue
        policy = load_policy(e.param("policyDocument"))
        reasons = broad_grants(policy, ctx.config.sensitive_services)
        if not reasons:
            continue
        severity = Severity.CRITICAL if has_full_admin(policy) else Severity.HIGH
        targets = targets_of(e) or ([f"policy:{e.param('policyArn') or e.param('policyName')}"])
        findings.append(_finding(
            rule, severity,
            f"Ungewöhnlich weitreichende Berechtigungen für {', '.join(targets)}",
            "Eine Policy gewährt Wildcard-Rechte auf alle Aktionen oder auf sicherheitskritische Dienste.",
            f"{e.event_name} enthält: {'; '.join(reasons)}.",
            [e], targets,
            [Evidence(e.event_id, "requestParameters.policyDocument", reasons)]
            + ([Evidence(e.event_id, "requestParameters.policyName", e.param("policyName"))] if e.param("policyName") else []),
        ))
    return findings


# ---------------------------------------------------------------- IT-003
def _sensitive_access_key(rule: Rule, events: list[Event], ctx: RuleContext) -> list[Finding]:
    findings = []
    for e in events:
        if e.event_name != "CreateAccessKey":
            continue
        target_user = e.param("userName") or (e.actor_name if e.actor_type == "IAMUser" else None)
        target = f"user:{target_user}" if target_user else (e.actor or "unknown")
        if e.actor_type == "Root" and not e.param("userName"):
            target = "root"
        sensitive, why = ctx.is_sensitive(target, e.timestamp)
        if not sensitive:
            continue
        created_by_other = e.actor != target
        new_key = (e.response_elements.get("accessKey") or {}).get("accessKeyId") if isinstance(e.response_elements.get("accessKey"), dict) else None
        rationale = f"CreateAccessKey für {target}; das Konto gilt als sensibel ({why})."
        if created_by_other:
            rationale += f" Der Schlüssel wurde von einer anderen Identität ({e.actor}) erzeugt."
        evidence = [Evidence(e.event_id, "requestParameters.userName", target_user)]
        if new_key:
            evidence.append(Evidence(e.event_id, "responseElements.accessKey.accessKeyId", new_key))
        findings.append(_finding(
            rule, Severity.HIGH,
            f"Neuer API-Schlüssel für sensibles Konto {target}",
            "Für ein privilegiertes oder besonders schützenswertes Konto wurde ein langlebiger Zugangsschlüssel erzeugt.",
            rationale, [e], [target], evidence,
        ))
    return findings


# ---------------------------------------------------------------- IT-004
def _audit_logging_tampering(rule: Rule, events: list[Event], ctx: RuleContext) -> list[Finding]:
    findings = []
    for e in events:
        key = (e.event_source, e.event_name)
        if key == ("guardduty.amazonaws.com", "UpdateDetector") and str(e.param("enable")).lower() == "false":
            severity, label = Severity.HIGH, "GuardDuty-Detector deaktiviert"
        elif key in AUDIT_TAMPERING:
            severity, label = AUDIT_TAMPERING[key]
        else:
            continue
        resource = str(e.param("name", "trailName", "detectorId", "configurationRecorderName", "logGroupName") or "unbekannt")
        if resource.startswith("arn:") and "/" in resource:
            resource = resource.rsplit("/", 1)[-1]
        findings.append(_finding(
            rule, severity, f"{label}: {resource}",
            "Eine Änderung an der Sicherheitsprotokollierung kann Spuren verwischen und schafft blinde Flecken.",
            f"{e.event_source} {e.event_name} am {e.timestamp.isoformat() if e.timestamp else 'unbekannten Zeitpunkt'} durch {e.actor}.",
            [e], [f"logging:{resource}"],
            [Evidence(e.event_id, "eventName", e.event_name), Evidence(e.event_id, "eventTime", e.timestamp.isoformat() if e.timestamp else None)],
        ))
    return findings


# ---------------------------------------------------------------- IT-005
def _self_privilege_modification(rule: Rule, events: list[Event], ctx: RuleContext) -> list[Finding]:
    findings = []
    for e in events:
        if e.event_name not in PERMISSION_CHANGE_EVENTS or not e.actor:
            continue
        if e.actor not in targets_of(e):
            continue
        policy_arn = e.param("policyArn")
        doc = load_policy(e.param("policyDocument"))
        privileged = policy_arn in ctx.config.privileged_managed_policies or has_full_admin(doc)
        findings.append(_finding(
            rule, Severity.CRITICAL if privileged else Severity.HIGH,
            f"{e.actor} ändert die eigenen Berechtigungen",
            "Eine Identität hat ihre eigenen Rechte verändert. Das umgeht das Vier-Augen-Prinzip.",
            f"Akteur ({e.actor}) und Ziel von {e.event_name} sind identisch."
            + (" Die neue Berechtigung ist administrativ." if privileged else ""),
            [e], [e.actor],
            [Evidence(e.event_id, "userIdentity", e.actor), Evidence(e.event_id, "requestParameters", targets_of(e))],
        ))
    return findings


RULES: list[Rule] = [
    Rule("IT-001", "Privilegierte Rolle angelegt oder verändert",
         "Admin-Policy angehängt, neue Rolle mit Admin-Rechten oder Trust-Policy für Fremde.",
         ("T1098", "T1098.003"), _privileged_role_change),
    Rule("IT-002", "Ungewöhnlich weitreichende Berechtigungen",
         "Inline- oder verwaltete Policy mit Action \"*\", NotAction oder Wildcards auf sensible Dienste.",
         ("T1098",), _overly_broad_permissions),
    Rule("IT-003", "API-Schlüssel für sensibles Konto",
         "CreateAccessKey für Root, Admin-Konten oder Konten, die im Log privilegiert wurden.",
         ("T1098.001",), _sensitive_access_key),
    Rule("IT-004", "Audit-Protokollierung deaktiviert oder verändert",
         "StopLogging, DeleteTrail, UpdateTrail, Event-Selektoren, Config/GuardDuty/Flow-Logs.",
         ("T1562.008",), _audit_logging_tampering),
    Rule("IT-005", "Benutzer verändert eigene Berechtigungen",
         "Akteur und Ziel einer Berechtigungsänderung sind identisch.",
         ("T1098",), _self_privilege_modification),
]

BURST_RULE_ID = "IT-006"
BURST_RULE_NAME = "Häufung auffälliger Ereignisse"
