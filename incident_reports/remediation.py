"""Safe remediation recommendations.

IdentityTrace never changes cloud resources. Recommendations are text plus
CLI hints for the analyst. Each one starts with read-only verification;
state-changing steps are marked `requires_approval` and are run by a human
outside the tool. The result is then documented in the case log.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from correlation.models import Incident
from detections.models import Finding
from parser.models import Event


@dataclass
class Recommendation:
    rec_id: str
    title: str
    rationale: str
    verify_steps: list[str]  # read-only
    change_steps: list[str]  # state-changing, approval required
    requires_approval: bool = True
    related_finding_ids: list[str] = field(default_factory=list)


def _name(entity: str) -> str:
    return entity.split(":", 1)[-1]


def recommend(incident: Incident, findings: list[Finding], events: dict[str, Event]) -> list[Recommendation]:
    recs: list[Recommendation] = []
    seen: set[str] = set()

    def add(rec: Recommendation) -> None:
        if rec.rec_id not in seen:
            seen.add(rec.rec_id)
            recs.append(rec)

    own = [f for f in findings if f.finding_id in incident.finding_ids]
    for f in own:
        trigger = events.get(f.event_ids[-1])
        for target in f.targets:
            kind, name = (target.split(":", 1) + [""])[:2]
            if f.rule_id in {"IT-001", "IT-002", "IT-005"} and kind in {"user", "role", "group"}:
                cmd_kind = {"user": "user", "role": "role", "group": "group"}[kind]
                policy_arn = trigger.param("policyArn") if trigger else None
                policy_name = trigger.param("policyName") if trigger else None
                change = []
                if policy_arn:
                    change.append(f"aws iam detach-{cmd_kind}-policy --{cmd_kind}-name {name} --policy-arn {policy_arn}")
                if policy_name:
                    change.append(f"aws iam delete-{cmd_kind}-policy --{cmd_kind}-name {name} --policy-name {policy_name}")
                add(Recommendation(
                    rec_id=f"revert-permissions:{target}",
                    title=f"Berechtigungen von {target} prüfen und ggf. zurücksetzen",
                    rationale=f"{f.rule_id}: {f.rationale}",
                    verify_steps=[
                        f"aws iam list-attached-{cmd_kind}-policies --{cmd_kind}-name {name}",
                        f"aws iam list-{cmd_kind}-policies --{cmd_kind}-name {name}",
                        "Change-Ticket bzw. Freigabe für die Änderung suchen",
                    ],
                    change_steps=change or ["Vorherigen Policy-Stand aus IaC/Versionierung wiederherstellen"],
                    related_finding_ids=[f.finding_id],
                ))
        if f.rule_id == "IT-003" and trigger:
            key = (trigger.response_elements.get("accessKey") or {}).get("accessKeyId") if isinstance(trigger.response_elements.get("accessKey"), dict) else None
            user = trigger.param("userName") or trigger.actor_name
            add(Recommendation(
                rec_id=f"review-key:{key or user}",
                title=f"Neuen Schlüssel {key or ''} für {user} überprüfen",
                rationale=f.rationale,
                verify_steps=[
                    f"aws iam get-access-key-last-used --access-key-id {key}" if key else f"aws iam list-access-keys --user-name {user}",
                    f"Mit dem Kontoinhaber von {user} klären, ob der Schlüssel beauftragt war",
                ],
                change_steps=[
                    f"aws iam update-access-key --user-name {user} --access-key-id {key} --status Inactive" if key else "Schlüssel deaktivieren",
                    "Nach Bestätigung: Schlüssel löschen und betroffene Secrets rotieren",
                ],
                related_finding_ids=[f.finding_id],
            ))
        if f.rule_id == "IT-004" and trigger:
            trail = trigger.param("name", "trailName") or "<trail>"
            add(Recommendation(
                rec_id=f"restore-logging:{trail}",
                title="Protokollierung wiederherstellen und Lücke bewerten",
                rationale=f.rationale,
                verify_steps=[
                    f"aws cloudtrail get-trail-status --name {trail}",
                    f"aws cloudtrail get-event-selectors --trail-name {trail}",
                    "Für die Zeit ohne Protokollierung andere Quellen prüfen (Config, VPC Flow Logs, Anwendungslogs)",
                ],
                change_steps=[] if f.attempt_failed else [
                    f"aws cloudtrail start-logging --name {trail}",
                    "Event-Selektoren und Multi-Region-Einstellung aus dem Soll-Zustand wiederherstellen",
                ],
                requires_approval=not f.attempt_failed,
                related_finding_ids=[f.finding_id],
            ))
    for actor in incident.actors:
        if actor.startswith("user:"):
            add(Recommendation(
                rec_id=f"contain-actor:{actor}",
                title=f"Zugangsdaten von {actor} prüfen",
                rationale="Der Akteur hat auslösende Ereignisse verursacht. Ob die Zugangsdaten kompromittiert sind, ist offen.",
                verify_steps=[
                    f"aws iam list-access-keys --user-name {_name(actor)}",
                    f"aws iam list-mfa-devices --user-name {_name(actor)}",
                    "Mit dem Kontoinhaber Rücksprache halten (bekannter Change? eigene IP?)",
                ],
                change_steps=[
                    f"Aktive Schlüssel von {_name(actor)} deaktivieren (update-access-key --status Inactive)",
                    "Konsolen-Passwort zurücksetzen und MFA neu registrieren",
                ],
            ))
    if incident.patterns:
        add(Recommendation(
            rec_id="scope-data-access",
            title="Umfang des Datenzugriffs bestimmen",
            rationale="Das erkannte Muster umfasst Zugriffe auf sensible Ressourcen.",
            verify_steps=[
                "Betroffene Secrets und Objekte aus der Zeitleiste auflisten",
                "S3-Server-Access-Logs bzw. Data-Events für die betroffenen Buckets prüfen",
            ],
            change_steps=["Gelesene Secrets rotieren", "Datenschutz-/Meldepflichten prüfen lassen"],
        ))
    return recs
