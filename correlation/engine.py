"""Incident reconstruction.

Findings are linked through shared identities: the actor of a finding, the
identities it changed, access keys created for them and every later call
made with those keys. Each connected group of findings becomes an incident
with a timeline that separates

  * facts       – literal log content,
  * inferences  – conclusions IdentityTrace draws (with confidence),
  * gaps        – information that is missing or unreliable.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from datetime import datetime, timedelta

from correlation.models import Incident, Statement, TimelineEntry
from detections.config import DetectionConfig
from detections.models import Finding, Severity
from detections.rules import targets_of
from parser.models import DataQualityReport, Event

SENSITIVE_ACCESS = {
    ("secretsmanager.amazonaws.com", "GetSecretValue"),
    ("secretsmanager.amazonaws.com", "ListSecrets"),
    ("ssm.amazonaws.com", "GetParameter"),
    ("ssm.amazonaws.com", "GetParameters"),
    ("kms.amazonaws.com", "Decrypt"),
    ("s3.amazonaws.com", "GetObject"),
}
RECON = {
    ("sts.amazonaws.com", "GetCallerIdentity"),
    ("iam.amazonaws.com", "ListUsers"),
    ("iam.amazonaws.com", "ListRoles"),
    ("iam.amazonaws.com", "ListAttachedUserPolicies"),
    ("iam.amazonaws.com", "GetAccountAuthorizationDetails"),
}
AUTH = {"ConsoleLogin", "AssumeRole", "GetSessionToken", "GetFederationToken"}
PRIVILEGE_RULES = {"IT-001", "IT-002", "IT-005"}
LOGGING_BLINDING = {"StopLogging", "DeleteTrail", "PutEventSelectors", "UpdateTrail"}


class _UnionFind:
    def __init__(self) -> None:
        self.parent: dict[str, str] = {}

    def find(self, x: str) -> str:
        self.parent.setdefault(x, x)
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra


def _kind(e: Event) -> str:
    key = (e.event_source, e.event_name)
    if key in SENSITIVE_ACCESS:
        return "sensitive_access"
    if key in RECON:
        return "reconnaissance"
    if e.event_name in AUTH:
        return "authentication"
    if e.read_only is False:
        return "change"
    return "context"


def _new_key(e: Event) -> str | None:
    key = e.response_elements.get("accessKey")
    return key.get("accessKeyId") if isinstance(key, dict) else None


def _identity_entities(findings: list[Finding], events: list[Event]) -> _UnionFind:
    uf = _UnionFind()
    by_id = {e.event_id: e for e in events}
    for f in findings:
        if f.actor:
            uf.find(f.actor)
        for event_id in f.event_ids:
            e = by_id.get(event_id)
            if e is None or not e.actor:
                continue
            for target in targets_of(e):
                uf.union(e.actor, target)
    for e in events:
        if not e.succeeded:
            continue
        if e.event_name == "CreateAccessKey" and _new_key(e):
            owner = e.param("userName") or e.actor_name
            if owner:
                uf.union(f"user:{owner}" if e.param("userName") or e.actor_type == "IAMUser" else e.actor, f"key:{_new_key(e)}")
        if e.access_key_id and e.access_key_id.startswith("AKIA") and e.actor:
            # Long-term keys belong to exactly one identity; temporary ASIA keys are linked via the role.
            uf.union(f"key:{e.access_key_id}", e.actor)
    return uf


def _ts(e: Event) -> str:
    return e.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC") if e.timestamp else "ohne Zeitstempel"


def _fact_for(e: Event) -> str:
    outcome = "erfolgreich" if e.succeeded else f"abgelehnt ({e.error_code})"
    target = ", ".join(targets_of(e))
    extra = f" auf {target}" if target else ""
    if e.param("policyArn"):
        extra += f", policyArn={e.param('policyArn')}"
    if e.param("secretId"):
        extra += f", secretId={e.param('secretId')}"
    if e.param("bucketName"):
        extra += f", bucket={e.param('bucketName')}/{e.param('key') or ''}"
    if _new_key(e):
        extra += f", neuer Schlüssel={_new_key(e)}"
    key = f" mit Schlüssel {e.access_key_id}" if e.access_key_id else ""
    return f"{_ts(e)}: {e.actor} rief {e.event_source} {e.event_name}{extra} auf{key}, Quell-IP {e.source_ip or 'unbekannt'}, {outcome}."


def _split_by_time(findings: list[Finding], gap: timedelta) -> list[list[Finding]]:
    ordered = sorted(findings, key=lambda f: f.first_seen.isoformat() if f.first_seen else "")
    groups: list[list[Finding]] = []
    last: datetime | None = None
    for f in ordered:
        if groups and last and f.first_seen and f.first_seen - last <= gap:
            groups[-1].append(f)
        else:
            groups.append([f])
        if f.last_seen and (last is None or f.last_seen > last):
            last = f.last_seen
    return groups


def correlate(
    events: list[Event],
    findings: list[Finding],
    quality: DataQualityReport,
    config: DetectionConfig | None = None,
) -> list[Incident]:
    config = config or DetectionConfig()
    usable = [e for e in events if e.is_usable]
    by_id = {e.event_id: e for e in usable}
    uf = _identity_entities(findings, usable)

    components: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        anchor = f.actor or (f.targets[0] if f.targets else f.finding_id)
        components[uf.find(anchor)].append(f)

    members: dict[str, set[str]] = defaultdict(set)
    for entity in list(uf.parent):
        members[uf.find(entity)].add(entity)

    incidents = []
    for root, comp_findings in components.items():
        for group in _split_by_time(comp_findings, timedelta(hours=config.incident_split_hours)):
            incidents.append(_build_incident(group, members[root], usable, by_id, quality, config))
    incidents.sort(key=lambda i: (-i.severity.rank, i.first_seen.isoformat() if i.first_seen else ""))
    return incidents


def _build_incident(
    findings: list[Finding],
    entities: set[str],
    events: list[Event],
    by_id: dict[str, Event],
    quality: DataQualityReport,
    config: DetectionConfig,
) -> Incident:
    trigger_ids: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        for event_id in f.event_ids:
            trigger_ids[event_id].append(f)

    starts = [f.first_seen for f in findings if f.first_seen]
    ends = [f.last_seen for f in findings if f.last_seen]
    window_start = min(starts) - timedelta(minutes=config.context_before_minutes)
    window_end = max(ends) + timedelta(minutes=config.context_after_minutes)

    actor_entities = {e for e in entities if not e.startswith("key:")}
    key_entities = {e[4:] for e in entities if e.startswith("key:")}

    selected: list[Event] = []
    for e in events:
        if e.event_id in trigger_ids:
            selected.append(e)
            continue
        if not (window_start <= e.timestamp <= window_end):
            continue
        belongs = e.actor in actor_entities or (e.access_key_id in key_entities)
        if belongs and (_kind(e) != "context"):
            selected.append(e)
    selected.sort(key=lambda e: (e.timestamp, e.record_index))
    selected = selected[:200]

    timeline = [
        TimelineEntry(
            event_id=e.event_id,
            timestamp=e.timestamp,
            event_name=e.event_name,
            event_source=e.event_source,
            actor=e.actor,
            source_ip=e.source_ip,
            access_key_id=e.access_key_id,
            outcome="success" if e.succeeded else str(e.error_code),
            kind="detection" if e.event_id in trigger_ids else _kind(e),
            finding_ids=[f.finding_id for f in trigger_ids.get(e.event_id, [])],
            rule_ids=sorted({f.rule_id for f in trigger_ids.get(e.event_id, [])}),
            instruction_like_fields=list(e.instruction_like_fields),
        )
        for e in selected
    ]

    facts = [Statement(_fact_for(e), [e.event_id]) for e in selected]
    inferences, patterns = _inferences(findings, selected, events, by_id)
    gaps = _gaps(findings, selected, events, quality, window_start, window_end, by_id)

    rule_ids = sorted({f.rule_id for f in findings})
    severity = Severity.max([f.severity for f in findings])
    if len(patterns) >= 1 and "Rechteausweitung → neuer Zugang → Zugriff auf sensible Daten" in patterns:
        severity = Severity.CRITICAL

    concrete = [f for f in findings if f.rule_id != "IT-006"] or findings
    primary = sorted(concrete, key=lambda f: (-f.severity.rank, f.first_seen.isoformat() if f.first_seen else ""))[0]
    actors = sorted({f.actor for f in findings if f.actor})
    if patterns:
        title = f"{patterns[0]} ({', '.join(actors)})"
    elif len(findings) == 1:
        title = primary.title
    else:
        title = f"{primary.title} (+{len(findings) - 1} weitere Findings)"
    digest = hashlib.sha256("|".join(sorted(f.finding_id for f in findings)).encode()).hexdigest()[:10]

    return Incident(
        incident_id=f"INC-{digest}",
        title=title,
        severity=severity,
        first_seen=min((t.timestamp for t in timeline if t.timestamp), default=None),
        last_seen=max((t.timestamp for t in timeline if t.timestamp), default=None),
        actors=actors,
        entities=sorted(entities),
        finding_ids=[f.finding_id for f in findings],
        rule_ids=rule_ids,
        patterns=patterns,
        timeline=timeline,
        facts=facts,
        inferences=inferences,
        gaps=gaps,
    )


def _inferences(findings: list[Finding], selected: list[Event], all_events: list[Event],
                by_id: dict[str, Event]) -> tuple[list[Statement], list[str]]:
    out: list[Statement] = []
    patterns: list[str] = []
    rule_ids = {f.rule_id for f in findings}

    # 1. Newly created keys and where they were used.
    used_new_key_for_sensitive = False
    for e in selected:
        new_key = _new_key(e) if e.event_name == "CreateAccessKey" and e.succeeded else None
        if not new_key:
            continue
        uses = [u for u in all_events if u.access_key_id == new_key]
        if not uses:
            out.append(Statement(
                f"Der Schlüssel {new_key} wurde erzeugt, im importierten Zeitraum aber nicht verwendet.",
                [e.event_id], "hoch"))
            continue
        ips = sorted({u.source_ip for u in uses if u.source_ip})
        sensitive = [u for u in uses if _kind(u) == "sensitive_access"]
        used_new_key_for_sensitive |= bool(sensitive)
        text = (f"Der am {_ts(e)} erzeugte Schlüssel {new_key} wurde {len(uses)}-mal verwendet "
                f"(erstmals {_ts(uses[0])}, IPs: {', '.join(ips)}).")
        if sensitive:
            text += f" Darunter {len(sensitive)} Zugriffe auf sensible Ressourcen ({', '.join(sorted({u.event_name for u in sensitive}))})."
        out.append(Statement(text, [e.event_id] + [u.event_id for u in uses[:10]], "hoch"))

    # 2. Source IPs never seen for the same actor outside this incident.
    selected_ids = {e.event_id for e in selected}
    for actor in sorted({f.actor for f in findings if f.actor}):
        inside = {e.source_ip for e in selected if e.actor == actor and e.source_ip}
        outside = {e.source_ip for e in all_events if e.actor == actor and e.event_id not in selected_ids and e.source_ip}
        new_ips = sorted(inside - outside)
        if new_ips and outside:
            basis = [e.event_id for e in selected if e.actor == actor and e.source_ip in new_ips][:10]
            out.append(Statement(
                f"{actor} handelte im Vorfall von {', '.join(new_ips)}; diese IP(s) kommen für {actor} sonst im "
                f"importierten Zeitraum nicht vor (sonst: {', '.join(sorted(outside)[:5])}). Möglicher Zugriff "
                f"durch Dritte; die Basislinie umfasst nur den importierten Zeitraum.", basis, "mittel"))

    # 3. Recognized attack patterns.
    if rule_ids & PRIVILEGE_RULES and "IT-003" in rule_ids and used_new_key_for_sensitive:
        patterns.append("Rechteausweitung → neuer Zugang → Zugriff auf sensible Daten")
        out.append(Statement(
            "Die Abfolge aus Rechteausweitung, neuem Zugangsschlüssel und anschließendem Zugriff auf sensible "
            "Ressourcen ist typisch für eine Kontoübernahme mit Persistenz. Ob ein autorisierter Change vorlag, "
            "lässt sich aus den Logs nicht entscheiden.",
            [eid for f in findings for eid in f.event_ids][:15], "mittel"))
    tamper = [f for f in findings if f.rule_id == "IT-004" and not f.attempt_failed]
    others = [f for f in findings if f.rule_id not in {"IT-004", "IT-006"}]
    if tamper and others and min(t.first_seen for t in tamper) >= min(o.first_seen for o in others):
        patterns.append("Spurenverwischung nach Änderung")
        out.append(Statement(
            "Die Protokollierung wurde nach anderen auffälligen Änderungen manipuliert. Das spricht für den "
            "Versuch, weitere Aktivität zu verbergen.",
            [eid for f in tamper for eid in f.event_ids], "mittel"))
    if findings and all(f.attempt_failed for f in findings):
        out.append(Statement(
            "Alle auslösenden Anfragen wurden abgelehnt. Mögliche Ursachen sind Erkundung durch einen "
            "Angreifer oder ein Bedienfehler; die Logs unterscheiden das nicht.",
            [eid for f in findings for eid in f.event_ids], "niedrig"))
    if any(by_id[eid].instruction_like_fields for f in findings for eid in f.event_ids if eid in by_id):
        out.append(Statement(
            "Mindestens ein auslösendes Ereignis enthält anweisungsartigen Text in Logfeldern. Er wurde als Daten "
            "behandelt und hat die Bewertung nicht beeinflusst. Solcher Text ist selbst ein Hinweis auf Manipulation.",
            [eid for f in findings for eid in f.event_ids if eid in by_id and by_id[eid].instruction_like_fields], "mittel"))
    return out, patterns


def _gaps(findings: list[Finding], selected: list[Event], all_events: list[Event], quality: DataQualityReport,
          start: datetime, end: datetime, by_id: dict[str, Event]) -> list[Statement]:
    gaps: list[Statement] = []
    for gap in quality.time_gaps:
        if gap.start <= end and gap.end >= start:
            gaps.append(Statement(
                f"Zwischen {gap.start:%Y-%m-%d %H:%M} und {gap.end:%Y-%m-%d %H:%M} UTC liegen keine Ereignisse vor "
                f"({gap.duration_minutes:.0f} Minuten). Aktivität in diesem Zeitraum ist unbekannt."))
    unplaceable = quality.unusable_events
    if unplaceable:
        gaps.append(Statement(
            f"{unplaceable} Datensätze im Import sind unvollständig oder fehlerhaft (ohne Zeit, Akteur oder "
            f"Ereignisname) und konnten nicht zugeordnet werden. Sie könnten zu diesem Vorfall gehören."))
    for f in findings:
        e = by_id.get(f.event_ids[-1])
        if f.rule_id == "IT-004" and not f.attempt_failed and e and e.event_name in LOGGING_BLINDING:
            gaps.append(Statement(
                f"Ab {_ts(e)} ist die Protokollierung möglicherweise eingeschränkt ({e.event_name}). Fehlende "
                f"Ereignisse danach beweisen keine Inaktivität.", [e.event_id]))
    if not quality.has_data_events:
        gaps.append(Statement("Der Import enthält keine Data-Events. Zugriffe auf S3-Objekte oder Lambda-Aufrufe sind deshalb nicht sichtbar."))
    for actor in sorted({f.actor for f in findings if f.actor}):
        gaps.append(Statement(
            f"Wie {actor} an die verwendeten Zugangsdaten kam, geht aus CloudTrail allein nicht hervor "
            f"(Endpoint-, IdP- oder VPN-Logs fehlen)."))
    return gaps
