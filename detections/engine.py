from __future__ import annotations

from datetime import datetime, timedelta

from detections.config import DetectionConfig
from detections.models import Evidence, Finding, Severity
from detections.policy import broad_grants, load_policy
from detections.rules import (
    ATTACH_EVENTS,
    BURST_RULE_ID,
    BURST_RULE_NAME,
    INLINE_POLICY_EVENTS,
    RULES,
    RuleContext,
    targets_of,
)
from parser.models import Event


def privileged_since(events: list[Event], config: DetectionConfig) -> dict[str, datetime]:
    """When did each identity first receive privileged permissions (according to the log)?"""
    since: dict[str, datetime] = {}
    for e in events:
        if not e.succeeded or e.timestamp is None:
            continue
        granted = False
        if e.event_name in ATTACH_EVENTS and e.param("policyArn") in config.privileged_managed_policies:
            granted = True
        elif e.event_name in INLINE_POLICY_EVENTS and broad_grants(load_policy(e.param("policyDocument")), config.sensitive_services):
            granted = True
        if granted:
            for target in targets_of(e):
                if target not in since or e.timestamp < since[target]:
                    since[target] = e.timestamp
    return since


def _burst_findings(findings: list[Finding], events_by_id: dict[str, Event], config: DetectionConfig) -> list[Finding]:
    window = timedelta(minutes=config.burst_window_minutes)
    by_actor: dict[str, list[tuple[datetime, str, str]]] = {}
    for f in findings:
        for event_id in f.event_ids:
            e = events_by_id.get(event_id)
            if e and e.timestamp and f.actor:
                by_actor.setdefault(f.actor, []).append((e.timestamp, event_id, f.rule_id))

    bursts = []
    for actor, items in by_actor.items():
        items = sorted(set(items))
        best: list[tuple[datetime, str, str]] = []
        start = 0
        for end in range(len(items)):
            while items[end][0] - items[start][0] > window:
                start += 1
            current = items[start:end + 1]
            if len({i[1] for i in current}) > len({i[1] for i in best}):
                best = current
        event_ids = sorted({i[1] for i in best}, key=lambda eid: events_by_id[eid].timestamp)
        rule_ids = sorted({i[2] for i in best})
        if len(event_ids) < config.burst_min_events or len(rule_ids) < config.burst_min_rules:
            continue
        first, last = best[0][0], best[-1][0]
        minutes = round((last - first).total_seconds() / 60, 1)
        bursts.append(Finding(
            finding_id=Finding.make_id(BURST_RULE_ID, event_ids),
            rule_id=BURST_RULE_ID,
            rule_name=BURST_RULE_NAME,
            severity=Severity.CRITICAL,
            title=f"{len(event_ids)} auffällige Ereignisse von {actor} in {minutes} Minuten",
            description="Mehrere unabhängige Regeln schlugen für dieselbe Identität in kurzer Zeit an.",
            rationale=(f"{len(event_ids)} Ereignisse aus den Regeln {', '.join(rule_ids)} innerhalb von "
                       f"{config.burst_window_minutes} Minuten (Schwelle: {config.burst_min_events} Ereignisse, "
                       f"{config.burst_min_rules} Regeln)."),
            event_ids=event_ids,
            actor=actor,
            targets=[],
            first_seen=first,
            last_seen=last,
            evidence=[Evidence(eid, "eventName", events_by_id[eid].event_name) for eid in event_ids],
            mitre_attack=[],
        ))
    return bursts


def run_detections(events: list[Event], config: DetectionConfig | None = None) -> list[Finding]:
    config = config or DetectionConfig()
    usable = [e for e in events if e.is_usable]
    ctx = RuleContext(config=config, privileged_since=privileged_since(usable, config))
    findings: list[Finding] = []
    for rule in RULES:
        findings.extend(rule.evaluate(rule, usable, ctx))
    events_by_id = {e.event_id: e for e in usable}
    findings.extend(_burst_findings(findings, events_by_id, config))
    findings.sort(key=lambda f: (f.first_seen is None, f.first_seen.isoformat() if f.first_seen else "", f.rule_id))
    return findings
