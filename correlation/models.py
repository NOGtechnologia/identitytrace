from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from detections.models import Severity


@dataclass
class TimelineEntry:
    event_id: str
    timestamp: datetime | None
    event_name: str | None
    event_source: str | None
    actor: str | None
    source_ip: str | None
    access_key_id: str | None
    outcome: str  # "success" | error code
    kind: str  # "detection" | "sensitive_access" | "reconnaissance" | "authentication" | "change" | "context"
    finding_ids: list[str] = field(default_factory=list)
    rule_ids: list[str] = field(default_factory=list)
    instruction_like_fields: list[str] = field(default_factory=list)


@dataclass
class Statement:
    """A sentence plus the log events it rests on."""

    text: str
    event_ids: list[str] = field(default_factory=list)
    confidence: str | None = None  # only for inferences: "hoch" | "mittel" | "niedrig"


@dataclass
class Incident:
    incident_id: str
    title: str
    severity: Severity
    first_seen: datetime | None
    last_seen: datetime | None
    actors: list[str]
    entities: list[str]
    finding_ids: list[str]
    rule_ids: list[str]
    patterns: list[str]
    timeline: list[TimelineEntry]
    facts: list[Statement]  # what the logs literally say
    inferences: list[Statement]  # what IdentityTrace derives from them
    gaps: list[Statement]  # what is missing or uncertain
