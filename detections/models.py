from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _RANK[self]

    def lowered(self) -> "Severity":
        order = list(Severity)
        return order[max(0, order.index(self) - 1)]

    @staticmethod
    def max(values: list["Severity"]) -> "Severity":
        return max(values, key=lambda s: s.rank) if values else Severity.INFO


_RANK = {Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3, Severity.CRITICAL: 4}


@dataclass
class Evidence:
    """One concrete log value that supports a finding."""

    event_id: str
    field: str
    value: Any


@dataclass
class Finding:
    finding_id: str
    rule_id: str
    rule_name: str
    severity: Severity
    title: str
    description: str
    rationale: str
    event_ids: list[str]
    actor: str | None
    targets: list[str]
    first_seen: datetime | None
    last_seen: datetime | None
    evidence: list[Evidence] = field(default_factory=list)
    attempt_failed: bool = False
    mitre_attack: list[str] = field(default_factory=list)

    @staticmethod
    def make_id(rule_id: str, event_ids: list[str]) -> str:
        digest = hashlib.sha256(f"{rule_id}|{'|'.join(sorted(event_ids))}".encode()).hexdigest()[:12]
        return f"F-{rule_id}-{digest}"
