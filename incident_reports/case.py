"""Investigation case: status workflow and a timestamped, append-only log."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

STATUSES = ["open", "investigating", "contained", "remediated", "closed", "false_positive"]
TRANSITIONS = {
    "open": {"investigating", "false_positive"},
    "investigating": {"contained", "remediated", "false_positive"},
    "contained": {"remediated"},
    "remediated": {"closed", "investigating"},
    "closed": {"investigating"},
    "false_positive": {"investigating"},
}


class CaseError(ValueError):
    pass


def _now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class LogEntry:
    timestamp: datetime
    analyst: str
    action: str
    note: str
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class Case:
    incident_id: str
    status: str = "open"
    log: list[LogEntry] = field(default_factory=list)
    approvals: dict[str, dict[str, Any]] = field(default_factory=dict)
    remediation: dict[str, Any] | None = None

    def record(self, analyst: str, action: str, note: str, at: datetime | None = None, **details: Any) -> LogEntry:
        if not analyst.strip():
            raise CaseError("Analyst muss angegeben werden")
        entry = LogEntry(at or _now(), analyst, action, note, details)
        self.log.append(entry)
        return entry

    def transition(self, new_status: str, analyst: str, note: str, at: datetime | None = None) -> None:
        if new_status not in STATUSES:
            raise CaseError(f"Unbekannter Status: {new_status}")
        if new_status not in TRANSITIONS[self.status]:
            raise CaseError(f"Übergang {self.status} → {new_status} ist nicht erlaubt")
        if new_status == "closed" and not self.remediation:
            raise CaseError("Vor dem Schließen muss der Zustand nach der Behebung dokumentiert sein")
        if new_status == "false_positive" and not note.strip():
            raise CaseError("Für false_positive ist eine Begründung erforderlich")
        old = self.status
        self.status = new_status
        self.record(analyst, "status_change", note, at, old=old, new=new_status)

    def approve(self, rec_id: str, analyst: str, note: str, at: datetime | None = None) -> None:
        """Record a human approval. Approval does not execute anything."""
        entry = self.record(analyst, "approval", note, at, recommendation=rec_id)
        self.approvals[rec_id] = {"approved_by": analyst, "at": entry.timestamp, "note": note, "executed_by_tool": False}

    def document_remediation(self, analyst: str, summary: str, verification: str, at: datetime | None = None) -> None:
        if not summary.strip() or not verification.strip():
            raise CaseError("Zusammenfassung und Verifikation sind erforderlich")
        entry = self.record(analyst, "remediation_documented", summary, at, verification=verification)
        self.remediation = {"summary": summary, "verification": verification, "documented_by": analyst, "at": entry.timestamp}
