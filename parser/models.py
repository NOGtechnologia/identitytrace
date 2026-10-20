"""Unified, provider-independent event model.

Every imported record becomes exactly one `Event`, even if it is broken.
Broken records keep their raw content and carry `quality_issues`, so data
gaps stay visible instead of silently disappearing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class Event:
    event_id: str
    record_index: int
    provider: str = "aws"
    timestamp: datetime | None = None
    event_source: str | None = None
    event_name: str | None = None
    event_category: str | None = None  # "Management" | "Data" | ...
    # Identity of the caller
    actor: str | None = None  # canonical entity key, e.g. "user:alice", "role:deployer", "root"
    actor_name: str | None = None
    actor_type: str | None = None  # IAMUser | AssumedRole | Root | AWSService | ...
    actor_arn: str | None = None
    session_name: str | None = None
    access_key_id: str | None = None
    mfa_authenticated: bool | None = None
    # Context
    source_ip: str | None = None
    user_agent: str | None = None
    region: str | None = None
    account_id: str | None = None
    read_only: bool | None = None
    error_code: str | None = None
    error_message: str | None = None
    request_parameters: dict[str, Any] = field(default_factory=dict)
    response_elements: dict[str, Any] = field(default_factory=dict)
    resources: list[dict[str, Any]] = field(default_factory=list)
    # Data quality
    quality_issues: list[str] = field(default_factory=list)
    instruction_like_fields: list[str] = field(default_factory=list)
    raw: Any = None

    @property
    def succeeded(self) -> bool:
        return self.error_code is None

    @property
    def is_usable(self) -> bool:
        """An event can feed detections only if it has a time, a name and an actor."""
        return self.timestamp is not None and bool(self.event_name) and bool(self.actor)

    def param(self, *names: str) -> Any:
        for name in names:
            value = self.request_parameters.get(name)
            if value not in (None, ""):
                return value
        return None


@dataclass
class DataGap:
    start: datetime
    end: datetime
    duration_minutes: float
    reason: str = "no_events"


@dataclass
class DataQualityReport:
    total_records: int = 0
    usable_events: int = 0
    unusable_events: int = 0
    issue_counts: dict[str, int] = field(default_factory=dict)
    affected_event_ids: list[str] = field(default_factory=list)
    instruction_like_event_ids: list[str] = field(default_factory=list)
    time_gaps: list[DataGap] = field(default_factory=list)
    first_event: datetime | None = None
    last_event: datetime | None = None
    has_data_events: bool = False


@dataclass
class ParseResult:
    events: list[Event]
    quality: DataQualityReport
