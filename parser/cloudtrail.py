"""AWS CloudTrail parser.

Accepted inputs:
  * a CloudTrail file: {"Records": [...]}
  * a plain JSON array of records
  * JSON Lines (one record per line)

Nothing in a record is ever interpreted as an instruction. Every record is
normalized into an `Event`; defects are recorded as `quality_issues`.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

from parser.models import DataGap, DataQualityReport, Event, ParseResult
from parser.untrusted import find_instruction_like_fields

DEFAULT_GAP_THRESHOLD = timedelta(hours=3)

# Sentinel for lines that could not be decoded as JSON at all.
_MALFORMED = object()


def load_records(source: str | Path | bytes | Any) -> list[Any]:
    """Load raw records from a path, a JSON string/bytes, or already-parsed JSON."""
    if isinstance(source, Path) or (isinstance(source, str) and _looks_like_path(source)):
        text = Path(source).read_text(encoding="utf-8-sig")
    elif isinstance(source, bytes):
        text = source.decode("utf-8-sig", errors="replace")
    elif isinstance(source, str):
        text = source
    else:
        return _records_from_obj(source)

    text = text.strip()
    if not text:
        return []
    try:
        return _records_from_obj(json.loads(text))
    except json.JSONDecodeError:
        records: list[Any] = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                records.append({"__malformed__": line[:2000]})
        return records


def _looks_like_path(value: str) -> bool:
    stripped = value.lstrip()
    return bool(stripped) and stripped[0] not in "{[" and len(value) < 1024 and "\n" not in value


def _records_from_obj(obj: Any) -> list[Any]:
    if isinstance(obj, dict) and isinstance(obj.get("Records"), list):
        return list(obj["Records"])
    if isinstance(obj, list):
        return list(obj)
    return [obj]


def parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _stable_id(index: int, raw: Any) -> str:
    blob = json.dumps(raw, sort_keys=True, default=str)[:4000]
    return "rec-" + hashlib.sha256(f"{index}:{blob}".encode()).hexdigest()[:16]


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _identity(user_identity: dict[str, Any]) -> dict[str, Any]:
    """Map CloudTrail userIdentity to a canonical actor key."""
    id_type = user_identity.get("type")
    arn = user_identity.get("arn")
    session_ctx = _as_dict(user_identity.get("sessionContext"))
    issuer = _as_dict(session_ctx.get("sessionIssuer"))
    attrs = _as_dict(session_ctx.get("attributes"))
    mfa = attrs.get("mfaAuthenticated")
    result: dict[str, Any] = {
        "actor_type": id_type,
        "actor_arn": arn,
        "access_key_id": user_identity.get("accessKeyId") or None,
        "mfa_authenticated": None if mfa is None else str(mfa).lower() == "true",
        "account_id": user_identity.get("accountId"),
    }
    if id_type == "IAMUser" and user_identity.get("userName"):
        name = user_identity["userName"]
        result.update(actor=f"user:{name}", actor_name=name)
    elif id_type == "AssumedRole":
        role = issuer.get("userName") or (arn.split("/")[1] if isinstance(arn, str) and arn.count("/") >= 2 else None)
        session = arn.rsplit("/", 1)[-1] if isinstance(arn, str) and "/" in arn else None
        if role:
            result.update(actor=f"role:{role}", actor_name=role, session_name=session)
    elif id_type == "Root":
        result.update(actor="root", actor_name="root")
    elif id_type == "AWSService":
        service = user_identity.get("invokedBy") or "aws-service"
        result.update(actor=f"service:{service}", actor_name=service)
    elif isinstance(arn, str) and arn:
        result.update(actor=f"arn:{arn}", actor_name=arn.rsplit("/", 1)[-1])
    return result


def normalize_record(raw: Any, index: int) -> Event:
    """Normalize one CloudTrail record. Never raises on bad input."""
    if not isinstance(raw, dict) or "__malformed__" in raw:
        return Event(
            event_id=_stable_id(index, raw),
            record_index=index,
            quality_issues=["malformed_record"],
            instruction_like_fields=find_instruction_like_fields(raw),
            raw=raw,
        )

    issues: list[str] = []
    event_id = raw.get("eventID")
    if not isinstance(event_id, str) or not event_id:
        issues.append("missing_event_id")
        event_id = _stable_id(index, raw)

    timestamp = parse_time(raw.get("eventTime"))
    if raw.get("eventTime") in (None, ""):
        issues.append("missing_event_time")
    elif timestamp is None:
        issues.append("invalid_event_time")

    event_name = raw.get("eventName") if isinstance(raw.get("eventName"), str) else None
    if not event_name:
        issues.append("missing_event_name")

    user_identity = raw.get("userIdentity")
    identity: dict[str, Any] = {}
    if not isinstance(user_identity, dict) or not user_identity:
        issues.append("missing_user_identity")
    else:
        identity = _identity(user_identity)
        if not identity.get("actor"):
            issues.append("unresolvable_actor")

    if not raw.get("sourceIPAddress"):
        issues.append("missing_source_ip")

    request_parameters = raw.get("requestParameters")
    response_elements = raw.get("responseElements")
    resources = raw.get("resources")

    read_only = raw.get("readOnly")
    if isinstance(read_only, str):
        read_only = read_only.lower() == "true"

    return Event(
        event_id=event_id,
        record_index=index,
        timestamp=timestamp,
        event_source=raw.get("eventSource"),
        event_name=event_name,
        event_category=raw.get("eventCategory"),
        actor=identity.get("actor"),
        actor_name=identity.get("actor_name"),
        actor_type=identity.get("actor_type"),
        actor_arn=identity.get("actor_arn"),
        session_name=identity.get("session_name"),
        access_key_id=identity.get("access_key_id"),
        mfa_authenticated=identity.get("mfa_authenticated"),
        source_ip=raw.get("sourceIPAddress"),
        user_agent=raw.get("userAgent"),
        region=raw.get("awsRegion"),
        account_id=raw.get("recipientAccountId") or identity.get("account_id"),
        read_only=read_only if isinstance(read_only, bool) else None,
        error_code=raw.get("errorCode") or None,
        error_message=raw.get("errorMessage") or None,
        request_parameters=_as_dict(request_parameters),
        response_elements=_as_dict(response_elements),
        resources=[r for r in resources if isinstance(r, dict)] if isinstance(resources, list) else [],
        quality_issues=issues,
        instruction_like_fields=find_instruction_like_fields(raw),
        raw=raw,
    )


def find_time_gaps(events: Iterable[Event], threshold: timedelta = DEFAULT_GAP_THRESHOLD) -> list[DataGap]:
    times = sorted(e.timestamp for e in events if e.timestamp is not None)
    gaps = []
    for prev, cur in zip(times, times[1:]):
        if cur - prev >= threshold:
            gaps.append(DataGap(start=prev, end=cur, duration_minutes=round((cur - prev).total_seconds() / 60, 1)))
    return gaps


def build_quality_report(events: list[Event], gap_threshold: timedelta = DEFAULT_GAP_THRESHOLD) -> DataQualityReport:
    report = DataQualityReport(total_records=len(events))
    for event in events:
        if event.is_usable:
            report.usable_events += 1
        else:
            report.unusable_events += 1
        if event.quality_issues:
            report.affected_event_ids.append(event.event_id)
        for issue in event.quality_issues:
            report.issue_counts[issue] = report.issue_counts.get(issue, 0) + 1
        if event.instruction_like_fields:
            report.instruction_like_event_ids.append(event.event_id)
        if event.event_category == "Data":
            report.has_data_events = True
    times = [e.timestamp for e in events if e.timestamp is not None]
    if times:
        report.first_event, report.last_event = min(times), max(times)
    report.time_gaps = find_time_gaps(events, gap_threshold)
    return report


def parse_cloudtrail(source: Any, gap_threshold: timedelta = DEFAULT_GAP_THRESHOLD) -> ParseResult:
    records = load_records(source)
    events = [normalize_record(raw, i) for i, raw in enumerate(records)]
    # Duplicate eventIDs would break evidence references; make them unique and flag them.
    seen: set[str] = set()
    for event in events:
        if event.event_id in seen:
            event.quality_issues.append("duplicate_event_id")
            event.event_id = f"{event.event_id}#{event.record_index}"
        seen.add(event.event_id)
    events.sort(key=lambda e: (e.timestamp is None, e.timestamp or datetime.min.replace(tzinfo=timezone.utc), e.record_index))
    return ParseResult(events=events, quality=build_quality_report(events, gap_threshold))
