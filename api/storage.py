"""Persistence with SQLAlchemy.

PostgreSQL in docker-compose (DATABASE_URL=postgresql+psycopg://...),
SQLite for the local demo and tests. Raw records are stored per dataset so
an analysis can always be reproduced; normalized events, findings and
incidents are stored for querying; case state and the investigation log
are stored per incident.
"""

from __future__ import annotations

import hashlib
import os
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, Text, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker
from sqlalchemy.pool import StaticPool

from correlation.pipeline import AnalysisResult, analyze
from incident_reports.case import Case, LogEntry
from parser.serialize import to_jsonable


class Base(DeclarativeBase):
    pass


class DatasetRow(Base):
    __tablename__ = "datasets"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    imported_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    sha256: Mapped[str] = mapped_column(String(64))
    record_count: Mapped[int] = mapped_column(Integer)
    raw: Mapped[str] = mapped_column(Text)
    quality: Mapped[dict] = mapped_column(JSON)


class EventRow(Base):
    __tablename__ = "events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    dataset_id: Mapped[int] = mapped_column(ForeignKey("datasets.id"), index=True)
    event_id: Mapped[str] = mapped_column(String(128), index=True)
    timestamp: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    event_source: Mapped[str | None] = mapped_column(String(128), nullable=True)
    event_name: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    actor: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    error_code: Mapped[str | None] = mapped_column(String(128), nullable=True)
    quality_issues: Mapped[list] = mapped_column(JSON)
    data: Mapped[dict] = mapped_column(JSON)


class FindingRow(Base):
    __tablename__ = "findings"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    dataset_id: Mapped[int] = mapped_column(ForeignKey("datasets.id"), index=True)
    finding_id: Mapped[str] = mapped_column(String(64), index=True)
    rule_id: Mapped[str] = mapped_column(String(16), index=True)
    severity: Mapped[str] = mapped_column(String(16))
    actor: Mapped[str | None] = mapped_column(String(255), nullable=True)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    data: Mapped[dict] = mapped_column(JSON)


class IncidentRow(Base):
    __tablename__ = "incidents"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    dataset_id: Mapped[int] = mapped_column(ForeignKey("datasets.id"), index=True)
    incident_id: Mapped[str] = mapped_column(String(64), index=True)
    title: Mapped[str] = mapped_column(String(512))
    severity: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(32), default="open")
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    approvals: Mapped[dict] = mapped_column(JSON, default=dict)
    remediation: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    ai_analysis: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    data: Mapped[dict] = mapped_column(JSON)


class CaseLogRow(Base):
    __tablename__ = "case_log"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    incident_pk: Mapped[int] = mapped_column(ForeignKey("incidents.id"), index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    analyst: Mapped[str] = mapped_column(String(128))
    action: Mapped[str] = mapped_column(String(64))
    note: Mapped[str] = mapped_column(Text)
    details: Mapped[dict] = mapped_column(JSON)


def _aware(value: datetime | None) -> datetime | None:
    # SQLite drops tzinfo; everything in IdentityTrace is UTC.
    if value is not None and value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


class Store:
    def __init__(self, url: str | None = None) -> None:
        url = url or os.environ.get("DATABASE_URL", "sqlite:///./identitytrace.db")
        kwargs: dict[str, Any] = {"connect_args": {"check_same_thread": False}} if url.startswith("sqlite") else {}
        if url in ("sqlite://", "sqlite:///:memory:"):
            kwargs["poolclass"] = StaticPool  # one shared in-memory database for tests
        self.engine = create_engine(url, **kwargs)
        Base.metadata.create_all(self.engine)
        self.sessions = sessionmaker(self.engine, expire_on_commit=False)
        self._cache: dict[int, AnalysisResult] = {}

    # ------------------------------------------------------------ datasets
    def import_dataset(self, name: str, raw_text: str) -> tuple[int, AnalysisResult]:
        result = analyze(raw_text)
        with self.sessions.begin() as s:
            ds = DatasetRow(
                name=name[:255], imported_at=datetime.now(timezone.utc),
                sha256=hashlib.sha256(raw_text.encode()).hexdigest(), record_count=result.quality.total_records,
                raw=raw_text, quality=to_jsonable(result.quality),
            )
            s.add(ds)
            s.flush()
            for e in result.events:
                s.add(EventRow(dataset_id=ds.id, event_id=e.event_id, timestamp=e.timestamp, event_source=e.event_source,
                               event_name=e.event_name, actor=e.actor, source_ip=e.source_ip, error_code=e.error_code,
                               quality_issues=e.quality_issues, data=to_jsonable(e, include_raw=False)))
            for f in result.findings:
                s.add(FindingRow(dataset_id=ds.id, finding_id=f.finding_id, rule_id=f.rule_id, severity=f.severity.value,
                                 actor=f.actor, first_seen=f.first_seen, data=to_jsonable(f)))
            for inc in result.incidents:
                s.add(IncidentRow(dataset_id=ds.id, incident_id=inc.incident_id, title=inc.title[:512],
                                  severity=inc.severity.value, status="open", first_seen=inc.first_seen,
                                  approvals={}, data=to_jsonable(inc)))
            dataset_id = ds.id
        self._cache[dataset_id] = result
        return dataset_id, result

    def datasets(self) -> list[dict[str, Any]]:
        with self.sessions() as s:
            rows = s.scalars(select(DatasetRow).order_by(DatasetRow.id.desc())).all()
            return [{"id": r.id, "name": r.name, "imported_at": _aware(r.imported_at).isoformat(), "sha256": r.sha256,
                     "record_count": r.record_count} for r in rows]

    def result(self, dataset_id: int) -> AnalysisResult:
        if dataset_id not in self._cache:
            with self.sessions() as s:
                ds = s.get(DatasetRow, dataset_id)
                if ds is None:
                    raise KeyError(dataset_id)
                self._cache[dataset_id] = analyze(ds.raw)
        return self._cache[dataset_id]

    def dataset_name(self, dataset_id: int) -> str:
        with self.sessions() as s:
            ds = s.get(DatasetRow, dataset_id)
            if ds is None:
                raise KeyError(dataset_id)
            return ds.name

    def events(self, dataset_id: int, actor: str | None = None, event_name: str | None = None,
               only_issues: bool = False, limit: int = 500, offset: int = 0) -> list[dict[str, Any]]:
        with self.sessions() as s:
            q = select(EventRow).where(EventRow.dataset_id == dataset_id)
            if actor:
                q = q.where(EventRow.actor == actor)
            if event_name:
                q = q.where(EventRow.event_name == event_name)
            rows = s.scalars(q.order_by(EventRow.id).offset(offset).limit(min(limit, 2000))).all()
            return [r.data for r in rows if not only_issues or r.quality_issues]

    def findings(self, dataset_id: int, severity: str | None = None, rule_id: str | None = None) -> list[dict[str, Any]]:
        with self.sessions() as s:
            q = select(FindingRow).where(FindingRow.dataset_id == dataset_id)
            if severity:
                q = q.where(FindingRow.severity == severity)
            if rule_id:
                q = q.where(FindingRow.rule_id == rule_id)
            return [r.data for r in s.scalars(q.order_by(FindingRow.id)).all()]

    # ------------------------------------------------------------ incidents / cases
    def _incident_row(self, s: Session, dataset_id: int, incident_id: str) -> IncidentRow:
        row = s.scalars(select(IncidentRow).where(IncidentRow.dataset_id == dataset_id,
                                                  IncidentRow.incident_id == incident_id)).first()
        if row is None:
            raise KeyError(incident_id)
        return row

    def incidents(self, dataset_id: int) -> list[dict[str, Any]]:
        with self.sessions() as s:
            rows = s.scalars(select(IncidentRow).where(IncidentRow.dataset_id == dataset_id).order_by(IncidentRow.id)).all()
            return [{"incident_id": r.incident_id, "title": r.title, "severity": r.severity, "status": r.status,
                     "first_seen": _aware(r.first_seen).isoformat() if r.first_seen else None,
                     "actors": r.data.get("actors", []), "rule_ids": r.data.get("rule_ids", []),
                     "patterns": r.data.get("patterns", [])} for r in rows]

    def incident(self, dataset_id: int, incident_id: str) -> dict[str, Any]:
        with self.sessions() as s:
            row = self._incident_row(s, dataset_id, incident_id)
            return {**row.data, "status": row.status, "ai_analysis": row.ai_analysis}

    def load_case(self, dataset_id: int, incident_id: str) -> Case:
        with self.sessions() as s:
            row = self._incident_row(s, dataset_id, incident_id)
            logs = s.scalars(select(CaseLogRow).where(CaseLogRow.incident_pk == row.id).order_by(CaseLogRow.id)).all()
            case = Case(incident_id=incident_id, status=row.status, approvals=dict(row.approvals or {}),
                        remediation=row.remediation)
            case.log = [LogEntry(_aware(r.timestamp), r.analyst, r.action, r.note, r.details or {}) for r in logs]
            return case

    def save_case(self, dataset_id: int, case: Case, ai_analysis: dict[str, Any] | None = None) -> None:
        """Persist status and append log entries that are not stored yet (the log is append-only)."""
        with self.sessions.begin() as s:
            row = self._incident_row(s, dataset_id, case.incident_id)
            existing = len(s.scalars(select(CaseLogRow.id).where(CaseLogRow.incident_pk == row.id)).all())
            for entry in case.log[existing:]:
                s.add(CaseLogRow(incident_pk=row.id, timestamp=entry.timestamp, analyst=entry.analyst,
                                 action=entry.action, note=entry.note, details=to_jsonable(entry.details)))
            row.status = case.status
            row.approvals = to_jsonable(case.approvals)
            row.remediation = to_jsonable(case.remediation)
            if ai_analysis is not None:
                row.ai_analysis = ai_analysis

    def ai_analysis(self, dataset_id: int, incident_id: str) -> dict[str, Any] | None:
        with self.sessions() as s:
            return self._incident_row(s, dataset_id, incident_id).ai_analysis
