"""IdentityTrace HTTP API.

    uvicorn api.main:create_app --factory --host 127.0.0.1 --port 8000

The API is read-only towards the cloud: it imports log files, but has no
endpoint and no code path that calls a cloud provider API. It has no
authentication and is meant for local use; see docs/security-controls.md.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Literal

from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from ai.assistant import AnalysisUnavailable, analyze_incident
from api.storage import Store
from incident_reports.case import STATUSES, CaseError
from incident_reports.report import build_report, render_html
from parser.serialize import to_jsonable

ROOT = Path(__file__).resolve().parent.parent
DEMO_FILE = ROOT / "examples" / "synthetic_cloudtrail.json"
MAX_UPLOAD_BYTES = 25 * 1024 * 1024


class LogNote(BaseModel):
    analyst: str = Field(min_length=1, max_length=128)
    note: str = Field(min_length=1, max_length=5000)


class StatusChange(BaseModel):
    analyst: str = Field(min_length=1, max_length=128)
    status: Literal[tuple(STATUSES)]  # type: ignore[valid-type]
    note: str = Field(default="", max_length=5000)


class Approval(BaseModel):
    analyst: str = Field(min_length=1, max_length=128)
    recommendation_id: str = Field(min_length=1, max_length=512)
    note: str = Field(min_length=1, max_length=5000)


class Remediation(BaseModel):
    analyst: str = Field(min_length=1, max_length=128)
    summary: str = Field(min_length=1, max_length=10000)
    verification: str = Field(min_length=1, max_length=10000)


class AnalysisRequest(BaseModel):
    analyst: str = Field(min_length=1, max_length=128)


def create_app(store: Store | None = None) -> FastAPI:
    app = FastAPI(title="IdentityTrace", version="0.1.0",
                  description="Cloud Identity Threat Detection & Forensics â€“ lokal, read-only.")
    app.state.store = store or Store()

    def st() -> Store:
        return app.state.store

    def not_found(what: str) -> HTTPException:
        return HTTPException(status_code=404, detail=f"{what} nicht gefunden")

    @app.get("/api/health")
    def health() -> dict[str, Any]:
        return {"status": "ok", "llm": os.environ.get("IDENTITYTRACE_LLM", "offline"), "cloud_write_access": False}

    @app.post("/api/datasets/demo")
    def load_demo() -> dict[str, Any]:
        dataset_id, result = st().import_dataset("synthetic_cloudtrail.json (Demo)", DEMO_FILE.read_text(encoding="utf-8"))
        return _summary(dataset_id, result)

    @app.post("/api/datasets")
    async def upload(file: UploadFile = File(...)) -> dict[str, Any]:
        data = await file.read(MAX_UPLOAD_BYTES + 1)
        if len(data) > MAX_UPLOAD_BYTES:
            raise HTTPException(status_code=413, detail="Datei zu groÃŸ (max. 25 MB)")
        dataset_id, result = st().import_dataset(file.filename or "upload.json", data.decode("utf-8-sig", errors="replace"))
        return _summary(dataset_id, result)

    @app.get("/api/datasets")
    def datasets() -> list[dict[str, Any]]:
        return st().datasets()

    @app.get("/api/datasets/{dataset_id}/quality")
    def quality(dataset_id: int) -> dict[str, Any]:
        try:
            return to_jsonable(st().result(dataset_id).quality)
        except KeyError:
            raise not_found("Datensatz")

    @app.get("/api/datasets/{dataset_id}/events")
    def events(dataset_id: int, actor: str | None = None, event_name: str | None = None,
               only_issues: bool = False, limit: int = Query(500, le=2000), offset: int = 0) -> list[dict[str, Any]]:
        return st().events(dataset_id, actor, event_name, only_issues, limit, offset)

    @app.get("/api/datasets/{dataset_id}/findings")
    def findings(dataset_id: int, severity: str | None = None, rule_id: str | None = None) -> list[dict[str, Any]]:
        return st().findings(dataset_id, severity, rule_id)

    @app.get("/api/datasets/{dataset_id}/incidents")
    def incidents(dataset_id: int) -> list[dict[str, Any]]:
        return st().incidents(dataset_id)

    @app.get("/api/datasets/{dataset_id}/incidents/{incident_id}")
    def incident(dataset_id: int, incident_id: str) -> dict[str, Any]:
        try:
            data = st().incident(dataset_id, incident_id)
            case = st().load_case(dataset_id, incident_id)
        except KeyError:
            raise not_found("Vorfall")
        report = build_report(st().result(dataset_id), incident_id, case, data.get("ai_analysis"))
        return {**data, "findings": report["findings"], "recommendations": report["recommendations"],
                "investigation_log": report["investigation_log"], "remediation": report["remediation"]}

    def _with_case(dataset_id: int, incident_id: str, mutate) -> dict[str, Any]:
        try:
            case = st().load_case(dataset_id, incident_id)
        except KeyError:
            raise not_found("Vorfall")
        try:
            mutate(case)
        except CaseError as exc:
            raise HTTPException(status_code=409, detail=str(exc))
        st().save_case(dataset_id, case)
        return {"status": case.status, "log_entries": len(case.log)}

    @app.post("/api/datasets/{dataset_id}/incidents/{incident_id}/log")
    def add_note(dataset_id: int, incident_id: str, body: LogNote) -> dict[str, Any]:
        return _with_case(dataset_id, incident_id, lambda c: c.record(body.analyst, "note", body.note))

    @app.post("/api/datasets/{dataset_id}/incidents/{incident_id}/status")
    def change_status(dataset_id: int, incident_id: str, body: StatusChange) -> dict[str, Any]:
        return _with_case(dataset_id, incident_id, lambda c: c.transition(body.status, body.analyst, body.note))

    @app.post("/api/datasets/{dataset_id}/incidents/{incident_id}/approvals")
    def approve(dataset_id: int, incident_id: str, body: Approval) -> dict[str, Any]:
        """Records a human approval. IdentityTrace does not execute the approved step."""
        return _with_case(dataset_id, incident_id, lambda c: c.approve(body.recommendation_id, body.analyst, body.note))

    @app.post("/api/datasets/{dataset_id}/incidents/{incident_id}/remediation")
    def remediation(dataset_id: int, incident_id: str, body: Remediation) -> dict[str, Any]:
        return _with_case(dataset_id, incident_id,
                          lambda c: c.document_remediation(body.analyst, body.summary, body.verification))

    @app.post("/api/datasets/{dataset_id}/incidents/{incident_id}/analysis")
    def ai_analysis(dataset_id: int, incident_id: str, body: AnalysisRequest) -> dict[str, Any]:
        try:
            result = st().result(dataset_id)
            case = st().load_case(dataset_id, incident_id)
        except KeyError:
            raise not_found("Vorfall")
        try:
            analysis = analyze_incident(result, incident_id)
        except AnalysisUnavailable as exc:
            raise HTTPException(status_code=502, detail=str(exc))
        case.record(body.analyst, "ai_analysis", f"KI-Analyse angefordert ({analysis['provider']})",
                    warnings=analysis["validation_warnings"])
        st().save_case(dataset_id, case, ai_analysis=analysis)
        return analysis

    def _report(dataset_id: int, incident_id: str, fmt: str) -> dict[str, Any]:
        try:
            case = st().load_case(dataset_id, incident_id)
            ai = st().ai_analysis(dataset_id, incident_id)
            name = st().dataset_name(dataset_id)
        except KeyError:
            raise not_found("Vorfall")
        case.record("system", "report_exported", f"Bericht als {fmt} exportiert")
        st().save_case(dataset_id, case)
        return build_report(st().result(dataset_id), incident_id, case, ai, name)

    @app.get("/api/datasets/{dataset_id}/incidents/{incident_id}/report.json")
    def report_json(dataset_id: int, incident_id: str) -> JSONResponse:
        return JSONResponse(_report(dataset_id, incident_id, "JSON"),
                            headers={"Content-Disposition": f'attachment; filename="{incident_id}.json"'})

    @app.get("/api/datasets/{dataset_id}/incidents/{incident_id}/report.html", response_class=HTMLResponse)
    def report_html(dataset_id: int, incident_id: str) -> HTMLResponse:
        return HTMLResponse(render_html(_report(dataset_id, incident_id, "HTML")),
                            headers={"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'"})

    dist = ROOT / "dashboard" / "dist"
    if dist.is_dir():
        app.mount("/", StaticFiles(directory=dist, html=True), name="dashboard")
    return app


def _summary(dataset_id: int, result) -> dict[str, Any]:
    return {
        "dataset_id": dataset_id,
        "records": result.quality.total_records,
        "unusable_records": result.quality.unusable_events,
        "findings": len(result.findings),
        "incidents": len(result.incidents),
        "time_gaps": len(result.quality.time_gaps),
    }

