"""JSON and HTML incident reports.

The HTML report is static and inert: every log-derived value is escaped and
a Content-Security-Policy forbids scripts, so hostile strings from logs
cannot execute in an analyst's browser.
"""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from typing import Any

from correlation.pipeline import AnalysisResult
from incident_reports.case import Case
from incident_reports.remediation import recommend
from parser.serialize import to_jsonable

TOOL_VERSION = "0.1.0"
DISCLAIMER = (
    "IdentityTrace hat keine Änderungen an Cloud-Ressourcen vorgenommen. Empfehlungen mit Freigabevermerk "
    "wurden von Menschen außerhalb des Tools umgesetzt und hier dokumentiert."
)


def build_report(result: AnalysisResult, incident_id: str, case: Case | None = None,
                 ai_analysis: dict[str, Any] | None = None, dataset_name: str | None = None) -> dict[str, Any]:
    incident = result.incident(incident_id)
    if incident is None:
        raise KeyError(incident_id)
    case = case or Case(incident_id)
    findings = [f for f in result.findings if f.finding_id in incident.finding_ids]
    events = {e.event_id: e for e in result.events}
    recs = recommend(incident, findings, events)
    q = result.quality
    return to_jsonable({
        "report_type": "identitytrace.incident",
        "tool_version": TOOL_VERSION,
        "generated_at": datetime.now(timezone.utc),
        "dataset": dataset_name,
        "incident": {
            "id": incident.incident_id,
            "title": incident.title,
            "severity": incident.severity,
            "status": case.status,
            "first_seen": incident.first_seen,
            "last_seen": incident.last_seen,
            "actors": incident.actors,
            "entities": incident.entities,
            "patterns": incident.patterns,
            "rule_ids": incident.rule_ids,
        },
        "findings": findings,
        "timeline": incident.timeline,
        "facts": incident.facts,
        "inferences": incident.inferences,
        "gaps": incident.gaps,
        "evidence_events": [
            {k: v for k, v in to_jsonable(events[t.event_id], include_raw=True).items()
             if k in {"event_id", "timestamp", "event_source", "event_name", "actor", "source_ip", "user_agent",
                      "access_key_id", "error_code", "request_parameters", "response_elements",
                      "instruction_like_fields", "quality_issues"}}
            for t in incident.timeline if t.kind == "detection"
        ],
        "data_quality": {
            "total_records": q.total_records,
            "unusable_events": q.unusable_events,
            "issue_counts": q.issue_counts,
            "time_gaps": q.time_gaps,
            "instruction_like_event_ids": q.instruction_like_event_ids,
            "has_data_events": q.has_data_events,
        },
        "recommendations": [
            {**to_jsonable(r), "approval": case.approvals.get(r.rec_id)} for r in recs
        ],
        "investigation_log": case.log,
        "remediation": case.remediation,
        "ai_analysis": ai_analysis,
        "disclaimer": DISCLAIMER,
    })


def render_json(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2, ensure_ascii=False)


# ------------------------------------------------------------------ HTML
def _e(value: Any) -> str:
    if value is None:
        return "–"
    if isinstance(value, (list, dict)):
        value = json.dumps(value, ensure_ascii=False)
    return html.escape(str(value), quote=True)


def _list(items: list[dict[str, Any]], with_confidence: bool = False) -> str:
    if not items:
        return "<p class='muted'>Keine Einträge.</p>"
    rows = []
    for s in items:
        conf = f"<span class='tag'>Konfidenz: {_e(s.get('confidence'))}</span> " if with_confidence and s.get("confidence") else ""
        refs = " ".join(f"<code>{_e(i)}</code>" for i in s.get("event_ids", [])[:12])
        rows.append(f"<li>{conf}{_e(s.get('text'))}{'<br><span class=refs>Belege: ' + refs + '</span>' if refs else ''}</li>")
    return "<ul>" + "".join(rows) + "</ul>"


_CSS = """
:root{--bg:#f7f7f5;--fg:#1d1d1b;--muted:#6b6b66;--card:#fff;--line:#e2e1dc;--crit:#b3261e;--high:#c25e00;
--med:#8a6d00;--low:#2f6f4f;--accent:#2b4c7e}
@media (prefers-color-scheme:dark){:root{--bg:#161615;--fg:#ecebe6;--muted:#a3a29b;--card:#201f1d;--line:#34332f;
--crit:#ff8a80;--high:#ffb066;--med:#e6c84f;--low:#7fcfa4;--accent:#9db8e8}}
body{background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif;margin:0;padding:24px 16px}
main{max-width:1080px;margin:0 auto}h1{font-size:1.5rem;margin:.2em 0}h2{font-size:1.1rem;margin-top:2em;border-bottom:1px solid var(--line);padding-bottom:.3em}
section{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px 16px;margin:12px 0}
.sev{display:inline-block;padding:2px 8px;border-radius:4px;font-weight:600;font-size:.8rem;text-transform:uppercase;border:1px solid currentColor}
.sev-critical{color:var(--crit)}.sev-high{color:var(--high)}.sev-medium{color:var(--med)}.sev-low,.sev-info{color:var(--low)}
.muted,.refs{color:var(--muted);font-size:.85rem}code{font-size:.8rem;background:var(--bg);padding:1px 4px;border-radius:3px;word-break:break-all}
table{width:100%;border-collapse:collapse;font-size:.85rem}th,td{text-align:left;padding:6px;border-bottom:1px solid var(--line);vertical-align:top}
.tag{font-size:.75rem;border:1px solid var(--line);border-radius:3px;padding:0 4px;margin-right:4px;color:var(--muted)}
.det{font-weight:600}.warn{color:var(--high)}.wrap{overflow-x:auto}
"""


def render_html(report: dict[str, Any]) -> str:
    inc = report["incident"]
    findings_html = "".join(
        f"<section><span class='sev sev-{_e(f['severity'])}'>{_e(f['severity'])}</span> "
        f"<strong>{_e(f['rule_id'])} – {_e(f['title'])}</strong>"
        f"<p>{_e(f['description'])}</p><p><b>Begründung:</b> {_e(f['rationale'])}</p>"
        f"<p class='muted'>Regel: {_e(f['rule_name'])} · MITRE ATT&amp;CK: {_e(', '.join(f['mitre_attack']) or '–')} · "
        f"Auslösende Ereignisse: {' '.join('<code>' + _e(i) + '</code>' for i in f['event_ids'])}</p>"
        "<table><tr><th>Ereignis</th><th>Feld</th><th>Wert</th></tr>"
        + "".join(f"<tr><td><code>{_e(ev['event_id'])}</code></td><td>{_e(ev['field'])}</td><td>{_e(ev['value'])}</td></tr>" for ev in f["evidence"])
        + "</table></section>"
        for f in report["findings"]
    )
    timeline_rows = "".join(
        f"<tr class='{'det' if t['kind'] == 'detection' else ''}'><td>{_e(t['timestamp'])}</td><td>{_e(t['kind'])}</td>"
        f"<td>{_e(t['event_source'])}<br>{_e(t['event_name'])}</td><td>{_e(t['actor'])}</td><td>{_e(t['source_ip'])}</td>"
        f"<td>{_e(t['access_key_id'])}</td><td>{_e(t['outcome'])}</td><td>{_e(', '.join(t['rule_ids']))}"
        f"{'<br><span class=warn>anweisungsartiger Text: ' + _e(', '.join(t['instruction_like_fields'])) + '</span>' if t['instruction_like_fields'] else ''}</td></tr>"
        for t in report["timeline"]
    )
    recs_html = "".join(
        f"<section><strong>{_e(r['title'])}</strong>"
        f"{' <span class=tag>Freigabe erforderlich</span>' if r['requires_approval'] else ''}"
        f"<p>{_e(r['rationale'])}</p><p><b>Prüfen (read-only):</b></p><ul>{''.join('<li><code>' + _e(s) + '</code></li>' for s in r['verify_steps'])}</ul>"
        + (f"<p><b>Ändern (nur nach Freigabe, außerhalb des Tools):</b></p><ul>{''.join('<li><code>' + _e(s) + '</code></li>' for s in r['change_steps'])}</ul>" if r["change_steps"] else "")
        + (f"<p class='muted'>Freigegeben von {_e(r['approval']['approved_by'])} am {_e(r['approval']['at'])}: {_e(r['approval']['note'])}</p>" if r.get("approval") else "")
        + "</section>"
        for r in report["recommendations"]
    )
    log_rows = "".join(
        f"<tr><td>{_e(entry['timestamp'])}</td><td>{_e(entry['analyst'])}</td><td>{_e(entry['action'])}</td><td>{_e(entry['note'])}</td></tr>"
        for entry in report["investigation_log"]
    ) or "<tr><td colspan=4 class='muted'>Noch keine Einträge.</td></tr>"
    dq = report["data_quality"]
    ai = report.get("ai_analysis")
    ai_html = "<p class='muted'>Keine KI-Analyse angefordert.</p>"
    if ai:
        ai_html = (
            f"<p class='muted'>Quelle: {_e(ai.get('provider'))} · Nur Assistenz: Schweregrad und Findings stammen aus den Regeln.</p>"
            f"<p>{_e(ai.get('summary'))}</p><h3>Fakten</h3>{_list(ai.get('facts', []))}"
            f"<h3>Hypothesen</h3>{_list(ai.get('hypotheses', []), True)}"
            f"<h3>Unsicherheiten</h3><ul>{''.join('<li>' + _e(u) + '</li>' for u in ai.get('uncertainties', []))}</ul>"
            f"<h3>Vorgeschlagene Untersuchungsschritte</h3><ul>{''.join('<li>' + _e(s) + '</li>' for s in ai.get('investigation_steps', []))}</ul>"
            + (f"<p class='warn'>Validierung: {_e('; '.join(ai.get('validation_warnings', [])))}</p>" if ai.get("validation_warnings") else "")
        )
    remediation = report.get("remediation")
    rem_html = (f"<p>{_e(remediation['summary'])}</p><p><b>Verifikation:</b> {_e(remediation['verification'])}</p>"
                f"<p class='muted'>Dokumentiert von {_e(remediation['documented_by'])} am {_e(remediation['at'])}</p>"
                if remediation else "<p class='muted'>Noch nicht dokumentiert.</p>")
    return f"""<!doctype html>
<html lang="de"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Incident {_e(inc['id'])}</title><style>{_CSS}</style></head>
<body><main>
<p class="muted">IdentityTrace {_e(report['tool_version'])} · erstellt {_e(report['generated_at'])} · Datensatz {_e(report.get('dataset'))}</p>
<h1>{_e(inc['title'])}</h1>
<p><span class="sev sev-{_e(inc['severity'])}">{_e(inc['severity'])}</span> <span class="tag">Status: {_e(inc['status'])}</span>
<span class="tag">{_e(inc['id'])}</span> {_e(inc['first_seen'])} – {_e(inc['last_seen'])}</p>
<p>Akteure: {_e(', '.join(inc['actors']))} · Beteiligte Identitäten: {_e(', '.join(inc['entities']))}</p>
{('<p><b>Erkannte Muster:</b> ' + _e('; '.join(inc['patterns'])) + '</p>') if inc['patterns'] else ''}
<h2>Findings und Belege</h2>{findings_html}
<h2>Zeitleiste</h2><div class="wrap"><table><tr><th>Zeit (UTC)</th><th>Art</th><th>Ereignis</th><th>Akteur</th><th>IP</th><th>Schlüssel</th><th>Ergebnis</th><th>Regeln</th></tr>{timeline_rows}</table></div>
<h2>Was in den Logs steht (Fakten)</h2><section>{_list(report['facts'])}</section>
<h2>Was daraus abgeleitet wird</h2><section>{_list(report['inferences'], True)}</section>
<h2>Was fehlt oder unsicher ist</h2><section>{_list(report['gaps'])}</section>
<h2>Datenqualität des Imports</h2><section><p>{_e(dq['total_records'])} Datensätze, davon {_e(dq['unusable_events'])} unbrauchbar. Probleme: {_e(dq['issue_counts'])}</p>
<p>Zeitlücken: {_e(len(dq['time_gaps']))} · Ereignisse mit anweisungsartigem Text: {_e(len(dq['instruction_like_event_ids']))}</p></section>
<h2>Empfohlene Maßnahmen</h2>{recs_html}
<h2>KI-gestützte Einordnung</h2><section>{ai_html}</section>
<h2>Untersuchungsprotokoll</h2><div class="wrap"><table><tr><th>Zeit (UTC)</th><th>Analyst</th><th>Aktion</th><th>Notiz</th></tr>{log_rows}</table></div>
<h2>Zustand nach der Behebung</h2><section>{rem_html}</section>
<p class="muted">{_e(report['disclaimer'])}</p>
</main></body></html>
"""
