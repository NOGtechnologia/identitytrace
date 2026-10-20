"""IdentityTrace command line.

    python cli.py analyze examples/synthetic_cloudtrail.json --out reports/
    python cli.py analyze my-trail.json --config detection-config.json --ai
    python cli.py generate        # regenerate the synthetic dataset
    python cli.py benchmark       # same as python -m benchmark.run
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from ai.assistant import AnalysisUnavailable, analyze_incident
from correlation.pipeline import analyze
from detections.config import DetectionConfig
from incident_reports.case import Case
from incident_reports.report import build_report, render_html, render_json


def cmd_analyze(args: argparse.Namespace) -> int:
    config = DetectionConfig.from_file(args.config) if args.config else None
    result = analyze(Path(args.file), config)
    q = result.quality
    print(f"{q.total_records} Datensätze · {q.unusable_events} unbrauchbar · {len(q.time_gaps)} Zeitlücken · "
          f"{len(q.instruction_like_event_ids)} mit anweisungsartigem Text")
    if q.issue_counts:
        print("  Datenqualität:", ", ".join(f"{k}={v}" for k, v in sorted(q.issue_counts.items())))
    print(f"{len(result.findings)} Findings · {len(result.incidents)} Vorfälle\n")
    for inc in result.incidents:
        print(f"[{inc.severity.value.upper():8}] {inc.incident_id}  {inc.title}")
        print(f"            Regeln: {', '.join(inc.rule_ids)} · Zeitleiste: {len(inc.timeline)} Ereignisse")
    if args.out:
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        for inc in result.incidents:
            case = Case(inc.incident_id)
            case.record(args.analyst, "report_exported", "Bericht per CLI erzeugt")
            ai = None
            if args.ai:
                try:
                    ai = analyze_incident(result, inc.incident_id)
                    case.record(args.analyst, "ai_analysis", f"KI-Analyse ({ai['provider']})")
                except AnalysisUnavailable as exc:
                    print(f"  KI-Analyse für {inc.incident_id} nicht verfügbar: {exc}", file=sys.stderr)
            report = build_report(result, inc.incident_id, case, ai, Path(args.file).name)
            (out / f"{inc.incident_id}.json").write_text(render_json(report), encoding="utf-8")
            (out / f"{inc.incident_id}.html").write_text(render_html(report), encoding="utf-8")
        print(f"\nBerichte geschrieben nach {out.resolve()}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="identitytrace", description="Cloud Identity Threat Detection & Forensics")
    sub = parser.add_subparsers(dest="command", required=True)
    a = sub.add_parser("analyze", help="CloudTrail-Datei analysieren")
    a.add_argument("file")
    a.add_argument("--out", help="Verzeichnis für JSON-/HTML-Berichte")
    a.add_argument("--config", help="JSON-Datei mit DetectionConfig-Überschreibungen")
    a.add_argument("--ai", action="store_true", help="KI-Analyse anhängen (offline, außer IDENTITYTRACE_LLM=claude)")
    a.add_argument("--analyst", default="cli", help="Name für das Untersuchungsprotokoll")
    sub.add_parser("generate", help="synthetischen Datensatz neu erzeugen")
    sub.add_parser("benchmark", help="Benchmark ausführen")
    args = parser.parse_args(argv)

    if args.command == "analyze":
        return cmd_analyze(args)
    if args.command == "generate":
        from examples.generate_synthetic import main as generate
        generate()
        return 0
    if args.command == "benchmark":
        from benchmark.run import main as bench
        sys.argv = [sys.argv[0], "--markdown", "docs/benchmark-results.md"]
        bench()
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
