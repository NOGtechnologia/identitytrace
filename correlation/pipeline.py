"""End-to-end analysis: parse → detect → correlate."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from correlation.engine import correlate
from correlation.models import Incident
from detections.config import DetectionConfig
from detections.engine import run_detections
from detections.models import Finding
from parser.cloudtrail import parse_cloudtrail
from parser.models import DataQualityReport, Event


@dataclass
class AnalysisResult:
    events: list[Event]
    quality: DataQualityReport
    findings: list[Finding]
    incidents: list[Incident]

    def event(self, event_id: str) -> Event | None:
        return next((e for e in self.events if e.event_id == event_id), None)

    def incident(self, incident_id: str) -> Incident | None:
        return next((i for i in self.incidents if i.incident_id == incident_id), None)


def analyze(source: Any, config: DetectionConfig | None = None) -> AnalysisResult:
    config = config or DetectionConfig()
    parsed = parse_cloudtrail(source)
    findings = run_detections(parsed.events, config)
    incidents = correlate(parsed.events, findings, parsed.quality, config)
    return AnalysisResult(parsed.events, parsed.quality, findings, incidents)
