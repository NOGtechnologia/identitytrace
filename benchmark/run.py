"""Reproducible detection benchmark against the labeled synthetic dataset.

    python -m benchmark.run            # prints metrics, writes benchmark/results.json
    python -m benchmark.run --markdown docs/benchmark-results.md

Metrics are computed at event level:
  * positive  = event labeled expected_alert=true in examples/ground_truth.json
  * alerted   = event referenced by at least one finding
  * precision = TP / (TP + FP), recall = TP / (TP + FN)
  * false positive rate = FP / (FP + TN) over all events with expected_alert=false
Unlabeled background events count as negatives.
"""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from correlation.pipeline import AnalysisResult, analyze
from detections.models import Severity

ROOT = Path(__file__).resolve().parent.parent
DATASET = ROOT / "examples" / "synthetic_cloudtrail.json"
TRUTH = ROOT / "examples" / "ground_truth.json"


def _ratio(num: int, den: int) -> float | None:
    return round(num / den, 4) if den else None


def evaluate(result: AnalysisResult, truth: dict[str, Any]) -> dict[str, Any]:
    labels = {lab["event_id"]: lab for lab in truth["labels"]}
    usable_ids = [e.event_id for e in result.events]
    alerted: dict[str, set[str]] = defaultdict(set)
    for f in result.findings:
        for eid in f.event_ids:
            alerted[eid].add(f.rule_id)

    tp = fp = fn = tn = 0
    for eid in usable_ids:
        expected = labels.get(eid, {}).get("expected_alert", False)
        hit = eid in alerted
        tp += expected and hit
        fn += expected and not hit
        fp += (not expected) and hit
        tn += (not expected) and not hit

    # Rule-level: expected (event, rule) pairs vs. produced pairs on labeled scenario events.
    per_rule: dict[str, dict[str, int]] = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})
    for eid, lab in labels.items():
        expected_rules = set(lab["expected_rules"])
        produced = alerted.get(eid, set())
        for rule in expected_rules | produced:
            if rule in expected_rules and rule in produced:
                per_rule[rule]["tp"] += 1
            elif rule in produced:
                per_rule[rule]["fp"] += 1
            else:
                per_rule[rule]["fn"] += 1
    for eid, rules in alerted.items():
        if eid not in labels:
            for rule in rules:
                per_rule[rule]["fp"] += 1
    rules_out = {
        rule: {**c, "precision": _ratio(c["tp"], c["tp"] + c["fp"]), "recall": _ratio(c["tp"], c["tp"] + c["fn"])}
        for rule, c in sorted(per_rule.items())
    }

    # Scenario-level outcome.
    incident_events = {t.event_id for inc in result.incidents for t in inc.timeline}
    scenarios = []
    for sc in truth["scenarios"]:
        sc_labels = [lab for lab in truth["labels"] if lab["scenario"] == sc["id"]]
        expected_events = [lab for lab in sc_labels if lab["expected_alert"]]
        benign_events = [lab for lab in sc_labels if not lab["expected_alert"]]
        detected = [lab for lab in expected_events if lab["event_id"] in alerted]
        rules_ok = all(set(lab["expected_rules"]) <= alerted.get(lab["event_id"], set()) for lab in expected_events)
        false_alarms = [lab for lab in benign_events if lab["event_id"] in alerted]
        malicious = [lab for lab in sc_labels if lab["malicious"]]
        in_timeline = [lab for lab in malicious if lab["event_id"] in incident_events]
        if sc["id"] == "S05":
            outcome = "erfüllt" if quality_ok(result, truth) else "verfehlt"
        elif expected_events:
            if len(detected) == len(expected_events) and rules_ok:
                outcome = "erkannt"
            elif detected:
                outcome = "teilweise erkannt"
            else:
                outcome = "übersehen"
        else:
            outcome = "Fehlalarm" if false_alarms else "korrekt still"
        scenarios.append({
            "id": sc["id"], "name": sc["name"], "outcome": outcome,
            "expected_alert_events": len(expected_events), "detected_events": len(detected),
            "expected_rules_matched": rules_ok if expected_events else None,
            "false_alarm_events": len(false_alarms),
            "malicious_events_in_incident_timeline": f"{len(in_timeline)}/{len(malicious)}" if malicious else None,
        })

    critical_on_benign = [
        f.finding_id for f in result.findings
        if f.severity in (Severity.CRITICAL,) and any(not labels.get(e, {}).get("expected_alert", False) for e in f.event_ids)
    ]
    malicious_ids = [lab["event_id"] for lab in truth["labels"] if lab["malicious"]]
    return {
        "dataset": str(DATASET.relative_to(ROOT)).replace("\\", "/"),
        "events_evaluated": len(usable_ids),
        "confusion": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
        "precision": _ratio(tp, tp + fp),
        "recall": _ratio(tp, tp + fn),
        "false_positive_rate": _ratio(fp, fp + tn),
        "per_rule": rules_out,
        "scenarios": scenarios,
        "incident_reconstruction": {
            "incidents": len(result.incidents),
            "malicious_events_in_any_timeline": f"{sum(e in incident_events for e in malicious_ids)}/{len(malicious_ids)}",
        },
        "critical_findings_on_benign_events": critical_on_benign,
        "data_quality": {
            "issue_counts": result.quality.issue_counts,
            "time_gaps": len(result.quality.time_gaps),
            "instruction_like_events": len(result.quality.instruction_like_event_ids),
            "matches_expectation": quality_ok(result, truth),
        },
    }


def quality_ok(result: AnalysisResult, truth: dict[str, Any]) -> bool:
    exp = truth["expected_quality"]
    counts_ok = all(result.quality.issue_counts.get(k, 0) >= v for k, v in exp["issue_counts"].items())
    return counts_ok and len(result.quality.time_gaps) >= exp["min_time_gaps"]


def to_markdown(m: dict[str, Any]) -> str:
    c = m["confusion"]
    pct = lambda v: "–" if v is None else f"{v * 100:.1f} %"  # noqa: E731
    lines = [
        "# Benchmark-Ergebnisse",
        "",
        "> Automatisch erzeugt mit `python -m benchmark.run --markdown docs/benchmark-results.md`.",
        "> Datensatz: `examples/synthetic_cloudtrail.json` (synthetisch, deterministisch). Ground Truth: `examples/ground_truth.json`.",
        "",
        "## Gesamtwerte (Ereignisebene)",
        "",
        "| Kennzahl | Wert |",
        "|---|---|",
        f"| Ausgewertete Ereignisse | {m['events_evaluated']} |",
        f"| True Positives | {c['tp']} |",
        f"| False Positives | {c['fp']} |",
        f"| False Negatives | {c['fn']} |",
        f"| True Negatives | {c['tn']} |",
        f"| **Precision** | **{pct(m['precision'])}** |",
        f"| **Recall** | **{pct(m['recall'])}** |",
        f"| **Fehlalarmquote (FPR)** | **{pct(m['false_positive_rate'])}** |",
        "",
        "## Pro Regel",
        "",
        "| Regel | TP | FP | FN | Precision | Recall |",
        "|---|---|---|---|---|---|",
    ]
    for rule, r in m["per_rule"].items():
        lines.append(f"| {rule} | {r['tp']} | {r['fp']} | {r['fn']} | {pct(r['precision'])} | {pct(r['recall'])} |")
    lines += ["", "## Testfälle", "", "| ID | Testfall | Ergebnis | Erkannt/erwartet | Fehlalarme | Bösartige Ereignisse in Zeitleiste |",
              "|---|---|---|---|---|---|"]
    for s in m["scenarios"]:
        lines.append(f"| {s['id']} | {s['name']} | {s['outcome']} | {s['detected_events']}/{s['expected_alert_events']} | "
                     f"{s['false_alarm_events']} | {s['malicious_events_in_incident_timeline'] or '–'} |")
    dq = m["data_quality"]
    lines += [
        "",
        "## Datenqualität und Manipulationsversuche",
        "",
        f"- Erkannte Defekte: {', '.join(f'{k}: {v}' for k, v in sorted(dq['issue_counts'].items()))}",
        f"- Erkannte Zeitlücken: {dq['time_gaps']}",
        f"- Ereignisse mit anweisungsartigem Text: {dq['instruction_like_events']}",
        f"- Erwartung erfüllt: {'ja' if dq['matches_expectation'] else 'nein'}",
        f"- Kritische Findings auf eigentlich harmlosen Ereignissen: {len(m['critical_findings_on_benign_events'])}",
        f"- Bösartige Ereignisse, die in einer Vorfalls-Zeitleiste auftauchen: {m['incident_reconstruction']['malicious_events_in_any_timeline']}",
        "",
        "## Einordnung",
        "",
        "- **S11 (Fehlalarm):** Eine genehmigte Terraform-Bereitstellung ist für IT-001 nicht von S02 zu unterscheiden. "
        "Den Regeln fehlt Kontext aus Change-Management und IaC. Abhilfe: Allowlist für Pipeline-Rollen "
        "oder Abgleich mit Change-Tickets. Beides ist bewusst nicht voreingestellt.",
        "- **S10 (übersehen):** Rechteausweitung über `iam:PassRole` + `lambda:CreateFunction` deckt keine Regel ab. "
        "Dafür müsste das Tool wissen, welche Rechte die übergebene Rolle hat.",
        "- **S15 (übersehen):** Eine kundenverwaltete Policy mit Admin-Rechten ist nur am Namen erkennbar. Ihr Inhalt "
        "entstand vor dem Importzeitraum. Ohne IAM-Inventar (read-only `GetPolicyVersion`) bleibt das unsichtbar.",
        "- **S08:** Aufklärungs- und Lesezugriffe (ListUsers, GetSecretValue, GetObject) lösen allein keine Regel aus. "
        "Sie erscheinen aber in der Vorfalls-Zeitleiste, weil die Korrelation den neuen Schlüssel verfolgt.",
        "- Der Datensatz ist klein und von denselben Personen entworfen wie die Regeln. Die Werte belegen, dass "
        "die Regeln die definierten Testfälle treffen. Über die Trefferquote in echten Umgebungen sagen sie nichts aus.",
        "",
    ]
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--markdown", type=Path, help="write a Markdown report to this path")
    parser.add_argument("--json", type=Path, default=ROOT / "benchmark" / "results.json")
    args = parser.parse_args()
    metrics = evaluate(analyze(DATASET), json.loads(TRUTH.read_text(encoding="utf-8")))
    args.json.write_text(json.dumps(metrics, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
    if args.markdown:
        args.markdown.write_text(to_markdown(metrics), encoding="utf-8", newline="\n")
    c = metrics["confusion"]
    print(f"precision={metrics['precision']} recall={metrics['recall']} fpr={metrics['false_positive_rate']} "
          f"(tp={c['tp']} fp={c['fp']} fn={c['fn']} tn={c['tn']})")
    for s in metrics["scenarios"]:
        print(f"  {s['id']:4} {s['outcome']:18} {s['name']}")


if __name__ == "__main__":
    main()
