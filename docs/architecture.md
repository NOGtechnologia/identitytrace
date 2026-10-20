# Architektur

```
CloudTrail-JSON ──► parser/ ──► detections/ ──► correlation/ ──► incident_reports/ ──► JSON / HTML
 (Datei, Upload)     │              │                │                  ▲
                     │              │                │                  │
                     ▼              ▼                ▼                  │
                 Datenqualität   Findings        Vorfälle ──► ai/ (nur lesend, validiert)
                     └──────────────┴────────────────┴──► api/ (FastAPI + SQLAlchemy) ──► dashboard/ (React)
```

Jede Stufe ist eine reine Funktion über Python-Dataclasses. Dadurch lässt sich jede Stufe ohne Datenbank, Netzwerk oder Sprachmodell testen. Die API und die Datenbank sitzen nur außen herum.

## Stufen

| Paket | Aufgabe | Wichtigste Datei |
|---|---|---|
| `parser/` | CloudTrail (`{"Records": []}`, JSON-Array, JSON Lines) einlesen und auf ein einheitliches `Event` abbilden. Defekte Datensätze werden **markiert, nicht verworfen**. Erkennt Zeitlücken und anweisungsartigen Text. | `cloudtrail.py`, `models.py`, `untrusted.py` |
| `detections/` | Sechs erklärbare Regeln (IT-001 … IT-006). Jedes Finding enthält auslösende Event-IDs, Feldwerte als Belege und eine Begründung. | `rules.py`, `engine.py`, `policy.py` |
| `correlation/` | Verknüpft Findings über Identitäten zu Vorfällen und baut eine Zeitleiste. Trennt Fakten, Ableitungen und Lücken. | `engine.py`, `pipeline.py` |
| `incident_reports/` | Fallbearbeitung (Status, append-only Protokoll, Freigaben, Zustand nach der Behebung), sichere Empfehlungen, JSON/HTML-Export. | `case.py`, `remediation.py`, `report.py` |
| `ai/` | Optionale KI-Einordnung. Offline-Vorlage als Standard, Claude per Opt-in. Eingabe gekapselt, Ausgabe validiert. | `assistant.py` |
| `api/` | FastAPI, Persistenz mit SQLAlchemy (SQLite für Demo/Tests, PostgreSQL per `DATABASE_URL`). | `main.py`, `storage.py` |
| `dashboard/` | React + TypeScript: Vorfallsliste, Filter, Zeitleiste, Belege, Untersuchungsprotokoll. | `src/App.tsx` |
| `benchmark/` | Precision, Recall und Fehlalarmquote gegen die Ground Truth. | `run.py` |

## Datenmodell

- **Event:** normalisierter CloudTrail-Datensatz. Der Akteur ist ein kanonischer Schlüssel (`user:<name>`, `role:<name>`, `root`, `service:<name>`). Das Event enthält `quality_issues`, `instruction_like_fields` und den unveränderten Rohdatensatz `raw` als Beweismittel.
- **Finding:** Regeltreffer mit `rule_id`, Schweregrad, `event_ids`, `evidence` (Event-ID, Feld, Wert), `rationale` und MITRE-ATT&CK-Bezug. Die ID ist deterministisch (Hash aus Regel und Event-IDs).
- **Incident:** zusammenhängende Findings mit Zeitleiste, `facts`, `inferences` (mit Konfidenz), `gaps` und erkannten Mustern.
- **Case:** Status-Workflow `open → investigating → contained → remediated → closed` (oder `false_positive`), append-only Protokoll mit UTC-Zeitstempeln und Analystennamen, Freigaben und dokumentiertem Endzustand.

## Korrelation

1. Jedes Finding verbindet seinen Akteur mit den Identitäten, die das auslösende Ereignis verändert hat (`userName`, `roleName`, `groupName`).
2. `CreateAccessKey` verbindet den Benutzer mit dem neuen Schlüssel aus `responseElements.accessKey.accessKeyId`.
3. Jeder Aufruf mit einem langlebigen Schlüssel (`AKIA…`) verbindet den Schlüssel mit seinem Besitzer.
4. Zusammenhängende Gruppen (Union-Find) mit mindestens einem Finding werden zu Vorfällen. Liegen mehr als 6 Stunden zwischen zwei Findings, wird der Vorfall geteilt.
5. Die Zeitleiste umfasst alle auslösenden Ereignisse sowie nicht-triviale Ereignisse (Änderungen, Logins, Aufklärung, Zugriff auf sensible Ressourcen) der beteiligten Identitäten in einem Fenster von 2 Stunden vor bis 6 Stunden nach dem Vorfall.

So landet in Szenario S08 der Zugriff auf `prod/db/credentials` in derselben Zeitleiste wie die Rechteausweitung, obwohl er keine Regel auslöst. Die Verbindung läuft über den neu erzeugten Schlüssel.

## Persistenz

Pro Datensatz werden die Rohdaten gespeichert. Jede Analyse ist dadurch reproduzierbar, auch nach Regeländerungen. Für Abfragen werden zusätzlich normalisierte Events, Findings und Vorfälle abgelegt. Fallstatus und Protokoll liegen pro Vorfall. Protokolleinträge werden nur angehängt, nie geändert.
