# IdentityTrace

**Cloud Identity Threat Detection & Forensics.** Ein defensives Werkzeug, das in AWS-CloudTrail-Logs verdächtige Änderungen an Identitäten und Berechtigungen erkennt, zusammengehörige Aktivitäten zu einem nachvollziehbaren Vorfall verknüpft und einen Bericht mit Zeitleiste, Belegen und Schweregrad erstellt.

- **Erklärbar:** Jedes Finding nennt die Regel, die auslösenden eventIDs, die konkreten Feldwerte und eine Begründung.
- **Ehrlich:** Der Bericht trennt, was in den Logs steht, was daraus abgeleitet wird und was fehlt.
- **Read-only:** Kein Codepfad ruft Cloud-APIs auf. Gegenmaßnahmen sind Empfehlungen, die ein Mensch freigibt und außerhalb des Tools umsetzt.
- **Gemessen:** Ein reproduzierbarer synthetischer Datensatz mit Ground Truth liefert Precision, Recall und Fehlalarmquote, inklusive der Fälle, die das Tool übersieht.

## Ergebnis auf dem Testdatensatz

| Precision | Recall | Fehlalarmquote | Testfälle |
|---|---|---|---|
| 86,7 % | 81,2 % | 0,5 % | 11 von 14 wie erwartet, 1 dokumentierter Fehlalarm, 2 dokumentierte Lücken |

Details, Werte pro Regel und Einordnung: [docs/benchmark-results.md](docs/benchmark-results.md). Die Werte stammen aus einem kleinen synthetischen Datensatz, den dieselben Personen entworfen haben wie die Regeln. Sie zeigen, dass die definierten Testfälle getroffen werden. Über die Trefferquote in echten Umgebungen sagen sie nichts aus.

## Schnellstart (lokal, ohne Docker)

Voraussetzung: Python 3.12.

```bash
python -m venv .venv
. .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
```

**Demo auf der Kommandozeile** (vollständig lokal, ohne Netzwerk):

```bash
python cli.py analyze examples/synthetic_cloudtrail.json --out reports --ai
```

```
452 Datensätze · 4 unbrauchbar · 1 Zeitlücken · 2 mit anweisungsartigem Text
16 Findings · 9 Vorfälle

[CRITICAL] INC-b9c823dd28  Rechteausweitung → neuer Zugang → Zugriff auf sensible Daten (user:backup-operator, user:ci-deployer)
            Regeln: IT-001, IT-002, IT-003, IT-004, IT-006 · Zeitleiste: 25 Ereignisse
...
```

Anschließend `reports/INC-b9c823dd28.html` im Browser öffnen. Beispielberichte liegen bereits in [examples/sample_reports/](examples/sample_reports/).

**Tests und Benchmark:**

```bash
pytest
python -m benchmark.run --markdown docs/benchmark-results.md
```

**API:**

```bash
uvicorn api.main:create_app --factory --host 127.0.0.1 --port 8000
```

Danach unter http://127.0.0.1:8000/docs `POST /api/datasets/demo` aufrufen und die Vorfälle unter `/api/datasets/{id}/incidents` abfragen.

**Dashboard** (React + TypeScript, Node 20):

```bash
cd dashboard
npm install
npm run dev        # http://localhost:5173, leitet /api an Port 8000 weiter
```

## Mit Docker (PostgreSQL)

```bash
docker compose up --build
```

Öffnet http://127.0.0.1:8000 mit Dashboard und API. Die Daten liegen in PostgreSQL.

## Demo-Ablauf: Kontoübernahme (Szenario S08)

1. Ein gestohlener CI-Schlüssel wird aus einem fremden Netz (`203.0.113.77`) verwendet.
2. `AttachUserPolicy IAMFullAccess` und `PutUserPolicy Action:*` für `backup-operator` → **IT-001, IT-002**
3. `CreateAccessKey` für `backup-operator` → **IT-003**. Das Konto gilt als sensibel, weil es laut Log gerade Admin-Rechte bekam.
4. Drei Regeln in drei Minuten → **IT-006**
5. Mit dem neuen Schlüssel: `ListSecrets`, `GetSecretValue prod/db/credentials`, `GetObject prod-customer-exports/…` → keine Regel, aber über die accessKeyId in der Zeitleiste
6. `PutEventSelectors` auf dem Trail → **IT-004** und eine „Lücke“: Was danach geschah, ist möglicherweise nicht protokolliert.

Der Bericht zeigt diese Kette als **einen** Vorfall. Er ist in Fakten, Ableitungen (z. B. „IP 203.0.113.77 kommt für ci-deployer sonst nicht vor“, Konfidenz mittel) und Lücken („Wie ci-deployer an die Zugangsdaten kam, geht aus CloudTrail allein nicht hervor“) gegliedert.

## Testfälle

| Testfall | Erwartet | Ergebnis |
|---|---|---|
| Normale Anmeldung (S14) | kein unbegründeter kritischer Alarm | ✔ still |
| Neue privilegierte Rolle (S02) | Warnung mit verknüpftem Audit-Ereignis | ✔ IT-001 mit `CreateRole` und `AttachRolePolicy` |
| Unerwartete Berechtigungserweiterung (S03) | Finding mit betroffener Rolle | ✔ IT-002, Ziel `role:app-reporting-role` |
| Audit-Protokollierung verändert (S04, S12) | Sicherheitsalarm mit Zeitstempel | ✔ IT-004 (critical bzw. „Versuch“) |
| Unvollständige Logs (S05) | Datenlücke sichtbar machen | ✔ 4 Defekte gezählt, Zeitlücke von 6,7 h gemeldet |
| Manipulative Texte in Logfeldern (S06) | als Daten behandeln | ✔ markiert, Erkennung unverändert, KI-Eingabe gekapselt |
| Selbständerung (S07), Schlüssel für Notfallkonto (S09), Kontoübernahme (S08) | Findings und verknüpfter Vorfall | ✔ |
| Schlüsselrotation (S13) | kein Alarm | ✔ still |
| Genehmigte Terraform-Bereitstellung (S11) | kein Alarm | ✘ **Fehlalarm** (IT-001, fehlender Change-Kontext) |
| PassRole + Lambda (S10) | Alarm | ✘ **übersehen** (keine Regel) |
| Selbst definierte Admin-Policy (S15) | Alarm | ✘ **übersehen** (Policy-Inhalt nicht im Log) |

## KI-Unterstützung

Standardmäßig arbeitet IdentityTrace **offline**: Die „KI-Einordnung“ ist dann eine deterministische Vorlage aus den Korrelationsdaten. Mit `IDENTITYTRACE_LLM=claude` und Anthropic-Zugangsdaten übernimmt Claude (`claude-opus-5-5`) die Einordnung. Dabei gilt:

- Das Modell erhält keine Werkzeuge und kann nichts ausführen.
- Logdaten sind gekapselt und als nicht vertrauenswürdig gekennzeichnet.
- Jede Aussage muss existierende eventIDs zitieren, sonst wird sie als „unbelegt“ herabgestuft.
- Schweregrad und Status kann das Modell nicht ändern.

Wichtig: Mit aktivierter KI werden Logauszüge an die Anthropic-API gesendet. Details in [docs/security-controls.md](docs/security-controls.md).

## Grenzen

- Nur AWS CloudTrail. Azure- und Entra-ID-Logs sind nicht umgesetzt; das Event-Modell hat dafür ein Feld `provider`.
- Keine Erkennung von Rechteausweitung über `iam:PassRole`, über Gruppenmitgliedschaften oder über Bedingungen in Policies.
- Ohne IAM-Inventar sind Rechte, die vor dem Importzeitraum vergeben wurden, unbekannt.
- Die IP-Basislinie umfasst nur den importierten Zeitraum, es gibt keine Langzeit-Verhaltensanalyse.
- Genehmigte Änderungen (Change-Tickets, IaC-Pipelines) erzeugen Fehlalarme, solange keine Allowlist gepflegt wird.
- Die API hat keine Authentifizierung und ist nur für den lokalen Einzelbetrieb gedacht.
- Getestet ausschließlich mit synthetischen Daten.

## Projektstruktur

```
├── parser/              CloudTrail einlesen, normalisieren, Datenqualität, Injection-Markierung
├── detections/          Regeln IT-001 … IT-006, Policy-Analyse, Konfiguration
├── correlation/         Vorfälle, Zeitleiste, Fakten/Ableitungen/Lücken, Pipeline
├── incident_reports/    Fallbearbeitung, Empfehlungen, JSON/HTML-Berichte
├── ai/                  KI-Einordnung mit Leitplanken (offline / Claude)
├── api/                 FastAPI + SQLAlchemy (SQLite / PostgreSQL)
├── dashboard/           React + TypeScript
├── benchmark/           Precision / Recall / Fehlalarmquote
├── examples/            synthetischer Datensatz, Ground Truth, Generator, Beispielberichte
├── tests/               pytest
├── docs/                Architektur, Bedrohungsmodell, Regeln, Kontrollen, Benchmark
├── cli.py
├── Dockerfile, docker-compose.yml
└── .github/workflows/ci.yml
```

## Lizenz

MIT, siehe [LICENSE](LICENSE).
