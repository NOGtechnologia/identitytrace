# Sicherheitskontrollen

## Grundsatz: lesen, nicht handeln

IdentityTrace hat **keine Schreibrechte und keinen Code, der Cloud-APIs aufruft**. Die API meldet das in `/api/health` (`"cloud_write_access": false`). Empfehlungen enthalten CLI-Befehle als Text. Ausgeführt werden sie von Menschen, außerhalb des Tools, nach Freigabe. Danach wird das Ergebnis im Fall dokumentiert.

Eine spätere Live-Anbindung an ein echtes Konto muss:
- ausschließlich **read-only** sein (z. B. `cloudtrail:LookupEvents`, `iam:Get*`, `iam:List*`, keine `*`-Rechte),
- nur ausdrücklich autorisierte Konten verwenden (Allowlist der Konto-IDs),
- kurzlebige Zugangsdaten nutzen (Rolle mit `ExternalId`, keine langlebigen Schlüssel).

## KI-Leitplanken (`ai/assistant.py`)

| Kontrolle | Umsetzung | Test |
|---|---|---|
| Standard ist offline | `IDENTITYTRACE_LLM` nicht gesetzt → deterministische Vorlage, kein Netzwerk | `test_api.py` |
| Keine Werkzeuge | Der Claude-Aufruf übergibt keine `tools`. Das Modell kann nur Text liefern. | `test_claude_adapter.py` |
| Daten statt Anweisungen | Logdaten werden JSON-kodiert, `<`, `>` und `&` escaped, in `<untrusted_log_data>` gekapselt, Felder auf 400 Zeichen gekürzt (mit Hinweis). Der System-Prompt erklärt den Block als Beweismaterial. | `test_prompt_injection.py` |
| Strukturierte Ausgabe | JSON-Schema über `output_config.format`, danach eigene Validierung | `test_prompt_injection.py` |
| Belegpflicht | Fakten und Hypothesen ohne gültige eventID werden zu „Unbelegt“ herabgestuft. Erfundene IDs werden entfernt und als Warnung gemeldet. | `test_validator_drops_fabricated_citations_and_unknown_fields` |
| Keine Hoheit über Bewertung | Unbekannte Felder (`severity`, `status`, `close_incident`) werden verworfen. Schweregrad und Status stammen nur aus Regeln und Fallbearbeitung. | `test_hostile_model_cannot_change_rule_severity` |
| Echo-Erkennung | Enthält die Ausgabe selbst anweisungsartigen Text, erscheint eine Warnung. | `test_validator_flags_model_that_parrots_injected_instructions` |
| Ablehnung und Abbruch | `stop_reason` `refusal` oder `max_tokens` → Fehler „nicht verfügbar“ statt Teilergebnis | `test_claude_adapter.py` |
| Fallback | Bei Ablehnung durch Sicherheitsklassifikatoren leitet die API serverseitig an ein Ersatzmodell weiter (`fallbacks: "default"`). Das Ergebnis durchläuft dieselbe Validierung. | – |

Die KI wird mit `IDENTITYTRACE_LLM=claude` und gesetzten Anthropic-Zugangsdaten aktiviert (`ANTHROPIC_API_KEY` oder `ant auth login`). Modell: `claude-opus-5-5`, Effort `medium`. Dabei werden Logauszüge eines Vorfalls an die Anthropic-API übertragen. Vor dem Einsatz mit echten Daten muss geklärt sein, ob das erlaubt ist.

## Beweissicherung

- Rohdatensätze werden unverändert gespeichert (`datasets.raw`, `Event.raw`) und mit SHA-256 versehen.
- Jedes Finding verweist auf eventIDs und konkrete Feldwerte.
- Das Untersuchungsprotokoll ist append-only (Zeitstempel in UTC, Analystenname Pflicht). Statuswechsel, Freigaben, KI-Anfragen und Berichtsexporte werden automatisch protokolliert.
- `closed` ist erst möglich, wenn der Zustand nach der Behebung dokumentiert ist. `false_positive` verlangt eine Begründung.

## Ausgabe

- HTML-Berichte: Jeder Wert ist escaped, CSP `default-src 'none'; style-src 'unsafe-inline'`, keine Skripte.
- Dashboard: React rendert Text escaped. Kein `dangerouslySetInnerHTML`. `localStorage` speichert nur den Analystennamen als Komfortfunktion.

## Betrieb

- Die API hat **keine Authentifizierung**. Sie ist an `127.0.0.1` gebunden, auch in docker-compose.
- Upload-Limit 25 MB.
- Container läuft als Nicht-Root-Benutzer.
- Das PostgreSQL-Passwort in docker-compose ist ein lokaler Platzhalter. Über `POSTGRES_PASSWORD` überschreiben.

## Offene Punkte

- Authentifizierung und Rollen (Analyst, Freigeber)
- Manipulationssicheres Protokoll (Hash-Kette oder WORM-Speicher)
- Signierte Berichte
- Mandantentrennung
