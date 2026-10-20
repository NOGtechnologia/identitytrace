# Benchmark-Ergebnisse

> Automatisch erzeugt mit `python -m benchmark.run --markdown docs/benchmark-results.md`.
> Datensatz: `examples/synthetic_cloudtrail.json` (synthetisch, deterministisch). Ground Truth: `examples/ground_truth.json`.

## Gesamtwerte (Ereignisebene)

| Kennzahl | Wert |
|---|---|
| Ausgewertete Ereignisse | 452 |
| True Positives | 13 |
| False Positives | 2 |
| False Negatives | 3 |
| True Negatives | 434 |
| **Precision** | **86.7 %** |
| **Recall** | **81.2 %** |
| **Fehlalarmquote (FPR)** | **0.5 %** |

## Pro Regel

| Regel | TP | FP | FN | Precision | Recall |
|---|---|---|---|---|---|
| IT-001 | 4 | 2 | 0 | 66.7 % | 100.0 % |
| IT-002 | 3 | 0 | 0 | 100.0 % | 100.0 % |
| IT-003 | 2 | 0 | 0 | 100.0 % | 100.0 % |
| IT-004 | 4 | 0 | 0 | 100.0 % | 100.0 % |
| IT-005 | 2 | 0 | 0 | 100.0 % | 100.0 % |
| IT-006 | 3 | 0 | 0 | 100.0 % | 100.0 % |

## Testfälle

| ID | Testfall | Ergebnis | Erkannt/erwartet | Fehlalarme | Bösartige Ereignisse in Zeitleiste |
|---|---|---|---|---|---|
| S11 | Genehmigte Bereitstellung (bekannter Fehlalarm) | Fehlalarm | 0/0 | 2 | – |
| S02 | Neue privilegierte Rolle | erkannt | 2/2 | 0 | 2/2 |
| S03 | Unerwartete Berechtigungserweiterung | erkannt | 1/1 | 0 | 1/1 |
| S04 | Audit-Protokollierung verändert | erkannt | 2/2 | 0 | 2/2 |
| S05 | Unvollständige Logs | erfüllt | 0/0 | 0 | – |
| S14 | Normale Anmeldung | korrekt still | 0/0 | 0 | – |
| S06 | Manipulative Texte in Logfeldern | erkannt | 1/1 | 0 | 1/1 |
| S07 | Benutzer verändert eigene Berechtigungen | erkannt | 1/1 | 0 | 1/1 |
| S12 | Abgelehnter Versuch, die Protokollierung zu stoppen | erkannt | 1/1 | 0 | 1/1 |
| S08 | Kontoübernahme mit Persistenz | erkannt | 4/4 | 0 | 10/10 |
| S09 | API-Schlüssel für Notfallkonto | erkannt | 1/1 | 0 | 1/1 |
| S13 | Routinemäßige Schlüsselrotation | korrekt still | 0/0 | 0 | – |
| S10 | Rechteausweitung über iam:PassRole (bekannte Lücke) | übersehen | 0/2 | 0 | 0/2 |
| S15 | Selbst definierte Admin-Policy (bekannte Lücke) | übersehen | 0/1 | 0 | 0/1 |

## Datenqualität und Manipulationsversuche

- Erkannte Defekte: invalid_event_time: 1, malformed_record: 1, missing_event_time: 1, missing_user_identity: 1
- Erkannte Zeitlücken: 1
- Ereignisse mit anweisungsartigem Text: 2
- Erwartung erfüllt: ja
- Kritische Findings auf eigentlich harmlosen Ereignissen: 0
- Bösartige Ereignisse, die in einer Vorfalls-Zeitleiste auftauchen: 19/22

## Einordnung

- **S11 (Fehlalarm):** Eine genehmigte Terraform-Bereitstellung ist für IT-001 nicht von S02 zu unterscheiden. Den Regeln fehlt Kontext aus Change-Management und IaC. Abhilfe: Allowlist für Pipeline-Rollen oder Abgleich mit Change-Tickets. Beides ist bewusst nicht voreingestellt.
- **S10 (übersehen):** Rechteausweitung über `iam:PassRole` + `lambda:CreateFunction` deckt keine Regel ab. Dafür müsste das Tool wissen, welche Rechte die übergebene Rolle hat.
- **S15 (übersehen):** Eine kundenverwaltete Policy mit Admin-Rechten ist nur am Namen erkennbar. Ihr Inhalt entstand vor dem Importzeitraum. Ohne IAM-Inventar (read-only `GetPolicyVersion`) bleibt das unsichtbar.
- **S08:** Aufklärungs- und Lesezugriffe (ListUsers, GetSecretValue, GetObject) lösen allein keine Regel aus. Sie erscheinen aber in der Vorfalls-Zeitleiste, weil die Korrelation den neuen Schlüssel verfolgt.
- Der Datensatz ist klein und von denselben Personen entworfen wie die Regeln. Die Werte belegen, dass die Regeln die definierten Testfälle treffen. Über die Trefferquote in echten Umgebungen sagen sie nichts aus.
