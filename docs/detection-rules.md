# Erkennungsregeln

Alle Regeln laufen nur auf **verwertbaren** Events, also mit Zeitstempel, Ereignisname und Akteur. Unvollständige Datensätze erscheinen im Datenqualitätsbericht und als Lücke im Vorfall. Sie lösen keine Regel aus.

**Fehlgeschlagene Anfragen** (`errorCode` gesetzt) erzeugen dasselbe Finding mit dem Präfix „Versuch:“. Ihr Schweregrad sinkt um eine Stufe, denn auch ein abgelehnter `StopLogging`-Aufruf ist auffällig.

| ID | Name | Schwere | MITRE ATT&CK |
|---|---|---|---|
| IT-001 | Privilegierte Rolle angelegt oder verändert | high | T1098, T1098.003 |
| IT-002 | Ungewöhnlich weitreichende Berechtigungen | high / critical | T1098 |
| IT-003 | API-Schlüssel für sensibles Konto | high | T1098.001 |
| IT-004 | Audit-Protokollierung deaktiviert oder verändert | medium … critical | T1562.008 |
| IT-005 | Benutzer verändert eigene Berechtigungen | high / critical | T1098 |
| IT-006 | Häufung auffälliger Ereignisse | critical | – |

## IT-001 – Privilegierte Rolle angelegt oder verändert

Schlägt an bei:
- `AttachUserPolicy` / `AttachRolePolicy` / `AttachGroupPolicy` mit einer Policy aus `privileged_managed_policies` (Standard: `AdministratorAccess`, `IAMFullAccess`, `PowerUserAccess`, `AWSOrganizationsFullAccess`). Wurde die Rolle in den 24 Stunden davor mit `CreateRole` angelegt, enthält das Finding beide Ereignisse („Neue privilegierte Rolle“).
- `CreateRole` oder `UpdateAssumeRolePolicy`, deren Trust-Policy `Principal: "*"` oder ein Konto außerhalb von `trusted_account_ids` erlaubt. Ist die Liste leer, gilt nur das eigene Konto als vertrauenswürdig.

Belege: `requestParameters.policyArn` bzw. die externen Prinzipale.

**Grenzen:** Kundenverwaltete Policies mit Admin-Rechten werden nur erkannt, wenn ihr Inhalt im Log steht (siehe S15). Genehmigte Änderungen über IaC sind nicht unterscheidbar (siehe S11).

## IT-002 – Ungewöhnlich weitreichende Berechtigungen

Prüft `policyDocument` von `PutUserPolicy`, `PutRolePolicy`, `PutGroupPolicy`, `CreatePolicy` und `CreatePolicyVersion` (nur mit `setAsDefault=true`). URL-kodierte Dokumente werden dekodiert.

Schlägt an bei `Effect: Allow` mit
- `Action: "*"` → **critical**
- `NotAction` → **critical**
- `<dienst>:*` auf `Resource: "*"` für einen Dienst aus `sensitive_services` (iam, sts, organizations, kms, cloudtrail, secretsmanager, guardduty, config) → **high**

**Grenzen:** Bedingungen (`Condition`) werden nicht ausgewertet. Gefährliche Einzelrechte wie `iam:PassRole` oder `iam:CreatePolicyVersion` ohne Wildcard werden nicht erkannt.

## IT-003 – API-Schlüssel für sensibles Konto

`CreateAccessKey` für ein Konto, das sensibel ist, weil es
1. das Root-Konto ist,
2. in `sensitive_principals` steht,
3. im Namen ein Muster aus `sensitive_name_patterns` trägt (Standard: admin, break-glass, root) oder
4. **laut Log zuvor privilegierte Rechte erhielt** (IT-001/IT-002-Ereignis mit diesem Ziel vor dem Schlüssel).

Punkt 4 erkennt die typische Persistenz nach einer Rechteausweitung, ohne dass jemand das Konto vorher als sensibel markiert haben muss. Erzeugt eine andere Identität den Schlüssel, steht das in der Begründung.

**Grenzen:** Rechte, die vor dem Importzeitraum vergeben wurden, sind unbekannt. Für solche Konten hilft nur die Konfiguration.

## IT-004 – Audit-Protokollierung deaktiviert oder verändert

| Ereignis | Schwere |
|---|---|
| cloudtrail `StopLogging`, `DeleteTrail` | critical |
| cloudtrail `UpdateTrail`, `PutEventSelectors` | high |
| config `StopConfigurationRecorder`, `DeleteConfigurationRecorder`, `DeleteDeliveryChannel` | high |
| guardduty `DeleteDetector`, `UpdateDetector` mit `enable=false` | high |
| cloudtrail `PutInsightSelectors`, ec2 `DeleteFlowLogs`, logs `DeleteLogGroup` | medium |

Belege: `eventName` und `eventTime`. Ein erfolgreicher Eingriff erscheint im Vorfall zusätzlich als **Lücke**: Fehlende Ereignisse danach beweisen keine Inaktivität.

**Grenzen:** `UpdateTrail` meldet jede Änderung, auch harmlose. Ob die Änderung den Trail tatsächlich schwächt, wird nicht geprüft.

## IT-005 – Benutzer verändert eigene Berechtigungen

Akteur und Ziel einer Berechtigungsänderung (`Attach*Policy`, `Put*Policy`, `AddUserToGroup`, `UpdateAssumeRolePolicy`) sind identisch. Bei einer übernommenen Rolle wird der Name der Rolle verglichen. Mit administrativer Berechtigung ist das Finding **critical**, sonst **high**.

**Grenzen:** Änderungen über Umwege bleiben unerkannt, etwa wenn ein Benutzer eine Gruppe ändert, in der er selbst Mitglied ist.

## IT-006 – Häufung auffälliger Ereignisse

Meta-Regel über die Findings von IT-001 bis IT-005: Eine Identität löst innerhalb von `burst_window_minutes` (30) mindestens `burst_min_events` (3) Ereignisse aus mindestens `burst_min_rules` (2) verschiedenen Regeln aus. Das Finding listet alle beteiligten Ereignisse.

**Grenzen:** Gruppiert nur nach Akteur. Ein Angreifer, der mehrere Identitäten nutzt, wird erst in der Korrelation zusammengeführt, nicht in IT-006.

## Konfiguration

Alle Schwellen und Listen stehen in `detections/config.py` (`DetectionConfig`). Sie lassen sich per JSON-Datei überschreiben:

```bash
python cli.py analyze trail.json --config examples/detection-config.example.json
```

## Neue Regel hinzufügen

1. Funktion `(rule, events, ctx) -> list[Finding]` in `detections/rules.py` schreiben. Für ein einheitliches Verhalten bei Fehlversuchen `_finding(...)` verwenden.
2. In `RULES` eintragen.
3. Positiv- und Negativtest in `tests/test_detections.py` schreiben.
4. Szenario mit Ground-Truth-Label in `examples/generate_synthetic.py` ergänzen, `python examples/generate_synthetic.py` und `python -m benchmark.run --markdown docs/benchmark-results.md` ausführen.
