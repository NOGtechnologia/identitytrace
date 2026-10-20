import { useCallback, useEffect, useMemo, useState } from "react";
import { api, IncidentDetail, IncidentSummary, Quality, Severity, Statement } from "./api";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];
const STATUSES = ["investigating", "contained", "remediated", "closed", "false_positive"];
const KINDS = ["detection", "sensitive_access", "reconnaissance", "authentication", "change"];

function readAnalyst(): string {
  try {
    return localStorage.getItem("it.analyst") ?? "";
  } catch {
    return "";
  }
}

function SeverityBadge({ value }: { value: Severity }) {
  return <span className={`sev sev-${value}`}>{value}</span>;
}

function Statements({ items, title, hint }: { items: Statement[]; title: string; hint: string }) {
  return (
    <div className="card">
      <h3>{title}</h3>
      <p className="muted">{hint}</p>
      {items.length === 0 ? (
        <p className="muted">Keine Einträge.</p>
      ) : (
        <ul>
          {items.map((s, i) => (
            <li key={i}>
              {s.confidence && <span className="tag">Konfidenz: {s.confidence}</span>}
              {s.text}
              {s.event_ids.length > 0 && <div className="refs">Belege: {s.event_ids.slice(0, 6).join(", ")}</div>}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

export default function App() {
  const [datasetId, setDatasetId] = useState<number | null>(null);
  const [incidents, setIncidents] = useState<IncidentSummary[]>([]);
  const [quality, setQuality] = useState<Quality | null>(null);
  const [selected, setSelected] = useState<IncidentDetail | null>(null);
  const [severityFilter, setSeverityFilter] = useState<Severity | "">("");
  const [search, setSearch] = useState("");
  const [kindFilter, setKindFilter] = useState<string[]>(KINDS);
  const [analyst, setAnalyst] = useState(readAnalyst);
  const [note, setNote] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    try {
      localStorage.setItem("it.analyst", analyst);
    } catch {
      /* storage unavailable: keep in memory only */
    }
  }, [analyst]);

  useEffect(() => {
    api.datasets().then((ds) => ds.length && setDatasetId(ds[0].id)).catch((e) => setError(String(e.message ?? e)));
  }, []);

  useEffect(() => {
    if (datasetId === null) return;
    setSelected(null);
    Promise.all([api.incidents(datasetId), api.quality(datasetId)])
      .then(([inc, q]) => {
        setIncidents(inc);
        setQuality(q);
      })
      .catch((e) => setError(e.message));
  }, [datasetId]);

  const open = useCallback(
    (id: string) => {
      if (datasetId === null) return;
      api.incident(datasetId, id).then(setSelected).catch((e) => setError(e.message));
    },
    [datasetId],
  );

  const run = async (fn: () => Promise<unknown>) => {
    setBusy(true);
    setError(null);
    try {
      await fn();
      if (selected) open(selected.incident_id);
      if (datasetId !== null) setIncidents(await api.incidents(datasetId));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const visible = useMemo(
    () =>
      incidents.filter(
        (i) =>
          (!severityFilter || i.severity === severityFilter) &&
          (!search || `${i.title} ${i.actors.join(" ")} ${i.rule_ids.join(" ")}`.toLowerCase().includes(search.toLowerCase())),
      ),
    [incidents, severityFilter, search],
  );

  const needAnalyst = !analyst.trim();
  const post = (action: string, body: object) =>
    run(() => api.post(datasetId!, selected!.incident_id, action, { analyst, ...body }));

  return (
    <div className="app">
      <header>
        <div>
          <h1>IdentityTrace</h1>
          <p className="muted">Cloud Identity Threat Detection & Forensics · lokal · read-only</p>
        </div>
        <div className="actions">
          <input placeholder="Analyst" value={analyst} onChange={(e) => setAnalyst(e.target.value)} aria-label="Analyst" />
          <button disabled={busy} onClick={() => run(async () => setDatasetId((await api.loadDemo()).dataset_id))}>
            Demo laden
          </button>
          <label className="button">
            CloudTrail-Datei importieren
            <input
              type="file"
              accept=".json,.jsonl"
              hidden
              onChange={(e) => {
                const file = e.target.files?.[0];
                if (file) run(async () => setDatasetId((await api.upload(file)).dataset_id));
              }}
            />
          </label>
        </div>
      </header>

      {error && <div className="error">{error}</div>}

      {quality && (
        <section className="quality">
          <strong>{quality.total_records}</strong> Datensätze · <strong>{quality.unusable_events}</strong> unbrauchbar ·{" "}
          <strong>{quality.time_gaps.length}</strong> Zeitlücken ·{" "}
          <strong>{quality.instruction_like_event_ids.length}</strong> mit anweisungsartigem Text
          {Object.keys(quality.issue_counts).length > 0 && (
            <span className="muted">
              {" "}
              ({Object.entries(quality.issue_counts).map(([k, v]) => `${k}: ${v}`).join(", ")})
            </span>
          )}
          {quality.time_gaps.map((g) => (
            <div key={g.start} className="warn">
              Datenlücke {g.start} → {g.end} ({Math.round(g.duration_minutes)} min)
            </div>
          ))}
        </section>
      )}

      <div className="layout">
        <aside>
          <div className="filters">
            <select value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value as Severity | "")}>
              <option value="">Alle Schweregrade</option>
              {SEVERITIES.map((s) => (
                <option key={s}>{s}</option>
              ))}
            </select>
            <input placeholder="Suche (Akteur, Regel …)" value={search} onChange={(e) => setSearch(e.target.value)} />
          </div>
          {datasetId === null && <p className="muted">Noch kein Datensatz. „Demo laden“ startet mit synthetischen Daten.</p>}
          <ul className="incidents">
            {visible.map((i) => (
              <li key={i.incident_id}>
                <button
                  className={selected?.incident_id === i.incident_id ? "active" : ""}
                  onClick={() => open(i.incident_id)}
                >
                  <SeverityBadge value={i.severity} /> <span className="tag">{i.status}</span>
                  <div className="title">{i.title}</div>
                  <div className="muted">
                    {i.rule_ids.join(", ")} · {i.first_seen?.slice(0, 16).replace("T", " ")}
                  </div>
                </button>
              </li>
            ))}
          </ul>
        </aside>

        <main>
          {!selected ? (
            <p className="muted">Vorfall auswählen.</p>
          ) : (
            <>
              <div className="card">
                <SeverityBadge value={selected.severity} /> <span className="tag">Status: {selected.status}</span>
                <h2>{selected.title}</h2>
                <p>Akteure: {selected.actors.join(", ")}</p>
                {selected.patterns.length > 0 && <p>Muster: {selected.patterns.join("; ")}</p>}
                <p>
                  <a href={api.reportUrl(datasetId!, selected.incident_id, "html")} target="_blank" rel="noreferrer">
                    HTML-Bericht
                  </a>{" "}
                  ·{" "}
                  <a href={api.reportUrl(datasetId!, selected.incident_id, "json")} target="_blank" rel="noreferrer">
                    JSON-Bericht
                  </a>
                </p>
              </div>

              <h3>Findings</h3>
              {selected.findings.map((f) => (
                <details key={f.finding_id} className="card">
                  <summary>
                    <SeverityBadge value={f.severity} /> {f.rule_id} – {f.title}
                  </summary>
                  <p>
                    <b>Begründung:</b> {f.rationale}
                  </p>
                  <table>
                    <tbody>
                      {f.evidence.map((ev, i) => (
                        <tr key={i}>
                          <td className="mono">{ev.event_id}</td>
                          <td>{ev.field}</td>
                          <td className="mono">{typeof ev.value === "string" ? ev.value : JSON.stringify(ev.value)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </details>
              ))}

              <h3>Zeitleiste</h3>
              <div className="filters">
                {KINDS.map((k) => (
                  <label key={k} className="check">
                    <input
                      type="checkbox"
                      checked={kindFilter.includes(k)}
                      onChange={(e) => setKindFilter(e.target.checked ? [...kindFilter, k] : kindFilter.filter((x) => x !== k))}
                    />
                    {k}
                  </label>
                ))}
              </div>
              <div className="wrap">
                <table className="timeline">
                  <thead>
                    <tr>
                      <th>Zeit (UTC)</th>
                      <th>Art</th>
                      <th>Ereignis</th>
                      <th>Akteur</th>
                      <th>IP</th>
                      <th>Schlüssel</th>
                      <th>Ergebnis</th>
                      <th>Regeln</th>
                    </tr>
                  </thead>
                  <tbody>
                    {selected.timeline
                      .filter((t) => kindFilter.includes(t.kind) || t.kind === "context")
                      .map((t) => (
                        <tr key={t.event_id} className={`kind-${t.kind}`}>
                          <td className="mono">{t.timestamp?.replace("T", " ").replace("Z", "")}</td>
                          <td>{t.kind}</td>
                          <td>{t.event_name}</td>
                          <td>{t.actor}</td>
                          <td className="mono">{t.source_ip}</td>
                          <td className="mono">{t.access_key_id}</td>
                          <td>{t.outcome}</td>
                          <td>
                            {t.rule_ids.join(", ")}
                            {t.instruction_like_fields.length > 0 && (
                              <div className="warn">anweisungsartiger Text in {t.instruction_like_fields.join(", ")} (als Daten behandelt)</div>
                            )}
                          </td>
                        </tr>
                      ))}
                  </tbody>
                </table>
              </div>

              <div className="three">
                <Statements title="Fakten" hint="Steht so in den Logs." items={selected.facts.filter((f) =>
                  selected.timeline.some((t) => t.kind === "detection" && f.event_ids.includes(t.event_id)))} />
                <Statements title="Ableitungen" hint="Schlussfolgerungen mit Konfidenz." items={selected.inferences} />
                <Statements title="Lücken" hint="Fehlt oder ist unsicher." items={selected.gaps} />
              </div>

              <h3>Empfohlene Maßnahmen</h3>
              <p className="muted">IdentityTrace führt keine Änderungen aus. Eine Freigabe wird nur protokolliert.</p>
              {selected.recommendations.map((r) => (
                <div key={r.rec_id} className="card">
                  <strong>{r.title}</strong> {r.requires_approval && <span className="tag">Freigabe erforderlich</span>}
                  <p className="muted">{r.rationale}</p>
                  <div>Prüfen (read-only):</div>
                  <ul>{r.verify_steps.map((s) => <li key={s} className="mono">{s}</li>)}</ul>
                  {r.change_steps.length > 0 && (
                    <>
                      <div>Ändern (außerhalb des Tools):</div>
                      <ul>{r.change_steps.map((s) => <li key={s} className="mono">{s}</li>)}</ul>
                    </>
                  )}
                  {r.approval ? (
                    <p className="muted">Freigegeben von {r.approval.approved_by} ({r.approval.at})</p>
                  ) : (
                    r.requires_approval && (
                      <button disabled={busy || needAnalyst || !note.trim()}
                        onClick={() => post("approvals", { recommendation_id: r.rec_id, note })}>
                        Freigabe protokollieren (Notiz erforderlich)
                      </button>
                    )
                  )}
                </div>
              ))}

              <h3>Untersuchung</h3>
              <div className="card">
                <textarea placeholder="Notiz, Begründung oder Ergebnis eines Prüfschritts" value={note}
                  onChange={(e) => setNote(e.target.value)} rows={3} />
                <div className="actions">
                  <button disabled={busy || needAnalyst || !note.trim()} onClick={() => post("log", { note }).then(() => setNote(""))}>
                    Notiz speichern
                  </button>
                  {STATUSES.map((s) => (
                    <button key={s} disabled={busy || needAnalyst} onClick={() => post("status", { status: s, note })}>
                      → {s}
                    </button>
                  ))}
                  <button disabled={busy || needAnalyst || !note.trim()}
                    onClick={() => post("remediation", { summary: note, verification: note })}>
                    Behebung dokumentieren
                  </button>
                  <button disabled={busy || needAnalyst} onClick={() => post("analysis", {})}>
                    KI-Einordnung anfordern
                  </button>
                </div>
                {needAnalyst && <p className="warn">Bitte oben einen Analystennamen eintragen. Jeder Schritt wird namentlich protokolliert.</p>}
                <table>
                  <tbody>
                    {selected.investigation_log.map((l, i) => (
                      <tr key={i}>
                        <td className="mono">{l.timestamp}</td>
                        <td>{l.analyst}</td>
                        <td>{l.action}</td>
                        <td>{l.note}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {selected.ai_analysis && (
                <div className="card">
                  <h3>KI-Einordnung ({selected.ai_analysis.provider})</h3>
                  <p className="muted">Nur Assistenz. Schweregrad und Findings kommen aus den Regeln.</p>
                  <p>{selected.ai_analysis.summary}</p>
                  {selected.ai_analysis.validation_warnings.length > 0 && (
                    <p className="warn">{selected.ai_analysis.validation_warnings.join("; ")}</p>
                  )}
                  <div className="three">
                    <Statements title="Fakten" hint="Mit Belegen geprüft." items={selected.ai_analysis.facts} />
                    <Statements title="Hypothesen" hint="Nicht bewiesen." items={selected.ai_analysis.hypotheses} />
                    <div className="card">
                      <h3>Unsicherheiten</h3>
                      <ul>{selected.ai_analysis.uncertainties.map((u, i) => <li key={i}>{u}</li>)}</ul>
                    </div>
                  </div>
                </div>
              )}
            </>
          )}
        </main>
      </div>
    </div>
  );
}
