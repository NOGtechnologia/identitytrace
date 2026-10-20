// Typed client for the IdentityTrace API. All values originate from untrusted logs:
// React escapes text by default, and this app never uses dangerouslySetInnerHTML.

export type Severity = "info" | "low" | "medium" | "high" | "critical";

export interface IncidentSummary {
  incident_id: string;
  title: string;
  severity: Severity;
  status: string;
  first_seen: string | null;
  actors: string[];
  rule_ids: string[];
  patterns: string[];
}

export interface TimelineEntry {
  event_id: string;
  timestamp: string | null;
  event_name: string | null;
  event_source: string | null;
  actor: string | null;
  source_ip: string | null;
  access_key_id: string | null;
  outcome: string;
  kind: string;
  rule_ids: string[];
  instruction_like_fields: string[];
}

export interface Statement {
  text: string;
  event_ids: string[];
  confidence: string | null;
}

export interface Finding {
  finding_id: string;
  rule_id: string;
  rule_name: string;
  severity: Severity;
  title: string;
  rationale: string;
  event_ids: string[];
  evidence: { event_id: string; field: string; value: unknown }[];
}

export interface Recommendation {
  rec_id: string;
  title: string;
  rationale: string;
  verify_steps: string[];
  change_steps: string[];
  requires_approval: boolean;
  approval: { approved_by: string; at: string; note: string } | null;
}

export interface LogEntry {
  timestamp: string;
  analyst: string;
  action: string;
  note: string;
}

export interface IncidentDetail extends IncidentSummary {
  timeline: TimelineEntry[];
  facts: Statement[];
  inferences: Statement[];
  gaps: Statement[];
  findings: Finding[];
  recommendations: Recommendation[];
  investigation_log: LogEntry[];
  remediation: { summary: string; verification: string } | null;
  ai_analysis: AiAnalysis | null;
}

export interface AiAnalysis {
  provider: string;
  summary: string;
  facts: Statement[];
  hypotheses: Statement[];
  uncertainties: string[];
  investigation_steps: string[];
  validation_warnings: string[];
}

export interface Quality {
  total_records: number;
  unusable_events: number;
  issue_counts: Record<string, number>;
  time_gaps: { start: string; end: string; duration_minutes: number }[];
  instruction_like_event_ids: string[];
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    ...init,
    headers: init?.body ? { "Content-Type": "application/json" } : undefined,
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(typeof body.detail === "string" ? body.detail : `HTTP ${res.status}`);
  }
  return res.json() as Promise<T>;
}

export const api = {
  datasets: () => request<{ id: number; name: string; record_count: number }[]>("/api/datasets"),
  loadDemo: () => request<{ dataset_id: number }>("/api/datasets/demo", { method: "POST" }),
  upload: async (file: File) => {
    const form = new FormData();
    form.append("file", file);
    const res = await fetch("/api/datasets", { method: "POST", body: form });
    if (!res.ok) throw new Error(`Upload fehlgeschlagen (HTTP ${res.status})`);
    return (await res.json()) as { dataset_id: number };
  },
  incidents: (ds: number) => request<IncidentSummary[]>(`/api/datasets/${ds}/incidents`),
  quality: (ds: number) => request<Quality>(`/api/datasets/${ds}/quality`),
  incident: (ds: number, id: string) => request<IncidentDetail>(`/api/datasets/${ds}/incidents/${id}`),
  post: (ds: number, id: string, action: string, body: object) =>
    request(`/api/datasets/${ds}/incidents/${id}/${action}`, { method: "POST", body: JSON.stringify(body) }),
  reportUrl: (ds: number, id: string, fmt: "html" | "json") => `/api/datasets/${ds}/incidents/${id}/report.${fmt}`,
};
