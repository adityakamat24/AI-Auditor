// ─── Domain types matching the AI Auditor data model (§8, §10.2) ──────────────

export type Severity = "critical" | "high" | "medium" | "low";

export type FlagStatus = "open" | "in_review" | "resolved" | "dismissed";

export type AsiCategory =
  | "ASI-01"
  | "ASI-02"
  | "ASI-03"
  | "ASI-04"
  | "ASI-05"
  | "ASI-06"
  | "ASI-07"
  | "ASI-08"
  | "ASI-09"
  | "ASI-10";

export type DecisionAction = "continue" | "abort" | "quarantine";

export type EventChannel = "voluntary" | "involuntary";

export interface Flag {
  flag_id: string;
  run_id: string;
  tenant_id: string;
  severity: Severity;
  asi_categories: AsiCategory[];
  status: FlagStatus;
  opened_at: string; // ISO 8601
  updated_at: string;
  summary: string;
  evidence: Evidence[];
  judge_scores: JudgeScore[];
}

export interface Evidence {
  evidence_id: string;
  kind: string;
  description: string;
  ts: string;
  raw?: Record<string, unknown>;
}

export interface JudgeScore {
  asi_category: AsiCategory;
  score: number; // 0–1
  rationale: string;
  rubric_version: string;
}

export interface Decision {
  decision_id: string;
  flag_id: string;
  decision: DecisionAction;
  rationale: string;
  decided_by: string;
  decided_at: string;
}

export interface DecisionRequest {
  decision: DecisionAction;
  rationale: string;
}

export interface Run {
  run_id: string;
  tenant_id: string;
  started_at: string;
  ended_at?: string;
  status: "running" | "completed" | "aborted" | "quarantined";
  agent_kind: string;
  task_summary: string;
}

export interface Event {
  event_id: string;
  run_id: string;
  channel: EventChannel;
  event_type: string;
  ts: string;
  payload: Record<string, unknown>;
  divergence?: boolean;
}

export interface Verdict {
  verdict_id: string;
  run_id: string;
  flag_id: string;
  asi_category: AsiCategory;
  score: number;
  rationale: string;
  created_at: string;
}

export interface CalibrationMetric {
  asi_category: AsiCategory;
  precision: number;
  recall: number;
  f1: number;
  tp: number;
  fp: number;
  fn: number;
  evaluated_at: string;
}

export interface ReplayBundle {
  run_id: string;
  events: Event[];
  flags: Flag[];
}

// ─── API list-response wrappers ───────────────────────────────────────────────
export interface FlagListResponse {
  flags: Flag[];
  total: number;
  page: number;
  page_size: number;
}

// ─── Incident types (§9.10.5) ─────────────────────────────────────────────────

export type IncidentState =
  | "OPEN"
  | "TRIAGING"
  | "INVESTIGATING"
  | "CONTAINED"
  | "RESOLVED"
  | "POST_MORTEM_COMPLETE"
  | "DISMISSED";

export interface Incident {
  incident_id: string;
  tenant_id: string;
  primary_flag_id: string;
  related_flag_ids: string[];
  severity: Severity;
  state: IncidentState;
  assignee_id: string | null;
  assignee_name?: string | null;
  opened_at: string; // ISO 8601
  triaged_at: string | null;
  contained_at: string | null;
  resolved_at: string | null;
  post_mortem_uri: string | null;
  dismissal_rationale: string | null;
  title?: string;
}

export interface IncidentComment {
  comment_id: string;
  incident_id: string;
  author_id: string;
  author_name?: string;
  body: string;
  ts: string; // ISO 8601
}

export type ActionItemStatus = "open" | "in_progress" | "done" | "cancelled";

export interface ActionItem {
  action_id: string;
  incident_id: string;
  owner_id: string | null;
  owner_name?: string | null;
  description: string;
  status: ActionItemStatus;
  due_date: string | null; // ISO date
  created_at: string;
  completed_at: string | null;
}

export interface IncidentListResponse {
  incidents: Incident[];
  total: number;
  page: number;
  page_size: number;
}

export interface SimilarIncident {
  incident_id: string;
  severity: Severity;
  state: IncidentState;
  opened_at: string;
  similarity_score: number;
  title?: string;
}

// ─── Shadow verdict types (§9.13) ─────────────────────────────────────────────

export type DetectorState =
  | "PROPOSED"
  | "SHADOW"
  | "CANARY"
  | "ENFORCING"
  | "DISABLED"
  | "DEPRECATED"
  | "REMOVED";

export interface ShadowVerdict {
  verdict_id: string;
  detector_name: string;
  detector_version: string;
  detector_state: DetectorState;
  run_id: string;
  asi_category: AsiCategory;
  score: number; // 0–1
  rationale: string;
  created_at: string; // ISO 8601
}

export interface ShadowDetectorSummary {
  detector_name: string;
  detector_version: string;
  detector_state: DetectorState;
  verdict_count: number;
  avg_score: number;
  high_score_count: number; // score >= 0.7
  last_verdict_at: string | null;
}

// ─── Interactive agent runs (control plane) ───────────────────────────────────

export interface AgentRunStart {
  run_id: string;
  tenant_id: string;
  task: string;
  started_at: string;
}

export interface AgentVerdict {
  detector: string;
  asi_category: string;
  result: "OK" | "VIOLATION" | "NEEDS_REVIEW";
  confidence: number;
  reason: string;
}

export interface AgentCheck {
  title: string;
  verdicts: AgentVerdict[];
}

export interface AgentEvent {
  event_id: string;
  ts: string | null;
  event_type: string;
  channel: string;
  payload: Record<string, unknown>;
}

export interface AgentRunState {
  run_id: string;
  harness_status: string;
  audited: boolean;
  run: {
    status: string;
    declared_goal: string | null;
    started_at: string | null;
    ended_at: string | null;
  } | null;
  sampler: {
    tier: string;
    reason: string;
    cohort_rate: number | null;
  } | null;
  events: AgentEvent[];
  checks: Record<string, AgentCheck>;
  flag: {
    flag_id: string;
    severity: string;
    asi_categories: string[];
    status: string;
  } | null;
  incident: {
    incident_id: string;
    state: string;
    severity: string;
  } | null;
}

// ─── Sampler runtime settings (control plane) ─────────────────────────────────

export type SamplerMode = "percentage" | "every_nth" | "interval" | "always" | "never";

export interface SamplerSettings {
  mode: SamplerMode;
  rate: number;                    // for "percentage": 0.0–1.0
  every_n: number;                 // for "every_nth"
  interval_seconds: number;        // for "interval"
  critical_risk_threshold: number; // L1 cheap-risk cutoff (0–100)
}
