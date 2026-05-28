/// <reference types="vite/client" />
/**
 * Typed API client for the AI Auditor HITL backend (§10.2).
 *
 * Base URL is read from VITE_API_BASE (defaults to http://localhost:8000).
 * A Bearer token is attached automatically from AuthContext / localStorage.
 */

import type {
  ActionItem,
  CalibrationMetric,
  Decision,
  DecisionRequest,
  Event,
  Flag,
  Incident,
  IncidentComment,
  ReplayBundle,
  Run,
  ShadowVerdict,
  SimilarIncident,
} from "../types";

const BASE = (import.meta.env.VITE_API_BASE as string | undefined) ?? "http://localhost:8000";

function getToken(): string | null {
  return localStorage.getItem("hitl_token");
}

function getStoredEmail(): string | null {
  return localStorage.getItem("hitl_email");
}

function authHeaders(): HeadersInit {
  const token = getToken();
  return token ? { Authorization: `Bearer ${token}` } : {};
}

/**
 * Silent re-auth — when a request 401s mid-session, try to grab a fresh dev JWT using the email the
 * user signed in with (stored in localStorage on devLogin success). Shared promise so concurrent
 * 401s don't trigger N parallel logins; cleared 1s after settling so the next failure can retry.
 */
let refreshPromise: Promise<boolean> | null = null;
async function tryRefresh(): Promise<boolean> {
  if (refreshPromise) return refreshPromise;
  const email = getStoredEmail() ?? "admin@demo.local";
  refreshPromise = (async () => {
    try {
      const r = await fetch(`${BASE}/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password: "demo" }),
      });
      if (!r.ok) return false;
      const data = (await r.json()) as { access_token: string };
      localStorage.setItem("hitl_token", data.access_token);
      return true;
    } catch {
      return false;
    } finally {
      setTimeout(() => { refreshPromise = null; }, 1000);
    }
  })();
  return refreshPromise;
}

async function request<T>(path: string, init?: RequestInit, _retried = false): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`${BASE}${path}`, {
      ...init,
      headers: {
        "Content-Type": "application/json",
        ...authHeaders(),
        ...(init?.headers ?? {}),
      },
    });
  } catch (e) {
    // `fetch` rejects with TypeError on network-level failures (server down, CORS reject,
    // connection drop during the request). Surface a friendlier message than "Failed to fetch".
    throw new Error(`Auditor unreachable at ${BASE} — check the backend is running on :8000`);
  }

  // Token-expired path: try a single silent re-auth, then retry the original request.
  if (res.status === 401 && !_retried && getToken()) {
    const refreshed = await tryRefresh();
    if (refreshed) return request<T>(path, init, true);
    // Refresh failed — drop the stale token and notify the UI to re-prompt sign-in.
    localStorage.removeItem("hitl_token");
    window.dispatchEvent(new Event("hitl:auth-expired"));
  }

  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText);
    throw new Error(`API ${res.status}: ${text}`);
  }

  return res.json() as Promise<T>;
}

// ─── Flags ────────────────────────────────────────────────────────────────────

export interface FlagFilters {
  status?: string;
  severity?: string;
  asi_category?: string;
  tenant_id?: string;
  page?: number;
  page_size?: number;
}

// NOTE: the HITL router is mounted at `/hitl` in the auditor. The backend returns plain arrays for the
// list endpoints (not wrapper objects), so we type them as `Flag[]` and the pages consume them directly.

export function getFlags(filters: FlagFilters = {}): Promise<Flag[]> {
  const params = new URLSearchParams();
  (Object.keys(filters) as Array<keyof FlagFilters>).forEach((k) => {
    const v = filters[k];
    if (v !== undefined && v !== "") params.set(k, String(v));
  });
  const qs = params.toString() ? `?${params.toString()}` : "";
  return request<Flag[]>(`/hitl/flags${qs}`);
}

/**
 * Flag detail — backend returns `{flag, trace}`; we unwrap so callers get the Flag directly.
 * Use `getFlagDetail` if you want the trace in the same call (avoids a second round-trip).
 */
export async function getFlag(flagId: string): Promise<Flag> {
  const resp = await request<{ flag: Flag; trace: Event[] }>(`/hitl/flags/${flagId}`);
  return resp.flag;
}

export function getFlagDetail(flagId: string): Promise<{ flag: Flag; trace: Event[] }> {
  return request<{ flag: Flag; trace: Event[] }>(`/hitl/flags/${flagId}`);
}

export function postDecision(flagId: string, body: DecisionRequest): Promise<Decision> {
  return request<Decision>(`/hitl/flags/${flagId}/decisions`, {
    method: "POST",
    body: JSON.stringify(body),
  });
}

// ─── Runs ─────────────────────────────────────────────────────────────────────

export function getRun(runId: string): Promise<Run> {
  return request<Run>(`/hitl/runs/${runId}`);
}

export interface EventFilters {
  since?: string;
  limit?: number;
}

export function getRunEvents(runId: string, filters: EventFilters = {}): Promise<Event[]> {
  const params = new URLSearchParams();
  if (filters.since) params.set("since", filters.since);
  if (filters.limit !== undefined) params.set("limit", String(filters.limit));
  const qs = params.toString() ? `?${params.toString()}` : "";
  return request<Event[]>(`/hitl/runs/${runId}/events${qs}`);
}

export function getReplayBundle(runId: string): Promise<ReplayBundle> {
  return request<ReplayBundle>(`/hitl/runs/${runId}/replay`);
}

// ─── Calibration ──────────────────────────────────────────────────────────────

export function getCalibrationMetrics(): Promise<CalibrationMetric[]> {
  return request<CalibrationMetric[]>("/admin/calibration/latest");
}

// ─── Incidents ────────────────────────────────────────────────────────────────

export interface IncidentFilters {
  state?: string;
  severity?: string;
  tenant_id?: string;
  page?: number;
  page_size?: number;
}

export interface IncidentDetail {
  incident: Incident;
  comments: IncidentComment[];
  action_items: ActionItem[];
  similar: SimilarIncident[];
}

export function getIncidents(filters: IncidentFilters = {}): Promise<Incident[]> {
  const params = new URLSearchParams();
  (Object.keys(filters) as Array<keyof IncidentFilters>).forEach((k) => {
    const v = filters[k];
    if (v !== undefined && v !== "") params.set(k, String(v));
  });
  const qs = params.toString() ? `?${params.toString()}` : "";
  return request<Incident[]>(`/incidents${qs}`);
}

/**
 * Incident detail — backend returns `{incident, comments, action_items, similar}` so the queue page
 * gets everything in one round-trip. `getIncident` unwraps to the bare Incident for callers that
 * don't need the rest (e.g. legacy code paths); `getIncidentDetail` returns the full envelope.
 */
export async function getIncident(incidentId: string): Promise<Incident> {
  const resp = await request<IncidentDetail | Incident>(`/incidents/${incidentId}`);
  if (resp && typeof resp === "object" && "incident" in (resp as object)) {
    return (resp as IncidentDetail).incident;
  }
  return resp as Incident;
}

export function getIncidentDetail(incidentId: string): Promise<IncidentDetail> {
  return request<IncidentDetail>(`/incidents/${incidentId}`);
}

export interface TransitionRequest {
  new_state: string;
  rationale: string;
  post_mortem_uri?: string;
}

export function transitionIncident(
  incidentId: string,
  body: TransitionRequest,
): Promise<Incident> {
  return request<Incident>(`/incidents/${incidentId}/transition`, {
    method: "POST",
    body: JSON.stringify(body),
  });
}

export function getIncidentComments(incidentId: string): Promise<IncidentComment[]> {
  return request<IncidentComment[]>(`/incidents/${incidentId}/comments`);
}

export function postIncidentComment(
  incidentId: string,
  body: string,
): Promise<IncidentComment> {
  return request<IncidentComment>(`/incidents/${incidentId}/comments`, {
    method: "POST",
    body: JSON.stringify({ body }),
  });
}

export function getActionItems(incidentId: string): Promise<ActionItem[]> {
  return request<ActionItem[]>(`/incidents/${incidentId}/action-items`);
}

export interface ActionItemRequest {
  description: string;
  owner_id?: string;
  due_date?: string;
}

export function postActionItem(
  incidentId: string,
  body: ActionItemRequest,
): Promise<ActionItem> {
  return request<ActionItem>(`/incidents/${incidentId}/action-items`, {
    method: "POST",
    body: JSON.stringify(body),
  });
}

export function getSimilarIncidents(incidentId: string): Promise<SimilarIncident[]> {
  return request<SimilarIncident[]>(`/incidents/${incidentId}/similar`);
}

// ─── Shadow Verdicts ──────────────────────────────────────────────────────────

export interface ShadowVerdictFilters {
  detector_name?: string;
  asi_category?: string;
  page?: number;
  page_size?: number;
}

export function getShadowVerdicts(filters: ShadowVerdictFilters = {}): Promise<ShadowVerdict[]> {
  const params = new URLSearchParams();
  (Object.keys(filters) as Array<keyof ShadowVerdictFilters>).forEach((k) => {
    const v = filters[k];
    if (v !== undefined && v !== "") params.set(k, String(v));
  });
  const qs = params.toString() ? `?${params.toString()}` : "";
  return request<ShadowVerdict[]>(`/shadow/verdicts${qs}`);
}

// ─── WebSocket helper ─────────────────────────────────────────────────────────

const WS_BASE = BASE.replace(/^http/, "ws");

export interface FlagWsMessage {
  type: "flag_created" | "flag_updated";
  flag: Flag;
}

export function connectFlagsWs(
  tenantId: string,
  onMessage: (msg: FlagWsMessage) => void,
  onError?: (ev: globalThis.Event) => void,
): WebSocket {
  const token = getToken();
  const params = new URLSearchParams({ tenant_id: tenantId });
  if (token) params.set("token", token);
  const ws = new WebSocket(`${WS_BASE}/hitl/ws/flags?${params.toString()}`);

  ws.onmessage = (e: MessageEvent) => {
    try {
      const msg = JSON.parse(e.data as string) as FlagWsMessage;
      onMessage(msg);
    } catch {
      // ignore malformed frames
    }
  };

  if (onError) {
    ws.onerror = onError;
  }

  return ws;
}

// ─── Interactive agent runs ───────────────────────────────────────────────────

import type { AgentRunStart, AgentRunState } from "../types";

export function runAgent(task: string, maxTurns = 12): Promise<AgentRunStart> {
  return request<AgentRunStart>("/agent/runs", {
    method: "POST",
    body: JSON.stringify({ task, max_turns: maxTurns }),
  });
}

export function getAgentRun(runId: string): Promise<AgentRunState> {
  return request<AgentRunState>(`/agent/runs/${runId}`);
}

// ─── Dev login (Phase-7 local fallback) ───────────────────────────────────────

export interface LoginResponse {
  access_token: string;
  token_type: string;
  role: string;
  tenant_id: string;
  user_id: string;
}

export function devLogin(email: string, password = "demo"): Promise<LoginResponse> {
  return fetch(`${BASE}/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  }).then(async (r) => {
    if (!r.ok) throw new Error(`login ${r.status}: ${await r.text().catch(() => r.statusText)}`);
    const data = (await r.json()) as LoginResponse;
    // Remember the email so silent re-auth can use the same account on token expiry.
    localStorage.setItem("hitl_email", email);
    return data;
  });
}

// ─── Sampler settings ─────────────────────────────────────────────────────────

import type { SamplerSettings } from "../types";

export function getSamplerSettings(): Promise<SamplerSettings> {
  return request<SamplerSettings>("/admin/sampler");
}

export function updateSamplerSettings(patch: Partial<SamplerSettings>): Promise<SamplerSettings> {
  return request<SamplerSettings>("/admin/sampler", {
    method: "PUT",
    body: JSON.stringify(patch),
  });
}

// ─── Demo reset ───────────────────────────────────────────────────────────────

export function resetDemoData(): Promise<{ wiped: string[] }> {
  return request<{ wiped: string[] }>("/admin/reset", { method: "POST" });
}
