/**
 * Incident detail — schema-honest, clean light visual.
 *
 * Header card with severity + state + lifecycle timeline. State transitions follow STATE_FLOW.
 * Comments + action items + similar incidents load lazily via Promise.allSettled — a freshly
 * seeded incident won't 404 the page if those endpoints are empty.
 */

import React, { useCallback, useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import {
  getActionItems,
  getIncident,
  getIncidentComments,
  getSimilarIncidents,
  postActionItem,
  postIncidentComment,
  transitionIncident,
} from "../api/client";
import { useToast } from "../components/Toast";
import { formatRelative } from "../lib/time";
import type {
  ActionItem,
  Incident,
  IncidentComment,
  IncidentState,
  Severity,
  SimilarIncident,
} from "../types";

const STATE_FLOW: Record<IncidentState, IncidentState[]> = {
  OPEN: ["TRIAGING", "DISMISSED"],
  TRIAGING: ["INVESTIGATING", "DISMISSED"],
  INVESTIGATING: ["CONTAINED"],
  CONTAINED: ["RESOLVED"],
  RESOLVED: ["POST_MORTEM_COMPLETE"],
  POST_MORTEM_COMPLETE: [],
  DISMISSED: [],
};

const SEV_TONE: Record<Severity, { dot: string; chip: string; bar: string }> = {
  critical: { dot: "bg-red-500",     chip: "bg-red-50 dark:bg-red-950/40 text-red-700 dark:text-red-300 ring-1 ring-inset ring-red-200 dark:ring-red-900",         bar: "bg-red-500" },
  high:     { dot: "bg-orange-500",  chip: "bg-orange-50 dark:bg-orange-950/40 text-orange-700 dark:text-orange-300 ring-1 ring-inset ring-orange-200 dark:ring-orange-900", bar: "bg-orange-500" },
  medium:   { dot: "bg-amber-500",   chip: "bg-amber-50 dark:bg-amber-950/40 text-amber-700 dark:text-amber-300 ring-1 ring-inset ring-amber-200 dark:ring-amber-900",    bar: "bg-amber-500" },
  low:      { dot: "bg-sky-500",     chip: "bg-sky-50 dark:bg-sky-950/40 text-sky-700 dark:text-sky-300 ring-1 ring-inset ring-sky-200 dark:ring-sky-900",          bar: "bg-sky-500" },
};

const STATE_TONE: Record<IncidentState, string> = {
  OPEN:                 "bg-red-50 dark:bg-red-950/40 text-red-700 dark:text-red-300 ring-1 ring-inset ring-red-200 dark:ring-red-900",
  TRIAGING:             "bg-orange-50 dark:bg-orange-950/40 text-orange-700 dark:text-orange-300 ring-1 ring-inset ring-orange-200 dark:ring-orange-900",
  INVESTIGATING:        "bg-amber-50 dark:bg-amber-950/40 text-amber-700 dark:text-amber-300 ring-1 ring-inset ring-amber-200 dark:ring-amber-900",
  CONTAINED:            "bg-sky-50 dark:bg-sky-950/40 text-sky-700 dark:text-sky-300 ring-1 ring-inset ring-sky-200 dark:ring-sky-900",
  RESOLVED:             "bg-emerald-50 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-300 ring-1 ring-inset ring-emerald-200 dark:ring-emerald-900",
  POST_MORTEM_COMPLETE: "bg-indigo-50 dark:bg-indigo-950/40 text-indigo-700 dark:text-indigo-300 ring-1 ring-inset ring-indigo-200 dark:ring-indigo-900",
  DISMISSED:            "bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-400 ring-1 ring-inset ring-gray-200",
};

function Card({ title, sub, children }: { title?: string; sub?: string; children: React.ReactNode }) {
  return (
    <section className="rounded-xl border border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900">
      {title && (
        <header className="px-5 py-3 border-b border-gray-100 dark:border-gray-800">
          <h2 className="text-[13px] font-semibold uppercase tracking-wider text-gray-700 dark:text-gray-300">{title}</h2>
          {sub && <p className="text-[12px] text-gray-500 dark:text-gray-400 mt-0.5">{sub}</p>}
        </header>
      )}
      <div className="px-5 py-4">{children}</div>
    </section>
  );
}

function Timeline({ incident }: { incident: Incident }) {
  const steps: { label: string; ts: string | null }[] = [
    { label: "Opened",    ts: incident.opened_at },
    { label: "Triaged",   ts: incident.triaged_at },
    { label: "Contained", ts: incident.contained_at },
    { label: "Resolved",  ts: incident.resolved_at },
  ];
  return (
    <div className="grid grid-cols-4 gap-3">
      {steps.map((s, i) => (
        <div key={i} className="flex-1 min-w-0">
          <div className="flex items-center">
            <span className={`w-2.5 h-2.5 rounded-full ${s.ts ? "bg-emerald-500" : "bg-gray-300"}`} />
            {i < steps.length - 1 && <span className="h-px flex-1 bg-gray-200" />}
          </div>
          <div className={`mt-1.5 text-[11px] font-semibold uppercase tracking-wider ${s.ts ? "text-gray-900 dark:text-gray-100" : "text-gray-400 dark:text-gray-500"}`}>
            {s.label}
          </div>
          <div className={`text-[11px] mt-0.5 truncate ${s.ts ? "text-gray-600 dark:text-gray-400" : "text-gray-400 dark:text-gray-500"}`}>
            {s.ts ? new Date(s.ts).toLocaleString() : "—"}
          </div>
        </div>
      ))}
    </div>
  );
}

const INPUT =
  "rounded-md border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-900 text-gray-900 dark:text-gray-100 placeholder-gray-400 dark:placeholder-gray-500 px-3 py-2 text-[13px] focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500";

export default function IncidentDetail(): React.ReactElement {
  const { incidentId } = useParams<{ incidentId: string }>();
  const navigate = useNavigate();
  const toast = useToast();
  const [incident, setIncident] = useState<Incident | null>(null);
  const [comments, setComments] = useState<IncidentComment[]>([]);
  const [actionItems, setActionItems] = useState<ActionItem[]>([]);
  const [similar, setSimilar] = useState<SimilarIncident[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [newComment, setNewComment] = useState("");
  const [newAction, setNewAction] = useState("");
  const [postMortemUri, setPostMortemUri] = useState("");
  const [transitionRationale, setTransitionRationale] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const load = useCallback(async () => {
    if (!incidentId) return;
    setLoading(true);
    setError(null);
    try {
      const inc = await getIncident(incidentId);
      setIncident(inc);
      const [cs, ais, sims] = await Promise.allSettled([
        getIncidentComments(incidentId),
        getActionItems(incidentId),
        getSimilarIncidents(incidentId),
      ]);
      if (cs.status === "fulfilled") setComments(cs.value);
      if (ais.status === "fulfilled") setActionItems(ais.value);
      if (sims.status === "fulfilled") setSimilar(sims.value);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  }, [incidentId]);

  useEffect(() => { void load(); }, [load]);

  const doTransition = async (target: IncidentState) => {
    if (!incidentId || submitting) return;
    setSubmitting(true);
    try {
      const updated = await transitionIncident(incidentId, {
        new_state: target,
        rationale: transitionRationale || `transitioning to ${target}`,
        post_mortem_uri: target === "POST_MORTEM_COMPLETE" ? postMortemUri || undefined : undefined,
      });
      setIncident(updated);
      setTransitionRationale("");
      setPostMortemUri("");
      toast.success(`Moved to ${target.replace(/_/g, " ")}`);
    } catch (e) {
      const msg = (e as Error).message;
      setError(msg);
      toast.error(`Transition failed — ${msg}`);
    } finally {
      setSubmitting(false);
    }
  };

  const addComment = async () => {
    if (!incidentId || !newComment.trim()) return;
    try {
      const c = await postIncidentComment(incidentId, newComment.trim());
      setComments((prev) => [...prev, c]);
      setNewComment("");
      toast.success("Comment posted");
    } catch (e) {
      const msg = (e as Error).message;
      setError(msg);
      toast.error(`Could not post comment — ${msg}`);
    }
  };

  const addAction = async () => {
    if (!incidentId || !newAction.trim()) return;
    try {
      const a = await postActionItem(incidentId, { description: newAction.trim() });
      setActionItems((prev) => [...prev, a]);
      setNewAction("");
      toast.success("Action item added");
    } catch (e) {
      const msg = (e as Error).message;
      setError(msg);
      toast.error(`Could not add action item — ${msg}`);
    }
  };

  if (loading) {
    return <div className="max-w-5xl mx-auto px-6 py-10 text-[13px] text-gray-500 dark:text-gray-400">Loading incident…</div>;
  }
  if (error && !incident) {
    return (
      <div className="max-w-5xl mx-auto px-6 py-10">
        <div className="rounded-xl border border-red-200 dark:border-red-900 bg-red-50 dark:bg-red-950/40 text-[13px] text-red-700 dark:text-red-300 p-4">{error}</div>
        <button onClick={() => navigate(-1)} className="mt-4 text-[13px] text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-100">← Back</button>
      </div>
    );
  }
  if (!incident) {
    return <div className="max-w-5xl mx-auto px-6 py-10 text-[13px] text-gray-500 dark:text-gray-400">Incident not found.</div>;
  }

  const nextStates = STATE_FLOW[incident.state as IncidentState] ?? [];
  const tone = SEV_TONE[incident.severity];

  return (
    <div className="max-w-5xl mx-auto px-6 py-6 space-y-4">
      <button onClick={() => navigate(-1)} className="text-[12px] text-gray-500 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-100 inline-flex items-center gap-1">
        ← Back to incidents
      </button>

      {/* Header */}
      <div className="rounded-xl border border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900 overflow-hidden">
        <div className={`h-1 ${tone.bar}`} />
        <div className="px-6 py-5">
          <div className="flex items-center gap-2 flex-wrap mb-2">
            <span className={`inline-flex items-center gap-2 px-2 py-0.5 rounded text-[11px] font-semibold uppercase tracking-wider ${tone.chip}`}>
              <span className={`w-1.5 h-1.5 rounded-full ${tone.dot}`} />
              {incident.severity}
            </span>
            <span className={`inline-block px-2 py-0.5 rounded text-[11px] font-semibold uppercase tracking-wider ${STATE_TONE[incident.state]}`}>
              {incident.state.replace(/_/g, " ")}
            </span>
          </div>
          <h1 className="text-[20px] font-semibold text-gray-900 dark:text-gray-100 leading-tight">
            {incident.title ?? "Incident"}{" "}
            <span className="font-mono text-gray-500 dark:text-gray-400 text-[18px]">{incident.incident_id.slice(0, 12)}</span>
          </h1>

          <div className="mt-5">
            <h3 className="text-[10px] uppercase tracking-wider text-gray-500 dark:text-gray-400 font-semibold mb-2.5">Lifecycle</h3>
            <Timeline incident={incident} />
          </div>

          <div className="mt-5 grid grid-cols-1 sm:grid-cols-2 gap-x-8 gap-y-3 text-[13px]">
            <div>
              <dt className="text-[10px] uppercase tracking-wider text-gray-500 dark:text-gray-400 font-semibold mb-0.5">Primary flag</dt>
              <dd>
                <Link to={`/flags/${incident.primary_flag_id}`} className="font-mono text-indigo-600 dark:text-indigo-400 hover:text-indigo-800 dark:hover:text-indigo-200 hover:underline">
                  {incident.primary_flag_id.slice(0, 12)} →
                </Link>
              </dd>
            </div>
            <div>
              <dt className="text-[10px] uppercase tracking-wider text-gray-500 dark:text-gray-400 font-semibold mb-0.5">Assignee</dt>
              <dd className="text-gray-700 dark:text-gray-300">
                {incident.assignee_name ?? incident.assignee_id ?? <span className="text-gray-400 dark:text-gray-500 italic">unassigned</span>}
              </dd>
            </div>
            {incident.post_mortem_uri && (
              <div className="sm:col-span-2">
                <dt className="text-[10px] uppercase tracking-wider text-gray-500 dark:text-gray-400 font-semibold mb-0.5">Post-mortem</dt>
                <dd className="font-mono text-[12px] text-gray-700 dark:text-gray-300 break-all">{incident.post_mortem_uri}</dd>
              </div>
            )}
            {incident.dismissal_rationale && (
              <div className="sm:col-span-2">
                <dt className="text-[10px] uppercase tracking-wider text-gray-500 dark:text-gray-400 font-semibold mb-0.5">Dismissed</dt>
                <dd className="text-gray-700 dark:text-gray-300">{incident.dismissal_rationale}</dd>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Transition */}
      {nextStates.length > 0 && (
        <Card title="Advance state" sub={`Allowed next states from ${incident.state}.`}>
          <textarea
            value={transitionRationale}
            onChange={(e) => setTransitionRationale(e.target.value)}
            rows={2}
            placeholder="Optional — rationale for the transition"
            className={`${INPUT} w-full resize-none mb-3`}
          />
          {nextStates.includes("POST_MORTEM_COMPLETE") && (
            <input
              type="text"
              value={postMortemUri}
              onChange={(e) => setPostMortemUri(e.target.value)}
              placeholder="Post-mortem URI (required for critical incidents)"
              className={`${INPUT} w-full mb-3`}
            />
          )}
          <div className="flex flex-wrap gap-2">
            {nextStates.map((s) => (
              <button
                key={s}
                type="button"
                disabled={submitting}
                onClick={() => void doTransition(s)}
                className="px-3 py-1.5 rounded-lg bg-gray-900 dark:bg-gray-700 text-white text-[12px] font-medium hover:bg-gray-700 disabled:opacity-50"
              >
                → {s.replace(/_/g, " ")}
              </button>
            ))}
          </div>
          {error && <div className="mt-3 text-[12px] text-red-600">{error}</div>}
        </Card>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Comments */}
        <Card title="Comments">
          <div className="space-y-2.5 mb-3 max-h-64 overflow-y-auto pr-1">
            {comments.length === 0 && <div className="text-[12px] text-gray-500 dark:text-gray-400">No comments yet.</div>}
            {comments.map((c) => (
              <div key={c.comment_id} className="text-[13px] border-l-2 border-gray-200 dark:border-gray-800 pl-3">
                <div className="text-[11px] text-gray-500 dark:text-gray-400">
                  {c.author_name ?? c.author_id?.slice(0, 8)} · <span title={c.ts}>{formatRelative(c.ts)}</span>
                </div>
                <div className="text-gray-800 dark:text-gray-200 mt-0.5">{c.body}</div>
              </div>
            ))}
          </div>
          <div className="flex gap-2">
            <input
              type="text"
              value={newComment}
              onChange={(e) => setNewComment(e.target.value)}
              placeholder="Add a comment…"
              className={`${INPUT} flex-1`}
            />
            <button
              type="button"
              onClick={addComment}
              disabled={!newComment.trim()}
              className="px-3 py-1.5 rounded-lg bg-indigo-600 text-white text-[13px] font-medium hover:bg-indigo-700 disabled:opacity-50"
            >
              Post
            </button>
          </div>
        </Card>

        {/* Action items */}
        <Card title="Action items">
          <div className="space-y-2 mb-3 max-h-64 overflow-y-auto pr-1">
            {actionItems.length === 0 && <div className="text-[12px] text-gray-500 dark:text-gray-400">No action items yet.</div>}
            {actionItems.map((a) => (
              <div key={a.action_id} className="text-[13px] flex items-start gap-2">
                <span className="text-[10px] uppercase font-semibold text-gray-500 dark:text-gray-400 mt-0.5 w-20 flex-shrink-0">{a.status}</span>
                <span className="text-gray-800 dark:text-gray-200 flex-1">{a.description}</span>
              </div>
            ))}
          </div>
          <div className="flex gap-2">
            <input
              type="text"
              value={newAction}
              onChange={(e) => setNewAction(e.target.value)}
              placeholder="New action item…"
              className={`${INPUT} flex-1`}
            />
            <button
              type="button"
              onClick={addAction}
              disabled={!newAction.trim()}
              className="px-3 py-1.5 rounded-lg bg-indigo-600 text-white text-[13px] font-medium hover:bg-indigo-700 disabled:opacity-50"
            >
              Add
            </button>
          </div>
        </Card>
      </div>

      {/* Similar */}
      {similar.length > 0 && (
        <Card title="Similar incidents">
          <ul className="space-y-2">
            {similar.map((s) => {
              const sevTone = SEV_TONE[s.severity];
              return (
                <li key={s.incident_id} className="flex items-center gap-3 text-[13px]">
                  <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wider ${sevTone.chip}`}>
                    <span className={`w-1.5 h-1.5 rounded-full ${sevTone.dot}`} />
                    {s.severity}
                  </span>
                  <Link to={`/incidents/${s.incident_id}`} className="font-mono text-[12px] text-indigo-600 dark:text-indigo-400 hover:text-indigo-800 dark:hover:text-indigo-200 hover:underline">
                    {s.title ?? s.incident_id.slice(0, 12)}
                  </Link>
                  <span className="ml-auto text-[11px] text-gray-500 dark:text-gray-400">
                    similarity {(s.similarity_score * 100).toFixed(0)}%
                  </span>
                </li>
              );
            })}
          </ul>
        </Card>
      )}
    </div>
  );
}
