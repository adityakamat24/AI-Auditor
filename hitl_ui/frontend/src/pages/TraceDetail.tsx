/**
 * Flag detail — schema-honest. Uses only fields the backend actually returns:
 *   flag_id / run_id / tenant_id / severity / status / asi_categories / opened_at + the run's events.
 *
 * Visual: matches the operator console aesthetic — soft borders, clean chips, explicit text colors.
 */

import React, { useCallback, useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { getFlag, getRunEvents, postDecision } from "../api/client";
import { useToast } from "../components/Toast";
import { formatRelative } from "../lib/time";
import type { DecisionAction, Event, Flag, Severity } from "../types";

const SEV_TONE: Record<Severity, { dot: string; chip: string; bar: string; text: string }> = {
  critical: { dot: "bg-red-500",     chip: "bg-red-50 dark:bg-red-950/40 text-red-700 dark:text-red-300 ring-1 ring-inset ring-red-200 dark:ring-red-900",         bar: "bg-red-500",    text: "text-red-700 dark:text-red-300" },
  high:     { dot: "bg-orange-500",  chip: "bg-orange-50 dark:bg-orange-950/40 text-orange-700 dark:text-orange-300 ring-1 ring-inset ring-orange-200 dark:ring-orange-900", bar: "bg-orange-500", text: "text-orange-700 dark:text-orange-300" },
  medium:   { dot: "bg-amber-500",   chip: "bg-amber-50 dark:bg-amber-950/40 text-amber-700 dark:text-amber-300 ring-1 ring-inset ring-amber-200 dark:ring-amber-900",    bar: "bg-amber-500",  text: "text-amber-700 dark:text-amber-300" },
  low:      { dot: "bg-sky-500",     chip: "bg-sky-50 dark:bg-sky-950/40 text-sky-700 dark:text-sky-300 ring-1 ring-inset ring-sky-200 dark:ring-sky-900",          bar: "bg-sky-500",    text: "text-sky-700 dark:text-sky-300" },
};

const STATUS_TONE: Record<string, string> = {
  open:      "bg-blue-50 dark:bg-blue-950/40 text-blue-700 dark:text-blue-300 ring-1 ring-inset ring-blue-200 dark:ring-blue-900",
  in_review: "bg-indigo-50 dark:bg-indigo-950/40 text-indigo-700 dark:text-indigo-300 ring-1 ring-inset ring-indigo-200 dark:ring-indigo-900",
  resolved:  "bg-emerald-50 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-300 ring-1 ring-inset ring-emerald-200 dark:ring-emerald-900",
  dismissed: "bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-400 ring-1 ring-inset ring-gray-200",
};

function Card({ title, sub, children, className = "" }: { title?: string; sub?: string; children: React.ReactNode; className?: string }) {
  return (
    <section className={`rounded-xl border border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900 ${className}`}>
      {title && (
        <header className="px-5 py-3 border-b border-gray-100 dark:border-gray-800 flex items-center justify-between">
          <div>
            <h2 className="text-[13px] font-semibold uppercase tracking-wider text-gray-700 dark:text-gray-300">{title}</h2>
            {sub && <p className="text-[12px] text-gray-500 dark:text-gray-400 mt-0.5">{sub}</p>}
          </div>
        </header>
      )}
      <div className="px-5 py-4">{children}</div>
    </section>
  );
}

function EventRow({ event }: { event: Event }) {
  const payload = event.payload as Record<string, unknown>;
  const tool = payload.tool_name as string | undefined;
  const args = payload.tool_args;
  const summary = payload.result_summary as string | undefined;
  const intent = payload.intent as string | undefined;
  const stamp = event.ts ? new Date(event.ts).toLocaleTimeString() : "";
  return (
    <div className="grid grid-cols-[80px_150px_1fr] gap-3 py-2 text-[12px] font-mono border-b border-gray-100 dark:border-gray-800 last:border-0">
      <span className="text-gray-400 dark:text-gray-500">{stamp}</span>
      <span className="text-indigo-700 dark:text-indigo-300 truncate">{event.event_type}</span>
      <div className="min-w-0 space-y-0.5">
        {tool && <div className="text-emerald-700 dark:text-emerald-300">{tool}</div>}
        {args !== undefined && (
          <div className="text-gray-500 dark:text-gray-400 break-all">{JSON.stringify(args).slice(0, 300)}</div>
        )}
        {summary && (
          <div className="text-amber-700 dark:text-amber-300 break-words">→ {summary.slice(0, 400)}</div>
        )}
        {intent && (
          <div className="text-gray-700 dark:text-gray-300 break-words">{intent.slice(0, 400)}</div>
        )}
      </div>
    </div>
  );
}

export default function TraceDetail(): React.ReactElement {
  const { flagId } = useParams<{ flagId: string }>();
  const navigate = useNavigate();
  const toast = useToast();
  const [flag, setFlag] = useState<Flag | null>(null);
  const [events, setEvents] = useState<Event[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [rationale, setRationale] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [decided, setDecided] = useState<DecisionAction | null>(null);

  const load = useCallback(async () => {
    if (!flagId) return;
    setLoading(true);
    setError(null);
    try {
      const f = await getFlag(flagId);
      setFlag(f);
      const evs = await getRunEvents(f.run_id, { limit: 500 });
      setEvents(evs);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  }, [flagId]);

  useEffect(() => { void load(); }, [load]);

  const decide = async (decision: DecisionAction) => {
    if (!flagId || submitting) return;
    setSubmitting(true);
    try {
      await postDecision(flagId, { decision, rationale: rationale || `${decision} via review` });
      setDecided(decision);
      toast.success(`Decision recorded — ${decision}`);
    } catch (e) {
      const msg = (e as Error).message;
      setError(`Decision failed: ${msg}`);
      toast.error(`Decision failed — ${msg}`);
    } finally {
      setSubmitting(false);
    }
  };

  if (loading) {
    return <div className="max-w-5xl mx-auto px-6 py-10 text-[13px] text-gray-500 dark:text-gray-400">Loading flag…</div>;
  }
  if (error && !flag) {
    return (
      <div className="max-w-5xl mx-auto px-6 py-10">
        <div className="rounded-xl border border-red-200 dark:border-red-900 bg-red-50 dark:bg-red-950/40 text-[13px] text-red-700 dark:text-red-300 p-4">{error}</div>
        <button onClick={() => navigate(-1)} className="mt-4 text-[13px] text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-100">← Back</button>
      </div>
    );
  }
  if (!flag) {
    return <div className="max-w-5xl mx-auto px-6 py-10 text-[13px] text-gray-500 dark:text-gray-400">Flag not found.</div>;
  }

  const tone = SEV_TONE[flag.severity];
  const opened = (flag as Flag & { created_at?: string }).created_at ?? flag.opened_at;
  const decisionBtns: Array<{ a: DecisionAction; label: string; cls: string }> = [
    { a: "continue",   label: "Allow",      cls: "bg-emerald-600 hover:bg-emerald-700 text-white" },
    { a: "abort",      label: "Abort",      cls: "bg-red-600 hover:bg-red-700 text-white" },
    { a: "quarantine", label: "Quarantine", cls: "bg-amber-600 hover:bg-amber-700 text-white" },
  ];

  return (
    <div className="max-w-5xl mx-auto px-6 py-6 space-y-4">
      <button onClick={() => navigate(-1)} className="text-[12px] text-gray-500 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-100 inline-flex items-center gap-1">
        ← Back to queue
      </button>

      {/* Header card */}
      <div className="rounded-xl border border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900 overflow-hidden">
        <div className={`h-1 ${tone.bar}`} />
        <div className="px-6 py-5">
          <div className="flex items-center gap-2 flex-wrap mb-2">
            <span className={`inline-flex items-center gap-2 px-2 py-0.5 rounded text-[11px] font-semibold uppercase tracking-wider ${tone.chip}`}>
              <span className={`w-1.5 h-1.5 rounded-full ${tone.dot}`} />
              {flag.severity}
            </span>
            <span className={`inline-block px-2 py-0.5 rounded text-[11px] font-semibold uppercase tracking-wider ${STATUS_TONE[flag.status] ?? "bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300"}`}>
              {flag.status.replace("_", " ")}
            </span>
          </div>
          <h1 className="text-[20px] font-semibold text-gray-900 dark:text-gray-100 leading-tight">
            Flag <span className="font-mono text-gray-500 dark:text-gray-400 text-[18px]">{flag.flag_id.slice(0, 12)}</span>
          </h1>
          <dl className="mt-5 grid grid-cols-1 sm:grid-cols-2 gap-x-8 gap-y-3 text-[13px]">
            <div>
              <dt className="text-[10px] uppercase tracking-wider text-gray-500 dark:text-gray-400 font-semibold mb-0.5">Run</dt>
              <dd className="font-mono text-gray-700 dark:text-gray-300 break-all">{flag.run_id}</dd>
            </div>
            <div>
              <dt className="text-[10px] uppercase tracking-wider text-gray-500 dark:text-gray-400 font-semibold mb-0.5">Tenant</dt>
              <dd className="font-mono text-gray-700 dark:text-gray-300 break-all">{flag.tenant_id}</dd>
            </div>
            <div>
              <dt className="text-[10px] uppercase tracking-wider text-gray-500 dark:text-gray-400 font-semibold mb-0.5">Opened</dt>
              <dd className="text-gray-700 dark:text-gray-300" title={opened ?? undefined}>{formatRelative(opened)}</dd>
            </div>
            <div>
              <dt className="text-[10px] uppercase tracking-wider text-gray-500 dark:text-gray-400 font-semibold mb-0.5">Categories</dt>
              <dd className="flex flex-wrap gap-1">
                {flag.asi_categories?.length ? (
                  flag.asi_categories.map((c) => (
                    <span key={c} className="px-1.5 py-0.5 rounded text-[11px] bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300 font-mono">{c}</span>
                  ))
                ) : (
                  <span className="text-gray-400 dark:text-gray-500">—</span>
                )}
              </dd>
            </div>
          </dl>
        </div>
      </div>

      {/* Decision */}
      <Card title="HITL decision" sub="Your choice is recorded against the flag and feeds the calibration loop.">
        {decided ? (
          <div className="text-[13px] text-emerald-700 dark:text-emerald-300">
            <span className="font-semibold uppercase tracking-wider text-[11px]">{decided}</span>{" "}
            recorded at {new Date().toLocaleTimeString()}.
          </div>
        ) : (
          <>
            <textarea
              value={rationale}
              onChange={(e) => setRationale(e.target.value)}
              placeholder="Optional — why are you making this decision?"
              rows={2}
              className="w-full text-[13px] rounded-lg border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-900 text-gray-900 dark:text-gray-100 placeholder-gray-400 dark:placeholder-gray-500 px-3 py-2 mb-3 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 resize-none"
            />
            <div className="grid grid-cols-3 gap-2">
              {decisionBtns.map(({ a, label, cls }) => (
                <button
                  key={a}
                  type="button"
                  disabled={submitting}
                  onClick={() => void decide(a)}
                  className={`px-3 py-2 rounded-lg text-[13px] font-medium disabled:opacity-50 ${cls}`}
                >
                  {label}
                </button>
              ))}
            </div>
            {error && <div className="mt-2 text-[12px] text-red-600">{error}</div>}
          </>
        )}
      </Card>

      {/* Trace */}
      <Card title={`Trace · ${events.length} events`}>
        {events.length === 0 ? (
          <div className="text-[13px] text-gray-500 dark:text-gray-400">No events recorded for this run.</div>
        ) : (
          <div className="max-h-[32rem] overflow-y-auto pr-1">
            {events.map((e) => <EventRow key={e.event_id} event={e} />)}
          </div>
        )}
        <div className="mt-3">
          <Link to={`/runs/${flag.run_id}/replay`} className="text-[12px] text-indigo-600 dark:text-indigo-400 hover:text-indigo-800 dark:hover:text-indigo-200 hover:underline font-medium">
            Open in replay →
          </Link>
        </div>
      </Card>
    </div>
  );
}
