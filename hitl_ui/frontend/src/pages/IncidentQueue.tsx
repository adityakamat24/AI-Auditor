/**
 * Incident queue - auto-refreshing chronological list of incidents.
 *
 * Refresh strategy:
 *   - Initial fetch on mount.
 *   - Polls every 6s while the tab is visible (light load, looks live without spamming).
 *   - Re-fetches on `visibilitychange` so coming back from another tab catches up immediately.
 */

import React, { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { getIncidents } from "../api/client";
import { TableRowSkeleton } from "../components/Skeleton";
import { formatRelative } from "../lib/time";
import type { Incident, IncidentState, Severity } from "../types";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];
const STATES: IncidentState[] = [
  "OPEN", "TRIAGING", "INVESTIGATING", "CONTAINED", "RESOLVED", "POST_MORTEM_COMPLETE", "DISMISSED",
];

const SEV_TONE: Record<Severity, { dot: string; chip: string }> = {
  critical: { dot: "bg-red-500",     chip: "bg-red-50 dark:bg-red-950/40 text-red-700 dark:text-red-300 ring-1 ring-inset ring-red-200 dark:ring-red-900" },
  high:     { dot: "bg-orange-500",  chip: "bg-orange-50 dark:bg-orange-950/40 text-orange-700 dark:text-orange-300 ring-1 ring-inset ring-orange-200 dark:ring-orange-900" },
  medium:   { dot: "bg-amber-500",   chip: "bg-amber-50 dark:bg-amber-950/40 text-amber-700 dark:text-amber-300 ring-1 ring-inset ring-amber-200 dark:ring-amber-900" },
  low:      { dot: "bg-sky-500",     chip: "bg-sky-50 dark:bg-sky-950/40 text-sky-700 dark:text-sky-300 ring-1 ring-inset ring-sky-200 dark:ring-sky-900" },
};

const STATE_TONE: Record<IncidentState, string> = {
  OPEN:                 "bg-red-50 dark:bg-red-950/40 text-red-700 dark:text-red-300 ring-1 ring-inset ring-red-200 dark:ring-red-900",
  TRIAGING:             "bg-orange-50 dark:bg-orange-950/40 text-orange-700 dark:text-orange-300 ring-1 ring-inset ring-orange-200 dark:ring-orange-900",
  INVESTIGATING:        "bg-amber-50 dark:bg-amber-950/40 text-amber-700 dark:text-amber-300 ring-1 ring-inset ring-amber-200 dark:ring-amber-900",
  CONTAINED:            "bg-sky-50 dark:bg-sky-950/40 text-sky-700 dark:text-sky-300 ring-1 ring-inset ring-sky-200 dark:ring-sky-900",
  RESOLVED:             "bg-emerald-50 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-300 ring-1 ring-inset ring-emerald-200 dark:ring-emerald-900",
  POST_MORTEM_COMPLETE: "bg-indigo-50 dark:bg-indigo-950/40 text-indigo-700 dark:text-indigo-300 ring-1 ring-inset ring-indigo-200 dark:ring-indigo-900",
  DISMISSED:            "bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-400 ring-1 ring-inset ring-gray-200 dark:ring-gray-700",
};

const SELECT =
  "rounded-md border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-900 text-gray-900 dark:text-gray-100 px-2.5 py-1.5 text-[13px] focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500";

function StatTile({ label, value, tone, loading }: { label: string; value: number; tone: string; loading: boolean }) {
  return (
    <div className="rounded-xl border border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900 p-4 flex items-center gap-3">
      <span className={`w-2 h-10 rounded-full ${tone}`} />
      <div>
        <div className="text-[20px] font-semibold text-gray-900 dark:text-gray-100 leading-none tabular-nums">
          {loading ? "-" : value}
        </div>
        <div className="text-[11px] uppercase tracking-wider text-gray-500 dark:text-gray-400 mt-1">{label}</div>
      </div>
    </div>
  );
}

export default function IncidentQueue(): React.ReactElement {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastFetchAt, setLastFetchAt] = useState<number>(0);

  const [severity, setSeverity] = useState("");
  const [state, setState] = useState("OPEN");

  const fetchIncidents = useCallback(async (showSpinner: boolean) => {
    if (showSpinner) setLoading(true);
    else setRefreshing(true);
    setError(null);
    try {
      const res = await getIncidents({
        severity: severity || undefined,
        state: state || undefined,
      });
      setIncidents(res);
      setLastFetchAt(Date.now());
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load incidents");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [severity, state]);

  // Initial + filter-change fetch.
  useEffect(() => { void fetchIncidents(true); }, [fetchIncidents]);

  // Background polling while the tab is visible.
  useEffect(() => {
    const tick = () => { if (!document.hidden) void fetchIncidents(false); };
    const id = window.setInterval(tick, 6_000);
    const onVisible = () => { if (!document.hidden) void fetchIncidents(false); };
    document.addEventListener("visibilitychange", onVisible);
    return () => {
      window.clearInterval(id);
      document.removeEventListener("visibilitychange", onVisible);
    };
  }, [fetchIncidents]);

  const counts = {
    open: incidents.filter((i) => i.state === "OPEN").length,
    investigating: incidents.filter((i) => i.state === "TRIAGING" || i.state === "INVESTIGATING").length,
    contained: incidents.filter((i) => i.state === "CONTAINED").length,
    resolved: incidents.filter((i) => i.state === "RESOLVED" || i.state === "POST_MORTEM_COMPLETE").length,
  };

  return (
    <div className="max-w-7xl mx-auto px-6 py-7 space-y-5">
      <div className="flex items-end justify-between">
        <div>
          <h1 className="text-[22px] font-semibold text-gray-900 dark:text-gray-100 tracking-tight">Incidents</h1>
          <p className="text-[12px] text-gray-500 dark:text-gray-400 mt-0.5">
            Confirmed incidents and their lifecycle state.
          </p>
        </div>
        <div className="flex items-center gap-3 text-[11px] text-gray-500 dark:text-gray-400">
          <span className={`inline-flex items-center gap-1.5 ${refreshing ? "text-blue-600 dark:text-blue-400" : ""}`}>
            <span className={`w-1.5 h-1.5 rounded-full ${refreshing ? "bg-blue-500 animate-pulse" : "bg-emerald-500"}`} />
            {refreshing ? "refreshing…" : "live"}
          </span>
          <button onClick={() => void fetchIncidents(false)} className="text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-100 underline-offset-2 hover:underline">
            Refresh
          </button>
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <StatTile label="Open"          value={counts.open}          tone="bg-red-500"     loading={loading} />
        <StatTile label="Investigating" value={counts.investigating} tone="bg-amber-500"   loading={loading} />
        <StatTile label="Contained"     value={counts.contained}     tone="bg-sky-500"     loading={loading} />
        <StatTile label="Resolved"      value={counts.resolved}      tone="bg-emerald-500" loading={loading} />
      </div>

      <div className="rounded-xl border border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900 px-4 py-3 flex flex-wrap items-end gap-4">
        <label className="flex flex-col gap-1 text-[11px] font-medium text-gray-600 dark:text-gray-400 uppercase tracking-wider">
          Severity
          <select value={severity} onChange={(e) => setSeverity(e.target.value)} className={SELECT}>
            <option value="">All</option>
            {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
        </label>
        <label className="flex flex-col gap-1 text-[11px] font-medium text-gray-600 dark:text-gray-400 uppercase tracking-wider">
          State
          <select value={state} onChange={(e) => setState(e.target.value)} className={SELECT}>
            <option value="">All</option>
            {STATES.map((s) => <option key={s} value={s}>{s.replace(/_/g, " ")}</option>)}
          </select>
        </label>
        <div className="ml-auto text-[11px] text-gray-500 dark:text-gray-400 self-end pb-1">
          {incidents.length} incident{incidents.length === 1 ? "" : "s"}
          {lastFetchAt > 0 && (
            <> · updated {formatRelative(new Date(lastFetchAt).toISOString())}</>
          )}
        </div>
      </div>

      {error && (
        <div className="rounded-xl border border-red-200 dark:border-red-900 bg-red-50 dark:bg-red-950/40 p-3 text-[13px] text-red-700 dark:text-red-300">
          {error}
        </div>
      )}

      {loading && (
        <div className="rounded-xl border border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900 overflow-hidden">
          <table className="w-full text-[13px]">
            <thead>
              <tr className="border-b border-gray-200 dark:border-gray-800 bg-gray-50/50 dark:bg-gray-800/40">
                {["Severity", "State", "Incident", "Source flag", "Assignee", "Opened"].map((h) => (
                  <th key={h} className="px-4 py-2.5 text-left text-[11px] font-semibold text-gray-600 dark:text-gray-400 uppercase tracking-wider">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody><TableRowSkeleton cols={6} /><TableRowSkeleton cols={6} /><TableRowSkeleton cols={6} /></tbody>
          </table>
        </div>
      )}

      {!loading && !error && incidents.length === 0 && (
        <div className="rounded-xl border border-dashed border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-900 py-16 text-center animate-hitl-fade-in">
          <div className="inline-flex items-center justify-center w-10 h-10 rounded-xl bg-emerald-50 dark:bg-emerald-950/40 mb-3">
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="w-5 h-5 text-emerald-600 dark:text-emerald-400">
              <path d="M5 12l5 5L20 7" />
            </svg>
          </div>
          <p className="text-[14px] font-medium text-gray-700 dark:text-gray-300">All clear.</p>
          <p className="text-[12px] text-gray-500 dark:text-gray-400 mt-1">No incidents match this filter - try widening the state.</p>
        </div>
      )}

      {!loading && !error && incidents.length > 0 && (
        <div className="rounded-xl border border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900 overflow-hidden">
          <table className="w-full text-[13px]">
            <thead>
              <tr className="border-b border-gray-200 dark:border-gray-800 bg-gray-50/50 dark:bg-gray-800/40">
                {["Severity", "State", "Incident", "Source flag", "Assignee", "Opened"].map((h) => (
                  <th key={h} className="px-4 py-2.5 text-left text-[11px] font-semibold text-gray-600 dark:text-gray-400 uppercase tracking-wider">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100 dark:divide-gray-800">
              {incidents.map((inc) => {
                const tone = SEV_TONE[inc.severity];
                return (
                  <tr key={inc.incident_id} className="hover:bg-gray-50/70 dark:hover:bg-gray-800/40 transition-colors">
                    <td className="px-4 py-3">
                      <span className={`inline-flex items-center gap-2 px-2 py-0.5 rounded text-[11px] font-semibold uppercase tracking-wider ${tone.chip}`}>
                        <span className={`w-1.5 h-1.5 rounded-full ${tone.dot}`} />
                        {inc.severity}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`inline-block px-2 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wider ${STATE_TONE[inc.state]}`}>
                        {inc.state.replace(/_/g, " ")}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <Link to={`/incidents/${inc.incident_id}`} className="text-indigo-600 dark:text-indigo-400 hover:text-indigo-800 dark:hover:text-indigo-200 hover:underline font-medium">
                        {inc.title ?? `Incident ${inc.incident_id.slice(0, 8)}…`}
                      </Link>
                    </td>
                    <td className="px-4 py-3 font-mono text-[11px] text-gray-600 dark:text-gray-400" title={inc.primary_flag_id}>
                      {inc.primary_flag_id.slice(0, 12)}…
                    </td>
                    <td className="px-4 py-3 text-gray-600 dark:text-gray-400 text-[12px]">
                      {inc.assignee_name ?? inc.assignee_id ?? (
                        <span className="text-gray-400 dark:text-gray-500 italic">unassigned</span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-gray-500 dark:text-gray-400 text-[12px] whitespace-nowrap" title={inc.opened_at}>
                      {formatRelative(inc.opened_at)}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
