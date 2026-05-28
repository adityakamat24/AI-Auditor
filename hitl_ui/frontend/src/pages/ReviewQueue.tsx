/**
 * Review queue — operator-facing list of open flags. Clean light-first layout.
 *
 * Filters: severity / status / ASI category / tenant. WS push updates in place.
 */

import React, { useCallback, useEffect, useRef, useState } from "react";
import { connectFlagsWs, getFlags } from "../api/client";
import FlagTable from "../components/FlagTable";
import type { AsiCategory, Flag, FlagStatus, Severity } from "../types";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];
const STATUSES: FlagStatus[] = ["open", "in_review", "resolved", "dismissed"];
const ASI_CATEGORIES: AsiCategory[] = [
  "ASI-01", "ASI-02", "ASI-03", "ASI-04", "ASI-05",
  "ASI-06", "ASI-07", "ASI-08", "ASI-09", "ASI-10",
];

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0, high: 1, medium: 2, low: 3,
};

function sortFlags(flags: Flag[]): Flag[] {
  return [...flags].sort((a, b) => {
    const sev = SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity];
    if (sev !== 0) return sev;
    return new Date(b.opened_at).getTime() - new Date(a.opened_at).getTime();
  });
}

const SELECT =
  "rounded-md border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-900 text-gray-900 dark:text-gray-100 px-2.5 py-1.5 text-[13px] focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500";

function StatTile({ label, value, tone }: { label: string; value: number; tone: string }) {
  return (
    <div className="rounded-xl border border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900 p-4 flex items-center gap-3">
      <span className={`w-2 h-10 rounded-full ${tone}`} />
      <div>
        <div className="text-[20px] font-semibold text-gray-900 dark:text-gray-100 leading-none">{value}</div>
        <div className="text-[11px] uppercase tracking-wider text-gray-500 dark:text-gray-400 mt-1">{label}</div>
      </div>
    </div>
  );
}

export default function ReviewQueue(): React.ReactElement {
  const [flags, setFlags] = useState<Flag[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("open");
  const [asiCategory, setAsiCategory] = useState("");
  const [tenantId, setTenantId] = useState("");

  const wsRef = useRef<WebSocket | null>(null);

  const fetchFlags = useCallback(() => {
    setLoading(true);
    setError(null);
    getFlags({
      severity: severity || undefined,
      status: status || undefined,
      asi_category: asiCategory || undefined,
      tenant_id: tenantId || undefined,
    })
      .then((res) => setFlags(sortFlags(res)))
      .catch((e: unknown) =>
        setError(e instanceof Error ? e.message : "Failed to load flags"),
      )
      .finally(() => setLoading(false));
  }, [severity, status, asiCategory, tenantId]);

  useEffect(() => { fetchFlags(); }, [fetchFlags]);

  useEffect(() => {
    wsRef.current?.close();
    const ws = connectFlagsWs(tenantId || "default", (msg) => {
      if (msg.type === "flag_created") {
        setFlags((prev) => sortFlags([msg.flag, ...prev]));
      } else if (msg.type === "flag_updated") {
        setFlags((prev) =>
          sortFlags(prev.map((f) => (f.flag_id === msg.flag.flag_id ? msg.flag : f))),
        );
      }
    });
    wsRef.current = ws;
    return () => ws.close();
  }, [tenantId]);

  const counts = {
    critical: flags.filter((f) => f.severity === "critical").length,
    high: flags.filter((f) => f.severity === "high").length,
    medium: flags.filter((f) => f.severity === "medium").length,
    low: flags.filter((f) => f.severity === "low").length,
  };

  return (
    <div className="max-w-7xl mx-auto px-6 py-7 space-y-5">
      <div className="flex items-end justify-between">
        <div>
          <h1 className="text-[22px] font-semibold text-gray-900 dark:text-gray-100 tracking-tight">Review queue</h1>
          <p className="text-[12px] text-gray-500 dark:text-gray-400 mt-0.5">
            Open flags awaiting operator decision. Sorted by severity, then newest.
          </p>
        </div>
        <button
          onClick={fetchFlags}
          className="text-[12px] text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-100 underline-offset-2 hover:underline"
        >
          Refresh
        </button>
      </div>

      {/* Severity counts */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <StatTile label="Critical" value={counts.critical} tone="bg-red-500" />
        <StatTile label="High"     value={counts.high}     tone="bg-orange-500" />
        <StatTile label="Medium"   value={counts.medium}   tone="bg-amber-500" />
        <StatTile label="Low"      value={counts.low}      tone="bg-sky-500" />
      </div>

      {/* Filters */}
      <div className="rounded-xl border border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900 px-4 py-3 flex flex-wrap items-end gap-4">
        <label className="flex flex-col gap-1 text-[11px] font-medium text-gray-600 dark:text-gray-400 uppercase tracking-wider">
          Severity
          <select value={severity} onChange={(e) => setSeverity(e.target.value)} className={SELECT}>
            <option value="">All</option>
            {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
        </label>

        <label className="flex flex-col gap-1 text-[11px] font-medium text-gray-600 dark:text-gray-400 uppercase tracking-wider">
          Status
          <select value={status} onChange={(e) => setStatus(e.target.value)} className={SELECT}>
            <option value="">All</option>
            {STATUSES.map((s) => <option key={s} value={s}>{s.replace("_", " ")}</option>)}
          </select>
        </label>

        <label className="flex flex-col gap-1 text-[11px] font-medium text-gray-600 dark:text-gray-400 uppercase tracking-wider">
          Category
          <select value={asiCategory} onChange={(e) => setAsiCategory(e.target.value)} className={SELECT}>
            <option value="">All</option>
            {ASI_CATEGORIES.map((c) => <option key={c} value={c}>{c}</option>)}
          </select>
        </label>

        <label className="flex flex-col gap-1 text-[11px] font-medium text-gray-600 dark:text-gray-400 uppercase tracking-wider">
          Tenant
          <input
            type="text"
            value={tenantId}
            onChange={(e) => setTenantId(e.target.value)}
            placeholder="all tenants"
            className={`${SELECT} w-44 placeholder-gray-400 dark:placeholder-gray-500`}
          />
        </label>

        <div className="ml-auto text-[11px] text-gray-500 dark:text-gray-400 flex items-center gap-2 self-end pb-1">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
          live · {flags.length} flag{flags.length === 1 ? "" : "s"}
        </div>
      </div>

      {loading && <p className="text-[13px] text-gray-500 dark:text-gray-400">Loading flags…</p>}
      {error && (
        <div className="rounded-xl border border-red-200 dark:border-red-900 bg-red-50 dark:bg-red-950/40 p-3 text-[13px] text-red-700 dark:text-red-300">
          {error}
        </div>
      )}
      {!loading && !error && <FlagTable flags={flags} />}
    </div>
  );
}
