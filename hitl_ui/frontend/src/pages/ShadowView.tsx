/**
 * Shadow detector performance - verdicts from detectors not yet ENFORCING.
 *
 * Light-first visual, soft pastels, clean tabs.
 */

import React, { useCallback, useEffect, useState } from "react";
import { getShadowVerdicts } from "../api/client";
import type { AsiCategory, DetectorState, ShadowVerdict } from "../types";

const ASI_CATEGORIES: AsiCategory[] = [
  "ASI-01", "ASI-02", "ASI-03", "ASI-04", "ASI-05",
  "ASI-06", "ASI-07", "ASI-08", "ASI-09", "ASI-10",
];

const STATE_TONE: Record<DetectorState, string> = {
  PROPOSED:   "bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-400 ring-1 ring-inset ring-gray-200",
  SHADOW:     "bg-indigo-50 dark:bg-indigo-950/40 text-indigo-700 dark:text-indigo-300 ring-1 ring-inset ring-indigo-200 dark:ring-indigo-900",
  CANARY:     "bg-amber-50 dark:bg-amber-950/40 text-amber-700 dark:text-amber-300 ring-1 ring-inset ring-amber-200 dark:ring-amber-900",
  ENFORCING:  "bg-emerald-50 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-300 ring-1 ring-inset ring-emerald-200 dark:ring-emerald-900",
  DISABLED:   "bg-red-50 dark:bg-red-950/40 text-red-700 dark:text-red-300 ring-1 ring-inset ring-red-200 dark:ring-red-900",
  DEPRECATED: "bg-orange-50 dark:bg-orange-950/40 text-orange-700 dark:text-orange-300 ring-1 ring-inset ring-orange-200 dark:ring-orange-900",
  REMOVED:    "bg-gray-100 dark:bg-gray-800 text-gray-400 dark:text-gray-500 ring-1 ring-inset ring-gray-200",
};

function StateBadge({ state }: { state: DetectorState }) {
  return (
    <span className={`inline-block px-2 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wider ${STATE_TONE[state]}`}>
      {state}
    </span>
  );
}

function ScoreBar({ score }: { score: number }) {
  const pct = Math.min(Math.max(score, 0), 1);
  const color = pct >= 0.7 ? "bg-red-500" : pct >= 0.4 ? "bg-amber-500" : "bg-emerald-500";
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-1.5 bg-gray-100 dark:bg-gray-800 rounded">
        <div className={`h-1.5 rounded ${color}`} style={{ width: `${pct * 100}%` }} />
      </div>
      <span className="text-[11px] tabular-nums w-9 text-right text-gray-600 dark:text-gray-400">
        {(pct * 100).toFixed(0)}%
      </span>
    </div>
  );
}

interface DetectorSummary {
  detector_name: string;
  detector_version: string;
  detector_state: DetectorState;
  verdict_count: number;
  avg_score: number;
  high_score_count: number;
  last_verdict_at: string | null;
}

function buildSummaries(verdicts: ShadowVerdict[]): DetectorSummary[] {
  const byDetector = new Map<string, ShadowVerdict[]>();
  for (const v of verdicts) {
    const key = `${v.detector_name}@${v.detector_version}`;
    const bucket = byDetector.get(key) ?? [];
    bucket.push(v);
    byDetector.set(key, bucket);
  }
  const summaries: DetectorSummary[] = [];
  byDetector.forEach((vs) => {
    const avg = vs.reduce((acc, v) => acc + v.score, 0) / vs.length;
    const highCount = vs.filter((v) => v.score >= 0.7).length;
    const sorted = [...vs].sort(
      (a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime(),
    );
    summaries.push({
      detector_name: vs[0].detector_name,
      detector_version: vs[0].detector_version,
      detector_state: vs[0].detector_state,
      verdict_count: vs.length,
      avg_score: avg,
      high_score_count: highCount,
      last_verdict_at: sorted[0]?.created_at ?? null,
    });
  });
  return summaries.sort((a, b) => b.verdict_count - a.verdict_count);
}

const SELECT =
  "rounded-md border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-900 text-gray-900 dark:text-gray-100 px-2.5 py-1.5 text-[13px] focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500";

export default function ShadowView(): React.ReactElement {
  const [verdicts, setVerdicts] = useState<ShadowVerdict[]>([]);
  const [summaries, setSummaries] = useState<DetectorSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [filterDetector, setFilterDetector] = useState("");
  const [filterCategory, setFilterCategory] = useState("");

  const [activeTab, setActiveTab] = useState<"summary" | "verdicts">("summary");

  const fetchVerdicts = useCallback(() => {
    setLoading(true);
    setError(null);
    getShadowVerdicts({
      detector_name: filterDetector || undefined,
      asi_category: filterCategory || undefined,
    })
      .then((vs) => {
        setVerdicts(vs);
        setSummaries(buildSummaries(vs));
      })
      .catch((e: unknown) =>
        setError(e instanceof Error ? e.message : "Failed to load shadow verdicts"),
      )
      .finally(() => setLoading(false));
  }, [filterDetector, filterCategory]);

  useEffect(() => { fetchVerdicts(); }, [fetchVerdicts]);

  const uniqueDetectors = Array.from(new Set(verdicts.map((v) => v.detector_name))).sort();

  return (
    <div className="max-w-7xl mx-auto px-6 py-7 space-y-5">
      <div className="flex items-end justify-between">
        <div>
          <h1 className="text-[22px] font-semibold text-gray-900 dark:text-gray-100 tracking-tight">Shadow detectors</h1>
          <p className="text-[12px] text-gray-500 dark:text-gray-400 mt-0.5">
            Verdicts from detectors in SHADOW or CANARY state - zero weight in production, analyzed
            here before promotion to ENFORCING.
          </p>
        </div>
        <button onClick={fetchVerdicts} className="text-[12px] text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-100 hover:underline">
          Refresh
        </button>
      </div>

      {/* Filters */}
      <div className="rounded-xl border border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900 px-4 py-3 flex flex-wrap items-end gap-4">
        <label className="flex flex-col gap-1 text-[11px] font-medium text-gray-600 dark:text-gray-400 uppercase tracking-wider">
          Detector
          <select value={filterDetector} onChange={(e) => setFilterDetector(e.target.value)} className={SELECT}>
            <option value="">All detectors</option>
            {uniqueDetectors.map((d) => <option key={d} value={d}>{d}</option>)}
          </select>
        </label>
        <label className="flex flex-col gap-1 text-[11px] font-medium text-gray-600 dark:text-gray-400 uppercase tracking-wider">
          Category
          <select value={filterCategory} onChange={(e) => setFilterCategory(e.target.value)} className={SELECT}>
            <option value="">All categories</option>
            {ASI_CATEGORIES.map((c) => <option key={c} value={c}>{c}</option>)}
          </select>
        </label>
        <div className="ml-auto text-[11px] text-gray-500 dark:text-gray-400 self-end pb-1">
          {verdicts.length} verdict{verdicts.length === 1 ? "" : "s"}
        </div>
      </div>

      {loading && <p className="text-[13px] text-gray-500 dark:text-gray-400">Loading shadow verdicts…</p>}

      {error && (
        <div className="rounded-xl border border-red-200 dark:border-red-900 bg-red-50 dark:bg-red-950/40 p-3 text-[13px] text-red-700 dark:text-red-300">
          {error}
          <p className="text-[11px] text-red-500 mt-1">
            (No shadow detectors are processing yet - promote one to SHADOW state to populate this view.)
          </p>
        </div>
      )}

      {!loading && !error && verdicts.length === 0 && (
        <div className="rounded-xl border border-dashed border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-900 py-16 text-center">
          <p className="text-[14px] font-medium text-gray-700 dark:text-gray-300">No shadow verdicts.</p>
          <p className="text-[12px] text-gray-500 dark:text-gray-400 mt-1">
            Verdicts appear here once a detector is promoted to SHADOW state and has processed real traffic.
          </p>
        </div>
      )}

      {!loading && !error && verdicts.length > 0 && (
        <div className="space-y-3">
          {/* Tabs */}
          <div className="flex gap-1 border-b border-gray-200 dark:border-gray-800">
            {(["summary", "verdicts"] as const).map((tab) => (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                className={[
                  "px-3 py-2 text-[13px] font-medium transition-colors border-b-2 -mb-px",
                  activeTab === tab
                    ? "border-indigo-600 text-indigo-700 dark:text-indigo-300"
                    : "border-transparent text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:text-gray-300",
                ].join(" ")}
              >
                {tab === "summary" ? "Per-detector summary" : `Raw verdicts (${verdicts.length})`}
              </button>
            ))}
          </div>

          {activeTab === "summary" && (
            <div className="rounded-xl border border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900 overflow-hidden overflow-x-auto">
              <table className="w-full text-[13px]">
                <thead>
                  <tr className="border-b border-gray-200 dark:border-gray-800 bg-gray-50/50 dark:bg-gray-800/40">
                    {["Detector", "Version", "State", "Verdicts", "Avg score", "High (≥0.7)", "Last verdict"].map((h) => (
                      <th key={h} className="px-4 py-2.5 text-left text-[11px] font-semibold text-gray-600 dark:text-gray-400 uppercase tracking-wider">
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100 dark:divide-gray-800">
                  {summaries.map((s) => (
                    <tr key={`${s.detector_name}@${s.detector_version}`} className="hover:bg-gray-50/70 dark:hover:bg-gray-800/40 transition-colors">
                      <td className="px-4 py-3 font-mono text-[12px] font-semibold text-gray-900 dark:text-gray-100">{s.detector_name}</td>
                      <td className="px-4 py-3 font-mono text-[11px] text-gray-500 dark:text-gray-400">{s.detector_version}</td>
                      <td className="px-4 py-3"><StateBadge state={s.detector_state} /></td>
                      <td className="px-4 py-3 text-gray-700 dark:text-gray-300 tabular-nums">{s.verdict_count}</td>
                      <td className="px-4 py-3 min-w-[150px]"><ScoreBar score={s.avg_score} /></td>
                      <td className="px-4 py-3 text-gray-700 dark:text-gray-300 tabular-nums">
                        {s.high_score_count}
                        <span className="text-gray-400 dark:text-gray-500 ml-1 text-[11px]">
                          ({s.verdict_count > 0 ? ((s.high_score_count / s.verdict_count) * 100).toFixed(0) : 0}%)
                        </span>
                      </td>
                      <td className="px-4 py-3 text-gray-500 dark:text-gray-400 text-[11px] whitespace-nowrap">
                        {s.last_verdict_at ? new Date(s.last_verdict_at).toLocaleString() : "-"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {activeTab === "verdicts" && (
            <div className="rounded-xl border border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900 overflow-hidden overflow-x-auto">
              <table className="w-full text-[13px]">
                <thead>
                  <tr className="border-b border-gray-200 dark:border-gray-800 bg-gray-50/50 dark:bg-gray-800/40">
                    {["Detector", "State", "Category", "Run", "Score", "Rationale", "Created"].map((h) => (
                      <th key={h} className="px-4 py-2.5 text-left text-[11px] font-semibold text-gray-600 dark:text-gray-400 uppercase tracking-wider">
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100 dark:divide-gray-800">
                  {verdicts.map((v) => (
                    <tr key={v.verdict_id} className="hover:bg-gray-50/70 dark:hover:bg-gray-800/40 transition-colors">
                      <td className="px-4 py-3 font-mono text-[12px] text-gray-800 dark:text-gray-200">
                        {v.detector_name}
                        <span className="text-gray-400 dark:text-gray-500 ml-1">@{v.detector_version}</span>
                      </td>
                      <td className="px-4 py-3"><StateBadge state={v.detector_state} /></td>
                      <td className="px-4 py-3">
                        <span className="px-1.5 py-0.5 text-[10px] font-mono bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300 rounded">
                          {v.asi_category}
                        </span>
                      </td>
                      <td className="px-4 py-3 font-mono text-[11px]">
                        <a href={`/runs/${v.run_id}/replay`} className="text-indigo-600 dark:text-indigo-400 hover:text-indigo-800 dark:hover:text-indigo-200 hover:underline">
                          {v.run_id.slice(0, 12)}…
                        </a>
                      </td>
                      <td className="px-4 py-3 min-w-[150px]"><ScoreBar score={v.score} /></td>
                      <td className="px-4 py-3 text-gray-600 dark:text-gray-400 text-[12px] max-w-xs truncate" title={v.rationale}>
                        {v.rationale}
                      </td>
                      <td className="px-4 py-3 text-gray-500 dark:text-gray-400 text-[11px] whitespace-nowrap">
                        {new Date(v.created_at).toLocaleString()}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
