/**
 * Calibration dashboard — per-ASI precision/recall/F1 from the latest nightly evaluation.
 */

import React, { useEffect, useState } from "react";
import { getCalibrationMetrics } from "../api/client";
import type { CalibrationMetric } from "../types";

function pct(n: number): string {
  return (n * 100).toFixed(1) + "%";
}

function Bar({ value }: { value: number }) {
  const v = Math.min(Math.max(value, 0), 1);
  const color = v >= 0.8 ? "bg-emerald-500" : v >= 0.5 ? "bg-amber-500" : "bg-red-500";
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-1.5 bg-gray-100 dark:bg-gray-800 rounded">
        <div className={`h-1.5 rounded ${color}`} style={{ width: `${v * 100}%` }} />
      </div>
      <span className="text-[11px] tabular-nums w-12 text-right text-gray-600 dark:text-gray-400">{pct(v)}</span>
    </div>
  );
}

export default function Calibration(): React.ReactElement {
  const [metrics, setMetrics] = useState<CalibrationMetric[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    getCalibrationMetrics()
      .then(setMetrics)
      .catch((e: unknown) =>
        setError(e instanceof Error ? e.message : "Failed to load calibration metrics"),
      )
      .finally(() => setLoading(false));
  }, []);

  return (
    <div className="max-w-6xl mx-auto px-6 py-7 space-y-5">
      <div>
        <h1 className="text-[22px] font-semibold text-gray-900 dark:text-gray-100 tracking-tight">Calibration</h1>
        <p className="text-[12px] text-gray-500 dark:text-gray-400 mt-0.5">
          Per-ASI precision, recall, and F1 from the latest nightly evaluation against the labelled set.
        </p>
      </div>

      {loading && <p className="text-[13px] text-gray-500 dark:text-gray-400">Loading metrics…</p>}

      {error && (
        <div className="rounded-xl border border-red-200 dark:border-red-900 bg-red-50 dark:bg-red-950/40 p-3 text-[13px] text-red-700 dark:text-red-300">
          {error}
          <p className="text-[11px] text-red-500 mt-1">
            (The calibration pipeline hasn't produced metrics yet for this tenant.)
          </p>
        </div>
      )}

      {!loading && metrics.length === 0 && !error && (
        <div className="rounded-xl border border-dashed border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-900 py-16 text-center">
          <p className="text-[14px] font-medium text-gray-700 dark:text-gray-300">No calibration data yet.</p>
          <p className="text-[12px] text-gray-500 dark:text-gray-400 mt-1">Metrics are produced by the nightly evaluation job.</p>
        </div>
      )}

      {metrics.length > 0 && (
        <div className="rounded-xl border border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900 overflow-hidden overflow-x-auto">
          <table className="w-full text-[13px]">
            <thead>
              <tr className="border-b border-gray-200 dark:border-gray-800 bg-gray-50/50 dark:bg-gray-800/40">
                {["Category", "Precision", "Recall", "F1", "TP", "FP", "FN", "Evaluated"].map((h) => (
                  <th key={h} className="px-4 py-2.5 text-left text-[11px] font-semibold text-gray-600 dark:text-gray-400 uppercase tracking-wider">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100 dark:divide-gray-800">
              {metrics.map((m) => (
                <tr key={m.asi_category} className="hover:bg-gray-50/70 dark:hover:bg-gray-800/40 transition-colors">
                  <td className="px-4 py-3 font-mono font-semibold text-gray-900 dark:text-gray-100">{m.asi_category}</td>
                  <td className="px-4 py-3 min-w-[160px]"><Bar value={m.precision} /></td>
                  <td className="px-4 py-3 min-w-[160px]"><Bar value={m.recall} /></td>
                  <td className="px-4 py-3 min-w-[160px]"><Bar value={m.f1} /></td>
                  <td className="px-4 py-3 text-gray-700 dark:text-gray-300 tabular-nums">{m.tp}</td>
                  <td className="px-4 py-3 text-gray-700 dark:text-gray-300 tabular-nums">{m.fp}</td>
                  <td className="px-4 py-3 text-gray-700 dark:text-gray-300 tabular-nums">{m.fn}</td>
                  <td className="px-4 py-3 text-gray-500 dark:text-gray-400 whitespace-nowrap text-[11px]">
                    {new Date(m.evaluated_at).toLocaleString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
