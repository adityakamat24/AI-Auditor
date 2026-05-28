import React from "react";
import { Link } from "react-router-dom";
import { formatRelative } from "../lib/time";
import type { Flag, Severity } from "../types";

interface Props {
  flags: Flag[];
}

const SEV_TONE: Record<Severity, { dot: string; chip: string }> = {
  critical: { dot: "bg-red-500",     chip: "bg-red-50 dark:bg-red-950/40 text-red-700 dark:text-red-300 ring-1 ring-inset ring-red-200 dark:ring-red-900" },
  high:     { dot: "bg-orange-500",  chip: "bg-orange-50 dark:bg-orange-950/40 text-orange-700 dark:text-orange-300 ring-1 ring-inset ring-orange-200 dark:ring-orange-900" },
  medium:   { dot: "bg-amber-500",   chip: "bg-amber-50 dark:bg-amber-950/40 text-amber-700 dark:text-amber-300 ring-1 ring-inset ring-amber-200 dark:ring-amber-900" },
  low:      { dot: "bg-sky-500",     chip: "bg-sky-50 dark:bg-sky-950/40 text-sky-700 dark:text-sky-300 ring-1 ring-inset ring-sky-200 dark:ring-sky-900" },
};

export default function FlagTable({ flags }: Props): React.ReactElement {
  if (flags.length === 0) {
    return (
      <div className="rounded-xl border border-dashed border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-900 py-16 text-center animate-hitl-fade-in">
        <div className="inline-flex items-center justify-center w-10 h-10 rounded-xl bg-emerald-50 dark:bg-emerald-950/40 mb-3">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="w-5 h-5 text-emerald-600 dark:text-emerald-400">
            <path d="M5 12l5 5L20 7" />
          </svg>
        </div>
        <p className="text-[14px] font-medium text-gray-700 dark:text-gray-300">Queue is clear.</p>
        <p className="text-[12px] text-gray-500 dark:text-gray-400 mt-1">
          No flags match your filters. Run an agent task in the console to generate one.
        </p>
      </div>
    );
  }

  return (
    <div className="rounded-xl border border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900 overflow-hidden">
      <table className="w-full text-[13px]">
        <thead>
          <tr className="border-b border-gray-200 dark:border-gray-800 bg-gray-50/50 dark:bg-gray-800/40">
            {["Severity", "Category", "Run", "Status", "Opened"].map((h) => (
              <th
                key={h}
                className="px-4 py-2.5 text-left text-[11px] font-semibold text-gray-600 dark:text-gray-400 uppercase tracking-wider"
              >
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-100 dark:divide-gray-800">
          {flags.map((flag) => {
            const tone = SEV_TONE[flag.severity];
            return (
              <tr key={flag.flag_id} className="hover:bg-gray-50/70 dark:hover:bg-gray-800/40 transition-colors">
                <td className="px-4 py-3">
                  <span className={`inline-flex items-center gap-2 px-2 py-0.5 rounded text-[11px] font-semibold uppercase tracking-wider ${tone.chip}`}>
                    <span className={`w-1.5 h-1.5 rounded-full ${tone.dot}`} />
                    {flag.severity}
                  </span>
                </td>
                <td className="px-4 py-3">
                  <div className="flex flex-wrap gap-1">
                    {flag.asi_categories.map((cat) => (
                      <span
                        key={cat}
                        className="px-1.5 py-0.5 text-[10px] font-mono bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300 rounded"
                      >
                        {cat}
                      </span>
                    ))}
                  </div>
                </td>
                <td className="px-4 py-3 font-mono text-[12px]">
                  <Link
                    to={`/flags/${flag.flag_id}`}
                    className="text-indigo-600 dark:text-indigo-400 hover:text-indigo-800 dark:hover:text-indigo-200 hover:underline"
                    title={flag.run_id}
                  >
                    {flag.run_id.slice(0, 12)}…
                  </Link>
                </td>
                <td className="px-4 py-3 text-gray-700 dark:text-gray-300 capitalize">
                  {flag.status.replace("_", " ")}
                </td>
                <td className="px-4 py-3 text-gray-500 dark:text-gray-400 text-[12px] whitespace-nowrap">
                  <span title={flag.opened_at}>{formatRelative(flag.opened_at)}</span>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
