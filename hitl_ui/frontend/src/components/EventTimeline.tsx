import React from "react";
import type { Event } from "../types";

interface Props {
  events: Event[];
  /** Index of the "current" event when stepping through replay; undefined = show all */
  currentIndex?: number;
}

function channelDot(channel: Event["channel"], divergence: boolean): string {
  if (divergence) return "bg-red-500";
  return channel === "voluntary" ? "bg-indigo-400" : "bg-green-500";
}

function fmtTs(iso: string): string {
  try {
    return new Date(iso).toLocaleTimeString(undefined, {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  } catch {
    return iso;
  }
}

export default function EventTimeline({ events, currentIndex }: Props): React.ReactElement {
  if (events.length === 0) {
    return <p className="text-gray-400 dark:text-gray-500 text-sm py-4">No events.</p>;
  }

  return (
    <ol className="relative border-l border-gray-200 dark:border-gray-700 ml-3">
      {events.map((ev, idx) => {
        const isActive = currentIndex === idx;
        const isDimmed = currentIndex !== undefined && idx > currentIndex;
        return (
          <li
            key={ev.event_id}
            className={`mb-6 ml-6 transition-opacity ${isDimmed ? "opacity-30" : ""}`}
          >
            <span
              className={`absolute -left-2 flex h-4 w-4 items-center justify-center rounded-full ring-2 ring-white dark:ring-gray-900 ${channelDot(ev.channel, !!ev.divergence)}`}
            />
            <div
              className={`rounded-lg border p-3 ${
                ev.divergence
                  ? "border-red-300 dark:border-red-700 bg-red-50 dark:bg-red-950/40"
                  : isActive
                  ? "border-indigo-300 dark:border-indigo-600 bg-indigo-50 dark:bg-indigo-950/40"
                  : "border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800"
              }`}
            >
              <div className="flex items-center gap-2 mb-1">
                <span className="text-xs font-mono text-gray-500 dark:text-gray-400">{fmtTs(ev.ts)}</span>
                <span
                  className={`text-xs font-semibold uppercase tracking-wide ${
                    ev.channel === "voluntary"
                      ? "text-indigo-600 dark:text-indigo-400"
                      : "text-green-700 dark:text-green-400"
                  }`}
                >
                  {ev.channel}
                </span>
                {ev.divergence && (
                  <span className="text-xs font-bold text-red-600 dark:text-red-400 uppercase tracking-wide">
                    DIVERGENCE
                  </span>
                )}
              </div>
              <p className="text-sm font-medium text-gray-800 dark:text-gray-200">{ev.event_type}</p>
              {Object.keys(ev.payload).length > 0 && (
                <pre className="mt-1 text-xs text-gray-500 dark:text-gray-400 overflow-x-auto whitespace-pre-wrap break-all">
                  {JSON.stringify(ev.payload, null, 2)}
                </pre>
              )}
            </div>
          </li>
        );
      })}
    </ol>
  );
}
