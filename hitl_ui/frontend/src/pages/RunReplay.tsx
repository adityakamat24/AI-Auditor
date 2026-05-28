import React, { useCallback, useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { getReplayBundle } from "../api/client";
import EventTimeline from "../components/EventTimeline";
import SeverityBadge from "../components/SeverityBadge";
import type { ReplayBundle } from "../types";

export default function RunReplay(): React.ReactElement {
  const { runId } = useParams<{ runId: string }>();
  const [bundle, setBundle] = useState<ReplayBundle | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [step, setStep] = useState<number | undefined>(undefined);
  const [playing, setPlaying] = useState(false);

  const load = useCallback(() => {
    if (!runId) return;
    setLoading(true);
    setError(null);
    getReplayBundle(runId)
      .then((b) => {
        setBundle(b);
        setStep(0);
      })
      .catch((e: unknown) =>
        setError(e instanceof Error ? e.message : "Failed to load replay"),
      )
      .finally(() => setLoading(false));
  }, [runId]);

  useEffect(() => {
    load();
  }, [load]);

  // Auto-play
  useEffect(() => {
    if (!playing || !bundle) return;
    if (step === undefined || step >= bundle.events.length - 1) {
      setPlaying(false);
      return;
    }
    const timer = setTimeout(() => setStep((s) => (s !== undefined ? s + 1 : 0)), 800);
    return () => clearTimeout(timer);
  }, [playing, step, bundle]);

  if (loading) return <div className="p-8 text-gray-500">Loading replay…</div>;
  if (error)
    return (
      <div className="p-8">
        <div className="rounded border border-red-200 bg-red-50 p-4 text-sm text-red-700">
          {error}
        </div>
      </div>
    );
  if (!bundle) return <div className="p-8 text-gray-500">No replay data.</div>;

  const eventsUpTo = step !== undefined ? bundle.events.slice(0, step + 1) : bundle.events;

  return (
    <div className="max-w-4xl mx-auto px-4 py-8 space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">
          Replay - <span className="font-mono text-base">{bundle.run_id}</span>
        </h1>
        <p className="text-sm text-gray-500 mt-1">Read-only event replay for investigation.</p>
      </div>

      {/* Flags on this run */}
      {bundle.flags.length > 0 && (
        <section>
          <h2 className="text-sm font-semibold text-gray-700 uppercase tracking-wide mb-2">
            Flags on this Run
          </h2>
          <ul className="flex flex-wrap gap-2">
            {bundle.flags.map((f) => (
              <li
                key={f.flag_id}
                className="flex items-center gap-2 rounded border border-gray-200 bg-gray-50 px-3 py-1.5 text-sm"
              >
                <SeverityBadge severity={f.severity} />
                <span className="text-gray-600 font-mono text-xs">{f.flag_id}</span>
              </li>
            ))}
          </ul>
        </section>
      )}

      {/* Controls */}
      <div className="flex items-center gap-4">
        <button
          onClick={() => setStep((s) => (s !== undefined && s > 0 ? s - 1 : 0))}
          disabled={step === 0}
          className="px-3 py-1.5 text-sm rounded border border-gray-300 hover:bg-gray-100 disabled:opacity-40"
        >
          ← Prev
        </button>
        <button
          onClick={() => setPlaying((p) => !p)}
          className="px-3 py-1.5 text-sm rounded border border-indigo-500 text-indigo-600 hover:bg-indigo-50"
        >
          {playing ? "⏸ Pause" : "▶ Play"}
        </button>
        <button
          onClick={() =>
            setStep((s) =>
              s !== undefined && s < bundle.events.length - 1 ? s + 1 : s,
            )
          }
          disabled={step === bundle.events.length - 1}
          className="px-3 py-1.5 text-sm rounded border border-gray-300 hover:bg-gray-100 disabled:opacity-40"
        >
          Next →
        </button>
        <span className="text-xs text-gray-500 tabular-nums">
          {step !== undefined ? step + 1 : bundle.events.length} / {bundle.events.length} events
        </span>
        <button
          onClick={() => { setStep(undefined); setPlaying(false); }}
          className="ml-auto text-xs text-gray-400 hover:text-gray-600"
        >
          Show all
        </button>
      </div>

      <EventTimeline events={eventsUpTo} currentIndex={step} />
    </div>
  );
}
