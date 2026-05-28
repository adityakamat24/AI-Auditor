/**
 * Settings - sampler runtime config + demo-data reset.
 *
 * Mirrors the operator console aesthetic: light surfaces, explicit text colors, generous padding.
 */

import React, { useCallback, useEffect, useState } from "react";
import { getSamplerSettings, resetDemoData, updateSamplerSettings } from "../api/client";
import { useToast } from "../components/Toast";
import { useChat } from "../context/ChatContext";
import type { SamplerMode, SamplerSettings } from "../types";

const MODES: { value: SamplerMode; title: string; blurb: string }[] = [
  { value: "percentage", title: "Percentage", blurb: "Audit each run with probability `rate` (PRD default)." },
  { value: "every_nth", title: "Every Nth", blurb: "Audit every Nth run, deterministically." },
  { value: "interval", title: "Time interval", blurb: "Audit at most one run per N seconds." },
  { value: "always", title: "Always", blurb: "Audit every run." },
  { value: "never", title: "Never", blurb: "Skip everything - including L1 hard triggers. Demo only." },
];

function Card({ title, sub, children }: { title: string; sub?: string; children: React.ReactNode }) {
  return (
    <section className="rounded-xl border border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900">
      <header className="px-5 py-3 border-b border-gray-100 dark:border-gray-800">
        <h2 className="text-[14px] font-semibold text-gray-900 dark:text-gray-100">{title}</h2>
        {sub && <p className="text-[12px] text-gray-500 dark:text-gray-400 mt-0.5">{sub}</p>}
      </header>
      <div className="px-5 py-4">{children}</div>
    </section>
  );
}

const INPUT =
  "rounded-md border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-900 text-gray-900 dark:text-gray-100 px-2.5 py-1.5 text-[13px] focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500";

export default function Settings(): React.ReactElement {
  const chat = useChat();
  const toast = useToast();
  const [settings, setSettings] = useState<SamplerSettings | null>(null);
  const [draft, setDraft] = useState<SamplerSettings | null>(null);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [status, setStatus] = useState<string | null>(null);
  const [resetting, setResetting] = useState(false);
  const [resetStatus, setResetStatus] = useState<string | null>(null);

  const load = useCallback(async () => {
    setError(null);
    try {
      const s = await getSamplerSettings();
      setSettings(s);
      setDraft(s);
    } catch (e) {
      setError((e as Error).message);
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  const save = useCallback(async () => {
    if (!draft) return;
    setSaving(true);
    setError(null);
    setStatus(null);
    try {
      const applied = await updateSamplerSettings(draft);
      setSettings(applied);
      setDraft(applied);
      setStatus(`Saved at ${new Date().toLocaleTimeString()} - applies to the next run.`);
      toast.success("Sampler settings saved");
    } catch (e) {
      const msg = (e as Error).message;
      setError(msg);
      toast.error(`Could not save - ${msg}`);
    } finally {
      setSaving(false);
    }
  }, [draft, toast]);

  if (!settings || !draft) {
    return (
      <div className="max-w-3xl mx-auto px-6 py-7 text-[13px] text-gray-600 dark:text-gray-400">
        {error ? <span className="text-red-600">Load failed: {error}</span> : "Loading…"}
      </div>
    );
  }

  const dirty = JSON.stringify(draft) !== JSON.stringify(settings);

  return (
    <div className="max-w-3xl mx-auto px-6 py-7 space-y-5">
      <div>
        <h1 className="text-[22px] font-semibold text-gray-900 dark:text-gray-100 tracking-tight">Settings</h1>
        <p className="text-[12px] text-gray-500 dark:text-gray-400 mt-0.5">
          Sampler controls what fraction of runs receive the expensive deep audit. L1 hard triggers
          (sensitive data, critical cheap-risk, recent incidents) still audit in every mode except
          <code className="font-mono ml-1">never</code>.
        </p>
      </div>

      <Card title="Mode" sub="How runs are selected for deep audit.">
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
          {MODES.map((m) => (
            <label
              key={m.value}
              className={[
                "flex gap-3 p-3 rounded-lg border cursor-pointer transition-colors",
                draft.mode === m.value
                  ? "border-indigo-500 bg-indigo-50/40 dark:bg-indigo-950/40 ring-1 ring-indigo-200 dark:ring-indigo-900"
                  : "border-gray-200 dark:border-gray-800 hover:border-gray-300 dark:border-gray-700 hover:bg-gray-50 dark:bg-gray-950",
              ].join(" ")}
            >
              <input
                type="radio"
                name="mode"
                value={m.value}
                checked={draft.mode === m.value}
                onChange={() => setDraft({ ...draft, mode: m.value })}
                className="mt-1 accent-indigo-600"
              />
              <div>
                <div className="text-[13px] font-medium text-gray-900 dark:text-gray-100">{m.title}</div>
                <div className="text-[12px] text-gray-600 dark:text-gray-400 mt-0.5">{m.blurb}</div>
              </div>
            </label>
          ))}
        </div>
      </Card>

      <Card title="Parameter" sub="Depends on the mode above.">
        {draft.mode === "percentage" && (
          <div>
            <div className="text-[13px] text-gray-700 dark:text-gray-300 mb-2">
              Sample rate: <span className="font-semibold text-gray-900 dark:text-gray-100">{(draft.rate * 100).toFixed(1)}%</span>
            </div>
            <input
              type="range"
              min={0}
              max={1}
              step={0.005}
              value={draft.rate}
              onChange={(e) => setDraft({ ...draft, rate: Number.parseFloat(e.target.value) })}
              className="w-full accent-indigo-600"
            />
            <div className="flex justify-between text-[11px] text-gray-500 dark:text-gray-400 mt-1">
              <span>0% (L1-only)</span>
              <span>100%</span>
            </div>
            <input
              type="number"
              step={0.01}
              min={0}
              max={1}
              value={draft.rate}
              onChange={(e) => setDraft({ ...draft, rate: Number.parseFloat(e.target.value || "0") })}
              className={`${INPUT} w-24 mt-3`}
            />
          </div>
        )}
        {draft.mode === "every_nth" && (
          <label className="block">
            <div className="text-[13px] text-gray-700 dark:text-gray-300 mb-2">N (audit every Nth run)</div>
            <input
              type="number"
              min={1}
              value={draft.every_n}
              onChange={(e) =>
                setDraft({ ...draft, every_n: Math.max(1, Number.parseInt(e.target.value || "1", 10)) })
              }
              className={`${INPUT} w-32`}
            />
          </label>
        )}
        {draft.mode === "interval" && (
          <label className="block">
            <div className="text-[13px] text-gray-700 dark:text-gray-300 mb-2">Interval (seconds between audits)</div>
            <input
              type="number"
              min={1}
              step={1}
              value={draft.interval_seconds}
              onChange={(e) =>
                setDraft({
                  ...draft,
                  interval_seconds: Math.max(1, Number.parseFloat(e.target.value || "60")),
                })
              }
              className={`${INPUT} w-32`}
            />
          </label>
        )}
        {(draft.mode === "always" || draft.mode === "never") && (
          <div className="text-[13px] text-gray-600 dark:text-gray-400">No parameter - mode applies as-is.</div>
        )}
      </Card>

      <Card title="L1 cheap-risk threshold" sub="Force always-audit when the cheap-risk score (0–100) exceeds this.">
        <input
          type="number"
          min={0}
          max={100}
          value={draft.critical_risk_threshold}
          onChange={(e) =>
            setDraft({
              ...draft,
              critical_risk_threshold: Math.max(
                0, Math.min(100, Number.parseInt(e.target.value || "70", 10)),
              ),
            })
          }
          className={`${INPUT} w-24`}
        />
        <p className="text-[11px] text-gray-500 dark:text-gray-400 mt-2">
          Lower = more aggressive auditing. Bypassed entirely in <code className="font-mono">never</code> mode.
        </p>
      </Card>

      <div className="flex items-center gap-3">
        <button
          type="button"
          onClick={save}
          disabled={!dirty || saving}
          className="px-4 py-2 rounded-lg bg-indigo-600 text-white text-[13px] font-medium hover:bg-indigo-700 disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {saving ? "Saving…" : "Save changes"}
        </button>
        <button
          type="button"
          onClick={() => setDraft(settings)}
          disabled={!dirty || saving}
          className="px-4 py-2 rounded-lg bg-white dark:bg-gray-900 border border-gray-300 dark:border-gray-700 text-gray-700 dark:text-gray-300 text-[13px] font-medium hover:bg-gray-50 dark:bg-gray-950 disabled:opacity-50 disabled:cursor-not-allowed"
        >
          Revert
        </button>
        {status && <span className="text-[12px] text-emerald-700 dark:text-emerald-300">{status}</span>}
        {error && <span className="text-[12px] text-red-600">{error}</span>}
      </div>

      {/* Reset session */}
      <Card title="Reset session" sub="Wipe all flags / incidents / verdicts / events / runs from the database and clear the chat thread.">
        <p className="text-[12px] text-gray-600 dark:text-gray-400 mb-3 leading-relaxed">
          Useful before a demo so the queues only show runs from this session. Tenants, users, and
          the sampler config are preserved. Safe to run while the auditor is up.
        </p>
        <div className="flex items-center gap-3">
          <button
            type="button"
            disabled={resetting}
            onClick={async () => {
              if (!window.confirm("Wipe all flags, incidents, runs, and audit log? This is irreversible.")) return;
              setResetting(true);
              setResetStatus(null);
              try {
                const r = await resetDemoData();
                chat.reset();
                setResetStatus(`Wiped ${r.wiped.length} tables. Chat thread cleared.`);
                toast.success(`Session reset - wiped ${r.wiped.length} tables`);
              } catch (e) {
                const msg = (e as Error).message;
                setResetStatus(`Reset failed: ${msg}`);
                toast.error(`Reset failed - ${msg}`);
              } finally {
                setResetting(false);
              }
            }}
            className="px-4 py-2 rounded-lg bg-red-600 text-white text-[13px] font-medium hover:bg-red-700 disabled:opacity-50"
          >
            {resetting ? "Resetting…" : "Reset session data"}
          </button>
          {resetStatus && (
            <span className={`text-[12px] ${resetStatus.startsWith("Wiped") ? "text-emerald-700 dark:text-emerald-300" : "text-red-600"}`}>
              {resetStatus}
            </span>
          )}
        </div>
      </Card>
    </div>
  );
}
