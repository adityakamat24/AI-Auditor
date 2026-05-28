import React, { useState } from "react";
import type { DecisionAction } from "../types";

interface Props {
  flagId: string;
  onDecision: (action: DecisionAction, rationale: string) => Promise<void>;
  disabled?: boolean;
  /** Called when a keyboard shortcut fires an action */
  shortcutAction?: DecisionAction | null;
}

const ACTIONS: { action: DecisionAction; label: string; style: string; key: string }[] = [
  {
    action: "continue",
    label: "Continue Run",
    style: "bg-green-600 hover:bg-green-700 text-white",
    key: "C",
  },
  {
    action: "abort",
    label: "Abort Run",
    style: "bg-red-600 hover:bg-red-700 text-white",
    key: "A",
  },
  {
    action: "quarantine",
    label: "Quarantine",
    style: "bg-yellow-500 hover:bg-yellow-600 text-white",
    key: "Q",
  },
];

export default function DecisionButtons({
  flagId: _flagId,
  onDecision,
  disabled,
  shortcutAction,
}: Props): React.ReactElement {
  const [rationale, setRationale] = useState("");
  const [pending, setPending] = useState<DecisionAction | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function handleClick(action: DecisionAction) {
    if (!rationale.trim()) {
      setError("Please provide a rationale before submitting a decision.");
      return;
    }
    setError(null);
    setPending(action);
    try {
      await onDecision(action, rationale.trim());
      setRationale("");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unknown error");
    } finally {
      setPending(null);
    }
  }

  return (
    <div className="space-y-3">
      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
        Rationale
        <textarea
          id="rationale-textarea"
          className="mt-1 block w-full rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500 placeholder-gray-400 dark:placeholder-gray-500"
          rows={3}
          placeholder="Explain your decision…"
          value={rationale}
          onChange={(e) => setRationale(e.target.value)}
          disabled={!!pending || disabled}
        />
      </label>

      {error && <p className="text-xs text-red-600 dark:text-red-400">{error}</p>}

      <div className="flex flex-wrap gap-3">
        {ACTIONS.map(({ action, label, style, key }) => (
          <button
            key={action}
            onClick={() => { void handleClick(action); }}
            disabled={!!pending || disabled}
            aria-label={`${label} (keyboard shortcut: ${key})`}
            className={`px-4 py-2 rounded text-sm font-semibold transition-colors ${style} disabled:opacity-50 disabled:cursor-not-allowed focus:outline-none focus:ring-2 focus:ring-offset-1 focus:ring-indigo-500`}
          >
            {pending === action || shortcutAction === action ? "Submitting…" : (
              <span className="flex items-center gap-1.5">
                {label}
                <kbd className="ml-1 px-1 text-xs font-mono bg-white/20 rounded">{key}</kbd>
              </span>
            )}
          </button>
        ))}
      </div>
    </div>
  );
}
