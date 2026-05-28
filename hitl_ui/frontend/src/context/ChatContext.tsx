/**
 * Chat session state - lives above the router so it survives navigation between tabs.
 *
 * Holds the turn thread + sign-in state + a single background poller that refreshes any pending
 * agent turn (so verdicts keep arriving even while the user is on another page).
 */

import React, { createContext, useCallback, useContext, useEffect, useState } from "react";
import { devLogin, getAgentRun, runAgent } from "../api/client";
import type { AgentRunState } from "../types";

export type UserTurn = { kind: "user"; text: string; ts: number };
export type AgentTurn = {
  kind: "agent";
  runId: string;
  state: AgentRunState | null;
  startedAt: number;
};
export type Turn = UserTurn | AgentTurn;

interface ChatContextValue {
  turns: Turn[];
  signedIn: boolean;
  error: string | null;
  submit: (text: string) => Promise<void>;
  signIn: () => Promise<void>;
  reset: () => void;
}

const ChatContext = createContext<ChatContextValue | null>(null);

export function useChat(): ChatContextValue {
  const ctx = useContext(ChatContext);
  if (!ctx) throw new Error("useChat must be used inside <ChatProvider>");
  return ctx;
}

function isAgentTurnDone(t: AgentTurn): boolean {
  return t.state !== null && t.state.audited && t.state.harness_status !== "running";
}

export function ChatProvider({ children }: { children: React.ReactNode }): React.ReactElement {
  const [turns, setTurns] = useState<Turn[]>([]);
  const [token, setToken] = useState<string | null>(() => localStorage.getItem("hitl_token"));
  const [error, setError] = useState<string | null>(null);

  const signIn = useCallback(async () => {
    setError(null);
    try {
      const r = await devLogin("admin@demo.local", "demo");
      localStorage.setItem("hitl_token", r.access_token);
      setToken(r.access_token);
    } catch (e) {
      setError(`Sign-in failed: ${(e as Error).message}`);
    }
  }, []);

  const submit = useCallback(async (text: string) => {
    const trimmed = text.trim();
    if (!trimmed) return;
    setError(null);
    setTurns((prev) => [...prev, { kind: "user", text: trimmed, ts: Date.now() }]);
    try {
      const r = await runAgent(trimmed);
      setTurns((prev) => [
        ...prev,
        { kind: "agent", runId: r.run_id, state: null, startedAt: Date.now() },
      ]);
    } catch (e) {
      setError(`Run failed: ${(e as Error).message}`);
    }
  }, []);

  const reset = useCallback(() => {
    setTurns([]);
    setError(null);
  }, []);

  // Listen for silent-refresh-failed events from api/client.ts. When the token expires AND a refresh
  // attempt also fails (or the user signed out everywhere), client clears localStorage and dispatches
  // this event. Drop our React state token so the UI flips to the sign-in screen.
  useEffect(() => {
    const onExpired = () => {
      setToken(null);
      setError("Your session expired - please sign in again.");
    };
    window.addEventListener("hitl:auth-expired", onExpired);
    return () => window.removeEventListener("hitl:auth-expired", onExpired);
  }, []);

  // Background polling for any pending agent turn. Lives in the provider, so it keeps running even
  // when the user is on another page; verdicts that arrive while you're on /settings still land.
  useEffect(() => {
    if (!token) return;
    let cancelled = false;
    const interval = window.setInterval(async () => {
      const pending = turns.filter(
        (t): t is AgentTurn => t.kind === "agent" && !isAgentTurnDone(t),
      );
      if (pending.length === 0) return;
      const updates = await Promise.allSettled(pending.map((p) => getAgentRun(p.runId)));
      if (cancelled) return;
      setTurns((prev) =>
        prev.map((t) => {
          if (t.kind !== "agent") return t;
          const idx = pending.findIndex((p) => p.runId === t.runId);
          if (idx < 0) return t;
          const u = updates[idx];
          return u.status === "fulfilled" ? { ...t, state: u.value } : t;
        }),
      );
    }, 1500);
    return () => {
      cancelled = true;
      window.clearInterval(interval);
    };
  }, [turns, token]);

  return (
    <ChatContext.Provider
      value={{ turns, signedIn: !!token, error, submit, signIn, reset }}
    >
      {children}
    </ChatContext.Provider>
  );
}
