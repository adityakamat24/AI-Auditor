/**
 * Lightweight toast system — no external deps. Stacks up to 3 toasts in the bottom-right;
 * each auto-dismisses after 4 seconds (5s for errors so the message is readable).
 *
 * Usage:
 *   const toast = useToast();
 *   toast.success("Saved");
 *   toast.error("Could not reach the auditor");
 *
 * Mount once near the top of the tree (above the router).
 */

import React, {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useState,
} from "react";

type ToastKind = "success" | "error" | "info";

interface ToastItem {
  id: string;
  kind: ToastKind;
  message: string;
}

interface ToastApi {
  show: (kind: ToastKind, message: string) => void;
  success: (message: string) => void;
  error: (message: string) => void;
  info: (message: string) => void;
}

const ToastContext = createContext<ToastApi | null>(null);

export function useToast(): ToastApi {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error("useToast must be used inside <ToastProvider>");
  return ctx;
}

const TONE: Record<ToastKind, string> = {
  success:
    "bg-emerald-50 dark:bg-emerald-950/60 border-emerald-200 dark:border-emerald-900 text-emerald-900 dark:text-emerald-100",
  error:
    "bg-red-50 dark:bg-red-950/60 border-red-200 dark:border-red-900 text-red-900 dark:text-red-100",
  info:
    "bg-gray-900 dark:bg-gray-800 border-gray-800 dark:border-gray-700 text-white",
};

const ICON_PATH: Record<ToastKind, string> = {
  success: "M5 12l5 5L20 7",
  error:   "M12 9v4 M12 17h.01 M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z",
  info:    "M12 16v-4 M12 8h.01 M12 22a10 10 0 100-20 10 10 0 000 20z",
};

function ToastIcon({ kind }: { kind: ToastKind }) {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none"
      stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"
      className="w-4 h-4 flex-shrink-0">
      <path d={ICON_PATH[kind]} />
    </svg>
  );
}

export function ToastProvider({ children }: { children: React.ReactNode }): React.ReactElement {
  const [items, setItems] = useState<ToastItem[]>([]);

  const show = useCallback((kind: ToastKind, message: string) => {
    const id = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    setItems((prev) => [...prev, { id, kind, message }].slice(-3));
    const ttl = kind === "error" ? 5000 : 4000;
    window.setTimeout(() => {
      setItems((prev) => prev.filter((t) => t.id !== id));
    }, ttl);
  }, []);

  const api = useMemo<ToastApi>(
    () => ({
      show,
      success: (m) => show("success", m),
      error: (m) => show("error", m),
      info: (m) => show("info", m),
    }),
    [show],
  );

  return (
    <ToastContext.Provider value={api}>
      {children}
      <div className="fixed bottom-4 right-4 z-50 flex flex-col gap-2 pointer-events-none">
        {items.map((item) => (
          <div
            key={item.id}
            className={[
              "pointer-events-auto rounded-lg shadow-lg border px-3.5 py-2.5 text-[13px]",
              "flex items-center gap-2.5 min-w-[260px] max-w-[400px] animate-hitl-slide-in",
              TONE[item.kind],
            ].join(" ")}
            role="status"
          >
            <ToastIcon kind={item.kind} />
            <span className="flex-1 leading-snug">{item.message}</span>
            <button
              type="button"
              onClick={() => setItems((prev) => prev.filter((t) => t.id !== item.id))}
              className="opacity-50 hover:opacity-100 transition-opacity text-[15px] leading-none px-1 -mr-1"
              aria-label="Dismiss"
            >
              ×
            </button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}
