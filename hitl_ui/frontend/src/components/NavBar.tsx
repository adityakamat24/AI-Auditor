/**
 * Top nav — clean white (or dark) sticky bar with live counts beside each tab.
 *
 * Counts are polled every 10s while the tab is visible; pauses when hidden to be a good citizen.
 * The pulsing "auditor online" pip flips to red if /health stops returning 200.
 */
import React, { useEffect, useState } from "react";
import { NavLink } from "react-router-dom";
import { getFlags, getIncidents } from "../api/client";
import { useTheme } from "../context/ThemeContext";

interface LinkDef {
  to: string;
  label: string;
  /** Optional key into the live counts state. */
  countKey?: "queue" | "incidents";
}

const LINKS: LinkDef[] = [
  { to: "/run",      label: "Console" },
  { to: "/queue",    label: "Review queue", countKey: "queue" },
  { to: "/incidents", label: "Incidents",    countKey: "incidents" },
  { to: "/settings", label: "Settings" },
];

interface Counts {
  queue: number;
  incidents: number;
  hasCritical: boolean;
}

function useLiveCounts(): { counts: Counts; online: boolean } {
  const [counts, setCounts] = useState<Counts>({ queue: 0, incidents: 0, hasCritical: false });
  const [online, setOnline] = useState(true);

  useEffect(() => {
    let cancelled = false;
    let intervalId: number | undefined;

    const tick = async () => {
      if (document.hidden) return; // pause when tab hidden
      try {
        const [flags, incs] = await Promise.allSettled([
          getFlags({ status: "open" }),
          getIncidents({ state: "OPEN" }),
        ]);
        if (cancelled) return;
        const flagArr = flags.status === "fulfilled" ? flags.value : [];
        const incArr = incs.status === "fulfilled" ? incs.value : [];
        const hasCritical =
          flagArr.some((f) => f.severity === "critical") ||
          incArr.some((i) => i.severity === "critical");
        setCounts({ queue: flagArr.length, incidents: incArr.length, hasCritical });
        setOnline(true);
      } catch {
        if (!cancelled) setOnline(false);
      }
    };

    void tick();
    intervalId = window.setInterval(tick, 10_000);
    const onVisible = () => { if (!document.hidden) void tick(); };
    document.addEventListener("visibilitychange", onVisible);

    return () => {
      cancelled = true;
      if (intervalId) window.clearInterval(intervalId);
      document.removeEventListener("visibilitychange", onVisible);
    };
  }, []);

  return { counts, online };
}

function CountBadge({ value, critical }: { value: number; critical?: boolean }) {
  if (value <= 0) return null;
  return (
    <span
      className={[
        "ml-1.5 inline-flex items-center justify-center min-w-[18px] h-[18px] px-1 rounded-full text-[10px] font-semibold tabular-nums",
        critical
          ? "bg-red-500 text-white"
          : "bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-200",
      ].join(" ")}
      title={critical ? "Critical item present" : undefined}
    >
      {value > 99 ? "99+" : value}
    </span>
  );
}

export default function NavBar(): React.ReactElement {
  const { theme, toggleTheme } = useTheme();
  const { counts, online } = useLiveCounts();

  return (
    <nav className="h-14 bg-white dark:bg-gray-900 border-b border-gray-200 dark:border-gray-800 px-6 flex items-center gap-6 sticky top-0 z-20 backdrop-blur supports-[backdrop-filter]:bg-white/95 supports-[backdrop-filter]:dark:bg-gray-900/95">
      {/* Brand */}
      <div className="flex items-center gap-2.5">
        <svg
          xmlns="http://www.w3.org/2000/svg"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
          className="w-5 h-5 text-indigo-600 dark:text-indigo-400"
          aria-hidden="true"
        >
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
          <path d="M9 12l2 2 4-4" />
        </svg>
        <span className="text-[14px] font-semibold text-gray-900 dark:text-gray-100 tracking-tight">
          AI Auditor
        </span>
        <span className="text-[10px] font-medium text-gray-400 dark:text-gray-500 uppercase tracking-wider ml-1">
          v1
        </span>
      </div>

      <div className="h-5 w-px bg-gray-200 dark:bg-gray-800" />

      {/* Nav */}
      <div className="flex items-center gap-0.5 flex-1">
        {LINKS.map(({ to, label, countKey }) => {
          const value = countKey ? counts[countKey] : 0;
          const critical = countKey ? counts.hasCritical && value > 0 : false;
          return (
            <NavLink
              key={to}
              to={to}
              end={to === "/run"}
              className={({ isActive }) =>
                [
                  "px-3 py-1.5 rounded-md text-[13px] font-medium transition-colors inline-flex items-center",
                  isActive
                    ? "bg-gray-900 dark:bg-gray-100 text-white dark:text-gray-900"
                    : "text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-100 hover:bg-gray-100 dark:hover:bg-gray-800",
                ].join(" ")
              }
            >
              {label}
              {countKey && <CountBadge value={value} critical={critical} />}
            </NavLink>
          );
        })}
      </div>

      <div className={`text-[11px] flex items-center gap-1.5 ${online ? "text-gray-500 dark:text-gray-400" : "text-red-600 dark:text-red-400"}`}>
        <span className={`w-1.5 h-1.5 rounded-full ${online ? "bg-emerald-500 animate-pulse" : "bg-red-500"}`} />
        {online ? "auditor online" : "auditor offline"}
      </div>

      <button
        type="button"
        onClick={toggleTheme}
        aria-label={theme === "dark" ? "Switch to light mode" : "Switch to dark mode"}
        title={theme === "dark" ? "Switch to light mode" : "Switch to dark mode"}
        className="w-8 h-8 rounded-md flex items-center justify-center text-gray-500 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-100 hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors focus:outline-none focus:ring-2 focus:ring-indigo-500"
      >
        {theme === "dark" ? (
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" className="w-4 h-4">
            <path d="M12 2.25a.75.75 0 01.75.75v2.25a.75.75 0 01-1.5 0V3a.75.75 0 01.75-.75zM7.5 12a4.5 4.5 0 119 0 4.5 4.5 0 01-9 0zM18.894 6.166a.75.75 0 00-1.06-1.06l-1.591 1.59a.75.75 0 101.06 1.061l1.591-1.59zM21.75 12a.75.75 0 01-.75.75h-2.25a.75.75 0 010-1.5H21a.75.75 0 01.75.75zM17.834 18.894a.75.75 0 001.06-1.06l-1.59-1.591a.75.75 0 10-1.061 1.06l1.59 1.591zM12 18a.75.75 0 01.75.75V21a.75.75 0 01-1.5 0v-2.25A.75.75 0 0112 18zM7.772 18.894a.75.75 0 00-1.06-1.06L5.11 19.424a.75.75 0 001.061 1.06l1.6-1.59zM3 12a.75.75 0 01.75-.75H6a.75.75 0 010 1.5H3.75A.75.75 0 013 12zM6.166 7.106a.75.75 0 001.06-1.06l-1.59-1.591a.75.75 0 00-1.061 1.06l1.591 1.591z" />
          </svg>
        ) : (
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" className="w-4 h-4">
            <path fillRule="evenodd" d="M9.528 1.718a.75.75 0 01.162.819A8.97 8.97 0 009 6a9 9 0 009 9 8.97 8.97 0 003.463-.69.75.75 0 01.981.98 10.503 10.503 0 01-9.694 6.46c-5.799 0-10.5-4.701-10.5-10.5 0-4.368 2.667-8.112 6.46-9.694a.75.75 0 01.818.162z" clipRule="evenodd" />
          </svg>
        )}
      </button>
    </nav>
  );
}
