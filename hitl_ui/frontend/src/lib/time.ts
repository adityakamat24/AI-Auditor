/**
 * Tiny time helpers - used everywhere a timestamp is shown.
 *
 * `formatRelative` produces a human-scannable string ("2m ago", "yesterday at 14:32", "Jan 14")
 * and `formatAbsolute` returns the full localised stamp (good for tooltips).
 *
 * Both are safe to call with null/undefined/empty input - they return a dash rather than throwing.
 */

export function formatRelative(iso: string | null | undefined): string {
  if (!iso) return "-";
  try {
    const t = new Date(iso).getTime();
    if (Number.isNaN(t)) return iso;
    const diff = Math.max(0, Date.now() - t);
    const s = Math.floor(diff / 1000);
    if (s < 5) return "just now";
    if (s < 60) return `${s}s ago`;
    const m = Math.floor(s / 60);
    if (m < 60) return `${m}m ago`;
    const h = Math.floor(m / 60);
    if (h < 24) return `${h}h ago`;
    const d = Math.floor(h / 24);
    if (d < 7) return `${d}d ago`;
    return new Date(iso).toLocaleDateString(undefined, { month: "short", day: "numeric" });
  } catch {
    return iso;
  }
}

export function formatAbsolute(iso: string | null | undefined): string {
  if (!iso) return "-";
  try {
    return new Date(iso).toLocaleString(undefined, {
      year: "numeric",
      month: "short",
      day: "numeric",
      hour: "numeric",
      minute: "2-digit",
    });
  } catch {
    return iso;
  }
}

/** A short HH:MM:SS for inline event log rows. */
export function formatClock(iso: string | null | undefined): string {
  if (!iso) return "";
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
