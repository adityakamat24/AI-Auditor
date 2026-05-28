/**
 * Skeleton placeholders - used while a network fetch is in flight. Animated pulse on a soft gray
 * surface; honors light + dark themes.
 */
import React from "react";

export function Skeleton({ className = "" }: { className?: string }): React.ReactElement {
  return (
    <div
      className={`animate-pulse bg-gray-200 dark:bg-gray-800 rounded ${className}`}
      aria-hidden
    />
  );
}

/** A row that mimics one table line (severity chip + 3 columns of text + a timestamp). */
export function TableRowSkeleton({ cols = 5 }: { cols?: number }): React.ReactElement {
  return (
    <tr className="border-b border-gray-100 dark:border-gray-800">
      {Array.from({ length: cols }).map((_, i) => (
        <td key={i} className="px-4 py-3.5">
          <Skeleton className={`h-3 ${i === 0 ? "w-16" : i === cols - 1 ? "w-14" : "w-full"}`} />
        </td>
      ))}
    </tr>
  );
}

export function CardSkeleton(): React.ReactElement {
  return (
    <div className="rounded-xl border border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900 p-4">
      <Skeleton className="h-4 w-1/3 mb-3" />
      <Skeleton className="h-3 w-full mb-2" />
      <Skeleton className="h-3 w-5/6 mb-2" />
      <Skeleton className="h-3 w-2/3" />
    </div>
  );
}
