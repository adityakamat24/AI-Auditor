import React from "react";
import type { Severity } from "../types";

interface Props {
  severity: Severity;
}

const STYLES: Record<Severity, string> = {
  critical:
    "bg-red-100 text-red-800 border border-red-300 dark:bg-red-900/40 dark:text-red-300 dark:border-red-700",
  high:
    "bg-orange-100 text-orange-800 border border-orange-300 dark:bg-orange-900/40 dark:text-orange-300 dark:border-orange-700",
  medium:
    "bg-yellow-100 text-yellow-800 border border-yellow-300 dark:bg-yellow-900/40 dark:text-yellow-300 dark:border-yellow-700",
  low:
    "bg-blue-100 text-blue-700 border border-blue-300 dark:bg-blue-900/40 dark:text-blue-300 dark:border-blue-700",
};

export default function SeverityBadge({ severity }: Props): React.ReactElement {
  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold uppercase tracking-wide ${STYLES[severity]}`}
    >
      {severity}
    </span>
  );
}
