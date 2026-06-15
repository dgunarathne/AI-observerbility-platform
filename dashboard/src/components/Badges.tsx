import clsx from "clsx";

const SEVERITY_STYLES: Record<string, string> = {
  critical: "bg-red-900/50 text-red-300 border border-red-700/50",
  high: "bg-orange-900/50 text-orange-300 border border-orange-700/50",
  medium: "bg-yellow-900/50 text-yellow-300 border border-yellow-700/50",
  low: "bg-blue-900/50 text-blue-300 border border-blue-700/50",
};

const STATUS_STYLES: Record<string, string> = {
  active: "bg-red-900/40 text-red-300",
  predicted: "bg-yellow-900/40 text-yellow-300",
  resolved: "bg-green-900/40 text-green-300",
  false_positive: "bg-gray-800 text-gray-400",
};

export function SeverityBadge({ severity }: { severity: string }) {
  return (
    <span
      className={clsx(
        "px-2 py-0.5 rounded-full text-xs font-medium",
        SEVERITY_STYLES[severity] ?? "bg-gray-800 text-gray-400"
      )}
    >
      {severity}
    </span>
  );
}

export function StatusBadge({ status }: { status: string }) {
  return (
    <span
      className={clsx(
        "px-2 py-0.5 rounded-full text-xs font-medium",
        STATUS_STYLES[status] ?? "bg-gray-800 text-gray-400"
      )}
    >
      {status.replace("_", " ")}
    </span>
  );
}
