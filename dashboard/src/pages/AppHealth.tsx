import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import { format } from "date-fns";
import clsx from "clsx";

interface AppSummary {
  namespace: string;
  app_label: string;
  total_windows: number;
  anomaly_windows: number;
  avg_error_rate: number;
  avg_latency_ms: number;
  last_seen: string;
}

interface AppHealthSnapshot {
  id: number;
  timestamp: string;
  namespace: string;
  app_label: string;
  error_rate: number;
  http_5xx_count: number;
  http_5xx_rate: number;
  exception_count: number;
  avg_latency_ms: number;
  total_log_lines: number;
  is_anomaly: boolean;
  anomalies: { type: string; message: string; severity: string }[];
}

function AnomalyBadge({ count }: { count: number }) {
  if (count === 0) return <span className="text-xs text-green-400">✅ Normal</span>;
  return <span className="text-xs bg-red-900/50 text-red-300 px-2 py-0.5 rounded-full">{count} anomalies</span>;
}

export default function AppHealth() {
  const [selectedNs, setSelectedNs] = useState("");
  const [selectedApp, setSelectedApp] = useState("");

  const { data: summaries } = useQuery<AppSummary[]>({
    queryKey: ["app-health-summary"],
    queryFn: () => api.get("/apps/health/summary").then((r) => r.data),
    refetchInterval: 30_000,
  });

  const { data: snapshots, isLoading } = useQuery<AppHealthSnapshot[]>({
    queryKey: ["app-health", selectedNs, selectedApp],
    queryFn: () =>
      api
        .get("/apps/health", {
          params: {
            limit: 100,
            ...(selectedNs && { namespace: selectedNs }),
            ...(selectedApp && { app_label: selectedApp }),
          },
        })
        .then((r) => r.data),
    refetchInterval: 30_000,
  });

  return (
    <div className="p-6 space-y-6">
      <h1 className="text-xl font-semibold">Application Health</h1>

      {/* App summary table */}
      <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
        <div className="px-4 py-3 border-b border-gray-800 text-sm font-medium">
          Applications ({summaries?.length ?? 0})
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-xs text-gray-400 border-b border-gray-800">
                <th className="px-3 py-2 text-left">App</th>
                <th className="px-3 py-2 text-left">Namespace</th>
                <th className="px-3 py-2 text-right">Error Rate</th>
                <th className="px-3 py-2 text-right">Avg Latency</th>
                <th className="px-3 py-2 text-right">Anomalies</th>
                <th className="px-3 py-2 text-left">Last Seen</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800/50">
              {summaries?.map((s) => (
                <tr
                  key={`${s.namespace}/${s.app_label}`}
                  className={clsx(
                    "cursor-pointer hover:bg-gray-800/40",
                    s.anomaly_windows > 0 && "bg-red-900/5"
                  )}
                  onClick={() => {
                    setSelectedNs(s.namespace);
                    setSelectedApp(s.app_label);
                  }}
                >
                  <td className="px-3 py-2 font-medium text-gray-200">{s.app_label || "—"}</td>
                  <td className="px-3 py-2 text-blue-300">{s.namespace}</td>
                  <td className="px-3 py-2 text-right">
                    <span className={clsx(
                      "text-xs",
                      s.avg_error_rate > 0.15 ? "text-red-400" :
                      s.avg_error_rate > 0.05 ? "text-yellow-400" : "text-green-400"
                    )}>
                      {(s.avg_error_rate * 100).toFixed(1)}%
                    </span>
                  </td>
                  <td className="px-3 py-2 text-right text-gray-300">{s.avg_latency_ms.toFixed(0)}ms</td>
                  <td className="px-3 py-2 text-right">
                    <AnomalyBadge count={s.anomaly_windows} />
                  </td>
                  <td className="px-3 py-2 text-xs text-gray-400">
                    {s.last_seen ? format(new Date(s.last_seen), "MMM d HH:mm") : "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Anomaly detail snapshots */}
      {(selectedNs || selectedApp) && (
        <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
          <div className="px-4 py-3 border-b border-gray-800 flex items-center justify-between">
            <span className="text-sm font-medium">
              {selectedApp} — {selectedNs}
            </span>
            <button
              onClick={() => { setSelectedNs(""); setSelectedApp(""); }}
              className="text-xs text-gray-400 hover:text-gray-200"
            >
              Clear
            </button>
          </div>
          <div className="divide-y divide-gray-800/50">
            {isLoading && <div className="p-4 text-center text-gray-400 text-sm">Loading...</div>}
            {snapshots?.filter((s) => s.is_anomaly).map((snap) => (
              <div key={snap.id} className="px-4 py-3 space-y-2">
                <div className="flex items-center gap-3 text-xs text-gray-400">
                  <span>{format(new Date(snap.timestamp), "MMM d HH:mm:ss")}</span>
                  <span>ERR: {(snap.error_rate * 100).toFixed(1)}%</span>
                  <span>5xx: {snap.http_5xx_count}</span>
                  <span>Exc: {snap.exception_count}</span>
                  <span>Lat: {snap.avg_latency_ms.toFixed(0)}ms</span>
                </div>
                <div className="space-y-1">
                  {snap.anomalies?.map((a, i) => (
                    <div key={i} className={clsx(
                      "text-xs px-2 py-1 rounded",
                      a.severity === "critical" ? "bg-red-900/30 text-red-300" :
                      a.severity === "high" ? "bg-orange-900/30 text-orange-300" :
                      "bg-yellow-900/30 text-yellow-300"
                    )}>
                      [{a.type}] {a.message}
                    </div>
                  ))}
                </div>
              </div>
            ))}
            {!isLoading && snapshots?.filter((s) => s.is_anomaly).length === 0 && (
              <div className="p-4 text-center text-gray-500 text-sm">No anomalies in recent windows</div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
