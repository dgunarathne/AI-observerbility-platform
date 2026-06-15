import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { getLogs } from "../api/client";
import { format } from "date-fns";
import clsx from "clsx";

export default function Logs() {
  const [namespace, setNamespace] = useState("");
  const [podName, setPodName] = useState("");
  const [anomaliesOnly, setAnomaliesOnly] = useState(false);

  const { data: logs, isLoading } = useQuery({
    queryKey: ["logs", namespace, podName, anomaliesOnly],
    queryFn: () =>
      getLogs({
        ...(namespace && { namespace }),
        ...(podName && { pod_name: podName }),
        anomalies_only: anomaliesOnly,
        limit: "200",
      }),
    refetchInterval: 10_000,
  });

  return (
    <div className="p-6 space-y-4">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <h1 className="text-xl font-semibold">Logs</h1>
        <div className="flex gap-2 flex-wrap">
          <input
            placeholder="Namespace"
            value={namespace}
            onChange={(e) => setNamespace(e.target.value)}
            className="bg-gray-800 border border-gray-700 rounded-md px-3 py-1.5 text-sm w-36"
          />
          <input
            placeholder="Pod name"
            value={podName}
            onChange={(e) => setPodName(e.target.value)}
            className="bg-gray-800 border border-gray-700 rounded-md px-3 py-1.5 text-sm w-40"
          />
          <label className="flex items-center gap-2 text-sm cursor-pointer">
            <input
              type="checkbox"
              checked={anomaliesOnly}
              onChange={(e) => setAnomaliesOnly(e.target.checked)}
              className="accent-blue-500"
            />
            Anomalies only
          </label>
        </div>
      </div>

      <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-gray-800 text-gray-400">
                <th className="px-3 py-2 text-left w-40">Time</th>
                <th className="px-3 py-2 text-left w-28">Namespace</th>
                <th className="px-3 py-2 text-left w-36">Pod</th>
                <th className="px-3 py-2 text-left w-24">Container</th>
                <th className="px-3 py-2 text-left">Message</th>
                <th className="px-3 py-2 text-right w-16">Score</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800/50 font-mono">
              {isLoading && (
                <tr>
                  <td colSpan={6} className="px-3 py-4 text-center text-gray-500">
                    Loading...
                  </td>
                </tr>
              )}
              {logs?.map((log) => (
                <tr
                  key={log.id}
                  className={clsx(
                    "hover:bg-gray-800/40",
                    log.is_anomaly && "bg-red-900/10"
                  )}
                >
                  <td className="px-3 py-1.5 text-gray-400 whitespace-nowrap">
                    {format(new Date(log.timestamp), "HH:mm:ss.SSS")}
                  </td>
                  <td className="px-3 py-1.5 text-blue-300 truncate max-w-[7rem]">
                    {log.namespace}
                  </td>
                  <td className="px-3 py-1.5 text-gray-300 truncate max-w-[9rem]">
                    {log.pod_name}
                  </td>
                  <td className="px-3 py-1.5 text-gray-400 truncate">
                    {log.container_name}
                  </td>
                  <td className="px-3 py-1.5 text-gray-200 max-w-xl truncate">
                    {log.message}
                  </td>
                  <td className="px-3 py-1.5 text-right">
                    {log.anomaly_score != null && (
                      <span
                        className={clsx(
                          "px-1.5 py-0.5 rounded text-xs",
                          log.anomaly_score > 0.7
                            ? "bg-red-900/50 text-red-300"
                            : log.anomaly_score > 0.4
                            ? "bg-yellow-900/50 text-yellow-300"
                            : "bg-gray-800 text-gray-400"
                        )}
                      >
                        {log.anomaly_score.toFixed(2)}
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
