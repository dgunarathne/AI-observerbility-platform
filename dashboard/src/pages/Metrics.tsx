import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { getMetrics } from "../api/client";
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, Legend,
} from "recharts";
import { format } from "date-fns";

export default function Metrics() {
  const [namespace, setNamespace] = useState("");
  const [podName, setPodName] = useState("");

  const { data: metrics } = useQuery({
    queryKey: ["metrics", namespace, podName],
    queryFn: () =>
      getMetrics({
        ...(namespace && { namespace }),
        ...(podName && { pod_name: podName }),
        limit: "300",
      }),
    refetchInterval: 30_000,
  });

  // Prepare chart data: group by pod, take last 50 points
  const chartData = (metrics ?? [])
    .slice(0, 50)
    .reverse()
    .map((m) => ({
      time: format(new Date(m.timestamp), "HH:mm"),
      cpu: m.cpu_millicores,
      memory: m.memory_mb,
      pod: m.pod_name,
    }));

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <h1 className="text-xl font-semibold">Metrics</h1>
        <div className="flex gap-2">
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
        </div>
      </div>

      {/* CPU chart */}
      <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
        <h2 className="text-sm font-medium mb-4">CPU Usage (millicores)</h2>
        <ResponsiveContainer width="100%" height={220}>
          <LineChart data={chartData}>
            <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
            <XAxis dataKey="time" tick={{ fill: "#9CA3AF", fontSize: 11 }} />
            <YAxis tick={{ fill: "#9CA3AF", fontSize: 11 }} />
            <Tooltip
              contentStyle={{ backgroundColor: "#111827", border: "1px solid #374151" }}
              labelStyle={{ color: "#E5E7EB" }}
            />
            <Legend />
            <Line
              type="monotone"
              dataKey="cpu"
              stroke="#3B82F6"
              strokeWidth={2}
              dot={false}
              name="CPU (m)"
            />
          </LineChart>
        </ResponsiveContainer>
      </div>

      {/* Memory chart */}
      <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
        <h2 className="text-sm font-medium mb-4">Memory Usage (MiB)</h2>
        <ResponsiveContainer width="100%" height={220}>
          <LineChart data={chartData}>
            <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
            <XAxis dataKey="time" tick={{ fill: "#9CA3AF", fontSize: 11 }} />
            <YAxis tick={{ fill: "#9CA3AF", fontSize: 11 }} />
            <Tooltip
              contentStyle={{ backgroundColor: "#111827", border: "1px solid #374151" }}
              labelStyle={{ color: "#E5E7EB" }}
            />
            <Legend />
            <Line
              type="monotone"
              dataKey="memory"
              stroke="#8B5CF6"
              strokeWidth={2}
              dot={false}
              name="Memory (MiB)"
            />
          </LineChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
