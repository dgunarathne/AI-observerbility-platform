import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import { formatDistanceToNow } from "date-fns";
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, ReferenceLine,
} from "recharts";
import clsx from "clsx";

interface ClusterHealthLatest {
  timestamp: string;
  health_score: number;
  summary: string;
  issues: Issue[];
  total_nodes: number;
  not_ready_nodes: number;
  running_pods: number;
  total_pods: number;
  crash_loop_pods: number;
  degraded_deployments: number;
  unbound_pvcs: number;
}

interface Issue {
  category: string;
  severity: string;
  title: string;
  description: string;
  affected_resources?: string[];
}

interface HealthHistory {
  timestamp: string;
  health_score: number;
  running_pods: number;
  total_pods: number;
  not_ready_nodes: number;
  crash_loop_pods: number;
}

const SEVERITY_STYLES: Record<string, string> = {
  critical: "border-l-red-500 bg-red-900/10",
  high:     "border-l-orange-500 bg-orange-900/10",
  medium:   "border-l-yellow-500 bg-yellow-900/10",
  low:      "border-l-blue-500 bg-blue-900/10",
};

const CATEGORY_ICONS: Record<string, string> = {
  node:       "🖥️",
  pod:        "📦",
  pvc:        "💾",
  deployment: "🚀",
  quota:      "📊",
};

function HealthScore({ score }: { score: number }) {
  const color =
    score >= 90 ? "text-green-400" :
    score >= 70 ? "text-yellow-400" :
    score >= 50 ? "text-orange-400" : "text-red-400";
  const label =
    score >= 90 ? "Healthy" :
    score >= 70 ? "Degraded" :
    score >= 50 ? "Unhealthy" : "Critical";

  return (
    <div className="flex flex-col items-center justify-center">
      <div className={`text-5xl font-bold ${color}`}>{score}</div>
      <div className={`text-sm mt-1 ${color}`}>{label}</div>
      <div className="text-xs text-gray-500 mt-0.5">/ 100</div>
    </div>
  );
}

export default function ClusterHealth() {
  const { data: latest } = useQuery<ClusterHealthLatest>({
    queryKey: ["cluster-health-latest"],
    queryFn: () => api.get("/cluster/health/latest").then((r) => r.data),
    refetchInterval: 30_000,
  });

  const { data: history } = useQuery<HealthHistory[]>({
    queryKey: ["cluster-health-history"],
    queryFn: () => api.get("/cluster/health?limit=60").then((r) => r.data),
    refetchInterval: 60_000,
  });

  const chartData = [...(history ?? [])].reverse().map((h) => ({
    time: new Date(h.timestamp).toLocaleTimeString("en", { hour: "2-digit", minute: "2-digit" }),
    score: h.health_score,
    pods: h.running_pods,
    crashLoop: h.crash_loop_pods,
    notReady: h.not_ready_nodes,
  }));

  return (
    <div className="p-6 space-y-6">
      <h1 className="text-xl font-semibold">Cluster Health</h1>

      {/* Health score + summary */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-6 flex flex-col items-center justify-center">
          {latest ? (
            <HealthScore score={latest.health_score} />
          ) : (
            <div className="text-gray-400 text-sm">No data yet</div>
          )}
          {latest?.timestamp && (
            <div className="text-xs text-gray-500 mt-3">
              Updated {formatDistanceToNow(new Date(latest.timestamp), { addSuffix: true })}
            </div>
          )}
        </div>

        {/* Quick stats */}
        <div className="lg:col-span-2 grid grid-cols-2 sm:grid-cols-3 gap-3">
          {[
            { label: "Nodes Ready", value: latest ? `${latest.total_nodes - latest.not_ready_nodes}/${latest.total_nodes}` : "—", ok: !latest?.not_ready_nodes },
            { label: "Pods Running", value: latest ? `${latest.running_pods}/${latest.total_pods}` : "—", ok: latest ? latest.running_pods === latest.total_pods : true },
            { label: "CrashLoopBackOff", value: latest?.crash_loop_pods ?? "—", ok: !latest?.crash_loop_pods },
            { label: "Degraded Deploys", value: latest?.degraded_deployments ?? "—", ok: !latest?.degraded_deployments },
            { label: "Unbound PVCs", value: latest?.unbound_pvcs ?? "—", ok: !latest?.unbound_pvcs },
            { label: "Open Issues", value: latest?.issues?.length ?? "—", ok: !latest?.issues?.length },
          ].map(({ label, value, ok }) => (
            <div key={label} className={clsx(
              "rounded-lg p-3 border",
              ok ? "bg-green-900/10 border-green-800/30" : "bg-red-900/10 border-red-800/30"
            )}>
              <div className={clsx("text-xl font-bold", ok ? "text-green-300" : "text-red-300")}>{String(value)}</div>
              <div className="text-xs text-gray-400 mt-1">{label}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Health score time series */}
      {chartData.length > 1 && (
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
          <h2 className="text-sm font-medium mb-4">Health Score Trend</h2>
          <ResponsiveContainer width="100%" height={180}>
            <LineChart data={chartData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
              <XAxis dataKey="time" tick={{ fill: "#9CA3AF", fontSize: 11 }} />
              <YAxis domain={[0, 100]} tick={{ fill: "#9CA3AF", fontSize: 11 }} />
              <Tooltip
                contentStyle={{ backgroundColor: "#111827", border: "1px solid #374151" }}
                labelStyle={{ color: "#E5E7EB" }}
              />
              <ReferenceLine y={70} stroke="#F59E0B" strokeDasharray="4 4" label={{ value: "70", fill: "#F59E0B", fontSize: 10 }} />
              <ReferenceLine y={50} stroke="#EF4444" strokeDasharray="4 4" label={{ value: "50", fill: "#EF4444", fontSize: 10 }} />
              <Line type="monotone" dataKey="score" stroke="#3B82F6" strokeWidth={2} dot={false} name="Score" />
            </LineChart>
          </ResponsiveContainer>
        </div>
      )}

      {/* Active issues */}
      {latest?.issues && latest.issues.length > 0 && (
        <div className="space-y-3">
          <h2 className="text-sm font-medium">Active Issues ({latest.issues.length})</h2>
          {latest.issues.map((issue, i) => (
            <div
              key={i}
              className={clsx(
                "border-l-4 rounded-r-lg p-4",
                SEVERITY_STYLES[issue.severity] ?? "border-l-gray-600 bg-gray-900"
              )}
            >
              <div className="flex items-start gap-2">
                <span className="text-lg">{CATEGORY_ICONS[issue.category] ?? "⚠️"}</span>
                <div className="flex-1">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-medium">{issue.title}</span>
                    <span className={clsx(
                      "text-xs px-1.5 py-0.5 rounded-full",
                      issue.severity === "critical" ? "bg-red-900/50 text-red-300" :
                      issue.severity === "high" ? "bg-orange-900/50 text-orange-300" :
                      "bg-yellow-900/50 text-yellow-300"
                    )}>
                      {issue.severity}
                    </span>
                  </div>
                  <p className="text-xs text-gray-400 mt-1">{issue.description}</p>
                  {issue.affected_resources && issue.affected_resources.length > 0 && (
                    <div className="flex flex-wrap gap-1 mt-2">
                      {issue.affected_resources.slice(0, 5).map((r) => (
                        <span key={r} className="text-xs bg-gray-800 px-2 py-0.5 rounded font-mono text-gray-300">{r}</span>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {latest?.issues?.length === 0 && (
        <div className="bg-green-900/10 border border-green-800/30 rounded-lg p-6 text-center text-green-400 text-sm">
          ✅ No cluster health issues detected
        </div>
      )}
    </div>
  );
}
