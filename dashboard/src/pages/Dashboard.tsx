import { useQuery } from "@tanstack/react-query";
import { AlertTriangle, CheckCircle, TrendingUp, Zap, Shield, Server, Activity } from "lucide-react";
import { getStats, getIncidents } from "../api/client";
import { SeverityBadge, StatusBadge } from "../components/Badges";
import { formatDistanceToNow } from "date-fns";
import { Link } from "react-router-dom";
import clsx from "clsx";

export default function Dashboard() {
  const { data: stats } = useQuery({ queryKey: ["stats"], queryFn: getStats });
  const { data: incidents } = useQuery({
    queryKey: ["incidents-recent"],
    queryFn: () => getIncidents({ limit: "10" }),
  });

  const healthScore = (stats as any)?.cluster_health_score;
  const healthColor =
    healthScore == null ? "text-gray-400" :
    healthScore >= 90 ? "text-green-400" :
    healthScore >= 70 ? "text-yellow-400" :
    healthScore >= 50 ? "text-orange-400" : "text-red-400";

  const statCards = [
    {
      label: "Active Incidents",
      value: stats?.active_incidents ?? "—",
      icon: AlertTriangle,
      color: "text-red-400",
      bg: "bg-red-900/20",
      href: "/incidents?status=active",
    },
    {
      label: "Security Threats",
      value: (stats as any)?.total_security_threats ?? "—",
      icon: Shield,
      color: "text-orange-400",
      bg: "bg-orange-900/20",
      href: "/security",
    },
    {
      label: "Cluster Health",
      value: healthScore != null ? `${healthScore}/100` : "—",
      icon: Server,
      color: healthColor,
      bg: "bg-blue-900/20",
      href: "/cluster",
    },
    {
      label: "App Anomalies",
      value: (stats as any)?.app_anomalies ?? "—",
      icon: Activity,
      color: "text-purple-400",
      bg: "bg-purple-900/20",
      href: "/apps",
    },
    {
      label: "Predicted",
      value: stats?.predicted_incidents ?? "—",
      icon: TrendingUp,
      color: "text-yellow-400",
      bg: "bg-yellow-900/20",
      href: "/incidents?status=predicted",
    },
    {
      label: "Log Anomalies",
      value: stats?.total_anomalies ?? "—",
      icon: Zap,
      color: "text-blue-400",
      bg: "bg-blue-900/20",
      href: "/logs?anomalies_only=true",
    },
  ];

  return (
    <div className="p-6 space-y-6">
      <h1 className="text-xl font-semibold">Overview</h1>

      {/* Stat cards */}
      <div className="grid grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-4">
        {statCards.map(({ label, value, icon: Icon, color, bg, href }) => (
          <Link key={label} to={href} className="bg-gray-900 border border-gray-800 rounded-lg p-4 hover:border-gray-600 transition-colors">
            <div className={`inline-flex p-2 rounded-md ${bg} mb-3`}>
              <Icon size={18} className={color} />
            </div>
            <div className={clsx("text-2xl font-bold", color)}>{value}</div>
            <div className="text-sm text-gray-400 mt-1">{label}</div>
          </Link>
        ))}
      </div>

      {/* Recent incidents */}
      <div className="bg-gray-900 border border-gray-800 rounded-lg">
        <div className="px-4 py-3 border-b border-gray-800 flex items-center justify-between">
          <h2 className="font-medium text-sm">Recent Incidents</h2>
          <Link to="/incidents" className="text-xs text-blue-400 hover:underline">
            View all →
          </Link>
        </div>
        <div className="divide-y divide-gray-800">
          {incidents?.length === 0 && (
            <div className="p-6 text-center text-gray-500 text-sm">No incidents yet</div>
          )}
          {incidents?.map((inc) => (
            <Link
              key={inc.id}
              to={`/incidents/${inc.id}`}
              className="flex items-center gap-4 px-4 py-3 hover:bg-gray-800/50 transition-colors"
            >
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium truncate">{inc.title}</p>
                <p className="text-xs text-gray-400 mt-0.5">
                  {inc.namespace ?? "—"} · {formatDistanceToNow(new Date(inc.detected_at), { addSuffix: true })}
                </p>
              </div>
              <div className="flex items-center gap-2 shrink-0">
                <SeverityBadge severity={inc.severity} />
                <StatusBadge status={inc.status} />
              </div>
            </Link>
          ))}
        </div>
      </div>
    </div>
  );
}
