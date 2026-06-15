import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import { format } from "date-fns";
import clsx from "clsx";
import { Shield, AlertOctagon, Activity } from "lucide-react";

interface SecurityThreat {
  id: number;
  timestamp: string;
  category: string;
  severity: string;
  source: string;
  namespace?: string;
  pod_name?: string;
  description: string;
  source_ips?: string[];
  mitigation?: string;
  alerted: boolean;
}

interface SecurityStats {
  total_threats: number;
  critical: number;
  high: number;
  top_categories: { category: string; count: number }[];
}

const SEVERITY_COLOR: Record<string, string> = {
  critical: "bg-red-900/50 text-red-300 border border-red-700/50",
  high:     "bg-orange-900/50 text-orange-300 border border-orange-700/50",
  medium:   "bg-yellow-900/50 text-yellow-300 border border-yellow-700/50",
  low:      "bg-blue-900/50 text-blue-300 border border-blue-700/50",
};

const CATEGORY_ICONS: Record<string, string> = {
  web_attack:           "🌐",
  brute_force:          "🔨",
  privilege_escalation: "⬆️",
  reverse_shell:        "🐚",
  container_escape:     "🔓",
  crypto_mining:        "⛏️",
  kubernetes_attack:    "☸️",
  secret_exfiltration:  "🔑",
  port_scan:            "🔍",
  privileged_workload:  "⚠️",
  network_exposure:     "🕸️",
};

export default function Security() {
  const { data: stats } = useQuery<SecurityStats>({
    queryKey: ["security-stats"],
    queryFn: () => api.get("/security/stats").then((r) => r.data),
    refetchInterval: 30_000,
  });

  const { data: threats, isLoading } = useQuery<SecurityThreat[]>({
    queryKey: ["security-threats"],
    queryFn: () => api.get("/security/threats?limit=100").then((r) => r.data),
    refetchInterval: 15_000,
  });

  const { data: correlation } = useQuery({
    queryKey: ["security-correlation"],
    queryFn: () => api.get("/security/correlation").then((r) => r.data),
    refetchInterval: 30_000,
  });

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center gap-2">
        <Shield className="text-red-400" size={20} />
        <h1 className="text-xl font-semibold">Security Threats</h1>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard label="Total Threats" value={stats?.total_threats ?? "—"} color="text-gray-300" />
        <StatCard label="Critical" value={stats?.critical ?? "—"} color="text-red-400" />
        <StatCard label="High" value={stats?.high ?? "—"} color="text-orange-400" />
        <StatCard
          label="Active IPs"
          value={Object.keys(correlation?.active_ip_threats ?? {}).length}
          color="text-yellow-400"
        />
      </div>

      {/* Top categories */}
      {stats?.top_categories && stats.top_categories.length > 0 && (
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
          <h2 className="text-sm font-medium mb-3">Threat Categories</h2>
          <div className="flex flex-wrap gap-2">
            {stats.top_categories.map((cat) => (
              <div
                key={cat.category}
                className="flex items-center gap-2 bg-gray-800 rounded-md px-3 py-1.5 text-sm"
              >
                <span>{CATEGORY_ICONS[cat.category] ?? "⚡"}</span>
                <span className="text-gray-300">{cat.category.replace(/_/g, " ")}</span>
                <span className="text-gray-500">×{cat.count}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Threat list */}
      <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
        <div className="px-4 py-3 border-b border-gray-800 text-sm font-medium">
          Recent Threats ({threats?.length ?? 0})
        </div>
        <div className="divide-y divide-gray-800/50">
          {isLoading && (
            <div className="p-6 text-center text-gray-400 text-sm">Loading...</div>
          )}
          {threats?.map((t) => (
            <ThreatRow key={t.id} threat={t} />
          ))}
          {!isLoading && threats?.length === 0 && (
            <div className="p-6 text-center text-gray-500 text-sm">
              No security threats detected — cluster looks clean ✅
            </div>
          )}
        </div>
      </div>

      {/* Active IP correlations */}
      {correlation && Object.keys(correlation.active_ip_threats ?? {}).length > 0 && (
        <div className="bg-gray-900 border border-red-800/50 rounded-lg p-4">
          <div className="flex items-center gap-2 mb-3">
            <AlertOctagon size={15} className="text-red-400" />
            <h2 className="text-sm font-medium">Active Attack Sources</h2>
          </div>
          <div className="space-y-2">
            {Object.entries(correlation.active_ip_threats).map(([ip, data]: [string, any]) => (
              <div key={ip} className="flex items-center justify-between bg-red-900/10 border border-red-800/30 rounded-md px-3 py-2 text-sm">
                <div>
                  <span className="font-mono text-red-300">{ip}</span>
                  <span className="text-gray-400 ml-3 text-xs">
                    {data.categories?.join(", ")}
                  </span>
                </div>
                <span className="text-gray-400 text-xs">{data.count} events</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function ThreatRow({ threat }: { threat: SecurityThreat }) {
  const [expanded, setExpanded] = React.useState(false);
  return (
    <div
      className="px-4 py-3 cursor-pointer hover:bg-gray-800/40"
      onClick={() => setExpanded((v) => !v)}
    >
      <div className="flex items-start gap-3">
        <span className="text-lg shrink-0">{CATEGORY_ICONS[threat.category] ?? "⚡"}</span>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className={clsx("text-xs px-2 py-0.5 rounded-full", SEVERITY_COLOR[threat.severity])}>
              {threat.severity}
            </span>
            <span className="text-xs text-gray-400">{threat.category.replace(/_/g, " ")}</span>
            <span className="text-xs text-gray-500">
              {format(new Date(threat.timestamp), "MMM d HH:mm:ss")}
            </span>
            {threat.namespace && (
              <span className="text-xs text-blue-400">{threat.namespace}</span>
            )}
            {threat.source_ips?.length ? (
              <span className="text-xs font-mono text-red-300">{threat.source_ips[0]}</span>
            ) : null}
          </div>
          <p className="text-sm text-gray-300 mt-1 truncate">{threat.description}</p>
          {expanded && (
            <div className="mt-2 space-y-2">
              {threat.source_ips && threat.source_ips.length > 0 && (
                <div className="text-xs text-gray-400">
                  Source IPs: {threat.source_ips.join(", ")}
                </div>
              )}
              {threat.mitigation && (
                <div className="bg-green-900/20 border border-green-800/40 rounded-md p-3 text-xs text-green-300 whitespace-pre-wrap">
                  <div className="font-medium mb-1">🛡️ Mitigation Steps</div>
                  {threat.mitigation}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function StatCard({ label, value, color }: { label: string; value: any; color: string }) {
  return (
    <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
      <div className={`text-2xl font-bold ${color}`}>{value}</div>
      <div className="text-xs text-gray-400 mt-1">{label}</div>
    </div>
  );
}

// Need React for useState
import React from "react";
