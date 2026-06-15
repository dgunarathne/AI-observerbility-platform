import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { getIncidents } from "../api/client";
import { SeverityBadge, StatusBadge } from "../components/Badges";
import { formatDistanceToNow } from "date-fns";

const STATUSES = ["", "active", "predicted", "resolved"];
const SEVERITIES = ["", "critical", "high", "medium", "low"];

export default function Incidents() {
  const [status, setStatus] = useState("");
  const [severity, setSeverity] = useState("");

  const { data: incidents, isLoading } = useQuery({
    queryKey: ["incidents", status, severity],
    queryFn: () =>
      getIncidents({
        ...(status && { status }),
        ...(severity && { severity }),
        limit: "100",
      }),
  });

  return (
    <div className="p-6 space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold">Incidents</h1>
        <div className="flex gap-2">
          <select
            value={status}
            onChange={(e) => setStatus(e.target.value)}
            className="bg-gray-800 border border-gray-700 rounded-md px-3 py-1.5 text-sm"
          >
            {STATUSES.map((s) => (
              <option key={s} value={s}>{s || "All statuses"}</option>
            ))}
          </select>
          <select
            value={severity}
            onChange={(e) => setSeverity(e.target.value)}
            className="bg-gray-800 border border-gray-700 rounded-md px-3 py-1.5 text-sm"
          >
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>{s || "All severities"}</option>
            ))}
          </select>
        </div>
      </div>

      <div className="bg-gray-900 border border-gray-800 rounded-lg divide-y divide-gray-800">
        {isLoading && (
          <div className="p-6 text-center text-gray-400 text-sm">Loading...</div>
        )}
        {!isLoading && incidents?.length === 0 && (
          <div className="p-6 text-center text-gray-500 text-sm">No incidents found</div>
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
                {inc.namespace ?? "—"} · {inc.pod_name ?? "—"} ·{" "}
                {formatDistanceToNow(new Date(inc.detected_at), { addSuffix: true })}
              </p>
              {inc.rca_summary && (
                <p className="text-xs text-gray-500 mt-1 truncate">{inc.rca_summary}</p>
              )}
            </div>
            <div className="flex items-center gap-2 shrink-0">
              <SeverityBadge severity={inc.severity} />
              <StatusBadge status={inc.status} />
            </div>
          </Link>
        ))}
      </div>
    </div>
  );
}
