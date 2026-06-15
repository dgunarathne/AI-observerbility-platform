import { useParams } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { getIncident, resolveIncident, triggerRCA } from "../api/client";
import { SeverityBadge, StatusBadge } from "../components/Badges";
import { format } from "date-fns";
import { CheckCircle, RefreshCw } from "lucide-react";

export default function IncidentDetail() {
  const { id } = useParams<{ id: string }>();
  const incidentId = Number(id);
  const qc = useQueryClient();

  const { data: incident, isLoading } = useQuery({
    queryKey: ["incident", incidentId],
    queryFn: () => getIncident(incidentId),
  });

  const resolveMut = useMutation({
    mutationFn: () => resolveIncident(incidentId),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["incident", incidentId] }),
  });

  const rcaMut = useMutation({
    mutationFn: () => triggerRCA(incidentId),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["incident", incidentId] }),
  });

  if (isLoading) return <div className="p-6 text-gray-400">Loading...</div>;
  if (!incident) return <div className="p-6 text-gray-400">Incident not found</div>;

  return (
    <div className="p-6 space-y-6 max-w-4xl">
      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold">{incident.title}</h1>
          <p className="text-sm text-gray-400 mt-1">{incident.description}</p>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <SeverityBadge severity={incident.severity} />
          <StatusBadge status={incident.status} />
        </div>
      </div>

      {/* Meta */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-sm">
        {[
          ["Namespace", incident.namespace ?? "—"],
          ["Pod", incident.pod_name ?? "—"],
          ["Node", incident.node_name ?? "—"],
          ["Detected", incident.detected_at ? format(new Date(incident.detected_at), "PPpp") : "—"],
          incident.prediction_confidence != null
            ? ["Confidence", `${(incident.prediction_confidence * 100).toFixed(0)}%`]
            : null,
          incident.resolved_at
            ? ["Resolved", format(new Date(incident.resolved_at), "PPpp")]
            : null,
        ]
          .filter(Boolean)
          .map(([k, v]) => (
            <div key={k as string} className="bg-gray-900 border border-gray-800 rounded-md p-3">
              <div className="text-gray-400 text-xs mb-1">{k as string}</div>
              <div className="font-medium truncate">{v as string}</div>
            </div>
          ))}
      </div>

      {/* Actions */}
      <div className="flex gap-3">
        {incident.status !== "resolved" && (
          <button
            onClick={() => resolveMut.mutate()}
            disabled={resolveMut.isPending}
            className="flex items-center gap-2 px-4 py-2 bg-green-700 hover:bg-green-600 rounded-md text-sm font-medium transition-colors disabled:opacity-50"
          >
            <CheckCircle size={15} />
            Mark Resolved
          </button>
        )}
        <button
          onClick={() => rcaMut.mutate()}
          disabled={rcaMut.isPending}
          className="flex items-center gap-2 px-4 py-2 bg-blue-700 hover:bg-blue-600 rounded-md text-sm font-medium transition-colors disabled:opacity-50"
        >
          <RefreshCw size={15} className={rcaMut.isPending ? "animate-spin" : ""} />
          {rcaMut.isPending ? "Generating RCA..." : "Generate / Refresh RCA"}
        </button>
      </div>

      {/* RCA */}
      {incident.rca_summary && (
        <div className="space-y-4">
          <h2 className="font-semibold">Root Cause Analysis</h2>
          <div className="bg-gray-900 border border-gray-800 rounded-lg p-4 text-sm text-gray-200">
            {incident.rca_summary}
          </div>

          {incident.rca_root_causes && incident.rca_root_causes.length > 0 && (
            <div>
              <h3 className="text-sm font-medium text-gray-300 mb-2">Root Causes</h3>
              <div className="space-y-2">
                {incident.rca_root_causes.map((rc, i) => (
                  <div key={i} className="bg-gray-900 border border-gray-800 rounded-lg p-3">
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-sm font-medium">{rc.title}</span>
                      <span className="text-xs text-gray-400">
                        {(rc.confidence * 100).toFixed(0)}% confidence
                      </span>
                    </div>
                    <p className="text-xs text-gray-400">{rc.description}</p>
                  </div>
                ))}
              </div>
            </div>
          )}

          {incident.rca_preventive_actions && incident.rca_preventive_actions.length > 0 && (
            <div>
              <h3 className="text-sm font-medium text-gray-300 mb-2">Preventive Actions</h3>
              <div className="space-y-2">
                {incident.rca_preventive_actions.map((a, i) => (
                  <div key={i} className="bg-gray-900 border border-gray-800 rounded-lg p-3 flex items-start gap-3">
                    <span
                      className={`text-xs px-2 py-0.5 rounded-full shrink-0 ${
                        a.priority === "high"
                          ? "bg-red-900/50 text-red-300"
                          : a.priority === "medium"
                          ? "bg-yellow-900/50 text-yellow-300"
                          : "bg-blue-900/50 text-blue-300"
                      }`}
                    >
                      {a.priority}
                    </span>
                    <div>
                      <p className="text-sm">{a.action}</p>
                      <p className="text-xs text-gray-500 mt-0.5">{a.category}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
