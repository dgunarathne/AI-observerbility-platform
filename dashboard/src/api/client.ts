import axios from "axios";

const BASE_URL = import.meta.env.VITE_API_URL ?? "http://localhost:8080/api/v1";

export const api = axios.create({ baseURL: BASE_URL });

export interface Incident {
  id: number;
  title: string;
  description: string;
  severity: "critical" | "high" | "medium" | "low";
  status: "predicted" | "active" | "resolved" | "false_positive";
  namespace?: string;
  pod_name?: string;
  node_name?: string;
  detected_at: string;
  predicted_at?: string;
  resolved_at?: string;
  rca_summary?: string;
  rca_root_causes?: RootCause[];
  rca_preventive_actions?: PreventiveAction[];
  prediction_confidence?: number;
}

export interface RootCause {
  title: string;
  description: string;
  confidence: number;
}

export interface PreventiveAction {
  action: string;
  priority: "high" | "medium" | "low";
  category: string;
}

export interface Stats {
  total_incidents: number;
  active_incidents: number;
  predicted_incidents: number;
  total_anomalies: number;
}

export interface LogEntry {
  id: number;
  timestamp: string;
  namespace: string;
  pod_name: string;
  container_name: string;
  message: string;
  anomaly_score?: number;
  is_anomaly: boolean;
}

export interface MetricEntry {
  timestamp: string;
  namespace: string;
  pod_name: string;
  container_name?: string;
  node_name?: string;
  cpu_millicores: number;
  memory_mb: number;
}

// API helpers
export const getStats = () => api.get<Stats>("/stats").then((r) => r.data);

export const getIncidents = (params?: Record<string, string>) =>
  api.get<Incident[]>("/incidents", { params }).then((r) => r.data);

export const getIncident = (id: number) =>
  api.get<Incident>(`/incidents/${id}`).then((r) => r.data);

export const resolveIncident = (id: number) =>
  api.post(`/incidents/${id}/resolve`).then((r) => r.data);

export const triggerRCA = (id: number) =>
  api.post(`/incidents/${id}/rca`).then((r) => r.data);

export const getLogs = (params?: Record<string, string | boolean>) =>
  api.get<LogEntry[]>("/logs", { params }).then((r) => r.data);

export const getMetrics = (params?: Record<string, string>) =>
  api.get<MetricEntry[]>("/metrics", { params }).then((r) => r.data);
