# Demo Suite

Run realistic incident simulations without a live Kubernetes cluster.
Each scenario fires real API calls to the AI engine and triggers all
configured alert channels (Slack, email, SMS, voice, etc.).

## Quick Start

```bash
# 1. Start the platform
cd ..
cp .env.example .env
# Fill in at least one alert channel in .env
docker compose up -d

# 2. Wait for the engine to be ready (~20 seconds)
curl http://localhost:8080/health

# 3. Run all demo scenarios
cd demo
pip install -r requirements.txt
python run_demo.py

# OR run a single scenario
python run_demo.py --scenario crash_loop       # CrashLoopBackOff
python run_demo.py --scenario oom              # OOM kill
python run_demo.py --scenario sql_injection    # SQL injection attack
python run_demo.py --scenario brute_force      # SSH brute-force
python run_demo.py --scenario node_pressure    # Node MemoryPressure
python run_demo.py --scenario latency_spike    # API latency degradation
python run_demo.py --scenario secret_theft     # Secret exfiltration attempt
python run_demo.py --scenario cluster_down     # Multiple nodes NotReady
python run_demo.py --scenario all              # Run everything (default)
```

## What Each Scenario Does

| Scenario | Type | Severity | What fires |
|---|---|---|---|
| `crash_loop` | App anomaly + K8s event | HIGH | RCA + all channels |
| `oom` | App anomaly + K8s event | CRITICAL | Immediate alert |
| `sql_injection` | Security threat | HIGH | Security channel + SMS |
| `brute_force` | Security threat (correlated) | CRITICAL | Voice call + all channels |
| `node_pressure` | Cluster health | HIGH | Cluster health alert |
| `latency_spike` | App anomaly | MEDIUM | App health alert |
| `secret_theft` | Security threat | CRITICAL | All channels + voice |
| `cluster_down` | Cluster health | CRITICAL | Emergency voice call |
