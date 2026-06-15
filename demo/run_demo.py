#!/usr/bin/env python3
"""
AI Observability Platform — Demo Runner

Fires realistic incident scenarios at the running AI engine and
shows live feedback from all configured alert channels.

Usage:
    python run_demo.py                          # run all scenarios
    python run_demo.py --scenario crash_loop    # single scenario
    python run_demo.py --api http://host:8080   # custom API URL
    python run_demo.py --dry-run               # print payloads, don't send
"""

import argparse
import asyncio
import json
import sys
import time
from datetime import datetime

import httpx
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich import print as rprint

from scenarios import ALL_SCENARIOS

console = Console()

# ─── Configuration ────────────────────────────────────────────────────────────

DEFAULT_API_URL = "http://localhost:8080"

# Internal ingest endpoints (bypass gRPC for demo simplicity —
# the AI engine also exposes these HTTP shims for testing)
INGEST_ROUTES = {
    "logs":             "/api/v1/ingest/logs",
    "events":           "/api/v1/ingest/events",
    "app_health":       "/api/v1/ingest/app-health",
    "cluster_health":   "/api/v1/ingest/cluster-health",
    "security_threats": "/api/v1/ingest/security-threats",
}

STEP_DELAY = 1.5   # seconds between steps within a scenario
SCENARIO_DELAY = 3  # seconds between scenarios


# ─── Main runner ──────────────────────────────────────────────────────────────

async def run_scenario(client: httpx.AsyncClient, name: str, scenario: dict,
                       api_url: str, dry_run: bool):
    console.print(Panel(
        f"[bold cyan]▶ Scenario: {name.upper().replace('_', ' ')}[/bold cyan]\n"
        f"[dim]{scenario.get('description', '')}[/dim]",
        border_style="cyan",
    ))

    steps = []

    if "logs" in scenario:
        steps.append(("logs", scenario["logs"], "📋 Injecting application logs"))
    if "events" in scenario:
        steps.append(("events", scenario["events"], "⚡ Injecting Kubernetes events"))
    if "app_health" in scenario:
        steps.append(("app_health", scenario["app_health"], "📊 Sending app health reports"))
    if "cluster_health" in scenario:
        steps.append(("cluster_health", scenario["cluster_health"], "🏥 Sending cluster health snapshot"))
    if "security_threats" in scenario:
        steps.append(("security_threats", scenario["security_threats"], "🛡️  Injecting security threats"))

    results = {}

    for data_type, payload, label in steps:
        console.print(f"  {label}...", end=" ")

        if dry_run:
            console.print("[yellow]DRY RUN[/yellow]")
            console.print(f"  [dim]POST {INGEST_ROUTES[data_type]}[/dim]")
            console.print(f"  [dim]{json.dumps(payload if isinstance(payload, dict) else payload[:2], indent=2)[:300]}...[/dim]")
            results[data_type] = "dry_run"
            continue

        url = f"{api_url}{INGEST_ROUTES[data_type]}"
        body = payload if isinstance(payload, list) else [payload]
        if data_type == "cluster_health":
            body = payload  # single object, not wrapped

        try:
            resp = await client.post(url, json=body, timeout=15.0)
            if resp.status_code in (200, 201, 204):
                console.print("[green]✓[/green]")
                results[data_type] = "ok"
            else:
                console.print(f"[red]✗ {resp.status_code}[/red]")
                console.print(f"  [dim red]{resp.text[:200]}[/dim red]")
                results[data_type] = f"error:{resp.status_code}"
        except httpx.ConnectError:
            console.print(f"[red]✗ Connection refused — is the AI engine running at {api_url}?[/red]")
            results[data_type] = "connection_error"
            return results
        except Exception as e:
            console.print(f"[red]✗ {e}[/red]")
            results[data_type] = f"error:{e}"

        await asyncio.sleep(STEP_DELAY)

    # Check what incidents were created
    if not dry_run:
        await asyncio.sleep(2)
        try:
            resp = await client.get(f"{api_url}/api/v1/incidents?limit=5", timeout=5.0)
            if resp.status_code == 200:
                incidents = resp.json()
                if incidents:
                    console.print(f"\n  [bold green]✅ {len(incidents)} incident(s) created:[/bold green]")
                    for inc in incidents[:3]:
                        sev_color = {"critical": "red", "high": "orange1", "medium": "yellow", "low": "blue"}.get(inc["severity"], "white")
                        console.print(
                            f"  • [{sev_color}][{inc['severity'].upper()}][/{sev_color}] "
                            f"[bold]{inc['title']}[/bold]"
                            f"  [dim]id={inc['id']} type={inc.get('incident_type','?')}[/dim]"
                        )
        except Exception:
            pass

    return results


async def check_health(api_url: str) -> bool:
    async with httpx.AsyncClient(timeout=5.0) as client:
        try:
            resp = await client.get(f"{api_url}/health")
            return resp.status_code == 200
        except Exception:
            return False


async def print_alert_channels(api_url: str):
    """Show which alert channels are configured."""
    async with httpx.AsyncClient(timeout=5.0) as client:
        try:
            resp = await client.get(f"{api_url}/api/v1/alerts/channels")
            if resp.status_code == 200:
                channels = resp.json()
                table = Table(title="Configured Alert Channels", border_style="dim")
                table.add_column("Channel", style="cyan")
                table.add_column("Status", style="green")
                for ch in channels:
                    status = "✅ Enabled" if ch.get("enabled") else "⬜ Not configured"
                    table.add_row(ch.get("name", "?"), status)
                console.print(table)
        except Exception:
            pass


async def main():
    parser = argparse.ArgumentParser(description="AI Observability Platform Demo")
    parser.add_argument("--scenario", default="all",
                        choices=list(ALL_SCENARIOS.keys()) + ["all"],
                        help="Which scenario to run (default: all)")
    parser.add_argument("--api", default=DEFAULT_API_URL,
                        help=f"AI engine HTTP URL (default: {DEFAULT_API_URL})")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print payloads without sending")
    args = parser.parse_args()

    console.print(Panel(
        "[bold blue]🤖 AI Observability Platform — Demo Suite[/bold blue]\n"
        "[dim]Simulating realistic incidents to test the full alert pipeline[/dim]",
        border_style="blue",
    ))

    if not args.dry_run:
        console.print(f"[dim]Checking AI engine at {args.api}...[/dim]", end=" ")
        healthy = await check_health(args.api)
        if healthy:
            console.print("[green]✓ Online[/green]")
        else:
            console.print("[red]✗ Not reachable[/red]")
            console.print(f"[red]Start the platform first:[/red] [bold]docker compose up -d[/bold]")
            console.print(f"[dim]Then wait ~20 seconds and retry.[/dim]")
            sys.exit(1)

        await print_alert_channels(args.api)
        console.print()

    scenarios_to_run = (
        list(ALL_SCENARIOS.items())
        if args.scenario == "all"
        else [(args.scenario, ALL_SCENARIOS[args.scenario])]
    )

    summary = []
    async with httpx.AsyncClient(timeout=30.0) as client:
        for i, (name, scenario) in enumerate(scenarios_to_run):
            if i > 0:
                console.print(f"[dim]Waiting {SCENARIO_DELAY}s before next scenario...[/dim]")
                await asyncio.sleep(SCENARIO_DELAY)

            results = await run_scenario(client, name, scenario, args.api, args.dry_run)
            summary.append((name, results))
            console.print()

    # Final summary table
    console.print()
    table = Table(title="Demo Run Summary", border_style="blue")
    table.add_column("Scenario", style="cyan bold")
    table.add_column("Data Types Sent")
    table.add_column("Status")

    for name, results in summary:
        data_types = ", ".join(results.keys())
        all_ok = all(v in ("ok", "dry_run") for v in results.values())
        status = "[green]✅ OK[/green]" if all_ok else "[red]⚠️ Partial[/red]"
        table.add_row(name.replace("_", " ").title(), data_types, status)

    console.print(table)
    console.print()
    console.print("[bold]📌 Dashboard:[/bold] http://localhost:3000")
    console.print("[bold]📌 API docs:[/bold]  http://localhost:8080/docs")
    console.print()
    console.print("[dim]All incidents are visible in the dashboard. "
                  "Check your Slack/email/SMS for alert notifications.[/dim]")


if __name__ == "__main__":
    asyncio.run(main())
