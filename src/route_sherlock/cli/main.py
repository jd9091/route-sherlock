"""
Route Sherlock CLI.

Historical BGP intelligence for network operators.
"""
from __future__ import annotations

import asyncio
import os
from datetime import datetime, timedelta
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box

app = typer.Typer(
    name="route-sherlock",
    help="Historical BGP intelligence for network operators",
    no_args_is_help=True,
)
console = Console()


def get_peeringdb_key() -> str | None:
    """Get PeeringDB API key from environment."""
    return os.environ.get("PEERINGDB_API_KEY")


@app.command()
def lookup(
    resource: str = typer.Argument(..., help="ASN (AS13335) or prefix (1.1.1.0/24)"),
):
    """
    Quick lookup for an ASN or prefix.

    Examples:
        route-sherlock lookup AS13335
        route-sherlock lookup 1.1.1.0/24
    """
    from route_sherlock.cli.commands import run_lookup
    asyncio.run(run_lookup(resource))


@app.command("peering-eval")
def peering_eval(
    my_asn: str = typer.Option(..., "--my-asn", "-m", help="Your ASN"),
    target: str = typer.Option(..., "--target", "-t", help="Target ASN to evaluate"),
    ix: Optional[str] = typer.Option(None, "--ix", "-i", help="Specific IX to evaluate"),
):
    """
    Evaluate peering opportunity with a target ASN.

    Examples:
        route-sherlock peering-eval --my-asn AS6939 --target AS13335
        route-sherlock peering-eval -m AS6939 -t AS13335 --ix "DE-CIX Frankfurt"

    Note: substitute your own ASN for --my-asn. Documentation ASNs
    (AS64496-AS64511, RFC 5398) are not in PeeringDB and will fail.
    """
    from route_sherlock.cli.commands import run_peering_eval
    asyncio.run(run_peering_eval(my_asn, target, ix))


@app.command()
def investigate(
    resource: str = typer.Argument(..., help="ASN or prefix to investigate"),
    time: str = typer.Option(
        None, "--time", "-t",
        help="Start time (ISO format or relative: '2h ago', 'yesterday 14:00')"
    ),
    duration: str = typer.Option(
        "1h", "--duration", "-d",
        help="Duration to analyze (e.g., '1h', '30m', '2d')"
    ),
    ai: bool = typer.Option(
        False, "--ai",
        help="Use Claude AI for natural language synthesis (requires ANTHROPIC_API_KEY)"
    ),
):
    """
    Investigate a routing incident.

    Examples:
        route-sherlock investigate AS16509 --time "2025-01-01 14:00" --duration 2h
        route-sherlock investigate 1.1.1.0/24 --time "2h ago"
        route-sherlock investigate AS13335 --ai  # AI-powered analysis
    """
    from route_sherlock.cli.commands import run_investigate
    asyncio.run(run_investigate(resource, time, duration, use_ai=ai))


@app.command("ix-presence")
def ix_presence(
    asn: str = typer.Argument(..., help="ASN to lookup"),
):
    """
    Show IX presence for an ASN.

    Examples:
        route-sherlock ix-presence AS13335
    """
    from route_sherlock.cli.commands import run_ix_presence
    asyncio.run(run_ix_presence(asn))


@app.command()
def compare(
    asn1: str = typer.Argument(..., help="First ASN"),
    asn2: str = typer.Argument(..., help="Second ASN"),
):
    """
    Compare two ASNs side by side.

    Examples:
        route-sherlock compare AS13335 AS15169
    """
    from route_sherlock.cli.commands import run_compare
    asyncio.run(run_compare(asn1, asn2))


@app.command()
def backtest(
    prefix: str = typer.Argument(..., help="Prefix to investigate (e.g., 1.1.1.0/24)"),
    origin: str = typer.Option(..., "--origin", "-o", help="Expected origin ASN"),
    time: str = typer.Option(..., "--time", "-t", help="Start time (ISO format: 2024-06-27 18:00)"),
    duration: str = typer.Option("3h", "--duration", "-d", help="Duration to analyze"),
    ai: bool = typer.Option(False, "--ai", help="Use Claude AI for analysis"),
):
    """
    Backtest against historical BGP data (requires pybgpstream).

    Uses BGPStream to access RouteViews/RIPE RIS archives for historical analysis.

    Examples:
        route-sherlock backtest 1.1.1.0/24 --origin AS13335 --time "2024-06-27 18:00" --duration 3h
        route-sherlock backtest 8.8.8.0/24 --origin AS15169 --time "2024-01-15 12:00" --ai
    """
    from route_sherlock.cli.commands import run_backtest
    run_backtest(prefix, origin, time, duration, use_ai=ai)


@app.command("peer-risk")
def peer_risk(
    target: str = typer.Argument(..., help="Target ASN to evaluate (e.g., AS13335)"),
    my_asn: Optional[str] = typer.Option(None, "--my-asn", "-m", help="Your ASN (for IX overlap analysis)"),
    days: int = typer.Option(90, "--days", "-d", help="Days of history to analyze"),
    ai: bool = typer.Option(False, "--ai", help="Use Claude AI for risk assessment"),
    offline: bool = typer.Option(
        False, "--offline", "-o",
        help="Serve only from the on-disk cache (~/.cache/route-sherlock). "
             "Useful when wifi is flaky or upstream APIs are unavailable.",
    ),
    json_output: bool = typer.Option(
        False, "--json",
        help="Emit the full risk_data blob as JSON instead of the Rich render. "
             "Pipe into jq or feed into automation.",
    ),
    output: Optional[str] = typer.Option(
        None, "--output",
        help="With --json, write the JSON to this file instead of stdout.",
    ),
    cache_ttl: int = typer.Option(
        86400, "--cache-ttl",
        help="How long to keep cached responses, in seconds. Default 24h. "
             "Set to 0 to bypass the cache; set to a large value (e.g. 604800 = 1 week) "
             "for batch / research runs that should not re-fetch mid-run. "
             "Time-bounded historical queries (BGP updates with explicit start/end) "
             "are always cached indefinitely — they describe frozen history.",
    ),
):
    """
    Evaluate peering risk for an ASN - should you peer with them?

    Analyzes stability, incident history, network maturity, and security posture
    to generate a risk score and recommendation.

    Examples:
        route-sherlock peer-risk AS13335
        route-sherlock peer-risk AS15169 --my-asn AS13335
        route-sherlock peer-risk AS267613 --days 180 --ai
        route-sherlock peer-risk AS13335 --offline
        route-sherlock peer-risk AS13335 --json | jq '.scores'
        route-sherlock peer-risk AS13335 --json --output AS13335.json
        route-sherlock peer-risk AS13335 --cache-ttl 604800   # week-long research run
    """
    from route_sherlock.cli.commands import run_peer_risk
    asyncio.run(run_peer_risk(
        target, my_asn, days,
        use_ai=ai, offline=offline,
        json_output=json_output, output_path=output,
        cache_ttl=cache_ttl,
    ))


@app.command("peer-risk-v2")
def peer_risk_v2(
    target: str = typer.Argument(..., help="Target ASN to evaluate (e.g., AS13335)"),
    history_months: int = typer.Option(
        60, "--history-months",
        help="How far back to scan the documented-incident registry. "
             "Default 60 (5y). For strict operational use, 24 is appropriate.",
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Emit full result as JSON instead of the Rich panel.",
    ),
):
    """
    Evaluate peer-risk with v2 three-pillar scoring.

    Outputs Track Record / Routing Hygiene / Coordination classifications,
    each backed by externally-measurable evidence. Replaces the v1 0–90
    composite. Every finding cites its data source.

    Examples:
        route-sherlock peer-risk-v2 AS13335
        route-sherlock peer-risk-v2 AS262504        # known leak injector
        route-sherlock peer-risk-v2 AS13335 --history-months 24
        route-sherlock peer-risk-v2 AS15169 --json
    """
    import json as _json
    from route_sherlock.analysis.peer_risk_v2 import evaluate_peer_risk_v2
    from route_sherlock.analysis.peer_risk_render import render
    from dataclasses import asdict

    asn_int = int(target.upper().lstrip("AS"))
    result = asyncio.run(evaluate_peer_risk_v2(asn_int, history_months=history_months))

    if json_output:
        # Convert dataclass tree to dict; raw already serialised
        out = asdict(result)
        print(_json.dumps(out, default=str, indent=2))
        return

    render(result, console)


def main():
    """Entry point for CLI."""
    app()


if __name__ == "__main__":
    main()
