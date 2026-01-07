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


def normalize_asn(asn: str) -> int:
    """Convert ASN string to integer."""
    asn = asn.strip().upper().replace("AS", "")
    return int(asn)


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
        route-sherlock peering-eval --my-asn AS64500 --target AS13335
        route-sherlock peering-eval -m AS64500 -t AS13335 --ix "DE-CIX Frankfurt"
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


@app.command()
def stability(
    asn: str = typer.Argument(..., help="ASN to analyze"),
    days: int = typer.Option(90, "--days", "-d", help="Days of history to analyze"),
):
    """
    Calculate stability score for an ASN.

    Examples:
        route-sherlock stability AS13335
        route-sherlock stability AS13335 --days 30
    """
    from route_sherlock.cli.commands import run_stability
    asyncio.run(run_stability(asn, days))


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
    target: str = typer.Argument(..., help="Target ASN to evaluate (e.g., AS64500)"),
    my_asn: Optional[str] = typer.Option(None, "--my-asn", "-m", help="Your ASN (for IX overlap analysis)"),
    days: int = typer.Option(90, "--days", "-d", help="Days of history to analyze"),
    ai: bool = typer.Option(False, "--ai", help="Use Claude AI for risk assessment"),
):
    """
    Evaluate peering risk for an ASN - should you peer with them?

    Analyzes stability, incident history, network maturity, and security posture
    to generate a risk score and recommendation.

    Examples:
        route-sherlock peer-risk AS64500
        route-sherlock peer-risk AS64500 --my-asn AS13335
        route-sherlock peer-risk AS64500 --days 180 --ai
    """
    from route_sherlock.cli.commands import run_peer_risk
    asyncio.run(run_peer_risk(target, my_asn, days, use_ai=ai))


def main():
    """Entry point for CLI."""
    app()


if __name__ == "__main__":
    main()
