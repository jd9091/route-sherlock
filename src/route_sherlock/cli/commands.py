"""
CLI Command Implementations.

Async implementations for all CLI commands with Rich output.
"""
from __future__ import annotations

import asyncio
import os
from datetime import datetime, timedelta
from typing import Any

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.markdown import Markdown
from rich import box

from route_sherlock.collectors.ripestat import RIPEstatClient
from route_sherlock.collectors.peeringdb import PeeringDBClient, PeeringDBNotFoundError
from route_sherlock.collectors.atlas import AtlasClient

console = Console()


def get_peeringdb_key() -> str | None:
    return os.environ.get("PEERINGDB_API_KEY")


def normalize_asn(asn: str) -> int:
    return int(asn.strip().upper().replace("AS", ""))


# ============================================================================
# Lookup Command
# ============================================================================

async def run_lookup(resource: str):
    """Quick lookup for ASN or prefix."""
    resource = resource.strip().upper()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task("Fetching data...", total=None)

        async with RIPEstatClient() as ripestat:
            if resource.replace("AS", "").isdigit():
                # ASN lookup
                asn = resource.replace("AS", "")
                overview = await ripestat.get_as_overview(asn)
                prefixes = await ripestat.get_announced_prefixes(asn)
                neighbours = await ripestat.get_as_neighbours(asn)

                # Panel header
                console.print()
                console.print(Panel(
                    f"[bold cyan]AS{asn}[/] - {overview.holder or 'Unknown'}",
                    box=box.ROUNDED,
                ))

                # Info table
                table = Table(show_header=False, box=box.SIMPLE)
                table.add_column("Field", style="dim")
                table.add_column("Value")

                table.add_row("RIR", overview.rir or "Unknown")
                table.add_row("Announced", "✓ Yes" if overview.announced else "✗ No")
                table.add_row("IPv4 Prefixes", str(len(prefixes.ipv4_prefixes)))
                table.add_row("IPv6 Prefixes", str(len(prefixes.ipv6_prefixes)))
                table.add_row("Upstreams", str(len(neighbours.upstreams)))
                table.add_row("Downstreams", str(len(neighbours.downstreams)))

                if neighbours.upstreams:
                    top_up = ", ".join(f"AS{n.asn}" for n in neighbours.upstreams[:3])
                    table.add_row("Top Upstreams", top_up)

                console.print(table)

                # PeeringDB info if available
                pdb_key = get_peeringdb_key()
                try:
                    async with PeeringDBClient(api_key=pdb_key) as pdb:
                        network = await pdb.get_network_by_asn(int(asn))
                        ixlans = await pdb.get_network_ixlans(int(asn))

                        console.print()
                        console.print("[bold]PeeringDB:[/]")
                        pdb_table = Table(show_header=False, box=box.SIMPLE)
                        pdb_table.add_column("Field", style="dim")
                        pdb_table.add_column("Value")
                        pdb_table.add_row("Type", network.info_type or "Unknown")
                        pdb_table.add_row("Policy", network.policy_general or "Unknown")
                        pdb_table.add_row("IXes", str(len(set(c.ix_id for c in ixlans))))
                        if network.irr_as_set:
                            pdb_table.add_row("IRR as-set", network.irr_as_set)
                        console.print(pdb_table)
                except Exception:
                    pass

            else:
                # Prefix lookup
                lg = await ripestat.get_looking_glass(resource)

                console.print()
                console.print(Panel(
                    f"[bold cyan]{resource}[/]",
                    box=box.ROUNDED,
                ))

                # Collect paths
                paths = {}
                for rrc in lg.rrcs:
                    for peer in rrc.peers:
                        if peer.as_path:
                            origin = peer.as_path.split()[-1] if peer.as_path else "?"
                            paths[peer.as_path] = origin

                origins = set(paths.values())

                table = Table(show_header=False, box=box.SIMPLE)
                table.add_column("Field", style="dim")
                table.add_column("Value")
                table.add_row("RRCs Reporting", str(len(lg.rrcs)))
                table.add_row("Unique Paths", str(len(paths)))
                table.add_row("Origin AS(es)", ", ".join(f"AS{o}" for o in origins))

                if len(origins) > 1:
                    table.add_row("⚠️ MOAS", "[yellow]Multiple origins detected[/]")

                console.print(table)

                console.print()
                console.print("[bold]Sample AS Paths:[/]")
                for path in list(paths.keys())[:5]:
                    console.print(f"  {path}")


# ============================================================================
# Peering Eval Command
# ============================================================================

async def run_peering_eval(my_asn: str, target_asn: str, ix: str | None):
    """Evaluate peering opportunity."""
    my_asn_int = normalize_asn(my_asn)
    target_asn_int = normalize_asn(target_asn)
    pdb_key = get_peeringdb_key()

    console.print()
    console.print(Panel(
        f"[bold]🔍 Peering Evaluation: AS{my_asn_int} → AS{target_asn_int}[/]",
        box=box.DOUBLE,
    ))

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Collecting data...", total=None)

        async with RIPEstatClient() as ripestat, \
                   PeeringDBClient(api_key=pdb_key) as pdb:

            # Get network info
            progress.update(task, description="Fetching network info...")

            try:
                target_net = await pdb.get_network_by_asn(target_asn_int)
                target_name = target_net.name
                target_policy = target_net.policy_general
            except PeeringDBNotFoundError:
                console.print("[red]Error: Target ASN not found in PeeringDB[/]")
                return

            try:
                my_net = await pdb.get_network_by_asn(my_asn_int)
                my_name = my_net.name
            except PeeringDBNotFoundError:
                my_name = f"AS{my_asn_int}"

            # Current paths
            progress.update(task, description="Analyzing current paths...")
            try:
                neighbours = await ripestat.get_as_neighbours(str(target_asn_int))
                lg = await ripestat.get_looking_glass(str(target_asn_int))
            except Exception:
                neighbours = None
                lg = None

            # IX presence
            progress.update(task, description="Checking IX presence...")
            my_ixlans = await pdb.get_network_ixlans(my_asn_int)
            target_ixlans = await pdb.get_network_ixlans(target_asn_int)

            my_ix_ids = set(c.ix_id for c in my_ixlans)
            target_ix_ids = set(c.ix_id for c in target_ixlans)
            common_ix_ids = my_ix_ids & target_ix_ids

            # Get prefix count
            progress.update(task, description="Counting prefixes...")
            try:
                prefixes = await ripestat.get_announced_prefixes(str(target_asn_int))
                prefix_count = prefixes.prefix_count
            except Exception:
                prefix_count = target_net.info_prefixes4 or 0

    # Output results
    console.print()
    console.print(f"[bold]Target: AS{target_asn_int} ({target_name})[/]")
    console.print()

    # Target info table
    console.print("[bold cyan]## Target Network Profile[/]")
    table = Table(box=box.SIMPLE)
    table.add_column("Attribute", style="dim")
    table.add_column("Value")
    table.add_row("Name", target_name)
    table.add_row("Peering Policy", target_policy or "Unknown")
    table.add_row("Type", target_net.info_type or "Unknown")
    table.add_row("Prefixes (v4/v6)", f"{target_net.info_prefixes4 or 0:,} / {target_net.info_prefixes6 or 0:,}")
    table.add_row("IXes Present", str(len(target_ix_ids)))
    if target_net.policy_url:
        table.add_row("Policy URL", target_net.policy_url)
    console.print(table)

    # IX presence comparison
    console.print()
    console.print("[bold cyan]## IX Presence Analysis[/]")

    ix_table = Table(box=box.ROUNDED)
    ix_table.add_column("IX", style="bold")
    ix_table.add_column("Location")
    ix_table.add_column("You", justify="center")
    ix_table.add_column("Target", justify="center")
    ix_table.add_column("Status")

    # Get details for common and target-only IXes
    shown_ixes = 0
    for ix_id in list(common_ix_ids)[:10]:
        try:
            ix_info = await get_ix_info(pdb, ix_id)
            my_speed = next((c.speed_gbps for c in my_ixlans if c.ix_id == ix_id), 0)
            target_speed = next((c.speed_gbps for c in target_ixlans if c.ix_id == ix_id), 0)
            ix_table.add_row(
                ix_info["name"],
                f"{ix_info['city']}, {ix_info['country']}",
                f"[green]✓ {my_speed:.0f}G[/]",
                f"[green]✓ {target_speed:.0f}G[/]",
                "[bold green]PEER HERE[/]"
            )
            shown_ixes += 1
        except Exception:
            pass

    # Show a few target-only IXes
    target_only = target_ix_ids - my_ix_ids
    for ix_id in list(target_only)[:5]:
        try:
            ix_info = await get_ix_info(pdb, ix_id)
            target_speed = next((c.speed_gbps for c in target_ixlans if c.ix_id == ix_id), 0)
            ix_table.add_row(
                ix_info["name"],
                f"{ix_info['city']}, {ix_info['country']}",
                "[red]✗[/]",
                f"[green]✓ {target_speed:.0f}G[/]",
                "[yellow]Join IX[/]"
            )
            shown_ixes += 1
        except Exception:
            pass

    if shown_ixes > 0:
        console.print(ix_table)

    console.print()
    console.print(f"[dim]Common IXes: {len(common_ix_ids)} | Target-only IXes: {len(target_only)}[/]")

    # Estimated impact
    console.print()
    console.print("[bold cyan]## Estimated Impact[/]")

    impact_table = Table(box=box.SIMPLE)
    impact_table.add_column("Metric", style="dim")
    impact_table.add_column("Current")
    impact_table.add_column("After Peering")

    impact_table.add_row("AS-path length", "2+ hops (via transit)", "[green]1 hop (direct)[/]")
    impact_table.add_row("Transit dependency", "Yes", "[green]No (direct)[/]")
    impact_table.add_row("Prefixes received", "0 (via transit)", f"[green]~{prefix_count:,}[/]")
    console.print(impact_table)

    # Recommendation
    console.print()
    if common_ix_ids and target_policy and target_policy.lower() == "open":
        console.print(Panel(
            f"[bold green]✅ RECOMMENDED: Peer with AS{target_asn_int} at common IXes[/]\n\n"
            f"Reasons:\n"
            f"  1. You share [bold]{len(common_ix_ids)}[/] IXes (no new membership needed)\n"
            f"  2. {target_name} has [bold]Open[/] peering policy\n"
            f"  3. Direct path reduces latency and transit costs\n\n"
            f"Next steps:\n"
            f"  1. Contact: {target_net.policy_url or 'Check PeeringDB'}\n"
            f"  2. Configure BGP session at your common IX router",
            title="Recommendation",
            box=box.DOUBLE,
        ))
    elif common_ix_ids:
        console.print(Panel(
            f"[bold yellow]⚠️ POSSIBLE: Peer with AS{target_asn_int}[/]\n\n"
            f"You share [bold]{len(common_ix_ids)}[/] IXes, but their policy is [bold]{target_policy}[/].\n"
            f"Contact them to discuss peering requirements.",
            title="Recommendation",
            box=box.DOUBLE,
        ))
    else:
        console.print(Panel(
            f"[bold red]❌ NO COMMON IXes[/]\n\n"
            f"You don't share any IXes with AS{target_asn_int}.\n"
            f"Consider joining one of their {len(target_ix_ids)} IXes.",
            title="Recommendation",
            box=box.DOUBLE,
        ))

    console.print()
    console.print(f"[dim]Data sources: RIPEstat, PeeringDB | {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}[/]")


async def get_ix_info(pdb: PeeringDBClient, ix_id: int) -> dict:
    """Get IX info with caching."""
    ix = await pdb.get_ix(ix_id)
    return {
        "name": ix.name,
        "city": ix.city,
        "country": ix.country,
    }


# ============================================================================
# Investigate Command
# ============================================================================

async def run_investigate(resource: str, time_str: str | None, duration: str, use_ai: bool = False):
    """Investigate routing incident."""
    resource = resource.strip().upper()

    # Parse time
    if time_str:
        # TODO: Better time parsing
        try:
            start_time = datetime.fromisoformat(time_str.replace(" ", "T"))
        except ValueError:
            if "ago" in time_str.lower():
                hours = int(time_str.split()[0].replace("h", ""))
                start_time = datetime.utcnow() - timedelta(hours=hours)
            else:
                start_time = datetime.utcnow() - timedelta(hours=24)
    else:
        start_time = datetime.utcnow() - timedelta(hours=24)

    # Parse duration
    if "h" in duration:
        hours = int(duration.replace("h", ""))
        end_time = start_time + timedelta(hours=hours)
    elif "d" in duration:
        days = int(duration.replace("d", ""))
        end_time = start_time + timedelta(days=days)
    else:
        end_time = start_time + timedelta(hours=1)

    console.print()
    console.print(Panel(
        f"[bold]🔍 Investigating {resource}[/]\n"
        f"[dim]Timeframe: {start_time.strftime('%Y-%m-%d %H:%M')} to {end_time.strftime('%Y-%m-%d %H:%M')} UTC[/]",
        box=box.DOUBLE,
    ))

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Collecting data...", total=None)

        async with RIPEstatClient() as ripestat:
            # Get BGP updates
            progress.update(task, description="Fetching BGP updates...")
            try:
                updates = await ripestat.get_bgp_updates(
                    resource,
                    start_time=start_time,
                    end_time=end_time,
                )
                update_count = len(updates.updates)
            except Exception:
                update_count = 0
                updates = None

            # Get routing history
            progress.update(task, description="Fetching routing history...")
            try:
                history = await ripestat.get_routing_history(
                    resource,
                    start_time=start_time,
                    end_time=end_time,
                )
            except Exception:
                history = None

            # Current state
            progress.update(task, description="Fetching current state...")
            if resource.replace("AS", "").isdigit():
                overview = await ripestat.get_as_overview(resource.replace("AS", ""))
                name = overview.holder or resource
            else:
                name = resource

    # Build timeline
    console.print()
    console.print("[bold cyan]## Data Collection[/]")

    table = Table(box=box.SIMPLE)
    table.add_column("Source", style="dim")
    table.add_column("Records")
    table.add_row("BGP Updates", str(update_count))
    table.add_row("Routing History", "✓" if history else "✗")
    console.print(table)

    # Analyze updates
    if updates and updates.updates:
        console.print()
        console.print("[bold cyan]## BGP Activity[/]")

        announcements = sum(1 for u in updates.updates if u.type == "A")
        withdrawals = sum(1 for u in updates.updates if u.type == "W")

        activity_table = Table(box=box.SIMPLE)
        activity_table.add_column("Type", style="dim")
        activity_table.add_column("Count")
        activity_table.add_row("Announcements", f"[green]{announcements}[/]")
        activity_table.add_row("Withdrawals", f"[red]{withdrawals}[/]")
        activity_table.add_row("Total Updates", str(update_count))
        console.print(activity_table)

        # Stability assessment
        console.print()
        if update_count < 10:
            console.print("[green]✓ Stable[/] - Very few BGP updates in this period")
        elif update_count < 50:
            console.print("[yellow]⚠ Moderate activity[/] - Some routing changes detected")
        else:
            console.print("[red]⚠ High activity[/] - Significant routing instability")

        # Show recent events
        if updates.updates:
            console.print()
            console.print("[bold cyan]## Recent Events (last 10)[/]")

            events_table = Table(box=box.SIMPLE)
            events_table.add_column("Time", style="dim")
            events_table.add_column("Type")
            events_table.add_column("Details")

            for update in updates.updates[-10:]:
                event_type = "[green]A[/]" if update.type == "A" else "[red]W[/]"
                path = " → ".join(str(a) for a in update.path[:5]) if update.path else "-"
                events_table.add_row(
                    update.timestamp[:19] if update.timestamp else "-",
                    event_type,
                    path[:50],
                )

            console.print(events_table)
    else:
        console.print()
        console.print("[green]✓ No BGP updates[/] - Routing was stable during this period")

    # AI Synthesis
    if use_ai:
        console.print()
        console.print("[bold cyan]## AI Analysis[/]")

        try:
            from route_sherlock.synthesis.engine import IncidentSynthesizer

            synth = IncidentSynthesizer()

            # Prepare data for synthesis
            update_data = []
            if updates and updates.updates:
                for u in updates.updates[:20]:
                    update_data.append({
                        "timestamp": u.timestamp,
                        "type": u.type,
                        "path": u.path,
                    })

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
                transient=True,
            ) as progress:
                progress.add_task("Generating AI analysis...", total=None)

                report = await synth.synthesize_from_raw(
                    asn=resource,
                    updates=update_data,
                    history=None,
                    start_time=start_time,
                    end_time=end_time,
                )

            console.print(Panel(
                Markdown(report),
                title="AI-Generated Incident Report",
                box=box.ROUNDED,
            ))
        except ImportError:
            console.print("[yellow]AI synthesis requires: pip install 'route-sherlock[ai]'[/]")
        except Exception as e:
            console.print(f"[yellow]AI synthesis unavailable: {e}[/]")

    console.print()
    console.print(f"[dim]Data source: RIPEstat | Analysis: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}[/]")


# ============================================================================
# Stability Command
# ============================================================================

async def run_stability(asn: str, days: int):
    """Calculate stability score for an ASN."""
    asn_int = normalize_asn(asn)

    console.print()
    console.print(f"[bold]📊 Stability Analysis: AS{asn_int}[/]")
    console.print(f"[dim]Period: Last {days} days[/]")
    console.print()

    end_time = datetime.utcnow()
    start_time = end_time - timedelta(days=days)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Analyzing...", total=None)

        async with RIPEstatClient() as ripestat:
            progress.update(task, description="Fetching BGP updates...")
            try:
                updates = await ripestat.get_bgp_updates(
                    str(asn_int),
                    start_time=start_time,
                    end_time=end_time,
                )
                update_count = len(updates.updates)
            except Exception:
                update_count = 0

            progress.update(task, description="Fetching prefix info...")
            try:
                prefixes = await ripestat.get_announced_prefixes(str(asn_int))
                prefix_count = prefixes.prefix_count
            except Exception:
                prefix_count = 0

    # Calculate score
    score = 100
    factors = {}

    # Updates per day
    updates_per_day = update_count / max(days, 1)
    if updates_per_day > 100:
        penalty = min(30, int(updates_per_day / 10))
        score -= penalty
        factors["High update rate"] = f"-{penalty}"
    elif updates_per_day > 10:
        penalty = min(15, int(updates_per_day / 2))
        score -= penalty
        factors["Moderate update rate"] = f"-{penalty}"

    score = max(0, min(100, score))

    # Output
    if score >= 90:
        score_color = "green"
        assessment = "Excellent"
    elif score >= 70:
        score_color = "yellow"
        assessment = "Good"
    elif score >= 50:
        score_color = "orange1"
        assessment = "Fair"
    else:
        score_color = "red"
        assessment = "Poor"

    console.print(Panel(
        f"[bold {score_color}]{score}/100[/]\n[dim]{assessment}[/]",
        title="Stability Score",
        box=box.DOUBLE,
    ))

    table = Table(box=box.SIMPLE)
    table.add_column("Metric", style="dim")
    table.add_column("Value")
    table.add_row("BGP Updates", f"{update_count:,}")
    table.add_row("Updates/Day", f"{updates_per_day:.1f}")
    table.add_row("Prefixes", f"{prefix_count:,}")
    console.print(table)

    if factors:
        console.print()
        console.print("[bold]Score Factors:[/]")
        for factor, impact in factors.items():
            console.print(f"  • {factor}: {impact}")


# ============================================================================
# IX Presence Command
# ============================================================================

async def run_ix_presence(asn: str):
    """Show IX presence for an ASN."""
    asn_int = normalize_asn(asn)
    pdb_key = get_peeringdb_key()

    console.print()
    console.print(f"[bold]🌐 IX Presence: AS{asn_int}[/]")
    console.print()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Fetching data...", total=None)

        async with PeeringDBClient(api_key=pdb_key) as pdb:
            try:
                network = await pdb.get_network_by_asn(asn_int)
                name = network.name
            except PeeringDBNotFoundError:
                console.print("[red]ASN not found in PeeringDB[/]")
                return

            ixlans = await pdb.get_network_ixlans(asn_int)

            # Group by IX
            ix_map: dict[int, list] = {}
            for conn in ixlans:
                ix_map.setdefault(conn.ix_id, []).append(conn)

            # Get IX details
            progress.update(task, description="Fetching IX details...")
            ix_details = []
            for ix_id, conns in list(ix_map.items())[:30]:
                try:
                    ix = await pdb.get_ix(ix_id)
                    total_speed = sum(c.speed for c in conns)
                    ix_details.append({
                        "name": ix.name,
                        "city": ix.city,
                        "country": ix.country,
                        "speed": total_speed / 1000,  # Gbps
                        "ports": len(conns),
                    })
                except Exception:
                    pass

    console.print(f"[bold]{name}[/] is present at [bold]{len(ix_map)}[/] IXes")
    console.print()

    # Sort by speed
    ix_details.sort(key=lambda x: x["speed"], reverse=True)

    table = Table(box=box.ROUNDED)
    table.add_column("Internet Exchange", style="bold")
    table.add_column("Location")
    table.add_column("Speed", justify="right")
    table.add_column("Ports", justify="center")

    for ix in ix_details[:20]:
        table.add_row(
            ix["name"],
            f"{ix['city']}, {ix['country']}",
            f"{ix['speed']:.0f}G",
            str(ix["ports"]),
        )

    console.print(table)

    if len(ix_details) > 20:
        console.print(f"[dim]... and {len(ix_details) - 20} more IXes[/]")


# ============================================================================
# Compare Command
# ============================================================================

async def run_compare(asn1: str, asn2: str):
    """Compare two ASNs."""
    asn1_int = normalize_asn(asn1)
    asn2_int = normalize_asn(asn2)
    pdb_key = get_peeringdb_key()

    console.print()
    console.print(Panel(
        f"[bold]AS{asn1_int} vs AS{asn2_int}[/]",
        box=box.DOUBLE,
    ))

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Fetching data...", total=None)

        async with RIPEstatClient() as ripestat, \
                   PeeringDBClient(api_key=pdb_key) as pdb:

            # Fetch data for both
            progress.update(task, description=f"Fetching AS{asn1_int}...")
            o1 = await ripestat.get_as_overview(str(asn1_int))
            p1 = await ripestat.get_announced_prefixes(str(asn1_int))
            n1 = await ripestat.get_as_neighbours(str(asn1_int))

            progress.update(task, description=f"Fetching AS{asn2_int}...")
            o2 = await ripestat.get_as_overview(str(asn2_int))
            p2 = await ripestat.get_announced_prefixes(str(asn2_int))
            n2 = await ripestat.get_as_neighbours(str(asn2_int))

            # PeeringDB
            try:
                net1 = await pdb.get_network_by_asn(asn1_int)
                ix1 = await pdb.get_network_ixlans(asn1_int)
                ix1_count = len(set(c.ix_id for c in ix1))
                policy1 = net1.policy_general
            except Exception:
                ix1_count = 0
                policy1 = "?"

            try:
                net2 = await pdb.get_network_by_asn(asn2_int)
                ix2 = await pdb.get_network_ixlans(asn2_int)
                ix2_count = len(set(c.ix_id for c in ix2))
                policy2 = net2.policy_general
            except Exception:
                ix2_count = 0
                policy2 = "?"

    # Comparison table
    table = Table(box=box.ROUNDED)
    table.add_column("Metric", style="bold")
    table.add_column(f"AS{asn1_int}", justify="right")
    table.add_column(f"AS{asn2_int}", justify="right")
    table.add_column("Winner", justify="center")

    def winner(v1, v2, higher_better=True):
        if v1 == v2:
            return "[dim]Tie[/]"
        if higher_better:
            return f"[green]AS{asn1_int}[/]" if v1 > v2 else f"[green]AS{asn2_int}[/]"
        return f"[green]AS{asn1_int}[/]" if v1 < v2 else f"[green]AS{asn2_int}[/]"

    table.add_row("Name", o1.holder or "?", o2.holder or "?", "")
    table.add_row(
        "IPv4 Prefixes",
        f"{len(p1.ipv4_prefixes):,}",
        f"{len(p2.ipv4_prefixes):,}",
        winner(len(p1.ipv4_prefixes), len(p2.ipv4_prefixes))
    )
    table.add_row(
        "IPv6 Prefixes",
        f"{len(p1.ipv6_prefixes):,}",
        f"{len(p2.ipv6_prefixes):,}",
        winner(len(p1.ipv6_prefixes), len(p2.ipv6_prefixes))
    )
    table.add_row(
        "Upstreams",
        str(len(n1.upstreams)),
        str(len(n2.upstreams)),
        winner(len(n1.upstreams), len(n2.upstreams))
    )
    table.add_row(
        "IXes",
        str(ix1_count),
        str(ix2_count),
        winner(ix1_count, ix2_count)
    )
    table.add_row("Peering Policy", policy1, policy2, "")

    console.print()
    console.print(table)


# ============================================================================
# Backtest Command
# ============================================================================

def run_backtest(prefix: str, origin: str, time_str: str, duration: str, use_ai: bool = False):
    """Backtest against historical BGP data using BGPStream."""
    from datetime import datetime, timedelta

    # Parse origin ASN
    origin_asn = normalize_asn(origin)

    # Parse time
    try:
        start_time = datetime.fromisoformat(time_str.replace(" ", "T"))
    except ValueError:
        console.print(f"[red]Invalid time format: {time_str}[/]")
        console.print("[dim]Use ISO format: 2024-06-27 18:00[/]")
        return

    # Parse duration
    if "h" in duration:
        hours = int(duration.replace("h", ""))
        end_time = start_time + timedelta(hours=hours)
    elif "d" in duration:
        days = int(duration.replace("d", ""))
        end_time = start_time + timedelta(days=days)
    else:
        end_time = start_time + timedelta(hours=3)

    console.print()
    console.print(Panel(
        f"[bold]🔬 Historical Backtest[/]\n"
        f"[dim]Prefix: {prefix} | Expected Origin: AS{origin_asn}[/]\n"
        f"[dim]Time: {start_time.strftime('%Y-%m-%d %H:%M')} to {end_time.strftime('%H:%M')} UTC[/]",
        box=box.DOUBLE,
    ))

    try:
        from route_sherlock.collectors.bgpstream import BGPStreamClient
    except ImportError:
        console.print("[red]BGPStream not available.[/]")
        console.print("[dim]Install with: brew install bgpstream && pip install pybgpstream[/]")
        return

    console.print()
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=False,
    ) as progress:
        task = progress.add_task("Connecting to BGP collectors...", total=None)

        client = BGPStreamClient()

        progress.update(task, description="Fetching historical BGP data (this may take a while)...")

        try:
            report = client.investigate_incident(
                prefix=prefix,
                expected_origin=origin_asn,
                start_time=start_time,
                end_time=end_time,
            )
        except Exception as e:
            progress.stop()
            console.print(f"[red]Error fetching data: {e}[/]")
            return

        progress.update(task, description="Analysis complete!")

    # Display results
    console.print()
    console.print("[bold cyan]## Data Collection[/]")
    table = Table(box=box.SIMPLE)
    table.add_column("Metric", style="dim")
    table.add_column("Value")
    table.add_row("Total Events", f"{report['total_events']:,}")
    table.add_row("Announcements", f"{report['announcements']:,}")
    table.add_row("Withdrawals", f"{report['withdrawals']:,}")
    table.add_row("Collectors", ", ".join(report['collectors_queried'][:3]) + "...")
    console.print(table)

    # Anomalies
    anomalies = report["anomalies"]
    console.print()
    if anomalies:
        console.print(f"[bold red]## 🚨 Anomalies Detected: {len(anomalies)}[/]")
        console.print()

        for i, a in enumerate(anomalies[:10], 1):
            severity_color = {
                "critical": "red",
                "high": "yellow",
                "medium": "blue",
                "low": "dim",
            }.get(a["severity"], "white")

            console.print(f"[{severity_color}]#{i} [{a['severity'].upper()}] {a['type'].upper()}[/]")
            console.print(f"   Time: {a['time']}")
            console.print(f"   Prefix: {a['prefix']}")
            console.print(f"   {a['description']}")
            if "as_path" in a["evidence"]:
                console.print(f"   AS Path: {' → '.join(str(x) for x in a['evidence']['as_path'])}")
            console.print()

        if len(anomalies) > 10:
            console.print(f"[dim]... and {len(anomalies) - 10} more anomalies[/]")
    else:
        console.print("[green]## ✓ No Anomalies Detected[/]")
        console.print("[dim]Routing appeared normal during this period.[/]")

    # Involved ASes
    if report["involved_ases"]:
        console.print()
        console.print("[bold]## Involved ASes (suspicious)[/]")
        console.print(f"   {', '.join(f'AS{asn}' for asn in report['involved_ases'][:10])}")

    # Timeline summary
    if report["first_anomaly"]:
        console.print()
        console.print("[bold]## Timeline[/]")
        console.print(f"   First anomaly: {report['first_anomaly']}")

    # AI Analysis
    if use_ai and anomalies:
        console.print()
        console.print("[bold cyan]## AI Analysis[/]")
        try:
            import os
            from route_sherlock.synthesis.engine import Synthesizer

            if not os.environ.get("ANTHROPIC_API_KEY"):
                console.print("[yellow]Set ANTHROPIC_API_KEY for AI analysis[/]")
            else:
                import asyncio
                synth = Synthesizer()

                async def get_analysis():
                    return await synth.synthesize_incident(report)

                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    console=console,
                    transient=True,
                ) as progress:
                    progress.add_task("Generating AI analysis...", total=None)
                    analysis = asyncio.run(get_analysis())

                console.print(Panel(
                    Markdown(analysis),
                    title="AI-Generated Incident Report",
                    box=box.ROUNDED,
                ))
        except Exception as e:
            console.print(f"[yellow]AI analysis unavailable: {e}[/]")

    console.print()
    console.print(f"[dim]Data source: BGPStream (RouteViews/RIPE RIS) | Analysis: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}[/]")


# ============================================================================
# Peer Risk Command
# ============================================================================

async def run_peer_risk(target_asn: str, my_asn: str | None, days: int, use_ai: bool = False):
    """
    Evaluate peering risk for an ASN.

    Generates a risk score based on:
    - Stability (BGP update frequency)
    - Incident history (involvement in leaks/hijacks)
    - Network maturity (PeeringDB completeness, IX presence)
    - Policy compatibility
    - Security posture (RPKI coverage)
    """
    target_asn_int = normalize_asn(target_asn)
    my_asn_int = normalize_asn(my_asn) if my_asn else None
    pdb_key = get_peeringdb_key()

    console.print()
    console.print(Panel(
        f"[bold]🔒 Peer Risk Assessment: AS{target_asn_int}[/]",
        box=box.DOUBLE,
    ))

    # Data collection
    risk_data = {
        "target_asn": target_asn_int,
        "my_asn": my_asn_int,
        "analysis_period_days": days,
        "scores": {},
        "factors": {},
        "warnings": [],
        "recommendations": [],
    }

    end_time = datetime.utcnow()
    start_time = end_time - timedelta(days=days)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Collecting data...", total=None)

        # ============================================================
        # 1. BASIC INFO & NETWORK MATURITY (0-20 points)
        # ============================================================
        progress.update(task, description="Fetching network info...")

        maturity_score = 0
        maturity_factors = []

        try:
            async with PeeringDBClient(api_key=pdb_key) as pdb:
                try:
                    network = await pdb.get_network_by_asn(target_asn_int)
                    risk_data["network"] = {
                        "name": network.name,
                        "type": network.info_type,
                        "policy": network.policy_general,
                        "prefixes_v4": network.info_prefixes4,
                        "prefixes_v6": network.info_prefixes6,
                    }

                    # PeeringDB presence = good sign
                    maturity_score += 5
                    maturity_factors.append("PeeringDB registered (+5)")

                    # Has IRR as-set
                    if network.irr_as_set:
                        maturity_score += 5
                        maturity_factors.append(f"IRR as-set: {network.irr_as_set} (+5)")
                        risk_data["network"]["irr_as_set"] = network.irr_as_set
                    else:
                        risk_data["warnings"].append("No IRR as-set registered")

                    # Has policy URL
                    if network.policy_url:
                        maturity_score += 3
                        maturity_factors.append("Published peering policy (+3)")
                        risk_data["network"]["policy_url"] = network.policy_url

                    # IX presence
                    ixlans = await pdb.get_network_ixlans(target_asn_int)
                    ix_count = len(set(c.ix_id for c in ixlans))
                    risk_data["network"]["ix_count"] = ix_count

                    if ix_count >= 10:
                        maturity_score += 7
                        maturity_factors.append(f"Strong IX presence: {ix_count} IXes (+7)")
                    elif ix_count >= 5:
                        maturity_score += 5
                        maturity_factors.append(f"Good IX presence: {ix_count} IXes (+5)")
                    elif ix_count >= 1:
                        maturity_score += 2
                        maturity_factors.append(f"Limited IX presence: {ix_count} IXes (+2)")
                    else:
                        risk_data["warnings"].append("No IX presence - may indicate limited reach")

                    # If we have our ASN, check IX overlap
                    if my_asn_int:
                        my_ixlans = await pdb.get_network_ixlans(my_asn_int)
                        my_ix_ids = set(c.ix_id for c in my_ixlans)
                        target_ix_ids = set(c.ix_id for c in ixlans)
                        common_ix_ids = my_ix_ids & target_ix_ids
                        risk_data["ix_overlap"] = {
                            "common_count": len(common_ix_ids),
                            "your_ix_count": len(my_ix_ids),
                            "target_ix_count": len(target_ix_ids),
                        }

                except PeeringDBNotFoundError:
                    risk_data["warnings"].append("Not in PeeringDB - cannot verify network details")
                    risk_data["network"] = {"name": f"AS{target_asn_int}", "peeringdb": False}
        except Exception as e:
            risk_data["warnings"].append(f"PeeringDB lookup failed: {e}")
            risk_data["network"] = {"name": f"AS{target_asn_int}"}

        risk_data["scores"]["maturity"] = {"score": maturity_score, "max": 20, "factors": maturity_factors}

        # ============================================================
        # 2. STABILITY SCORE (0-30 points)
        # ============================================================
        progress.update(task, description="Analyzing routing stability...")

        stability_score = 30  # Start high, deduct for instability
        stability_factors = []

        async with RIPEstatClient() as ripestat:
            try:
                # Get BGP updates
                updates = await ripestat.get_bgp_updates(
                    str(target_asn_int),
                    start_time=start_time,
                    end_time=end_time,
                )
                update_count = len(updates.updates)
                updates_per_day = update_count / max(days, 1)

                risk_data["stability"] = {
                    "total_updates": update_count,
                    "updates_per_day": round(updates_per_day, 1),
                    "period_days": days,
                }

                # Score based on update frequency
                if updates_per_day > 100:
                    penalty = min(25, int(updates_per_day / 20))
                    stability_score -= penalty
                    stability_factors.append(f"High churn: {updates_per_day:.0f} updates/day (-{penalty})")
                    risk_data["warnings"].append(f"High BGP churn detected: {updates_per_day:.0f} updates/day")
                elif updates_per_day > 50:
                    penalty = min(15, int(updates_per_day / 10))
                    stability_score -= penalty
                    stability_factors.append(f"Moderate churn: {updates_per_day:.0f} updates/day (-{penalty})")
                elif updates_per_day > 10:
                    penalty = min(5, int(updates_per_day / 5))
                    stability_score -= penalty
                    stability_factors.append(f"Some activity: {updates_per_day:.0f} updates/day (-{penalty})")
                else:
                    stability_factors.append(f"Stable routing: {updates_per_day:.1f} updates/day (+0)")

                # Check for prefix count
                prefixes = await ripestat.get_announced_prefixes(str(target_asn_int))
                risk_data["stability"]["prefix_count"] = prefixes.prefix_count

            except Exception as e:
                stability_factors.append(f"Could not fetch stability data: {e}")
                risk_data["stability"] = {"error": str(e)}

        stability_score = max(0, stability_score)
        risk_data["scores"]["stability"] = {"score": stability_score, "max": 30, "factors": stability_factors}

        # ============================================================
        # 3. INCIDENT HISTORY (0-30 points)
        # ============================================================
        progress.update(task, description="Checking incident history...")

        incident_score = 30  # Start high, deduct for incidents
        incident_factors = []

        # Check RIPEstat for routing history anomalies
        async with RIPEstatClient() as ripestat:
            try:
                # Get AS overview for basic info
                overview = await ripestat.get_as_overview(str(target_asn_int))
                if overview.holder:
                    risk_data["network"]["name"] = overview.holder

                # Get neighbour info to check for unusual patterns
                neighbours = await ripestat.get_as_neighbours(str(target_asn_int))

                upstream_count = len(neighbours.upstreams)
                downstream_count = len(neighbours.downstreams)

                risk_data["topology"] = {
                    "upstreams": upstream_count,
                    "downstreams": downstream_count,
                    "top_upstreams": [{"asn": n.asn, "power": n.power} for n in neighbours.upstreams[:5]],
                }

                # Single upstream is a risk factor
                if upstream_count == 1:
                    incident_score -= 5
                    incident_factors.append("Single upstream - limited redundancy (-5)")
                    risk_data["warnings"].append("Single upstream provider - potential single point of failure")
                elif upstream_count >= 3:
                    incident_factors.append(f"Multiple upstreams ({upstream_count}) - good redundancy (+0)")

                # Large downstream count might indicate transit provider
                if downstream_count > 100:
                    incident_factors.append(f"Major transit provider ({downstream_count} downstreams)")
                    risk_data["network"]["type_inferred"] = "transit"

            except Exception as e:
                incident_factors.append(f"Could not verify topology: {e}")

        # Check RPKI/ROA status
        progress.update(task, description="Checking RPKI status...")
        async with RIPEstatClient() as ripestat:
            try:
                prefixes = await ripestat.get_announced_prefixes(str(target_asn_int))

                # We can't easily check ROA coverage via RIPEstat in this version,
                # but we note the prefix count for reference
                prefix_count = prefixes.prefix_count
                risk_data["rpki"] = {
                    "prefixes_announced": prefix_count,
                    "note": "RPKI validation requires additional data sources",
                }

                # For now, give partial credit if they have reasonable prefix count
                if prefix_count > 0:
                    incident_factors.append(f"Announcing {prefix_count} prefixes")

            except Exception:
                pass

        incident_score = max(0, incident_score)
        risk_data["scores"]["incident_history"] = {"score": incident_score, "max": 30, "factors": incident_factors}

        # ============================================================
        # 4. POLICY COMPATIBILITY (0-10 points)
        # ============================================================
        policy_score = 0
        policy_factors = []

        policy = risk_data.get("network", {}).get("policy", "Unknown")
        if policy:
            policy_lower = policy.lower() if policy else ""
            if policy_lower == "open":
                policy_score = 10
                policy_factors.append("Open peering policy (+10)")
            elif policy_lower == "selective":
                policy_score = 7
                policy_factors.append("Selective peering policy (+7)")
            elif policy_lower == "restrictive":
                policy_score = 3
                policy_factors.append("Restrictive peering policy (+3)")
                risk_data["warnings"].append("Restrictive peering policy may make establishing session difficult")
            else:
                policy_score = 5
                policy_factors.append(f"Policy: {policy} (+5)")
        else:
            policy_factors.append("No policy information available (+0)")

        risk_data["scores"]["policy"] = {"score": policy_score, "max": 10, "factors": policy_factors}

        # ============================================================
        # 5. SECURITY POSTURE (0-10 points)
        # ============================================================
        security_score = 5  # Base score
        security_factors = []

        # IRR registration contributes to security
        if risk_data.get("network", {}).get("irr_as_set"):
            security_score += 3
            security_factors.append("IRR registered (+3)")

        # Multiple upstreams suggest better filtering
        if risk_data.get("topology", {}).get("upstreams", 0) >= 2:
            security_score += 2
            security_factors.append("Multiple transit relationships (+2)")

        security_score = min(10, security_score)
        risk_data["scores"]["security"] = {"score": security_score, "max": 10, "factors": security_factors}

    # ============================================================
    # CALCULATE TOTAL SCORE
    # ============================================================
    total_score = sum(s["score"] for s in risk_data["scores"].values())
    max_score = sum(s["max"] for s in risk_data["scores"].values())

    risk_data["total_score"] = total_score
    risk_data["max_score"] = max_score
    risk_data["percentage"] = round(total_score / max_score * 100, 1)

    # Determine risk level
    if total_score >= 80:
        risk_level = "LOW"
        risk_color = "green"
        recommendation = "RECOMMENDED"
    elif total_score >= 60:
        risk_level = "MODERATE"
        risk_color = "yellow"
        recommendation = "ACCEPTABLE"
    elif total_score >= 40:
        risk_level = "ELEVATED"
        risk_color = "orange1"
        recommendation = "CAUTION"
    else:
        risk_level = "HIGH"
        risk_color = "red"
        recommendation = "NOT RECOMMENDED"

    risk_data["risk_level"] = risk_level
    risk_data["recommendation"] = recommendation

    # ============================================================
    # DISPLAY RESULTS
    # ============================================================

    network_name = risk_data.get("network", {}).get("name", f"AS{target_asn_int}")
    console.print()
    console.print(f"[bold]{network_name}[/]")
    console.print()

    # Overall score panel
    console.print(Panel(
        f"[bold {risk_color}]{total_score}/{max_score}[/] ({risk_data['percentage']}%)\n"
        f"[bold]Risk Level: [{risk_color}]{risk_level}[/][/]\n"
        f"[dim]Recommendation: {recommendation}[/]",
        title="Peer Risk Score",
        box=box.DOUBLE,
    ))

    # Score breakdown
    console.print()
    console.print("[bold cyan]## Score Breakdown[/]")

    score_table = Table(box=box.ROUNDED)
    score_table.add_column("Category", style="bold")
    score_table.add_column("Score", justify="right")
    score_table.add_column("Key Factors")

    for category, data in risk_data["scores"].items():
        score_str = f"{data['score']}/{data['max']}"
        if data["score"] >= data["max"] * 0.8:
            score_str = f"[green]{score_str}[/]"
        elif data["score"] >= data["max"] * 0.5:
            score_str = f"[yellow]{score_str}[/]"
        else:
            score_str = f"[red]{score_str}[/]"

        factors_str = "; ".join(data["factors"][:2]) if data["factors"] else "-"
        if len(factors_str) > 50:
            factors_str = factors_str[:47] + "..."

        score_table.add_row(
            category.replace("_", " ").title(),
            score_str,
            factors_str,
        )

    console.print(score_table)

    # Network profile
    console.print()
    console.print("[bold cyan]## Network Profile[/]")

    profile_table = Table(box=box.SIMPLE)
    profile_table.add_column("Attribute", style="dim")
    profile_table.add_column("Value")

    net = risk_data.get("network", {})
    profile_table.add_row("Name", net.get("name", "Unknown"))
    profile_table.add_row("Type", net.get("type") or net.get("type_inferred") or "Unknown")
    profile_table.add_row("Peering Policy", net.get("policy", "Unknown"))
    profile_table.add_row("IXes", str(net.get("ix_count", "?")))

    if "irr_as_set" in net:
        profile_table.add_row("IRR as-set", net["irr_as_set"])

    stab = risk_data.get("stability", {})
    if "prefix_count" in stab:
        profile_table.add_row("Prefixes", str(stab["prefix_count"]))
    if "updates_per_day" in stab:
        profile_table.add_row("BGP Updates/Day", str(stab["updates_per_day"]))

    topo = risk_data.get("topology", {})
    if topo:
        profile_table.add_row("Upstreams", str(topo.get("upstreams", "?")))
        profile_table.add_row("Downstreams", str(topo.get("downstreams", "?")))

    console.print(profile_table)

    # IX overlap (if we have our ASN)
    if "ix_overlap" in risk_data:
        console.print()
        console.print("[bold cyan]## IX Overlap[/]")
        overlap = risk_data["ix_overlap"]
        console.print(f"   Common IXes: [bold]{overlap['common_count']}[/]")
        console.print(f"   Your IXes: {overlap['your_ix_count']} | Target IXes: {overlap['target_ix_count']}")

        if overlap["common_count"] > 0:
            console.print(f"   [green]✓ Can peer at {overlap['common_count']} location(s)[/]")
        else:
            console.print(f"   [yellow]⚠ No common IXes - would need PNI or new IX membership[/]")

    # Warnings
    if risk_data["warnings"]:
        console.print()
        console.print("[bold yellow]## ⚠️ Warnings[/]")
        for warning in risk_data["warnings"]:
            console.print(f"   • {warning}")

    # AI Analysis
    if use_ai:
        console.print()
        console.print("[bold cyan]## AI Risk Assessment[/]")
        try:
            import os
            from route_sherlock.synthesis.engine import Synthesizer

            if not os.environ.get("ANTHROPIC_API_KEY"):
                console.print("[yellow]Set ANTHROPIC_API_KEY for AI analysis[/]")
            else:
                from route_sherlock.synthesis.engine import PEER_RISK_PROMPT
                synth = Synthesizer()

                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    console=console,
                    transient=True,
                ) as progress:
                    progress.add_task("Generating AI risk assessment...", total=None)
                    analysis = await synth.synthesize(PEER_RISK_PROMPT, risk_data)

                console.print(Panel(
                    Markdown(analysis),
                    title="AI-Generated Risk Assessment",
                    box=box.ROUNDED,
                ))
        except ImportError as e:
            console.print(f"[yellow]AI synthesis unavailable: {e}[/]")
        except Exception as e:
            console.print(f"[yellow]AI analysis error: {e}[/]")

    # Final recommendation
    console.print()
    if recommendation == "RECOMMENDED":
        console.print(Panel(
            f"[bold green]✅ RECOMMENDED TO PEER[/]\n\n"
            f"AS{target_asn_int} ({network_name}) shows strong indicators:\n"
            f"• Stable routing behavior\n"
            f"• Good network maturity\n"
            f"• Compatible peering policy\n\n"
            f"[dim]Proceed with standard peering process.[/]",
            box=box.DOUBLE,
        ))
    elif recommendation == "ACCEPTABLE":
        console.print(Panel(
            f"[bold yellow]⚠️ ACCEPTABLE WITH MONITORING[/]\n\n"
            f"AS{target_asn_int} shows moderate risk factors.\n"
            f"Consider:\n"
            f"• Implementing strict prefix limits\n"
            f"• Monitoring BGP session closely\n"
            f"• Setting up alerting for anomalies\n",
            box=box.DOUBLE,
        ))
    elif recommendation == "CAUTION":
        console.print(Panel(
            f"[bold orange1]⚠️ PROCEED WITH CAUTION[/]\n\n"
            f"AS{target_asn_int} has elevated risk indicators.\n"
            f"If peering is necessary:\n"
            f"• Require strict IRR filtering\n"
            f"• Implement conservative prefix limits\n"
            f"• Consider RPKI-invalid rejection\n"
            f"• Monitor closely for anomalies\n",
            box=box.DOUBLE,
        ))
    else:
        console.print(Panel(
            f"[bold red]❌ NOT RECOMMENDED[/]\n\n"
            f"AS{target_asn_int} shows high risk indicators.\n"
            f"Issues found:\n" +
            "\n".join(f"• {w}" for w in risk_data["warnings"][:3]) +
            f"\n\n[dim]Recommend against establishing peering session.[/]",
            box=box.DOUBLE,
        ))

    console.print()
    console.print(f"[dim]Data sources: RIPEstat, PeeringDB | Analysis: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}[/]")
