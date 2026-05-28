"""Rich renderer for PeerRiskV2Result. Outputs the three-pillar panel."""
from __future__ import annotations

from rich import box
from rich.console import Console
from rich.panel import Panel

from route_sherlock.analysis.peer_risk_v2 import PeerRiskV2Result, PillarScore


_CLASS_COLOR = {
    "LOW": "green",
    "MEDIUM": "yellow",
    "HIGH": "red",
    "UNKNOWN": "dim",
}


_POSTURE_COLOR = {
    "PEER-STANDARD": "bold green",
    "PEER-WITH-SAFEGUARDS": "yellow",
    "PEER-CAUTIOUSLY": "bold yellow",
    "INVESTIGATE-FIRST": "bold red",
    "INSUFFICIENT-DATA": "dim",
}


def _bar(points: int | None) -> str:
    if points is None:
        return "[dim]░░░░░░░░░░[/]"
    filled = max(0, min(10, points))
    return f"[bold]{'█' * filled}[/]{'░' * (10 - filled)}"


def _render_pillar(p: PillarScore) -> str:
    colour = _CLASS_COLOR.get(p.classification, "")
    bar = _bar(p.points)
    line1 = f"  [bold]{p.name:16s}[/] {bar} [{colour}]{p.classification}[/]"
    if p.error and not p.findings:
        return f"{line1}\n    [dim]{p.error}[/]"
    body = "\n".join(f"    • {f}" for f in p.findings)
    return f"{line1}\n{body}" if body else line1


def render(result: PeerRiskV2Result, console: Console) -> None:
    pillars_block = "\n\n".join([
        _render_pillar(result.track_record),
        _render_pillar(result.routing_hygiene),
        _render_pillar(result.coordination),
    ])

    obs = result.observed
    obs_bits = []
    if obs.network_type:
        obs_bits.append(f"PeeringDB type: {obs.network_type}")
    if obs.transit_upstreams is not None:
        obs_bits.append(f"transit upstreams: {obs.transit_upstreams}")
    if obs.direct_downstreams is not None:
        obs_bits.append(f"direct downstreams: {obs.direct_downstreams}")
    obs_line = " · ".join(obs_bits) if obs_bits else "(no observed facts)"

    sg = result.safeguards
    posture_colour = _POSTURE_COLOR.get(sg.posture, "")
    sg_lines = [f"  [bold]Posture:[/] [{posture_colour}]{sg.posture}[/]"]
    sg_lines.append(f"    [dim]{sg.posture_rationale}[/]")
    sg_lines.append("")
    sg_lines.append(f"  [bold]Filter strategy:[/] {sg.filter_strategy}")
    if sg.max_prefix_v4 is not None:
        sg_lines.append(f"  [bold]Max-prefix v4:[/] {sg.max_prefix_v4:,} (hard cap)")
    if sg.max_prefix_v6 is not None:
        sg_lines.append(f"  [bold]Max-prefix v6:[/] {sg.max_prefix_v6:,} (hard cap)")
    if sg.preflight_steps:
        sg_lines.append("")
        sg_lines.append("  [bold]Pre-flight:[/]")
        for s in sg.preflight_steps:
            sg_lines.append(f"    • {s}")
    if sg.monitoring_steps:
        sg_lines.append("")
        sg_lines.append("  [bold]Ongoing monitoring:[/]")
        for s in sg.monitoring_steps:
            sg_lines.append(f"    • {s}")
    if sg.notes:
        sg_lines.append("")
        for n in sg.notes:
            sg_lines.append(f"  [dim]{n}[/]")
    sg_block = "\n".join(sg_lines)

    sources_block = "[dim]Data sources: " + " · ".join(result.data_sources) + "[/]"

    panel_body = (
        f"{pillars_block}\n\n"
        f"  [bold]Observed:[/] [dim]{obs_line}[/]\n\n"
        f"{sg_block}\n\n"
        f"{sources_block}"
    )

    console.print(Panel(
        panel_body,
        title=f"[bold]Peer Risk: AS{result.asn} ({result.network_name})[/]",
        box=box.ROUNDED,
        expand=True,
        padding=(1, 2),
    ))
