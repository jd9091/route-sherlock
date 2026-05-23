"""
Deck validation report generator.

Runs each CLI command demonstrated in the NANOG peering-risk deck,
captures the live output, checks expected substrings, and emits a
self-contained HTML report at ~/Desktop/route-sherlock-deck-validation.html
(override with --output).

Usage:
    python scripts/validate_deck.py
    python scripts/validate_deck.py --output /tmp/report.html
    python scripts/validate_deck.py --skip-slow   # skip backtest + --ai

The HTML matches the style of the prior report so it can drop in as a
replacement. Outputs are raw stdout+stderr (ANSI-stripped) so reviewers
can see exactly what the deck audience will see.
"""
from __future__ import annotations

import argparse
import html
import re
import shlex
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
DECK_FILENAME = "20260107_Dave_Peering_Risk_Intelligence_v2_fmt.pptx"


@dataclass
class Case:
    tid: str
    slide: str
    title: str
    claim: str
    command: str
    expect: list[str] = field(default_factory=list)
    soft_expect: list[str] = field(default_factory=list)
    timeout: int = 300
    slow: bool = False


CASES: list[Case] = [
    Case(
        tid="T01",
        slide="slide 4",
        title="CLI surface area",
        claim="The tool is a CLI with named commands (peer-risk, backtest, etc.).",
        command="route-sherlock --help",
        expect=["peer-risk", "stability", "backtest", "lookup", "compare", "ix-presence"],
    ),
    Case(
        tid="T02",
        slide="slide 6",
        title="Score AS13335 (Cloudflare) — slide 6 demo",
        claim="AS13335 returns LOW with CLOUDFLARENET. Policy: Open is a soft expectation (PeeringDB-dependent).",
        command="route-sherlock peer-risk AS13335",
        expect=["AS13335", "CLOUDFLARENET", "LOW", "Open"],
    ),
    Case(
        tid="T03",
        slide="slide 7",
        title="Score AS267613 (Eletronet) — slide 7 demo",
        claim="AS267613 returns MODERATE with churn warning.",
        command="route-sherlock peer-risk AS267613",
        expect=["AS267613", "ELETRONET", "MODERATE", "High BGP churn"],
    ),
    Case(
        tid="T04",
        slide="slide 10",
        title="Stability score — slide 10",
        claim="Stability command yields a numeric score and updates/day.",
        command="route-sherlock stability AS267613 --days 30",
        expect=["Stability", "AS267613", "Updates/Day"],
    ),
    Case(
        tid="T05",
        slide="slide 11",
        title="IX overlap (my-asn) — slide 11",
        claim="--my-asn renders shared/missing IX sections.",
        command="route-sherlock peer-risk AS15169 --my-asn AS13335",
        expect=["AS15169", "GOOGLE"],
        soft_expect=["IX Overlap"],
    ),
    Case(
        tid="T06",
        slide="slide 14",
        title="--ai flag — slide 14",
        claim="--ai produces a narrative risk assessment.",
        command="route-sherlock peer-risk AS13335 --ai",
        expect=["AS13335"],
        soft_expect=["AI", "Recommended"],
        timeout=180,
        slow=True,
    ),
    Case(
        tid="T07",
        slide="slide 5",
        title="--days option — slide 5",
        claim="--days extends the analysis window.",
        command="route-sherlock peer-risk AS13335 --days 180",
        expect=["AS13335", "CLOUDFLARENET"],
    ),
    Case(
        tid="T10",
        slide="—",
        title="lookup command",
        claim="lookup returns RIR-style ASN summary.",
        command="route-sherlock lookup AS13335",
        expect=["AS13335", "CLOUDFLARENET", "IPv4 Prefixes"],
    ),
    Case(
        tid="T11",
        slide="—",
        title="compare command",
        claim="compare shows two ASNs side-by-side with winners.",
        command="route-sherlock compare AS13335 AS15169",
        expect=["AS13335", "AS15169", "Winner"],
    ),
    Case(
        tid="T12",
        slide="—",
        title="ix-presence command",
        claim="ix-presence lists IXes for an ASN.",
        command="route-sherlock ix-presence AS13335",
        expect=["AS13335", "Equinix"],
    ),
    Case(
        tid="T13",
        slide="tests",
        title="Unit tests pass",
        claim="All pytest cases pass.",
        command="python -m pytest tests/ -q",
        expect=["passed"],
    ),
    Case(
        tid="T14",
        slide="—",
        title="Offline mode serves a previously-cached ASN",
        claim="--offline returns instantly from cache.",
        command="route-sherlock peer-risk AS267613 --offline",
        expect=["AS267613", "MODERATE", "offline"],
    ),
    Case(
        tid="T16",
        slide="security",
        title="RPKI sampling in peer-risk",
        claim="Security category surfaces RPKI sample result.",
        command="route-sherlock peer-risk AS267613",
        expect=["RPKI sample"],
    ),
]


def strip_ansi(s: str) -> str:
    return ANSI_RE.sub("", s)


def run_case(c: Case) -> dict:
    started = time.monotonic()
    try:
        proc = subprocess.run(
            shlex.split(c.command),
            capture_output=True,
            text=True,
            timeout=c.timeout,
            check=False,
        )
        stdout = strip_ansi(proc.stdout or "")
        stderr = strip_ansi(proc.stderr or "")
        output = stdout if stdout else stderr
        exit_code = proc.returncode
        timed_out = False
    except subprocess.TimeoutExpired:
        output = f"<timeout after {c.timeout}s>"
        exit_code = -1
        timed_out = True
    duration = time.monotonic() - started

    missing = [e for e in c.expect if e not in output]
    passed = not missing and exit_code == 0 and not timed_out
    return {
        "case": c,
        "output": output,
        "exit": exit_code,
        "duration": duration,
        "missing": missing,
        "passed": passed,
        "timed_out": timed_out,
    }


CSS = """:root {
  --bg: #0d1117; --fg: #c9d1d9; --dim: #8b949e; --card: #161b22;
  --border: #30363d; --pass: #3fb950; --pass-bg: #0d2818;
  --fail: #f85149; --fail-bg: #2d0f10; --code-bg: #010409; --accent: #58a6ff;
}
* { box-sizing: border-box; }
body { margin: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
       background: var(--bg); color: var(--fg); line-height: 1.55; }
.container { max-width: 1100px; margin: 0 auto; padding: 32px 24px 96px; }
h1 { font-size: 28px; margin: 0 0 8px; letter-spacing: -0.02em; }
h2 { font-size: 22px; margin: 48px 0 16px; padding-top: 16px; border-top: 1px solid var(--border); }
h3 { font-size: 16px; margin: 24px 0 12px; color: var(--accent); font-weight: 600; }
.subtitle { color: var(--dim); margin: 0 0 24px; font-size: 14px; }
.summary { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin: 24px 0 32px; }
.summary .tile { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 14px 18px; }
.summary .num { font-size: 28px; font-weight: 700; line-height: 1; }
.summary .lbl { color: var(--dim); font-size: 12px; text-transform: uppercase; letter-spacing: 0.06em; margin-top: 4px; }
.summary .tile.pass .num { color: var(--pass); }
.summary .tile.fail .num { color: var(--fail); }
.card { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 16px 20px; margin: 14px 0; }
.card.pass { border-left: 4px solid var(--pass); }
.card.fail { border-left: 4px solid var(--fail); }
.card header { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-bottom: 6px; }
.card header .left, .card header .right { display: flex; gap: 8px; align-items: center; }
.card h3 { margin: 4px 0 12px; color: var(--fg); font-size: 17px; }
.card p { margin: 6px 0; font-size: 14px; }
.lbl { color: var(--dim); margin-right: 6px; font-weight: 600; }
.badge { font-family: ui-monospace, monospace; font-size: 11px; padding: 2px 8px; border-radius: 4px; font-weight: 700; letter-spacing: 0.05em; }
.badge.pass { background: var(--pass-bg); color: var(--pass); border: 1px solid var(--pass); }
.badge.fail { background: var(--fail-bg); color: var(--fail); border: 1px solid var(--fail); }
.id, .slide, .dur, .exit { font-family: ui-monospace, monospace; font-size: 12px; color: var(--dim); }
code { background: var(--code-bg); border: 1px solid var(--border); padding: 2px 6px; border-radius: 4px; font-size: 13px; color: var(--fg); }
details { margin-top: 8px; }
summary { cursor: pointer; color: var(--accent); font-size: 13px; user-select: none; padding: 4px 0; }
pre { background: var(--code-bg); border: 1px solid var(--border); border-radius: 6px; padding: 12px 14px; overflow-x: auto; font-size: 12.5px; line-height: 1.5; max-height: 480px; margin: 8px 0 0; }
footer { margin-top: 56px; padding-top: 16px; border-top: 1px solid var(--border); color: var(--dim); font-size: 12px; }
"""


def render_report(results: list[dict], total_wall: float) -> str:
    passed = sum(1 for r in results if r["passed"])
    failed = len(results) - passed
    ts = time.strftime("%Y-%m-%d %H:%M")

    cards = []
    for r in results:
        c: Case = r["case"]
        badge = "pass" if r["passed"] else "fail"
        line_count = r["output"].count("\n") + 1
        missing_block = ""
        if r["missing"]:
            missing_block = (
                f'<p class="note"><span class="lbl">Missing strings:</span> '
                f'<code>{html.escape(", ".join(r["missing"]))}</code></p>'
            )
        cards.append(
            f'<article class="card {badge}">'
            f'<header><div class="left">'
            f'<span class="badge {badge}">{badge.upper()}</span>'
            f'<span class="id">{c.tid}</span>'
            f'<span class="slide">{html.escape(c.slide)}</span>'
            f'</div><div class="right">'
            f'<span class="dur">{r["duration"]:.1f}s</span>'
            f'<span class="exit">exit {r["exit"]}</span>'
            f'</div></header>'
            f'<h3>{html.escape(c.title)}</h3>'
            f'<p class="claim"><span class="lbl">Deck claim:</span> {html.escape(c.claim)}</p>'
            f'<p class="cmd"><span class="lbl">Command:</span> <code>{html.escape(c.command)}</code></p>'
            f'{missing_block}'
            f'<details><summary>Actual output ({line_count} lines)</summary>'
            f'<pre>{html.escape(r["output"]) or "&lt;no output&gt;"}</pre></details>'
            f'</article>'
        )

    return (
        f'<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">'
        f'<meta name="viewport" content="width=device-width,initial-scale=1">'
        f'<title>Route Sherlock — Deck Validation Report</title>'
        f'<style>{CSS}</style></head><body><div class="container">'
        f'<h1>Route Sherlock — Deck Validation</h1>'
        f'<p class="subtitle">Validating <code>{DECK_FILENAME}</code> '
        f'against the live <code>route-sherlock</code> CLI. Generated {ts}.</p>'
        f'<div class="summary">'
        f'<div class="tile pass"><div class="num">{passed}</div><div class="lbl">Passed</div></div>'
        f'<div class="tile fail"><div class="num">{failed}</div><div class="lbl">Failed</div></div>'
        f'<div class="tile"><div class="num">{len(results)}</div><div class="lbl">Total tests</div></div>'
        f'<div class="tile"><div class="num">{int(total_wall)}s</div><div class="lbl">Wall time</div></div>'
        f'</div><h2>Test cases</h2>'
        + "\n".join(cards)
        + '<footer>Report self-contained. Outputs are raw stdout/stderr from the '
        f'<code>route-sherlock</code> binary, ANSI-stripped. Live data sources: RIPEstat, PeeringDB.</footer>'
        f'</div></body></html>'
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--output",
        default=str(Path.home() / "Desktop" / "route-sherlock-deck-validation.html"),
    )
    ap.add_argument("--skip-slow", action="store_true",
                    help="Skip slow cases (currently: --ai).")
    ap.add_argument("--only", help="Comma-separated test ids to run (e.g. T01,T08).")
    args = ap.parse_args()

    cases = CASES
    if args.skip_slow:
        cases = [c for c in cases if not c.slow]
    if args.only:
        wanted = {x.strip() for x in args.only.split(",")}
        cases = [c for c in cases if c.tid in wanted]

    print(f"Running {len(cases)} cases…", flush=True)
    started = time.monotonic()
    results = []
    for c in cases:
        print(f"  [{c.tid}] {c.command}", flush=True)
        r = run_case(c)
        results.append(r)
        status = "PASS" if r["passed"] else "FAIL"
        print(f"      → {status} ({r['duration']:.1f}s, exit {r['exit']})", flush=True)
    total_wall = time.monotonic() - started

    html_text = render_report(results, total_wall)
    Path(args.output).write_text(html_text, encoding="utf-8")
    passed = sum(1 for r in results if r["passed"])
    print(f"\nReport: {args.output}")
    print(f"{passed}/{len(results)} passed in {total_wall:.0f}s")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
