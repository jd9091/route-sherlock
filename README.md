# Route Sherlock

Historical BGP intelligence CLI for network operators. Answer questions like "Should I peer with this network?" and "What happened during that routing incident?"

## Features

- **Peer Risk Scoring** - Quantitative risk assessment for peering decisions (0-100 score)
- **Practical Safeguards** - Concrete `maximum-prefix`, IRR, and RPKI policy recommendations per risk tier
- **Historical Backtesting** - Analyze past BGP incidents using RouteViews/RIPE RIS archives
- **AI-Powered Analysis** - Claude-powered synthesis of complex routing data
- **Multi-Source Intelligence** - Aggregates data from RIPEstat, PeeringDB, and BGPStream

## Installation

> All `pip install` steps below assume an **activated venv** running
> **Python 3.11**. Newer Pythons (3.14+) can break `pipx`/`ensurepip`
> workarounds, and `pybgpstream` only ships wheels for the supported
> CPython line. Activate the venv before each step.

```bash
# Clone the repo
git clone https://github.com/jd9091/route-sherlock.git
cd route-sherlock

# Create + activate virtual environment (Python 3.11)
python3.11 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install
pip install -e .

# (Optional) AI synthesis
pip install -e ".[ai]"
export ANTHROPIC_API_KEY="your-key"
```

### Optional: Historical backtesting

`route-sherlock backtest` reads RouteViews / RIPE RIS archives via
`libbgpstream`. The system library must be installed **before** the
Python bindings, and the bindings must go into the same activated venv
as `route-sherlock` itself.

```bash
# 1. System library
brew install bgpstream             # macOS
# sudo apt install libbgpstream2-dev  # Debian/Ubuntu
# (other distros: build from https://bgpstream.caida.org/)

# 2. Python bindings — venv must be activated
source venv/bin/activate
pip install pybgpstream
# Linux from-source: prepend
#   CFLAGS="-I/path/to/bgpstream/include" \
#   LDFLAGS="-L/path/to/bgpstream/lib"
```

> **First backtest is slow.** RouteViews / RIPE RIS dumps are pulled on
> demand and can take several minutes the first time a window is
> queried. Subsequent runs hit the local cache (`~/.cache/route-sherlock/`)
> and return in under a second — pre-warm before any live demo.

> **Multiple installs gotcha.** If `which -a route-sherlock` shows more
> than one path (e.g. a `~/.local/...` shim from a previous install),
> `pybgpstream` only counts if it lives in the same venv as the binary
> your shell actually resolves. Either uninstall the extras or call the
> intended binary by absolute path.

### Optional: PeeringDB API Key

For better rate limits and access to PeeringDB data:

```bash
export PEERINGDB_API_KEY="your-key"
```

## Commands

### `lookup` - Quick ASN/Prefix Information

```bash
$ route-sherlock lookup AS13335

╭──────────────────────────────────────────────────────────────────────────────╮
│ AS13335 - CLOUDFLARENET                                                      │
╰──────────────────────────────────────────────────────────────────────────────╯

  RIR             Unknown
  Announced       ✓ Yes
  IPv4 Prefixes   2445
  IPv6 Prefixes   3016
  Upstreams       2461
  Downstreams     0
  Top Upstreams   AS10030, AS10089, AS10094

PeeringDB:

  Type         Content
  Policy       Open
  IXes         350
  IRR as-set   AS13335:AS-CLOUDFLARE
```

### `peer-risk` - Peer Risk Assessment

```bash
$ route-sherlock peer-risk AS13335

╔══════════════════════════════════════════ Peer Risk Score ═══════════════════════════════════════════╗
║ 100/100 (100.0%)                                                                                     ║
║ Risk Level: LOW                                                                                      ║
║ Recommendation: RECOMMENDED                                                                          ║
╚══════════════════════════════════════════════════════════════════════════════════════════════════════╝

## Score Breakdown
╭──────────────────┬───────┬────────────────────────────────────────────────────╮
│ Category         │ Score │ Key Factors                                        │
├──────────────────┼───────┼────────────────────────────────────────────────────┤
│ Maturity         │ 20/20 │ PeeringDB registered (+5); IRR as-set: AS13335:... │
│ Stability        │ 30/30 │ Low BGP churn rate                                 │
│ Incident History │ 30/30 │ Multiple upstreams (2461) - good redundancy        │
│ Policy           │ 10/10 │ Open peering policy (+10)                          │
│ Security         │ 10/10 │ IRR registered (+3); Multiple transit relations... │
╰──────────────────┴───────┴────────────────────────────────────────────────────╯

╔══════════════════════════════════════════════════════════════════════════════════════════════════════╗
║ ✅ RECOMMENDED TO PEER                                                                               ║
╚══════════════════════════════════════════════════════════════════════════════════════════════════════╝
```

Add `--ai` for Claude-powered analysis:

```bash
$ route-sherlock peer-risk AS13335 --ai

## AI Risk Assessment
╭──────────────────────────────────── AI-Generated Risk Assessment ────────────────────────────────────╮
│                        BGP Peering Risk Assessment: AS13335 (Cloudflare)                             │
│                                                                                                      │
│                                          Executive Summary                                           │
│                                                                                                      │
│ Recommendation: YES - Establish peering with AS13335 immediately. This is an exceptional peering     │
│ candidate with perfect risk scores (100/100), representing one of the world's largest content        │
│ networks with open peering policies and excellent operational maturity.                              │
│                                                                                                      │
│                                           Key Risk Factors                                           │
│                                                                                                      │
│ Strengths (No significant concerns identified):                                                      │
│                                                                                                      │
│  1 Exceptional Network Maturity (20/20) - Cloudflare demonstrates gold-standard operational          │
│    practices with PeeringDB registration, proper IRR AS-set (AS13335:AS-CLOUDFLARE), published       │
│    peering policy, and massive global presence across 350 Internet Exchanges.                        │
│  2 Robust Network Architecture - Strong redundancy with 2,461 upstream relationships and             │
│    well-distributed connectivity through major carriers including diverse tier-1 providers.          │
│  3 Open Peering Policy (10/10) - Cloudflare maintains an open peering policy with published          │
│    guidelines, facilitating straightforward peering establishment.                                   │
│                                                                                                      │
│                                     Operational Recommendations                                      │
│                                                                                                      │
│ Low Risk - Standard Peering Process:                                                                 │
│  • Proceed with normal peering establishment procedures                                              │
│  • Contact Cloudflare's peering team through their published policy URL                              │
│  • No additional risk mitigation measures required beyond standard practices                         │
│                                                                                                      │
│                                         Technical Safeguards                                         │
│                                                                                                      │
│ Max-Prefix Limits:                                                                                   │
│  • IPv4: Set limit to 6,500 prefixes (20% buffer above current announced)                            │
│  • IPv6: Set limit to 1,000 prefixes                                                                 │
│                                                                                                      │
│ IRR Filtering Requirements:                                                                          │
│  • Mandatory: Filter against AS13335:AS-CLOUDFLARE AS-set                                            │
│  • Validate all received prefixes against their registered IRR objects                               │
│                                                                                                      │
│ RPKI Policy Recommendations:                                                                         │
│  • Apply "prefer-valid" RPKI validation policy                                                       │
│  • Given Cloudflare's operational excellence, expect high RPKI compliance                            │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

### `compare` - Side-by-Side ASN Comparison

```bash
$ route-sherlock compare AS13335 AS15169

╔══════════════════════════════════════════════════════════════════════════════╗
║ AS13335 vs AS15169                                                           ║
╚══════════════════════════════════════════════════════════════════════════════╝

╭────────────────┬───────────────┬───────────┬─────────╮
│ Metric         │       AS13335 │   AS15169 │ Winner  │
├────────────────┼───────────────┼───────────┼─────────┤
│ Name           │ CLOUDFLARENET │    GOOGLE │         │
│ IPv4 Prefixes  │         2,445 │     1,104 │ AS13335 │
│ IPv6 Prefixes  │         3,016 │       146 │ AS13335 │
│ Upstreams      │         2,461 │       326 │ AS13335 │
│ IXes           │           350 │       198 │ AS13335 │
│ Peering Policy │          Open │ Selective │         │
╰────────────────┴───────────────┴───────────┴─────────╯
```

### `stability` - ASN Stability Score

```bash
$ route-sherlock stability AS13335

📊 Stability Analysis: AS13335
Period: Last 90 days

Stability Score: 94/100
```

### `ix-presence` - IX Presence Lookup

```bash
$ route-sherlock ix-presence AS13335

🌐 IX Presence: AS13335

350 IXes found

Top IXes by speed:
  DE-CIX Frankfurt    600 Gbps
  LINX LON1           300 Gbps
  AMS-IX              200 Gbps
  ...
```

### `backtest` - Historical Incident Analysis

Analyze past BGP incidents using RouteViews/RIPE RIS archives:

```bash
$ route-sherlock backtest 1.1.1.0/24 --origin AS13335 --time "2024-06-27 18:00" --duration 3h

🚨 Anomalies Detected: 329

#1 [HIGH] LEAK
   Time: 2024-06-27T18:49:06
   AS Path: 50763 → 1031 → 262504 → 267613 → 13335
```

Requires `bgpstream` and `pybgpstream` to be installed.

### `investigate` - Routing Investigation

```bash
$ route-sherlock investigate AS16509 --time "2h ago"
```

### `peering-eval` - Peering Opportunity Evaluation

```bash
$ route-sherlock peering-eval --my-asn AS64500 --target AS13335
```

## Peer Risk Scoring

**Scoring (100 points max):**
- Maturity (20 pts): PeeringDB presence, IRR registration, IX count
- Stability (30 pts): BGP update frequency, churn rate
- Incident History (30 pts): Upstream diversity, topology redundancy
- Policy (10 pts): Open/Selective/Restrictive peering policy
- Security (10 pts): IRR registration, transit diversity

**Risk Levels:**
- 80-100: LOW RISK - Recommended to peer
- 60-79: MODERATE RISK - Acceptable with monitoring
- 40-59: ELEVATED RISK - Proceed with caution
- 0-39: HIGH RISK - Not recommended

## Data Sources

- **RIPEstat API** - Real-time BGP routing data
- **PeeringDB API** - Network metadata, IX presence, peering policies
- **BGPStream** - Historical BGP archives from RouteViews and RIPE RIS
- **Claude API** - AI-powered analysis and synthesis

## Documentation

- [Architecture](docs/ARCHITECTURE.md) - System design, data flow, API details
- [Features](docs/FEATURES.md) - Detailed feature documentation
- [Development Log](docs/DEVELOPMENT-LOG.md) - Development history

## Requirements

- Python 3.11+
- bgpstream (for historical backtesting)

## Known limitations

Route Sherlock leans on public APIs and a small fixed scoring model. A few things you should know going in:

- **Rate limits.** RIPEstat tolerates ~1000 req/day on the free tier; PeeringDB rate-limits aggressively under sustained load and will silently degrade policy/IX fields to `Unknown` rather than fail. The collectors retry with exponential backoff + jitter, but you'll feel it on large batch runs.
- **Cold-cache latency.** First call against a new ASN takes ~2 minutes (RPKI sampling dominates). Subsequent calls hit the file cache at `~/.cache/route-sherlock` and return in well under a second. Use `--offline` to force cache-only.
- **Data lag.** PeeringDB is self-reported by network operators; RIPEstat aggregates routing data with minutes-to-hours latency; BGPStream archives are minutes behind real-time.
- **Stability metric is not normalised by prefix count.** A real Tier-1 announcing thousands of prefixes will cross the absolute-updates/day thresholds on size alone. Normalisation is on the roadmap.
- **IX overlap counts membership, not peerability.** Today the score just intersects PeeringDB IX IDs; it doesn't yet check operational status, route-server availability, policy compatibility, or speed mismatch.
- **No point-in-time scoring.** `--days N` is a rolling window from *now*; there is no `--as-of <date>` yet, and no `last_incident_at` is surfaced separately from the rolling window.
- **RPKI is sampled, not exhaustive.** The default samples 8 prefixes per network. For a Tier-1 with thousands of ROAs that's a coverage estimate, not a complete audit.

These are tracked as open issues — see the [Contributing](#contributing) section if you want to fix one.

## Contributing

Issues, methodology critiques, and PRs welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for the dev setup, the issue templates, and the list of open work items. Three quick pointers:

- File a [bug](https://github.com/jd9091/route-sherlock/issues/new?template=bug_report.md), a [feature](https://github.com/jd9091/route-sherlock/issues/new?template=feature_request.md), or a [methodology critique](https://github.com/jd9091/route-sherlock/issues/new?template=methodology.md).
- Open-ended questions go in [Discussions](https://github.com/jd9091/route-sherlock/discussions).
- For anything that doesn't fit a public thread: davejd2990@gmail.com.

## License

Apache-2.0
