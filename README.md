# Route Sherlock

Historical BGP intelligence CLI for network operators. Answer questions like "Should I peer with this network?" and "What happened during that routing incident?"

## Features

- **Peer Risk Scoring** - Quantitative risk assessment for peering decisions (0-100 score)
- **Historical Backtesting** - Analyze past BGP incidents using RouteViews/RIPE RIS archives
- **AI-Powered Analysis** - Claude-powered synthesis of complex routing data
- **Multi-Source Intelligence** - Aggregates data from RIPEstat, PeeringDB, and BGPStream

## Installation

```bash
# Clone the repo
git clone https://github.com/jd9091/route-sherlock.git
cd route-sherlock

# Create virtual environment (requires Python 3.11+)
python3.11 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install
pip install -e .

# For AI synthesis (optional)
pip install -e ".[ai]"
export ANTHROPIC_API_KEY="your-key"

# For historical backtesting (optional)
brew install bgpstream  # macOS
pip install pybgpstream
```

### Optional: PeeringDB API Key

For better rate limits and access to PeeringDB data:

```bash
export PEERINGDB_API_KEY="your-key"
```

## Quick Start

```bash
# Quick ASN lookup
route-sherlock lookup AS13335

# Peer risk assessment
route-sherlock peer-risk AS64500
route-sherlock peer-risk AS64500 --ai  # With AI analysis

# Historical incident analysis
route-sherlock backtest 1.1.1.0/24 --origin AS13335 --time "2024-06-27 18:00" --duration 3h

# Investigate recent routing issues
route-sherlock investigate AS16509 --time "2h ago"
```

## Commands

| Command | Description |
|---------|-------------|
| `lookup` | Quick ASN or prefix information |
| `peer-risk` | Risk assessment for peering decisions |
| `backtest` | Historical BGP incident analysis |
| `investigate` | Real-time routing investigation |
| `peering-eval` | Evaluate peering opportunities |
| `stability` | ASN stability scoring |
| `ix-presence` | IX presence lookup |
| `compare` | Side-by-side ASN comparison |

## Peer Risk Scoring

The `peer-risk` command provides a quantitative assessment:

```bash
route-sherlock peer-risk AS64500 --my-asn AS13335
```

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

## Historical Backtesting

Analyze past incidents using BGPStream archives:

```bash
route-sherlock backtest 1.1.1.0/24 --origin AS13335 --time "2024-06-27 18:00" --duration 3h --ai
```

Detects:
- More-specific hijacks
- Origin mismatches
- Route leaks
- Path anomalies

## Data Sources

- **RIPEstat API** - Real-time BGP routing data
- **PeeringDB API** - Network metadata, IX presence, peering policies
- **BGPStream** - Historical BGP archives from RouteViews and RIPE RIS
- **Claude API** - AI-powered analysis and synthesis

## Requirements

- Python 3.11+
- bgpstream (for historical backtesting)

## License

Apache-2.0
