# Route Sherlock - Feature Documentation

## Overview

Route Sherlock is a BGP intelligence CLI tool for network operators. It provides historical analysis, risk scoring, and AI-powered synthesis of BGP data.

**Data Sources:**
- RIPEstat API (real-time BGP data)
- PeeringDB API (network metadata, IX presence)
- BGPStream/pybgpstream (historical BGP archives from RouteViews/RIPE RIS)
- Claude API (AI synthesis)

---

## Commands

### 1. `lookup` - Quick ASN/Prefix Lookup

```bash
route-sherlock lookup AS13335
route-sherlock lookup 1.1.1.0/24
```

**Output:**
- ASN: holder name, RIR, announced status, prefix counts, upstreams/downstreams
- Prefix: RRCs reporting, unique paths, origin ASes, MOAS detection

---

### 2. `peer-risk` - Peer Risk Assessment (NEW - USP Feature)

**Purpose:** Answer "Should I peer with this ASN?"

```bash
route-sherlock peer-risk AS64500
route-sherlock peer-risk AS64500 --my-asn AS13335    # IX overlap analysis
route-sherlock peer-risk AS64500 --days 180          # Extended history
route-sherlock peer-risk AS64500 --ai                # AI-powered assessment
```

**Scoring Algorithm (100 points):**

| Category | Max Points | Factors |
|----------|------------|---------|
| Maturity | 20 | PeeringDB presence (+5), IRR as-set (+5), Policy URL (+3), IX count (+2-7) |
| Stability | 30 | BGP update frequency - deductions for high churn |
| Incident History | 30 | Upstream diversity, topology redundancy |
| Policy | 10 | Open (+10), Selective (+7), Restrictive (+3) |
| Security | 10 | IRR registration (+3), Multiple transits (+2) |

**Risk Levels:**
- 80-100: LOW RISK - Recommended to peer
- 60-79: MODERATE RISK - Acceptable with monitoring
- 40-59: ELEVATED RISK - Proceed with caution
- 0-39: HIGH RISK - Not recommended

**Validated Results:**
```
AS13335 (Cloudflare)  → 100/100 LOW RISK
AS15169 (Google)      → 97/100  LOW RISK
AS267613 (Eletronet)  → 72/100  MODERATE RISK (flagged: 1637 updates/day churn)
```

---

### 3. `backtest` - Historical Incident Analysis

**Purpose:** Analyze historical BGP incidents using BGPStream archives

```bash
route-sherlock backtest 1.1.1.0/24 --origin AS13335 --time "2024-06-27 18:00" --duration 3h
route-sherlock backtest 1.1.1.0/24 --origin AS13335 --time "2024-06-27 18:00" --ai
```

**Requirements:**
- `brew install bgpstream`
- `pip install pybgpstream`

**Anomaly Detection:**
- More-specific hijacks (>/24 prefixes)
- Origin mismatches (unexpected origin AS)
- Route leaks (correct origin but unexpected path)
- Path-based leaks (extra ASes injected into path)

**Validated Against Real Incident:**
- Cloudflare 1.1.1.1 hijack (June 27, 2024)
- Tool detected AS267613/AS262504 at 18:49:02 UTC
- Cloudflare reported incident started ~18:51 UTC
- Found 329 route leak events over 7.6 hours

---

### 4. `investigate` - Routing Incident Investigation

```bash
route-sherlock investigate AS16509 --time "2025-01-01 14:00" --duration 2h
route-sherlock investigate 1.1.1.0/24 --time "2h ago"
route-sherlock investigate AS13335 --ai
```

**Output:**
- BGP update counts (announcements/withdrawals)
- Stability assessment
- Recent events timeline
- AI-generated incident report (with --ai)

---

### 5. `peering-eval` - Peering Opportunity Evaluation

```bash
route-sherlock peering-eval --my-asn AS64500 --target AS13335
route-sherlock peering-eval -m AS64500 -t AS13335 --ix "DE-CIX Frankfurt"
```

**Output:**
- Target network profile
- IX presence comparison (common IXes highlighted)
- Estimated peering impact
- Recommendation with next steps

---

### 6. `stability` - ASN Stability Score

```bash
route-sherlock stability AS13335
route-sherlock stability AS13335 --days 30
```

**Output:**
- Stability score (0-100)
- BGP update metrics
- Score factors

---

### 7. `ix-presence` - IX Presence Lookup

```bash
route-sherlock ix-presence AS13335
```

**Output:**
- List of IXes where ASN is present
- Speed and port count per IX
- Sorted by capacity

---

### 8. `compare` - Side-by-Side ASN Comparison

```bash
route-sherlock compare AS13335 AS15169
```

**Output:**
- Metrics comparison table
- IPv4/IPv6 prefixes, upstreams, IXes, peering policy

---

## AI Synthesis (`--ai` flag)

Available on: `investigate`, `backtest`, `peer-risk`

**Requirements:**
```bash
export ANTHROPIC_API_KEY="your-key"
```

**What it does:**
1. Raw BGP data collected from APIs
2. Data formatted into structured prompt
3. Claude API generates human-readable analysis
4. Report includes: summary, timeline, impact, recommendations

---

## Installation

```bash
# Core tool
pip install -e .

# For historical backtesting
brew install bgpstream
CFLAGS="-I/opt/homebrew/include" LDFLAGS="-L/opt/homebrew/lib" pip install pybgpstream

# For AI synthesis
pip install anthropic
export ANTHROPIC_API_KEY="your-key"

# For PeeringDB (optional but recommended)
export PEERINGDB_API_KEY="your-key"
```

---

## Architecture

```
route_sherlock/
├── cli/
│   ├── main.py          # Typer CLI entry point
│   └── commands.py      # Command implementations
├── collectors/
│   ├── ripestat.py      # RIPEstat API client
│   ├── peeringdb.py     # PeeringDB API client
│   ├── atlas.py         # RIPE Atlas client
│   └── bgpstream.py     # BGPStream client (historical)
├── analysis/
│   └── engine.py        # Analysis algorithms
└── synthesis/
    └── engine.py        # AI synthesis with Claude
```

---

## Key Differentiators vs Existing Tools

| Feature | BGPalerter | ARTEMIS | Cloudflare Radar | Route Sherlock |
|---------|------------|---------|------------------|----------------|
| Real-time monitoring | ✅ | ✅ | ✅ | ❌ |
| Historical backtesting | ❌ | ❌ | Limited | ✅ |
| Peer risk scoring | ❌ | ❌ | ❌ | ✅ |
| AI-powered analysis | ❌ | ❌ | ❌ | ✅ |
| "Should I peer?" answer | ❌ | ❌ | ❌ | ✅ |
| Open source | ✅ | ✅ | ❌ | ✅ |

---

## Validated Incidents

### Cloudflare 1.1.1.1 Hijack (June 27, 2024)

**Known facts (from Cloudflare post-mortem):**
- AS267613 (Eletronet) announced 1.1.1.1/32 at 18:51 UTC
- AS262504 leaked 1.1.1.0/24 at 18:52 UTC
- Incident lasted until ~02:28 UTC next day

**Route Sherlock detection:**
```
First anomaly: 2024-06-27 18:49:06 UTC
Route leaks found: 329 events
AS path: 50763 → 1031 → 262504 → 267613 → 13335
Duration detected: 7.6 hours
```

**Validation:** Tool correctly identified involved ASes and timeline within 2 minutes of actual incident start.
