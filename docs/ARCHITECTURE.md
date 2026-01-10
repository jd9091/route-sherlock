# Route Sherlock Architecture

## System Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        User Interface                           │
│  CLI (Typer + Rich)                                             │
├─────────────────────────────────────────────────────────────────┤
│  route-sherlock lookup AS13335                                  │
│  route-sherlock peer-risk AS64500 --ai                          │
│  route-sherlock backtest 1.1.1.0/24 --origin AS13335            │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Analysis Modules                            │
│  ┌─────────────────────┐    ┌─────────────────────┐            │
│  │ Incident Analyzer   │    │ Peering Evaluator   │            │
│  │ - Timeline builder  │    │ - Path analysis     │            │
│  │ - Anomaly detection │    │ - Risk scoring      │            │
│  │ - Impact assessment │    │ - IX overlap        │            │
│  └─────────────────────┘    └─────────────────────┘            │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Orchestration Layer                         │
│  - Query planning                                               │
│  - Multi-source correlation                                     │
│  - AI synthesis (Claude API)                                    │
└─────────────────────────────────────────────────────────────────┘
                              │
        ┌───────────┬─────────┴─────────┬───────────┐
        ▼           ▼                   ▼           ▼
┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────┐
│ RIPEstat   │ │ RIPE Atlas │ │ PeeringDB  │ │ BGPStream  │
│ • Routes   │ │ • Latency  │ │ • IX info  │ │ • Archives │
│ • History  │ │ • Probes   │ │ • Presence │ │ • RouteViews│
│ • AS-path  │ │ • Anchors  │ │ • Policy   │ │ • RIPE RIS │
└────────────┘ └────────────┘ └────────────┘ └────────────┘
```

## Directory Structure

```
src/route_sherlock/
├── cli/
│   ├── main.py          # Typer CLI entry point
│   └── commands.py      # Command implementations
├── collectors/
│   ├── ripestat.py      # RIPEstat API client
│   ├── peeringdb.py     # PeeringDB API client
│   ├── atlas.py         # RIPE Atlas client
│   └── bgpstream.py     # BGPStream client (historical)
├── analysis/
│   ├── analyzer.py      # Core analysis engine
│   ├── peering.py       # Peering evaluation logic
│   └── paths.py         # AS-path analysis
├── models/
│   ├── ripestat.py      # RIPEstat data models
│   ├── peeringdb.py     # PeeringDB data models
│   └── atlas.py         # RIPE Atlas data models
├── synthesis/
│   └── engine.py        # Claude AI integration
└── cache/
    └── store.py         # Response caching
```

## Data Flow

### 1. Lookup Command

```
User Input: route-sherlock lookup AS13335
                    │
                    ▼
            ┌───────────────┐
            │  CLI Parser   │
            │  (main.py)    │
            └───────┬───────┘
                    │
        ┌───────────┴───────────┐
        ▼                       ▼
┌───────────────┐       ┌───────────────┐
│   RIPEstat    │       │   PeeringDB   │
│ get_as_overview│      │ get_network   │
└───────┬───────┘       └───────┬───────┘
        │                       │
        └───────────┬───────────┘
                    ▼
            ┌───────────────┐
            │  Rich Output  │
            │  (formatted)  │
            └───────────────┘
```

### 2. Peer Risk Command

```
User Input: route-sherlock peer-risk AS64500 --ai
                    │
                    ▼
            ┌───────────────┐
            │  CLI Parser   │
            └───────┬───────┘
                    │
    ┌───────────────┼───────────────┐
    ▼               ▼               ▼
┌─────────┐   ┌─────────┐   ┌─────────┐
│RIPEstat │   │PeeringDB│   │BGPStream│
│-overview│   │-network │   │-updates │
│-prefixes│   │-ixlans  │   │-history │
│-upstreams│  │-policy  │   │         │
└────┬────┘   └────┬────┘   └────┬────┘
     │             │             │
     └─────────────┴─────────────┘
                    │
                    ▼
          ┌─────────────────┐
          │  Risk Scoring   │
          │  Algorithm      │
          │  (100 points)   │
          └────────┬────────┘
                   │
                   ▼ (if --ai flag)
          ┌─────────────────┐
          │  Claude API     │
          │  Synthesis      │
          └────────┬────────┘
                   │
                   ▼
          ┌─────────────────┐
          │  Rich Output    │
          └─────────────────┘
```

### 3. Backtest Command

```
User Input: route-sherlock backtest 1.1.1.0/24 --origin AS13335 --time "2024-06-27 18:00"
                    │
                    ▼
            ┌───────────────┐
            │  CLI Parser   │
            └───────┬───────┘
                    │
                    ▼
            ┌───────────────┐
            │  BGPStream    │
            │  Historical   │
            │  Query        │
            └───────┬───────┘
                    │
                    ▼
            ┌───────────────┐
            │  Anomaly      │
            │  Detection    │
            │  - Hijacks    │
            │  - Leaks      │
            │  - MOAS       │
            └───────┬───────┘
                    │
                    ▼
            ┌───────────────┐
            │  Timeline     │
            │  Builder      │
            └───────────────┘
```

## Data Sources

### RIPEstat API

**Base URL:** `https://stat.ripe.net/data/`

**Endpoints Used:**

| Endpoint | Purpose | Example |
|----------|---------|---------|
| `as-overview` | Basic ASN info | Name, RIR, announced status |
| `announced-prefixes` | Prefix list | IPv4/IPv6 prefixes for ASN |
| `as-routing-consistency` | Route health | Consistency scores |
| `bgp-updates` | Update activity | BGP update counts |
| `ris-peers` | Visibility | RIS peer count |

**Example Response (as-overview):**
```json
{
  "data": {
    "resource": "13335",
    "holder": "CLOUDFLARENET",
    "announced": true,
    "block": {
      "name": "ARIN"
    }
  }
}
```

### PeeringDB API

**Base URL:** `https://www.peeringdb.com/api/`

**Endpoints Used:**

| Endpoint | Purpose | Example |
|----------|---------|---------|
| `net` | Network info | Name, policy, type |
| `netixlan` | IX presence | IX connections |
| `ix` | IX details | IX metadata |

**Example Response (net):**
```json
{
  "data": [{
    "asn": 13335,
    "name": "Cloudflare",
    "policy_general": "Open",
    "irr_as_set": "AS13335:AS-CLOUDFLARE",
    "info_type": "Content"
  }]
}
```

### BGPStream (pybgpstream)

**Data Sources:**
- RouteViews archives
- RIPE RIS archives

**Record Types:**
- Announcements (A)
- Withdrawals (W)
- State changes (S)

**Example Usage:**
```python
stream = pybgpstream.BGPStream(
    from_time="2024-06-27 18:00:00",
    until_time="2024-06-27 21:00:00",
    collectors=["rrc00", "route-views2"],
    record_type="updates",
    filter="prefix more 1.1.1.0/24"
)
```

### RIPE Atlas API

**Base URL:** `https://atlas.ripe.net/api/v2/`

**Endpoints Used:**

| Endpoint | Purpose |
|----------|---------|
| `probes` | Probe discovery |
| `measurements` | Latency data |
| `anchors` | Anchor info |

## Risk Scoring Algorithm

### Categories (100 points total)

| Category | Max Points | Factors |
|----------|------------|---------|
| **Maturity** | 20 | PeeringDB presence (+5), IRR as-set (+5), Policy URL (+3), IX count (+2-7) |
| **Stability** | 30 | BGP update frequency, churn rate deductions |
| **Incident History** | 30 | Upstream diversity, topology redundancy |
| **Policy** | 10 | Open (+10), Selective (+7), Restrictive (+3) |
| **Security** | 10 | IRR registration (+3), Multiple transits (+2) |

### Risk Levels

| Score | Level | Recommendation |
|-------|-------|----------------|
| 80-100 | LOW | Recommended to peer |
| 60-79 | MODERATE | Acceptable with monitoring |
| 40-59 | ELEVATED | Proceed with caution |
| 0-39 | HIGH | Not recommended |

## AI Synthesis

### Claude Integration

The `--ai` flag triggers Claude API synthesis for human-readable analysis.

**Prompt Structure:**
```
You are a BGP network analyst. Given the following data about AS{asn}:

- Network: {name}
- Peering Policy: {policy}
- IX Presence: {ix_count} IXes
- Risk Score: {score}/100
- Factors: {factors}

Provide:
1. Executive summary (peer or not)
2. Key risk factors
3. Operational recommendations
4. Technical safeguards (max-prefix, IRR filtering, RPKI)
```

**Output Sections:**
- Executive Summary
- Key Risk Factors
- Operational Recommendations
- Technical Safeguards (Max-Prefix, IRR, RPKI)

## Caching

Responses are cached to reduce API calls:

```python
# Cache keys
"ripestat:as-overview:13335"
"peeringdb:net:asn=13335"
"peeringdb:netixlan:asn=13335"
```

**Cache Duration:** 15 minutes (configurable)

## Error Handling

| Error Type | Handling |
|------------|----------|
| Rate Limit (429) | Exponential backoff, retry 3x |
| Not Found (404) | Return None, display warning |
| Timeout | Retry with increased timeout |
| API Error | Log error, continue with partial data |

## Environment Variables

| Variable | Purpose | Required |
|----------|---------|----------|
| `PEERINGDB_API_KEY` | PeeringDB authentication | Optional (improves rate limits) |
| `ANTHROPIC_API_KEY` | Claude AI synthesis | Required for `--ai` flag |

## Dependencies

### Core
- `httpx` - Async HTTP client
- `pydantic` - Data validation
- `typer` - CLI framework
- `rich` - Terminal formatting

### Optional
- `anthropic` - Claude AI (for `--ai` flag)
- `pybgpstream` - Historical BGP data (for `backtest`)
