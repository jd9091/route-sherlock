# Route Sherlock: BGP Intelligence Platform
## Open Source Design Plan v2

**Project:** `route-sherlock`
**Tagline:** "Historical BGP intelligence for network operators"

---

## 1. Two Core Use Cases

### Use Case A: Incident Investigation
**Question:** "What happened to AS64500's connectivity to AWS on Tuesday?"

**Output:** Timeline-based explanation with correlated evidence

### Use Case B: Peering Decision Support  
**Question:** "Should I (AS64500) peer with AS13335 (Cloudflare) at DE-CIX?"

**Output:** Data-driven recommendation with historical analysis

**Why these work together:**
- Same data sources (BGP history, Atlas latency, PeeringDB)
- Both are historical/analytical (not real-time traffic)
- Complementary: one reactive, one proactive
- Both answer questions operators actually ask

---

## 2. Updated Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        User Interface                           │
│  CLI / Web UI / API                                             │
├─────────────────────────────────────────────────────────────────┤
│  investigate AS64500 --time "2025-01-01 14:00"                  │
│  peering-eval --my-asn AS64500 --target AS13335 --ix DE-CIX     │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Analysis Modules                            │
│  ┌─────────────────────┐    ┌─────────────────────┐            │
│  │ Incident Analyzer   │    │ Peering Evaluator   │            │
│  │ - Timeline builder  │    │ - Path analysis     │            │
│  │ - Anomaly detection │    │ - Latency modeling  │            │
│  │ - Impact assessment │    │ - Traffic estimation│            │
│  └─────────────────────┘    └─────────────────────┘            │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Orchestration Agent                         │
│  - Query planning                                               │
│  - Multi-source correlation                                     │
│  - AI synthesis (Claude)                                        │
└─────────────────────────────────────────────────────────────────┘
                              │
        ┌───────────┬─────────┴─────────┬───────────┐
        ▼           ▼                   ▼           ▼
┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────┐
│ RIPEstat   │ │ RIPE Atlas │ │ PeeringDB  │ │ RPKI       │
│ • Routes   │ │ • Latency  │ │ • IX info  │ │ • ROA      │
│ • History  │ │ • Probes   │ │ • Presence │ │ • Validity │
│ • AS-path  │ │ • Anchors  │ │ • Policy   │ │            │
└────────────┘ └────────────┘ └────────────┘ └────────────┘
```

---

## 3. Peering Decision Support: Deep Dive

### 3.1 What Data Can We Actually Use?

| Data Point | Source | What It Tells Us |
|------------|--------|------------------|
| Current AS-path to target | RIPEstat | How many hops today? Via which transit? |
| Historical AS-path stability | RIPEstat history | Does the path flap? |
| Latency from your region to target | RIPE Atlas | Current RTT baseline |
| Latency from IX members to target | RIPE Atlas | What latency do peers achieve? |
| Target's presence at IXes | PeeringDB | Where can you peer with them? |
| Target's peering policy | PeeringDB | Open? Selective? Restrictive? |
| Your current IX presence | PeeringDB (or user input) | Where are you already? |
| Common IX participants | PeeringDB | Who else is there? |
| Historical route changes | RIPEstat | Is target's routing stable? |
| Prefix count | RIPEstat | How many routes would you receive? |

### 3.2 What We CAN'T Know (Without User Data)

| Data Point | Why Unavailable | Workaround |
|------------|-----------------|------------|
| Your traffic volume to target | Requires your netflow | Ask user / estimate from prefix count |
| Your current transit costs | Business data | User provides or we skip |
| Exact latency improvement | Need probe in your network | Use nearest Atlas probe as proxy |
| Target's willingness to peer | Human decision | Note their stated policy |

### 3.3 The Analysis Approach

```python
class PeeringEvaluator:
    """
    Evaluates whether peering with a target ASN at a specific IX
    would benefit the user's network.
    """
    
    def __init__(self, my_asn: str, target_asn: str, ix: str = None):
        self.my_asn = my_asn
        self.target_asn = target_asn
        self.ix = ix  # Optional: specific IX to evaluate
    
    def analyze(self) -> PeeringReport:
        # Step 1: Current state analysis
        current_paths = self.get_current_paths()          # RIPEstat
        current_latency = self.get_current_latency()      # RIPE Atlas
        path_stability = self.get_path_stability()        # RIPEstat history
        
        # Step 2: Target analysis
        target_presence = self.get_ix_presence(self.target_asn)  # PeeringDB
        target_policy = self.get_peering_policy(self.target_asn) # PeeringDB
        target_prefixes = self.get_prefix_count(self.target_asn) # RIPEstat
        
        # Step 3: Opportunity analysis
        common_ixes = self.find_common_ix_opportunities()  # PeeringDB
        latency_at_ix = self.estimate_latency_at_ix()      # RIPE Atlas
        
        # Step 4: Historical analysis
        target_stability = self.analyze_route_stability(self.target_asn)
        outage_history = self.get_outage_history(self.target_asn)
        
        # Step 5: Synthesize recommendation
        return self.build_report()
```

### 3.4 Example Output: Peering Evaluation

```
$ route-sherlock peering-eval --my-asn AS64500 --target AS13335

🔍 Peering Evaluation: AS64500 → AS13335 (Cloudflare)

## Current Connectivity

Your paths to AS13335 (Cloudflare):
┌─────────────────────────────────────────────────────────────┐
│ Path                          │ Hops │ Via         │ Seen  │
├───────────────────────────────┼──────┼─────────────┼───────┤
│ AS64500 → AS3356 → AS13335    │ 2    │ Lumen       │ 67%   │
│ AS64500 → AS174 → AS13335     │ 2    │ Cogent      │ 28%   │
│ AS64500 → AS6939 → AS13335    │ 2    │ HE          │ 5%    │
└─────────────────────────────────────────────────────────────┘

Latency baseline (RIPE Atlas, nearest probes to your ASN):
  • Frankfurt: 12ms (via AS3356)
  • Amsterdam: 14ms (via AS3356)
  • London: 11ms (via AS174)

Path stability (last 90 days):
  • 3 path changes detected
  • No significant outages
  • Stability score: 94/100 ✓

## Peering Opportunity Analysis

AS13335 (Cloudflare) IX Presence:
┌─────────────────────────────────────────────────────────────┐
│ IX              │ Location    │ You Present? │ Speed      │
├─────────────────┼─────────────┼──────────────┼────────────┤
│ DE-CIX Frankfurt│ Frankfurt   │ ✓ Yes        │ 100G       │
│ AMS-IX          │ Amsterdam   │ ✗ No         │ 400G       │
│ LINX            │ London      │ ✗ No         │ 200G       │
│ Equinix Ashburn │ Virginia    │ ✓ Yes        │ 100G       │
└─────────────────────────────────────────────────────────────┘

Cloudflare peering policy: OPEN
  • PeeringDB: "We peer with everyone"
  • Contact: peering@cloudflare.com
  • Requirements: None listed

## Estimated Impact

If you peer at DE-CIX Frankfurt:
┌─────────────────────────────────────────────────────────────┐
│ Metric              │ Current       │ Estimated After      │
├─────────────────────┼───────────────┼──────────────────────┤
│ AS-path length      │ 2 hops        │ 1 hop (direct)       │
│ Latency (Frankfurt) │ 12ms          │ ~1-2ms               │
│ Transit dependency  │ Via AS3356    │ Direct (no transit)  │
│ Prefixes received   │ 0 (transit)   │ ~2,847 (from CF)     │
└─────────────────────────────────────────────────────────────┘

Latency estimate based on:
  • Other DE-CIX members see 0.5-2ms to AS13335
  • Your presence at DE-CIX confirmed via PeeringDB

## Recommendation

✅ **RECOMMENDED: Peer with AS13335 at DE-CIX Frankfurt**

Reasons:
1. You're already present at DE-CIX (no new IX cost)
2. Cloudflare has an open peering policy
3. Estimated latency reduction: 10-11ms (83% improvement)
4. Removes transit dependency for Cloudflare traffic
5. AS13335 has stable routing history (94/100)

Next steps:
1. Contact peering@cloudflare.com
2. Reference PeeringDB: https://www.peeringdb.com/net/4224
3. Configure BGP session on your DE-CIX router

## Caveats

⚠️ Estimates based on public data. Actual results depend on:
  • Your traffic volume to Cloudflare (unknown to this tool)
  • Your port capacity at DE-CIX
  • Cloudflare's acceptance of your peering request

---
Data sources: RIPEstat, RIPE Atlas, PeeringDB
Analysis timestamp: 2025-01-04T15:30:00Z
```

---

## 4. Data Requirements Matrix

| Feature | RIPEstat | RIPE Atlas | PeeringDB | RPKI | BGPStream |
|---------|----------|------------|-----------|------|-----------|
| Incident Investigation | ✓✓✓ | ✓✓ | ✓ | ✓ | ✓✓ |
| Peering Evaluation | ✓✓ | ✓✓✓ | ✓✓✓ | ✓ | ✓ |
| Path Analysis | ✓✓✓ | ✓ | ✓ | - | ✓✓ |
| Latency Estimation | - | ✓✓✓ | ✓ | - | - |
| IX Opportunity | ✓ | ✓ | ✓✓✓ | - | - |
| Stability Scoring | ✓✓ | ✓ | - | - | ✓✓ |

Legend: ✓✓✓ = Primary source, ✓✓ = Important, ✓ = Supplementary

---

## 5. Updated Implementation Plan

### Phase 1: Core Data Layer (Week 1-2)

```
src/
├── collectors/
│   ├── ripestat.py       # Routing history, AS-paths, prefixes
│   ├── atlas.py          # Latency measurements, probe discovery
│   ├── peeringdb.py      # IX presence, peering policies
│   ├── rpki.py           # ROA validation
│   └── bgpstream.py      # Real-time/historical updates
├── models/
│   ├── asn.py            # AS representation
│   ├── prefix.py         # Prefix representation  
│   ├── path.py           # AS-path representation
│   ├── ix.py             # IX representation
│   └── timeline.py       # Event timeline
└── cache/
    └── store.py          # DuckDB-based caching
```

### Phase 2: Analysis Modules (Week 3-4)

```
src/
├── analyzers/
│   ├── incident.py       # Incident investigation logic
│   ├── peering.py        # Peering evaluation logic
│   ├── stability.py      # Route stability scoring
│   └── latency.py        # Latency analysis & estimation
```

### Phase 3: AI Synthesis (Week 5)

```
src/
├── synthesis/
│   ├── prompts/
│   │   ├── incident.txt      # Incident explanation prompt
│   │   └── peering.txt       # Peering recommendation prompt
│   ├── engine.py             # Claude API integration
│   └── validator.py          # Fact-check AI output against data
```

### Phase 4: CLI & Polish (Week 6)

```
src/
├── cli/
│   ├── main.py           # Typer CLI app
│   ├── investigate.py    # Incident investigation command
│   ├── peering.py        # Peering evaluation command
│   └── output.py         # Rich console formatting
```

---

## 6. Key Algorithms

### 6.1 Latency Estimation for Peering

```python
def estimate_latency_if_peered(my_asn: str, target_asn: str, ix: str) -> float:
    """
    Estimate latency to target if we peered at IX.
    
    Approach:
    1. Find RIPE Atlas probes at the IX (or in member networks)
    2. Get their measured latency to target
    3. Use as proxy for what we'd achieve
    """
    
    # Get IX member ASNs from PeeringDB
    ix_members = peeringdb.get_ix_members(ix)
    
    # Find Atlas probes in those networks
    probes_at_ix = []
    for member_asn in ix_members:
        probes = atlas.get_probes_by_asn(member_asn)
        probes_at_ix.extend(probes)
    
    # Get latency measurements from those probes to target
    # Use built-in anchor measurements where possible
    latencies = []
    for probe in probes_at_ix:
        measurement = atlas.get_latency(
            probe_id=probe.id,
            target=target_asn,
            timeframe="7d"
        )
        if measurement:
            latencies.append(measurement.min_rtt)
    
    # Return conservative estimate (median, not minimum)
    return statistics.median(latencies) if latencies else None
```

### 6.2 Path Stability Scoring

```python
def calculate_stability_score(asn: str, days: int = 90) -> StabilityScore:
    """
    Score 0-100 based on historical routing behavior.
    """
    
    history = ripestat.get_routing_history(asn, days=days)
    
    factors = {
        'path_changes': count_path_changes(history),
        'prefix_churn': count_prefix_changes(history),
        'outages': detect_outages(history),
        'flapping': detect_flapping(history),
        'rpki_issues': count_rpki_invalids(asn)
    }
    
    # Weighted scoring
    score = 100
    score -= factors['path_changes'] * 0.5      # -0.5 per path change
    score -= factors['prefix_churn'] * 0.3      # -0.3 per prefix change
    score -= factors['outages'] * 10            # -10 per outage
    score -= factors['flapping'] * 5            # -5 per flapping incident
    score -= factors['rpki_issues'] * 2         # -2 per RPKI issue
    
    return StabilityScore(
        value=max(0, min(100, score)),
        factors=factors,
        period_days=days
    )
```

### 6.3 Common IX Discovery

```python
def find_peering_opportunities(my_asn: str, target_asn: str) -> List[IXOpportunity]:
    """
    Find IXes where both ASNs are present, or where peering is possible.
    """
    
    my_presence = peeringdb.get_ix_presence(my_asn)
    target_presence = peeringdb.get_ix_presence(target_asn)
    
    opportunities = []
    
    # Already co-located (easy wins)
    common_ixes = set(my_presence.keys()) & set(target_presence.keys())
    for ix in common_ixes:
        opportunities.append(IXOpportunity(
            ix=ix,
            type="COMMON",
            my_speed=my_presence[ix].speed,
            target_speed=target_presence[ix].speed,
            effort="LOW"
        ))
    
    # Target is present, I'm not (requires new IX membership)
    target_only = set(target_presence.keys()) - set(my_presence.keys())
    for ix in target_only:
        ix_info = peeringdb.get_ix(ix)
        opportunities.append(IXOpportunity(
            ix=ix,
            type="JOIN_IX",
            target_speed=target_presence[ix].speed,
            ix_location=ix_info.city,
            effort="MEDIUM"
        ))
    
    return sorted(opportunities, key=lambda x: x.effort)
```

---

## 7. CLI Command Structure

```bash
# Incident Investigation
route-sherlock investigate <resource> [options]
  
  resource              ASN (AS64500) or prefix (192.0.2.0/24)
  --time, -t            Start time (ISO format or relative: "2h ago")
  --duration, -d        Duration to analyze (default: 1h)
  --output, -o          Output format: text, json, markdown
  --verbose, -v         Include raw data in output

# Examples:
route-sherlock investigate AS16509 --time "2025-01-01 14:00" --duration 2h
route-sherlock investigate 1.1.1.0/24 --time "yesterday 09:00"


# Peering Evaluation  
route-sherlock peering-eval [options]

  --my-asn, -m          Your ASN (required)
  --target, -t          Target ASN to evaluate (required)
  --ix, -i              Specific IX to evaluate (optional)
  --output, -o          Output format: text, json, markdown

# Examples:
route-sherlock peering-eval --my-asn AS64500 --target AS13335
route-sherlock peering-eval -m AS64500 -t AS13335 --ix "DE-CIX Frankfurt"


# Utility Commands
route-sherlock lookup <asn>           # Quick AS info
route-sherlock prefixes <asn>         # List announced prefixes
route-sherlock path <src> <dst>       # Show AS-path between two ASNs
route-sherlock stability <asn>        # Stability score only
route-sherlock ix-presence <asn>      # IX presence from PeeringDB
```

---

## 8. User Input Handling

For peering evaluation, some data improves the analysis:

```bash
# Optional: provide your IX presence if not in PeeringDB
route-sherlock peering-eval \
  --my-asn AS64500 \
  --target AS13335 \
  --my-ixes "DE-CIX Frankfurt,AMS-IX"

# Optional: provide your approximate traffic (helps prioritization)
route-sherlock peering-eval \
  --my-asn AS64500 \
  --target AS13335 \
  --traffic-estimate "500Gbps"  # Your total, not to this target
```

If user doesn't provide, we:
1. Check PeeringDB for their IX presence
2. Skip traffic-based prioritization
3. Note limitations in output

---

## 9. Example: Full Investigation Flow

```bash
$ route-sherlock investigate AS16509 --time "2025-01-01 14:00" -d 2h -v

🔍 Investigating AS16509 (AMAZON-02)
   Timeframe: 2025-01-01 14:00:00 to 16:00:00 UTC

📡 Collecting data...
   ├── RIPEstat routing history .......... 127 events
   ├── RIPEstat BGP updates .............. 342 updates  
   ├── RIPE Atlas latency ................ 47 probes
   ├── RPKI validation ................... 1,247 prefixes
   └── BGPStream real-time ............... 89 messages

🔬 Analyzing...
   ├── Timeline construction ............. done
   ├── Anomaly detection ................. 2 anomalies found
   ├── Latency correlation ............... done
   └── Impact assessment ................. done

📋 Synthesizing report...

═══════════════════════════════════════════════════════════════════

## Incident Report: AS16509 (Amazon)
### 2025-01-01 14:00 - 16:00 UTC

### Executive Summary

At **14:02:17 UTC**, AS16509 withdrew 12 prefixes from AS3356 (Lumen), 
shifting traffic to AS174 (Cogent). The event lasted **47 minutes** 
until prefixes were re-announced at 14:49:03 UTC.

RIPE Atlas measurements show European users experienced **+15ms latency** 
during this window. North American users were unaffected.

### Timeline

| Time (UTC)    | Event                                           |
|---------------|-------------------------------------------------|
| 14:02:17      | 12 prefixes withdrawn from AS3356               |
| 14:02:18      | Traffic shifts to AS174 path                    |
| 14:03:00-14:45| Elevated latency observed (EU probes)           |
| 14:49:03      | 12 prefixes re-announced via AS3356             |
| 14:51:00      | Latency returns to baseline                     |

### Affected Prefixes

- 52.94.0.0/15 (and 11 more-specifics)
- Full list in appendix

### Latency Impact

| Region        | Baseline | During Event | Delta    |
|---------------|----------|--------------|----------|
| Europe        | 22ms     | 37ms         | +15ms    |
| North America | 18ms     | 19ms         | +1ms     |
| Asia Pacific  | 145ms    | 152ms        | +7ms     |

### Probable Cause

Pattern matches **scheduled maintenance** on AS3356:
- Withdrawals were orderly (not flapping)
- Re-announcements were clean
- No RPKI issues detected
- Duration consistent with maintenance window

### Evidence

1. **RIPEstat:** 12 withdrawal events at 14:02:17, matching origin AS16509
2. **RIPE Atlas:** Probe 28441 (Frankfurt) latency spike 22ms → 38ms
3. **RIPE Atlas:** Probe 31445 (Amsterdam) latency spike 24ms → 41ms
4. **BGPStream:** Confirmed path change AS16509→AS3356 to AS16509→AS174

### RPKI Status

All affected prefixes: ✅ VALID
No ROA misconfigurations detected.

═══════════════════════════════════════════════════════════════════

📎 Raw data saved to: ./incident-AS16509-2025-01-01.json
```

---

## 10. Project Metadata

```toml
# pyproject.toml
[tool.poetry]
name = "route-sherlock"
version = "0.1.0"
description = "Historical BGP intelligence for network operators"
authors = ["Your Name <you@example.com>"]
license = "Apache-2.0"
readme = "README.md"
repository = "https://github.com/yourusername/route-sherlock"
keywords = ["bgp", "networking", "peering", "routing", "incident-response"]

[tool.poetry.dependencies]
python = "^3.11"
httpx = "^0.27"
typer = "^0.9"
rich = "^13"
pydantic = "^2"
duckdb = "^0.10"
anthropic = "^0.18"
pybgpstream = "^2"

[tool.poetry.scripts]
route-sherlock = "route_sherlock.cli.main:app"
```

---

## 11. Claude Code Kickoff Prompt

When you're ready to start implementation, use this in Claude Code:

```
I'm building an open-source BGP intelligence tool called "route-sherlock". 

Two main features:
1. Incident investigation: "What happened to ASN X at time Y?"
2. Peering evaluation: "Should I peer with ASN X at IX Y?"

Tech stack:
- Python 3.11+
- Poetry for dependencies
- httpx for async HTTP
- Typer + Rich for CLI
- DuckDB for caching
- Claude API for synthesis

Start by:
1. Initialize the project structure
2. Create the RIPEstat API client with these endpoints:
   - /routing-status/
   - /routing-history/
   - /announced-prefixes/
   - /as-path-length/
3. Add response caching with DuckDB
4. Write tests using pytest

I'll paste the full design doc for context.
```

---

## 12. Success Metrics

### POC Complete When:
- [ ] `investigate AS16509 --time "2025-01-01"` returns coherent report
- [ ] `peering-eval --my-asn AS64500 --target AS13335` returns recommendation
- [ ] All data sourced from public APIs (no user credentials required)
- [ ] Runs with `pip install route-sherlock && route-sherlock investigate ...`
- [ ] Report includes citations to data sources
- [ ] < 60 seconds for typical query

### Demo Ready When:
- [ ] Polished CLI output with Rich formatting
- [ ] 3-5 compelling example investigations prepared
- [ ] README with GIFs showing usage
- [ ] Comparison table vs. manual workflow

---

## 13. Potential AI Tinkerers Narrative

**Title:** "Route Sherlock: Open-Source BGP Intelligence with AI Synthesis"

**Hook:** "Every network engineer has asked 'what happened?' and spent an hour 
clicking through 5 different tools. What if you could just ask?"

**Demo Flow:**
1. Show the manual workflow (painful, multi-tool)
2. Run `route-sherlock investigate` on a real incident
3. Show the synthesized report in seconds
4. Run `peering-eval` for a "should I peer?" question
5. Discuss the AI synthesis layer (not just an API wrapper)

**Novelty Points:**
- First open-source tool to synthesize across BGP data sources
- AI adds genuine value (correlation + explanation, not just formatting)
- Solves real operator pain points
- Built entirely on public data

---

## Appendix: API Endpoint Quick Reference

### RIPEstat
```
GET https://stat.ripe.net/data/routing-status/data.json?resource=AS16509
GET https://stat.ripe.net/data/routing-history/data.json?resource=AS16509&starttime=2025-01-01
GET https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS16509
GET https://stat.ripe.net/data/as-path-length/data.json?resource=AS16509
GET https://stat.ripe.net/data/bgp-updates/data.json?resource=AS16509&starttime=...
GET https://stat.ripe.net/data/rpki-validation/data.json?resource=AS16509
```

### RIPE Atlas
```
GET https://atlas.ripe.net/api/v2/probes/?asn=16509
GET https://atlas.ripe.net/api/v2/measurements/{id}/results/
GET https://atlas.ripe.net/api/v2/anchors/
```

### PeeringDB
```
GET https://www.peeringdb.com/api/net?asn=16509
GET https://www.peeringdb.com/api/netixlan?asn=16509
GET https://www.peeringdb.com/api/ix/{id}
```

### RPKI
```
GET https://rpki-validator.ripe.net/api/v1/validity/AS16509/52.94.0.0/15
```
