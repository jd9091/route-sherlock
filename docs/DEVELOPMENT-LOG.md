# Route Sherlock Development Log

## Project Overview

**Purpose:** BGP intelligence CLI tool for network operators
**Language:** Python 3.11+
**Framework:** Typer CLI + Rich for terminal UI

---

## Development Timeline

### Phase 1: Core Infrastructure

**Initial Setup:**
- Created project structure with collectors, analysis, synthesis modules
- Implemented RIPEstat API client for real-time BGP data
- Implemented PeeringDB API client for network metadata
- Implemented RIPE Atlas client for measurements
- Built Typer CLI with Rich formatting

**Commands implemented:**
- `lookup` - Quick ASN/prefix lookup
- `peering-eval` - Evaluate peering opportunities
- `investigate` - Routing incident investigation
- `stability` - ASN stability scoring
- `ix-presence` - IX presence lookup
- `compare` - Side-by-side ASN comparison

### Phase 2: Python Upgrade

**Changes:**
- Upgraded from Python 3.9 to 3.11+
- Removed `eval_type_backport` dependency
- Updated `pyproject.toml` with `requires-python = ">=3.11"`

### Phase 3: AI Synthesis

**Implementation:**
- Created synthesis engine using Claude API
- Added `--ai` flag to `investigate` command
- Prompts designed for incident reports, peering recommendations

**Flow:**
```
Raw BGP Data → Structured Prompt → Claude API → Human-readable Report
```

### Phase 4: Historical Backtesting (BGPStream)

**Challenge:** RIPEstat only retains ~2-4 weeks of historical data

**Solution:** Integrated BGPStream/pybgpstream for RouteViews/RIPE RIS archives

**Installation:**
```bash
brew install bgpstream
CFLAGS="-I/opt/homebrew/include" LDFLAGS="-L/opt/homebrew/lib" pip install pybgpstream
```

**Created:** `src/route_sherlock/collectors/bgpstream.py`

**Features:**
- `BGPStreamClient.get_updates()` - Fetch historical BGP events
- `BGPStreamClient.detect_anomalies()` - Detect hijacks, leaks, path anomalies
- `BGPStreamClient.investigate_incident()` - Full incident investigation

**Added command:** `backtest`

### Phase 5: Anomaly Detection Improvements

**Problem 1:** False positives from prefix filtering
- Initial filter "1.1.1" matched "1.1.179.0/24"
- Fixed by using "1.1.1." (trailing dot)

**Problem 2:** Missed route leaks where origin was correct
- Route leak from AS262504 had correct origin (AS13335)
- Hijack detection didn't trigger because origin matched

**Solution:** Added path-based leak detection
```python
# Detect when path has unexpected ASes even if origin is correct
if expected_origin and origin == expected_origin and len(event.as_path) > 2:
    intermediate_ases = set(event.as_path[1:-1])
    # Compare against baseline paths...
```

### Phase 6: Incident Validation

**Test Case:** Cloudflare 1.1.1.1 hijack (June 27, 2024)

**Known facts from Cloudflare post-mortem:**
- AS267613 (Eletronet) announced 1.1.1.1/32 at 18:51 UTC
- AS262504 leaked 1.1.1.0/24 at 18:52 UTC
- Incident lasted until ~02:28 UTC next day

**Route Sherlock results:**
```
First anomaly: 2024-06-27 18:49:06 UTC (2 min before reported)
Route leaks: 329 events
AS path: 50763 → 1031 → 262504 → 267613 → 13335
Duration: 7.6 hours
```

**Validation:** PASSED - correctly identified ASes and timeline

### Phase 7: Peer Risk Feature (USP)

**Research:** Analyzed NANOG 93-95 presentations (2024-2025)
- No peer risk scoring tool presented
- BGPalerter handles real-time monitoring
- Gap identified: "Should I peer with this ASN?"

**Implemented:** `peer-risk` command

**Scoring Algorithm (100 points):**

| Category | Points | Factors |
|----------|--------|---------|
| Maturity | 0-20 | PeeringDB, IRR, policy URL, IX count |
| Stability | 0-30 | BGP update frequency (churn) |
| Incident History | 0-30 | Topology, upstream diversity |
| Policy | 0-10 | Open/Selective/Restrictive |
| Security | 0-10 | IRR registration, transit relationships |

**Risk Levels:**
- 80-100: LOW - Recommended
- 60-79: MODERATE - Acceptable with monitoring
- 40-59: ELEVATED - Caution
- 0-39: HIGH - Not recommended

**Validation:**
```
AS13335 (Cloudflare)  → 100/100 LOW
AS15169 (Google)      → 97/100 LOW
AS267613 (Eletronet)  → 72/100 MODERATE (flagged high churn)
```

---

## Files Created/Modified

### New Files
- `src/route_sherlock/collectors/bgpstream.py` - BGPStream client
- `docs/FEATURES.md` - Feature documentation
- `docs/NANOG-SUBMISSION.md` - Presentation submission
- `docs/DEVELOPMENT-LOG.md` - This file

### Modified Files
- `pyproject.toml` - Python 3.11+, removed eval_type_backport
- `src/route_sherlock/cli/main.py` - Added backtest, peer-risk commands
- `src/route_sherlock/cli/commands.py` - Added run_backtest, run_peer_risk
- `src/route_sherlock/synthesis/engine.py` - Added PEER_RISK_PROMPT

---

## Key Code Snippets

### Path-Based Leak Detection
```python
# bgpstream.py - detect_anomalies()
if expected_origin and origin == expected_origin and len(event.as_path) > 2:
    intermediate_ases = set(event.as_path[1:-1])
    for baseline in baseline_paths:
        if len(baseline) <= 2 and event.as_path[0] == baseline[0] and event.as_path[-1] == baseline[-1]:
            extra_ases = intermediate_ases
            for asn in extra_ases:
                if asn not in suspicious_ases_seen:
                    suspicious_ases_seen.add(asn)
                    anomalies.append(AnomalyDetection(
                        anomaly_type="path_leak",
                        timestamp=event.timestamp,
                        prefix=prefix,
                        description=f"Path leak: AS{asn} injected into path",
                        evidence={"as_path": event.as_path, "baseline_path": list(baseline)},
                        severity="high",
                    ))
```

### Peer Risk Scoring
```python
# commands.py - run_peer_risk()
# Determine risk level
if total_score >= 80:
    risk_level = "LOW"
    recommendation = "RECOMMENDED"
elif total_score >= 60:
    risk_level = "MODERATE"
    recommendation = "ACCEPTABLE"
elif total_score >= 40:
    risk_level = "ELEVATED"
    recommendation = "CAUTION"
else:
    risk_level = "HIGH"
    recommendation = "NOT RECOMMENDED"
```

---

## Environment Setup

```bash
# Create virtual environment
python3.11 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -e .

# BGPStream for historical data
brew install bgpstream
CFLAGS="-I/opt/homebrew/include" LDFLAGS="-L/opt/homebrew/lib" pip install pybgpstream

# Optional: AI synthesis
pip install anthropic
export ANTHROPIC_API_KEY="your-key"

# Optional: PeeringDB
export PEERINGDB_API_KEY="your-key"

# Run
export PYTHONPATH="src:$PYTHONPATH"
python -m route_sherlock.cli.main --help
```

---

## Future Enhancements

1. **RPKI Validation** - Check ROA coverage for target ASN prefixes
2. **Historical Incident Database** - Track known incidents per ASN
3. **Real-time Mode** - Optional real-time monitoring capability
4. **Web UI** - Browser-based interface
5. **Webhook Alerts** - Notify on risk score changes
6. **AS Relationship Data** - Integrate CAIDA relationship database
