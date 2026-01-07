# NANOG Presentation Submission

## Submission Form Fields

### Presentation Title
```
Peer Risk Intelligence: Should You Peer With That ASN?
```

### Phone Number
```
[YOUR PHONE NUMBER]
```

### Presentation Format
```
[X] Open to presenting either in person or remotely
```

### User-Requested Duration
```
30 minutes
```

---

### Abstract (Will be published on Agenda)

```
Network operators make peering decisions based on incomplete information -
PeeringDB profiles, gut feel, and word of mouth. But what if you could
answer "Is this network safe to peer with?" using data?

This talk introduces Route Sherlock, an open-source CLI tool that provides
Peer Risk Intelligence for network operators. It combines data from RIPEstat,
PeeringDB, and BGPStream to generate a quantified risk score for any ASN,
helping you make informed peering decisions before establishing BGP sessions.

Key features demonstrated:
- Peer risk scoring algorithm (stability, incident history, network maturity)
- Historical incident backtesting against real BGP archives
- AI-powered synthesis of complex routing data
- Practical safeguards based on risk level (prefix limits, IRR filtering)

Live demo includes:
- Scoring real networks (Cloudflare, Google, and networks involved in incidents)
- Backtesting against the June 2024 Cloudflare 1.1.1.1 route leak
- IX overlap analysis for peering feasibility

Attendees will leave with:
- A free, open-source tool they can use immediately
- Understanding of what makes a network "risky" from a peering perspective
- Practical configuration templates for different risk levels
```

---

### Author Comment (Will not be published on Agenda)

```
This presentation addresses a gap I've identified in the open-source BGP
tooling landscape. While tools like BGPalerter and ARTEMIS handle real-time
monitoring, no open-source tool answers the pre-peering question: "Should I
peer with this network?"

I've validated the tool against real incidents:
- The June 2024 Cloudflare 1.1.1.1 hijack/leak was correctly detected
- AS267613 (Eletronet, involved in the incident) scores 72/100 "MODERATE RISK"
- The tool flagged their high BGP churn (1637 updates/day) as a warning

The talk includes live demos - all code is open source and attendees can
follow along or try it themselves. The risk scoring algorithm is transparent
and based on measurable factors, not black-box ML.

Target audience: Network engineers, peering coordinators, NOC teams
Technical level: Intermediate (assumes basic BGP knowledge)
```

---

### Materials for PC Review

**Suggested attachments:**

1. **Slide deck outline** (see below)
2. **Demo script** with expected outputs
3. **GitHub repository link** (if public)

---

## Presentation Outline (30 minutes)

### 1. The Problem (5 min)
- Current peering decision process (PeeringDB + gut feel)
- Real incident: Cloudflare 1.1.1.1 hijack story
- The question we can't easily answer: "Is this ASN safe to peer with?"

### 2. Introducing Route Sherlock (3 min)
- Open-source CLI tool
- Data sources: RIPEstat, PeeringDB, BGPStream
- Optional AI synthesis via Claude API

### 3. Live Demo: Peer Risk Command (10 min)
```bash
# Score a well-known network
route-sherlock peer-risk AS13335

# Score a network involved in incidents
route-sherlock peer-risk AS267613

# Check IX overlap for peering feasibility
route-sherlock peer-risk AS15169 --my-asn AS13335
```

**Show:**
- Score breakdown (Maturity, Stability, Incident History, Policy, Security)
- Warnings and recommendations
- IX overlap analysis

### 4. Under the Hood: Scoring Algorithm (5 min)
- Maturity factors (PeeringDB completeness, IRR registration)
- Stability factors (BGP update frequency analysis)
- What makes a network "risky"

### 5. Validation: Backtesting Real Incidents (5 min)
```bash
route-sherlock backtest 1.1.1.0/24 --origin AS13335 --time "2024-06-27 18:00"
```

**Show:**
- Detection of AS267613/AS262504 in leak path
- Timeline correlation with Cloudflare's post-mortem
- Anomaly types: hijack vs leak vs path injection

### 6. Practical Application (2 min)
- Sample configurations for different risk levels
- Prefix limit recommendations
- IRR filtering templates

### 7. Q&A / Getting Started (remaining time)
- Installation steps
- GitHub link
- Future roadmap

---

## Key Talking Points

1. **Novelty**: No existing open-source tool provides peer risk scoring
2. **Validation**: Tested against real incidents with verifiable results
3. **Practical**: Outputs actionable recommendations, not just data
4. **Transparent**: Scoring algorithm is visible and adjustable
5. **Open Source**: Free for the community to use and extend

---

## Demo Script

### Demo 1: Score Cloudflare
```bash
$ route-sherlock peer-risk AS13335

╔══════════════════════════════ Peer Risk Score ═══════════════════════════════╗
║ 100/100 (100.0%)                                                             ║
║ Risk Level: LOW                                                              ║
║ Recommendation: RECOMMENDED                                                  ║
╚══════════════════════════════════════════════════════════════════════════════╝

# Point out: Perfect score, Open policy, 350 IXes, IRR registered
```

### Demo 2: Score Eletronet (involved in incident)
```bash
$ route-sherlock peer-risk AS267613

╔══════════════════════════════ Peer Risk Score ═══════════════════════════════╗
║ 72/100 (72.0%)                                                               ║
║ Risk Level: MODERATE                                                         ║
║ Recommendation: ACCEPTABLE                                                   ║
╚══════════════════════════════════════════════════════════════════════════════╝

## ⚠️ Warnings
   • High BGP churn detected: 1637 updates/day

# Point out: Stability score 5/30, high churn warning
# This is the network that caused the Cloudflare incident!
```

### Demo 3: IX Overlap
```bash
$ route-sherlock peer-risk AS15169 --my-asn AS13335

## IX Overlap
   Common IXes: 164
   Your IXes: 350 | Target IXes: 198
   ✓ Can peer at 164 location(s)

# Point out: Practical for peering coordinators
```

### Demo 4: Backtest
```bash
$ route-sherlock backtest 1.1.1.0/24 --origin AS13335 --time "2024-06-27 18:00" --duration 8h

🚨 Anomalies Detected: 329

#1 [HIGH] LEAK
   Time: 2024-06-27T18:49:06
   AS Path: 50763 → 1031 → 262504 → 267613 → 13335

# Point out: Detected 2 minutes before Cloudflare reported
```

---

## Backup Slides / FAQ

**Q: How is this different from BGPalerter?**
A: BGPalerter monitors your own prefixes in real-time. Route Sherlock evaluates other networks before you peer with them - it's pre-peering intelligence, not monitoring.

**Q: Why not just use PeeringDB?**
A: PeeringDB tells you about a network's presence and policy, but not their routing behavior or stability. Route Sherlock combines PeeringDB data with actual BGP behavior analysis.

**Q: What about RPKI validation?**
A: Currently noted as a future enhancement. The tool checks for IRR registration as a proxy for routing hygiene.

**Q: Can this detect hijacks in real-time?**
A: No - use BGPalerter or ARTEMIS for that. Route Sherlock is for historical analysis and pre-peering risk assessment.
