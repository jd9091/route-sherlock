# Route Sherlock

Historical BGP intelligence CLI for network operators. Answer questions like *"Should I peer with this network?"* and *"What happened during that routing incident?"* by pulling from public BGP, RPKI, IRR, and PeeringDB sources and running them through transparent, rule-based scoring.

## What it does

| Question | Command |
|---|---|
| *Who is AS13335, and is it announcing anything?* | `lookup` |
| *Should I peer with this ASN?* (single-score, v1) | `peer-risk` |
| *Should I peer with this ASN?* (three-pillar audit, v2) | `peer-risk-v2` |
| *How does ASN A compare to ASN B?* | `compare` |
| *Where does this ASN show up at IXes?* | `ix-presence` |
| *What happened during this BGP incident?* | `backtest`, `investigate` |
| *Is this peering opportunity worth pursuing?* | `peering-eval` |

## How it works

Three layers: thin CLI on top, pluggable collectors on the bottom, scoring/synthesis in the middle. Every command goes through the same pipeline; what differs is which collectors fire and which scorer consumes the result. Collectors run concurrently via `asyncio.gather`, each one writes its result to the on-disk cache, and any one that returns `None` propagates as **UNKNOWN** through the v2 scorer rather than silently scoring 0 — that's the invariant that makes the output auditable.

```
┌────────────────────────────────────────────────────────────────────────────┐
│  route-sherlock CLI                                                        │
│  peer-risk-v2 · backtest · investigate · lookup · compare · ix-presence ·  │
│  peering-eval                                                              │
└────────────────────────────────────────────────────────────────────────────┘
                                     │
                                     ▼
┌────────────────────────────────────────────────────────────────────────────┐
│  Analysis & Scoring                                                        │
│  • Three-pillar audit (Track Record · Routing Hygiene · Coordination)      │
│    → Safeguards output: posture · filter strategy · max-prefix caps        │
│  • Incident analyzer (leak / hijack detection on historic windows)         │
│  • Optional Claude synthesis (`--ai`)                                      │
└────────────────────────────────────────────────────────────────────────────┘
                                     │
                                     ▼
┌────────────────────────────────────────────────────────────────────────────┐
│  Collectors (async, retry+backoff, cached at ~/.cache/route-sherlock)      │
│  ripestat · peeringdb · rpki · irr · bogons · contacts · grip · bgpstream  │
└────────────────────────────────────────────────────────────────────────────┘
                                     │
                                     ▼
                          External data sources

┌──────────────────────┐  ┌──────────────────────┐  ┌──────────────────────┐
│ RIPEstat             │  │ PeeringDB            │  │ Cloudflare rpki.json │
│                      │  │                      │  │                      │
│ Public BGP intel API.│  │ Network identity, IX │  │ The full Validated   │
│ Announced prefixes,  │  │ membership, peering  │  │ ROA Payload set.     │
│ neighbours, and BGP  │  │ policy, NOC + abuse  │  │ Audits every         │
│ update activity over │  │ contacts. The "who   │  │ announced prefix vs  │
│ time — the base      │  │ are they and how do  │  │ ROAs — the signal    │
│ layer for every      │  │ I reach them?" data. │  │ that says "are they  │
│ command.             │  │                      │  │ actually signing?".  │
└──────────────────────┘  └──────────────────────┘  └──────────────────────┘

┌──────────────────────┐  ┌──────────────────────┐  ┌──────────────────────┐
│ IRR (whois.radb.net) │  │ GRIP (Georgia Tech)  │  │ BGPStream →          │
│                      │  │                      │  │ RouteViews / RIS     │
│ AS-SET + route       │  │ Documented BGP       │  │                      │
│ object registrations.│  │ anomalies (~2019-).  │  │ Full-table BGP       │
│ What the ASN         │  │ Flags ASNs           │  │ archives. Replay any │
│ *claims* it will     │  │ historically         │  │ historic window to   │
│ announce — feeds     │  │ involved as          │  │ reconstruct the      │
│ prefix-filter        │  │ injector or          │  │ routing state during │
│ generation.          │  │ propagator.          │  │ a leak or hijack.    │
└──────────────────────┘  └──────────────────────┘  └──────────────────────┘
```

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for per-command data flow.

### Data sources in detail

#### RIPEstat — `https://stat.ripe.net/data/`

**What it is.** The RIPE NCC's public BGP intelligence API. Free, no key required, ~1000 req/day on the open tier. Built on top of the RIS (Routing Information Service) collectors, which peer with hundreds of networks worldwide and aggregate the global BGP view in near-real-time.

**Endpoints used.** `announced-prefixes` (what an ASN is currently announcing), `asn-neighbours` (upstreams + downstreams with neighbour-power weighting), `as-overview` (RIR + holder name), `bgp-update-activity` (update churn over a time window), `rpki-validation` (RIPEstat's own ROA validator — only used by v1's 8-prefix sample).

**Why it matters.** This is the canonical "what does this ASN look like in BGP *right now*" answer. Routing Hygiene needs the announced-prefix list to audit; Track Record needs neighbour topology for context; the v1 stability score is computed entirely from `bgp-update-activity`.

**Caveats.** Aggregates with minutes-to-hours latency, not seconds. Free-tier rate limit is real — the cache TTL (default 24h) exists specifically so a `peer-risk-v2` run on a big network doesn't burn the daily budget on a single ASN.

#### PeeringDB — `https://www.peeringdb.com/api`

**What it is.** The self-reported registry where networks publish their peering posture: which IXes they're at, what speed, what their policy is, who to contact at the NOC. The closest thing the industry has to a peering directory.

**Endpoints used.** `net` (network profile: name, info_type, info_prefixes4/6, policy_general, policy_url, irr_as_set), `netixlan` (IX membership with speed + ASN-port count), `poc` (NOC, abuse, technical, policy contacts).

**Why it matters.** Powers three pillars at once. **Maturity** rewards PeeringDB presence + IX count. **Coordination** scores entirely on POC presence (NOC and abuse). **Safeguards** derives max-prefix caps from `info_prefixes4` × multiplier. IX overlap (`peering-eval`) compares PeeringDB membership sets.

**Caveats.** Self-reported, so freshness varies wildly — Cloudflare keeps theirs minutes-fresh, a small regional network might have a 3-year-old record. Aggressive rate-limiting under load; collectors retry with exponential backoff but the policy/IX fields can silently degrade to `Unknown` if rate-limited mid-fetch. Setting `PEERINGDB_API_KEY` raises the ceiling.

#### Cloudflare rpki.json — `https://rpki.cloudflare.com/rpki.json`

**What it is.** A complete, continuously-updated dump of all Validated ROA Payloads (VRPs) — the cryptographic statements of "ASN X is authorized to announce prefix Y up to /Z". Cloudflare runs the RPKI validators and publishes the result as a single JSON blob for the entire global VRP set.

**How we use it.** `peer-risk-v2`'s Routing Hygiene pillar fetches the full VRP set once per run and audits **every** announced prefix of the target ASN against it locally. No per-prefix API calls. Each prefix is classified as `valid`, `invalid` (asn-mismatch or length-out-of-range), or `not-found`.

**Why it matters.** This is the difference between v1 (which sampled 8 prefixes from RIPEstat's validator) and v2 (which checks all of them). For a Tier-1 announcing 5,000+ prefixes, sampling is a coverage estimate; full audit gives you the real ROA coverage percentage and the exact invalid prefix list.

**Caveats.** The VRP set is built periodically (timestamp surfaced as `vrp_built_at` in output) — it's eventually-consistent with publication from the RIRs. A ROA published in the last hour may not appear yet.

#### IRR (Internet Routing Registry) — `whois.radb.net`

**What it is.** The pre-RPKI mechanism for declaring "ASN X intends to announce prefix Y". Distributed across ~25 IRR databases (RADB, NTTCOM, RIPE, ARIN, etc.); RADB is the largest aggregator and supports the persistent whois "expert mode" we need for fan-out queries.

**Queries used.** `!gAS<n>` (IPv4 route objects for ASN), `!6AS<n>` (IPv6 route objects), `!s<set>` (AS-SET expansion), and `-T as-set <name>` for last-modified metadata. All over a single persistent TCP connection per ASN to avoid per-prefix whois rate-limiting.

**Why it matters.** Operators build their inbound prefix filters from IRR data. If the target ASN's AS-SET resolves and covers ≥80% of what they actually announce, you can generate a tight prefix filter automatically. If the AS-SET is missing or only covers 30%, you're either accepting un-filtered announcements or doing hand-curated maintenance forever.

**Caveats.** Quality varies by database. Stale entries are common (multi-year-old prefix lists for networks that have since transferred). The `last_modified` timestamp on the AS-SET object is your freshness signal.

#### GRIP — `https://api.grip.inetintel.cc.gatech.edu/dev/json/events`

**What it is.** The Georgia Tech Internet Intelligence team's curated registry of documented BGP anomalies — leaks, hijacks, and misorigination events. Each event identifies the involved ASNs and labels each one's role: `injector` (caused the bad announcement), `propagator` (forwarded it), or `victim` (their prefix was hijacked).

**How we use it.** `peer-risk-v2`'s Track Record pillar queries GRIP for any event where the target ASN appears in the last N months (default 60). Each `injector`/`propagator` entry is weighted by role × recency × severity, summed, and a pattern bonus is applied if multiple events cluster across the window. `victim` appearances are counted but don't penalise.

**Why it matters.** Stability and topology metrics tell you what a network looks like *today*. GRIP tells you what they've actually done historically — the strongest single predictor of future routing risk. An ASN with three documented injector incidents over five years gets MEDIUM Track Record even if their current operational posture looks clean.

**Caveats.** Coverage starts ~2019. An absent record is not absence of history — older incidents (Spectrum/TWC 2015, Telia 2014, etc.) won't appear. Use the `--history-months` flag to narrow the window for stricter operational reads.

#### BGPStream → RouteViews / RIPE RIS — `https://bgpstream.caida.org/`

**What it is.** CAIDA's unified library over the two largest historical BGP archive projects: Oregon RouteViews and RIPE RIS. Together they collect full-table updates and snapshots from hundreds of vantage points worldwide and have done so continuously since the late 90s.

**How we use it.** `backtest` and `investigate` take a prefix or ASN + a time window, stream the relevant updates through the leak/hijack analyzer, and surface anomalies. This is the only path in Route Sherlock that touches historical data — everything else is "right now". The system library `libbgpstream` must be installed locally; we pin the Python bindings to the same venv.

**Why it matters.** When something went wrong yesterday, last week, or in 2019, this is how you reconstruct what the global routing table actually saw at that moment. Combined with the analyzer, it turns "we got blackholed at 18:49 UTC" into "AS50763 → AS1031 → AS262504 → AS267613 → AS13335 — confirmed leak, ROA-invalid".

**Caveats.** First query on a new window is slow — RouteViews/RIPE RIS dumps are pulled on demand and cached afterwards. Pre-warm the cache before any live demo.

## Installation

> All `pip install` steps below assume an **activated venv** running **Python 3.11**. Newer Pythons (3.14+) break `pipx`/`ensurepip` workarounds, and `pybgpstream` only ships wheels for the supported CPython line.

```bash
git clone https://github.com/jd9091/route-sherlock.git
cd route-sherlock

python3.11 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

pip install -e .

# Optional: AI synthesis
pip install -e ".[ai]"
export ANTHROPIC_API_KEY="your-key"

# Optional: better PeeringDB rate limits
export PEERINGDB_API_KEY="your-key"
```

### Optional: historical backtesting

`backtest` reads RouteViews / RIPE RIS archives via `libbgpstream`. The system library must be installed **before** the Python bindings, and the bindings must go into the same activated venv as `route-sherlock` itself.

```bash
brew install bgpstream             # macOS
# sudo apt install libbgpstream2-dev  # Debian/Ubuntu

source venv/bin/activate
pip install pybgpstream
```

> **First backtest is slow.** RouteViews / RIPE RIS dumps are pulled on demand and can take several minutes the first time a window is queried. Subsequent runs hit the local cache and return in under a second — pre-warm before any live demo.

## Commands

### `lookup` — quick ASN / prefix snapshot

Pulls basic identity and announcement state from RIPEstat plus PeeringDB metadata. No scoring.

```
$ route-sherlock lookup AS13335

╭──────────────────────────────────────────────────────────────────────────────╮
│ AS13335 - CLOUDFLARENET - Cloudflare, Inc.                                   │
╰──────────────────────────────────────────────────────────────────────────────╯
  Announced       ✓ Yes
  IPv4 Prefixes   2461
  IPv6 Prefixes   2982
  Upstreams       2494
  Top Upstreams   AS10030, AS10094, AS1031

PeeringDB:
  Policy       Open
  IXes         353
  IRR as-set   AS13335:AS-CLOUDFLARE
```

### `peer-risk` — single-score peering assessment (v1)

90-point composite across four weighted categories. Use for a fast read; use `peer-risk-v2` for an auditable breakdown.

```
$ route-sherlock peer-risk AS13335

╔══════════════════════════════ Peer Risk Score ═══════════════════════════════╗
║ 65/90 (72.2%)                                                                ║
║ Risk Level: MODERATE                                                         ║
║ Recommendation: ACCEPTABLE                                                   ║
╚══════════════════════════════════════════════════════════════════════════════╝

## Score Breakdown
╭───────────┬───────┬──────────────────────────────────────────────────────────╮
│ Category  │ Score │ Key Factors                                              │
├───────────┼───────┼──────────────────────────────────────────────────────────┤
│ Maturity  │ 20/20 │ PeeringDB registered (+5); IRR as-set: AS13335:... (+5); │
│           │       │ Published policy (+3); Strong IX presence: 353 IXes (+7) │
│ Stability │  5/30 │ High churn: 2,578,683/day across 5,443 prefixes =        │
│           │       │ 473.8/prefix/day (-25)                                   │
│ Topology  │ 30/30 │ Multiple upstreams (2494); RPKI sample: 7/8 valid        │
│ Security  │ 10/10 │ IRR registered (+3); Multiple transit (+2);              │
│           │       │ RPKI ROAs cover 88% of sampled prefixes (+3)             │
╰───────────┴───────┴──────────────────────────────────────────────────────────╯
```

Flags: `--ai` (Claude narrative) · `--json` (raw scoring) · `--output FILE` (write JSON to file) · `--cache-ttl SECONDS` (default 24h; 0 = bypass; 604800 = week for batch runs) · `--offline / -o` (cache-only; refuses network) · `--my-asn AS… / -m` (IX overlap) · `--days N / -d` (history window, default 90)

Add `--ai` for Claude-powered analysis on top of the numeric score:

```
$ route-sherlock peer-risk AS13335 --ai

## AI Risk Assessment
╭──────────────────────────────────── AI-Generated Risk Assessment ────────────────────────────────────╮
│                        BGP Peering Risk Assessment: AS13335 (Cloudflare)                             │
│                                                                                                      │
│                                          Executive Summary                                           │
│                                                                                                      │
│ Recommendation: PROCEED WITH MONITORING — establish peering with AS13335 with standard safeguards.   │
│ Current numeric score is 65/90 (MODERATE), driven entirely by an elevated stability signal           │
│ (473.8 updates/prefix/day across 5,443 prefixes); maturity, topology, and security all score full    │
│ marks. Cloudflare is one of the largest content networks globally with an open peering policy and    │
│ excellent operational maturity, so the stability flag warrants monitoring rather than rejection.     │
│                                                                                                      │
│                                           Key Risk Factors                                           │
│                                                                                                      │
│  1 Exceptional Network Maturity (20/20) — PeeringDB registered, IRR AS-set AS13335:AS-CLOUDFLARE,    │
│    published peering policy, and presence at 353 Internet Exchanges.                                 │
│  2 Robust Topology (30/30) — 2,494 upstream relationships across diverse tier-1 carriers, RPKI       │
│    sample at 7/8 valid.                                                                              │
│  3 Stability Caveat (5/30) — 473.8 updates/prefix/day exceeds the >50 high-churn threshold even      │
│    after per-prefix normalisation. Consistent with best-path churn on a globally-anycast network,    │
│    but worth monitoring during turn-up.                                                              │
│                                                                                                      │
│                                     Operational Recommendations                                      │
│                                                                                                      │
│  • Standard peering process via Cloudflare's published policy URL                                    │
│  • Set tight max-prefix utilisation alerts (80% of hard cap)                                         │
│  • Re-run `peer-risk` monthly; widen `--days` if stability remains the only flagged signal           │
│                                                                                                      │
│                                         Technical Safeguards                                         │
│                                                                                                      │
│ Max-Prefix Limits (from peer-risk-v2 Safeguards output):                                             │
│  • IPv4: 104,000 (hard cap, ~1.3× declared)                                                          │
│  • IPv6: 39,000  (hard cap, ~1.3× declared)                                                          │
│                                                                                                      │
│ IRR Filtering: filter against AS13335:AS-CLOUDFLARE; validate received prefixes against IRR objects. │
│ RPKI Policy: prefer-valid; reject invalid; accept not-found (Cloudflare ROA coverage is 95.6%).      │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

### `peer-risk-v2` — three-pillar peering audit

Drops the composite for three pillars classified independently: **Track Record**, **Routing Hygiene**, **Coordination**. Each returns LOW / MEDIUM / HIGH / **UNKNOWN** (preferred to a false LOW on collector failure) and the result terminates in a graduated `Safeguards` block — not a binary verdict.

```
$ route-sherlock peer-risk-v2 AS13335

╭────────────────────── Peer Risk: AS13335 (Cloudflare) ───────────────────────╮
│  Track Record     LOW                                                        │
│    • appears as VICTIM in 5 incident(s) (not a fault signal)                 │
│                                                                              │
│  Routing Hygiene  LOW                                                        │
│    • ROA coverage: 95.6% (5,203 / 5,443 prefixes valid)                      │
│    • ROA invalids: 8 (0.15% of announced) — informational                    │
│    • AS-SET: AS13335:AS-CLOUDFLARE (modified 2026-03-10)                     │
│    • IRR route-object coverage: 92.6%                                        │
│    • Bogons: none observed                                                   │
│                                                                              │
│  Coordination     LOW                                                        │
│    • NOC contact: noc@cloudflare.com                                         │
│    • Abuse contact: abuse@cloudflare.com                                     │
│                                                                              │
│  Posture: PEER-STANDARD                                                      │
│  Filter strategy: ROA-permissive (accept ROA-valid + AS-SET prefix-list)    │
│  Max-prefix v4: 104,000 (hard cap)                                           │
│  Max-prefix v6:  39,000 (hard cap)                                           │
│                                                                              │
│  Data sources: PeeringDB · RIPEstat announced-prefixes (5443) · RPKI VRP    │
│  set (Cloudflare rpki.json, audited 5443 prefixes) · IRR via whois.radb.net │
│  · PeeringDB POCs · GRIP API (7 total events, 0 attacker-role)              │
╰──────────────────────────────────────────────────────────────────────────────╯
```

Flags: `--history-months N` (default 60; use 24 for stricter operational read) · `--json`

### `compare` — side-by-side ASNs

```
$ route-sherlock compare AS13335 AS15169

╔══════════════════════════════════════════════════════════════════════════════╗
║ AS13335 vs AS15169                                                           ║
╚══════════════════════════════════════════════════════════════════════════════╝

╭────────────────┬───────────────┬───────────┬─────────╮
│ Metric         │       AS13335 │   AS15169 │ Winner  │
├────────────────┼───────────────┼───────────┼─────────┤
│ Name           │ CLOUDFLARENET │    GOOGLE │         │
│ IPv4 Prefixes  │         2,461 │     1,222 │ AS13335 │
│ IPv6 Prefixes  │         2,982 │       175 │ AS13335 │
│ Upstreams      │         2,494 │       334 │ AS13335 │
│ IXes           │           353 │       179 │ AS13335 │
│ Peering Policy │          Open │ Selective │         │
╰────────────────┴───────────────┴───────────┴─────────╯
```

### `ix-presence` — IX membership

```
$ route-sherlock ix-presence AS13335

🌐 IX Presence: AS13335

Cloudflare is present at 353 IXes

╭──────────────────────────┬──────────────────────┬───────┬───────╮
│ Internet Exchange        │ Location             │ Speed │ Ports │
├──────────────────────────┼──────────────────────┼───────┼───────┤
│ IX.br (PTT.br) São Paulo │ São Paulo/SP, BR     │ 1400G │   2   │
│ DE-CIX Frankfurt         │ Frankfurt, DE        │ 1200G │   2   │
│ BBIX Tokyo               │ Tokyo, JP            │ 1000G │   2   │
│ AMS-IX                   │ Amsterdam, NL        │ 1000G │   2   │
│ SIX Seattle              │ Seattle, US          │  800G │   2   │
│ France-IX Paris          │ Paris, FR            │  800G │   2   │
│ LINX LON1                │ London, GB           │  600G │   2   │
│ Equinix Chicago          │ Chicago, US          │  600G │   2   │
│ ...                      │                      │       │       │
╰──────────────────────────┴──────────────────────┴───────┴───────╯
```

### `backtest` — historical incident analysis

Replays RouteViews / RIPE RIS archives through the leak/hijack detector. Requires `pybgpstream`.

```
$ route-sherlock backtest 1.1.1.0/24 --origin AS13335 --time "2024-06-27 18:00" --duration 3h

🚨 Anomalies Detected: 329

#1 [HIGH] LEAK
   Time: 2024-06-27T18:49:06
   AS Path: 50763 → 1031 → 262504 → 267613 → 13335
```

### `investigate` — recent routing investigation

```
$ route-sherlock investigate AS16509 --time "2h ago"
```

### `peering-eval` — peering opportunity scoring

Combines IX overlap, path improvement potential, and target risk into a single recommendation.

```
$ route-sherlock peering-eval --my-asn AS6939 --target AS13335
```

## Scoring methodology

### v1 (`peer-risk`) — 90-point composite

Four categories, weighted, summed, then bucketed by percentage. If a collector fails, that category drops out (score=None) and `max_score` shrinks proportionally so the percentage stays honest.

| Category | Max | Drawn from | Scoring rules |
|---|---|---|---|
| **Maturity** | 20 | PeeringDB | PeeringDB registered (+5), IRR as-set declared (+5), policy URL (+3), IX presence: ≥10 (+7) / ≥5 (+5) / ≥1 (+2) |
| **Stability** | 30 | RIPEstat updates + announced-prefix count | Start at 30, deduct by **per-prefix-per-day** update rate: >50 (-25), >10 (-15), >2 (-5). Fail → score=None, category drops |
| **Topology** | 30 | RIPEstat neighbours, RIPEstat RPKI sample | Start at 30, deduct (-5) for single upstream. RPKI sample (8 prefixes) is reported here but doesn't deduct |
| **Security** | 10 | PeeringDB, RIPEstat, RPKI sample | Base 5 + IRR registered (+3) + multiple transit (+2). RPKI: ≥50% sampled valid (+3), partial (+1), any invalid (-3) |

> **No Policy category.** It was dropped because self-declared peering policy measures willingness, not operational risk, and double-counted what Maturity rewards for PeeringDB hygiene. Policy still surfaces on the Network Profile panel.

| Percentage | Risk | Verdict |
|---|---|---|
| 80–100% | LOW | RECOMMENDED |
| 60–79% | MODERATE | ACCEPTABLE |
| 40–59% | ELEVATED | CAUTION |
| 0–39% | HIGH | NOT RECOMMENDED |

### v2 (`peer-risk-v2`) — three pillars, rule-scored

Pillars classified independently. UNKNOWN is preferred over a false LOW on collector failure.

#### Track Record (0–10, capped)
**Source:** GRIP API (Georgia Tech, ~2019-present). **Rule:** per-event weight by `(role × recency × severity)`:

| Role | Recency | Severity: critical / high / medium |
|---|---|---|
| injector | recent (≤24mo) | 9 / 7 / 4 |
| injector | older | 5 / 3 / 1 |
| propagator | recent | 5 / 4 / 2 |
| propagator | older | 2 / 1 / 1 |

Plus a **pattern bonus**: 2 fault events `+3`, ≥3 `+5`. Cap 10. **Victim** appearances are summarized but not scored. **Classification:** 0–2 LOW · 3–6 MEDIUM · 7+ HIGH.

#### Routing Hygiene (0–10, capped)
**Sources:** RPKI VRPs (Cloudflare rpki.json) audited against **all** announced prefixes, bogon checker, IRR via whois.radb.net, PeeringDB AS-SET. **Rules:**

- ROA coverage <60% `+4` · <85% `+2`
- ROA invalids (ratio-based): ≥5% `+4` · ≥1% `+2` · ≥0.5% `+1` · <0.5% informational only
- Bogon announcements observed: `+3`
- AS-SET missing in IRR / not declared: `+2`
- IRR route-object coverage <80%: `+1`

**Classification:** 0–2 LOW · 3–5 MEDIUM · 6+ HIGH.

#### Coordination (0–10, capped)
**Source:** PeeringDB POCs. **Rules:** NOC contact absent `+4`, abuse contact absent `+4`. Technical and policy contacts are informational only (their absence with NOC+abuse present is acceptable practice). **Classification:** 0 LOW · 1–3 MEDIUM · 4+ HIGH.

#### Safeguards (the v2 output)

Posture is derived from the pillar matrix:

| Posture | Triggered by |
|---|---|
| `PEER-STANDARD` | All pillars LOW |
| `PEER-WITH-SAFEGUARDS` | Routing Hygiene HIGH, or any pillar MEDIUM/HIGH not covered below |
| `PEER-CAUTIOUSLY` | Track Record MEDIUM and Routing Hygiene HIGH |
| `INVESTIGATE-FIRST` | Track Record HIGH |
| `INSUFFICIENT-DATA` | Two or more pillars UNKNOWN |

Each posture maps to a **filter strategy** (`ROA-permissive`, `standard-IRR+ROA`, `strict-IRR`, `strict-IRR+ROA`), **max-prefix caps** (declared × 1.3 for backbones with >30 upstreams, × 1.5 otherwise), and pre-flight + monitoring checklists.

## Data sources

| Source | Provides | Used by |
|---|---|---|
| **RIPEstat** | Announced prefixes, neighbours, AS-path updates, RPKI sample | lookup, peer-risk, peer-risk-v2, compare, backtest, investigate |
| **PeeringDB** | Network metadata, IX membership, peering policy, NOC/abuse contacts | lookup, peer-risk, peer-risk-v2, ix-presence, peering-eval |
| **Cloudflare rpki.json** | Full VRP set for ROA validation across **all** announced prefixes (v2) | peer-risk-v2 (Routing Hygiene) |
| **whois.radb.net (IRR)** | as-set registration, prefix coverage | peer-risk-v2 (Routing Hygiene) |
| **Bogon checker** | Bogon prefix / private-ASN detection | peer-risk-v2 (Routing Hygiene) |
| **GRIP** (Georgia Tech) | Documented BGP anomalies, attacker-role clustering | peer-risk-v2 (Track Record) |
| **BGPStream → RouteViews / RIPE RIS** | Historical full-table archives | backtest, investigate |
| **Claude API** | Optional narrative on top of scored output | `--ai` |

## Caching & offline mode

All collectors write to `~/.cache/route-sherlock/` with per-source TTLs. Time-bounded historical queries (BGP updates with explicit start/end) are cached **indefinitely** — they describe frozen windows. Cold first run on a new ASN takes ~2 minutes (RPKI sampling dominates); warm cache returns in <1s. `--offline` on `peer-risk` refuses network calls entirely; `--cache-ttl 0` bypasses cache; `--cache-ttl 604800` pins for week-long research runs.

## Known limitations

- **Rate limits.** RIPEstat tolerates ~1000 req/day on the free tier; PeeringDB rate-limits aggressively and silently degrades policy/IX fields to `Unknown` rather than failing. Collectors retry with exponential backoff + jitter, but large batch runs will feel it.
- **Cold-cache latency.** First call against a new ASN takes ~2 minutes. Use `--offline` to force cache-only.
- **Data lag.** PeeringDB is self-reported; RIPEstat aggregates with minutes-to-hours latency; BGPStream archives are minutes behind real-time.
- **v1 stability sensitivity.** The per-prefix-per-day threshold (>50 = high churn) can still flag legitimate large networks during periods of heavy best-path churn — e.g. AS13335 currently lands at 473/prefix/day across 5,443 prefixes. Operationally, treat `--days` widening and v2's lack of a stability pillar as cross-checks.
- **v1 RPKI is sampled.** `peer-risk` only checks 8 prefixes; `peer-risk-v2` audits all announced prefixes against the full VRP set.
- **IX overlap counts membership, not peerability.** Today the score intersects PeeringDB IX IDs; it doesn't yet check operational status, route-server availability, policy compatibility, or speed mismatch.
- **No point-in-time scoring.** `--days N` is a rolling window from *now*; there is no `--as-of <date>` yet.
- **GRIP coverage.** ~2019-present; older incidents (pre-2019) are not in the registry, so an absent record is not absence of history.

## Documentation

- [Architecture](docs/ARCHITECTURE.md) — system design, per-command data flow
- [Features](docs/FEATURES.md) — detailed feature documentation
- [Development Log](docs/DEVELOPMENT-LOG.md) — development history

## Requirements

- Python 3.11+
- `bgpstream` (only for `backtest` / `investigate`)

## Contributing

Issues, methodology critiques, and PRs welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for dev setup and open work items.

- [Bug report](https://github.com/jd9091/route-sherlock/issues/new?template=bug_report.md) · [Feature request](https://github.com/jd9091/route-sherlock/issues/new?template=feature_request.md) · [Methodology critique](https://github.com/jd9091/route-sherlock/issues/new?template=methodology.md)
- Open-ended discussion: [GitHub Discussions](https://github.com/jd9091/route-sherlock/discussions)
- Private: davejd2990@gmail.com

## License

Apache-2.0
