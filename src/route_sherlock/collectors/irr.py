"""IRR queries against RADB / RIPE / ARIN / APNIC / LACNIC / AFRINIC.

We use whois.radb.net's persistent expert-mode protocol so a single TCP
connection can return every IRR-registered route for an ASN in two queries.
This avoids the per-prefix whois fan-out that would otherwise rate-limit us.

Expert-mode commands used:
- ``!!``  enable persistent mode (otherwise the server closes after one query)
- ``!gAS<num>``  list all IPv4 routes registered for this origin AS
- ``!6AS<num>``  list all IPv6 routes registered for this origin AS

Coverage is computed as the intersection of the AS's announced prefix set
(from RIPEstat) with the IRR-registered prefix set. Unregistered announcements
are the actionable signal — they're what upstreams can't filter.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from ipaddress import ip_network


@dataclass
class IRRCoverageResult:
    asn: int
    announced_prefixes: int
    registered_prefixes: int
    coverage_percent: float
    unregistered_examples: list[str] = field(default_factory=list)  # first ~10 missing
    error: str | None = None


@dataclass
class ASSetStatus:
    asn: int
    as_set_name: str | None       # from PeeringDB (None if not declared)
    exists_in_irr: bool
    last_modified: str | None = None
    error: str | None = None


async def _whois_query(commands: list[str], host: str = "whois.radb.net", port: int = 43,
                       timeout: float = 30.0) -> str:
    """Open a persistent whois session, send commands in order, return concatenated response."""
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port), timeout=timeout,
    )
    try:
        # Enable persistent / expert mode
        writer.write(b"!!\n")
        for cmd in commands:
            writer.write(f"{cmd}\n".encode())
        writer.write(b"!q\n")  # quit
        await writer.drain()
        chunks: list[bytes] = []
        while True:
            chunk = await asyncio.wait_for(reader.read(65536), timeout=timeout)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks).decode("utf-8", errors="replace")
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


def _parse_g_response(response: str) -> list[str]:
    """Extract prefix list from a !g/!6 response.

    Response format (RIPE-153 query response):
        A<byte-count>
        prefix1 prefix2 prefix3 ...
        C

    There can be multiple A-blocks for batched commands. Treat each whitespace
    token between an A-line and a C-line as a prefix.
    """
    prefixes: set[str] = set()
    in_block = False
    for line in response.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("A"):
            in_block = True
            continue
        if line in {"C", "D"}:
            in_block = False
            continue
        if line.startswith(("F", "E")):  # F = no match, E = error
            in_block = False
            continue
        if in_block:
            for tok in line.split():
                # Sanity-check: looks like a CIDR prefix
                try:
                    ip_network(tok, strict=False)
                    prefixes.add(tok)
                except ValueError:
                    pass
    return sorted(prefixes)


async def get_irr_coverage(asn: int, announced_prefixes: list[str]) -> IRRCoverageResult:
    """Compute % of announced prefixes that have an IRR route(6) object."""
    try:
        response = await _whois_query([f"!gAS{asn}", f"!6AS{asn}"])
    except (asyncio.TimeoutError, OSError) as e:
        return IRRCoverageResult(
            asn=asn, announced_prefixes=len(announced_prefixes),
            registered_prefixes=0, coverage_percent=0.0,
            error=f"whois query failed: {e}",
        )

    registered = set(_parse_g_response(response))
    announced_set = {p.strip() for p in announced_prefixes if p.strip()}

    covered = announced_set & registered
    missing = announced_set - registered

    coverage = 100.0 * len(covered) / max(len(announced_set), 1)
    return IRRCoverageResult(
        asn=asn,
        announced_prefixes=len(announced_set),
        registered_prefixes=len(registered),
        coverage_percent=coverage,
        unregistered_examples=sorted(missing)[:10],
    )


def _canonical_as_set_candidates(asn: int, network_name: str | None) -> list[str]:
    """Generate likely AS-SET names for an operator that didn't declare one in PeeringDB.

    Tier-1 carriers (Verizon, AT&T, Lumen, NTT, Telia) routinely leave the
    PeeringDB ``irr_as_set`` field empty even though they maintain AS-SETs
    in RADB/RIPE under canonical names. We try common patterns before
    concluding the operator has no AS-SET.
    """
    candidates: list[str] = [f"AS{asn}:AS-CUSTOMERS"]  # newer per-AS convention
    if network_name:
        # Extract a likely brand token: first capitalised word or longest token
        token = "".join(c for c in network_name.upper() if c.isalnum() or c == " ").strip()
        if token:
            first_word = token.split()[0]
            if len(first_word) >= 3:
                candidates.extend([
                    f"AS-{first_word}",
                    f"AS-{first_word}-CUSTOMER",
                    f"AS-{first_word}-CUSTOMERS",
                    f"AS{asn}:AS-{first_word}",
                ])
    return candidates


async def _lookup_as_set_in_irr(name: str) -> tuple[bool, str | None]:
    """Query whois for an AS-SET name. Returns (exists, last_modified)."""
    try:
        response = await _whois_query([f"!s{name}", f"-T as-set {name}"])
    except (asyncio.TimeoutError, OSError):
        return False, None
    exists = False
    last_modified: str | None = None
    for line in response.splitlines():
        s = line.strip()
        if s.lower().startswith("as-set:"):
            exists = True
        elif s.lower().startswith(("last-modified:", "changed:")):
            last_modified = s.split(":", 1)[1].strip()
    return exists, last_modified


async def check_as_set(asn: int, as_set_name: str | None,
                      network_name: str | None = None) -> ASSetStatus:
    """Check that an AS-SET for this operator exists in IRR.

    Lookup strategy:
    1. If PeeringDB ``irr_as_set`` is declared, verify it.
    2. If empty, try canonical fallbacks derived from the network name —
       this catches Tier-1 carriers that maintain AS-SETs in RADB without
       publishing the name in PeeringDB.
    3. Only after both fail do we report "missing".
    """
    # Strategy 1: declared AS-SET
    if as_set_name:
        name = as_set_name
        if "::" in name:
            name = name.split("::", 1)[1]
        if "@" in name:
            name = name.split("@", 1)[0]
        name = name.strip()
        exists, last_modified = await _lookup_as_set_in_irr(name)
        if exists:
            return ASSetStatus(asn=asn, as_set_name=name,
                              exists_in_irr=True, last_modified=last_modified)
        # Declared but not found: explicit error case (worse than missing)
        return ASSetStatus(
            asn=asn, as_set_name=name, exists_in_irr=False,
            error="declared in PeeringDB but not resolvable in IRR",
        )

    # Strategy 2: canonical-name fallback
    candidates = _canonical_as_set_candidates(asn, network_name)
    for cand in candidates:
        exists, last_modified = await _lookup_as_set_in_irr(cand)
        if exists:
            return ASSetStatus(
                asn=asn, as_set_name=f"{cand} (discovered)",
                exists_in_irr=True, last_modified=last_modified,
            )

    # Strategy 3: truly missing
    return ASSetStatus(
        asn=asn, as_set_name=None, exists_in_irr=False,
        error="no AS-SET declared in PeeringDB and no canonical fallback found in IRR",
    )
