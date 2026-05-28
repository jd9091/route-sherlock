"""RPKI bulk validation against the global VRP (Validated ROA Payload) set.

Replaces route-sherlock v1's 8-prefix sampling with a full audit of every
announced prefix. Source-of-truth is the Cloudflare RPKI portal's `rpki.json`
dump, which is built from `rpki-client` against the five TALs (AFRINIC, APNIC,
ARIN, LACNIC, RIPE NCC) and refreshed every ~10 minutes.

Validation logic follows RFC 6811:
- VALID      — at least one covering ROA matches the origin AS AND the
               announced prefix length <= ROA.maxLength
- INVALID    — at least one ROA covers the announced prefix, but no covering
               ROA matches both origin AS and length constraint
- NOT_FOUND  — no covering ROA exists for this prefix

Coverage is computed against the announced-prefix set, not the routing-table
sample.
"""
from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

import httpx
import radix

VRP_URL = "https://rpki.cloudflare.com/rpki.json"
CACHE_DIR = Path.home() / ".cache" / "route-sherlock" / "rpki"
VRP_CACHE_FILE = CACHE_DIR / "cloudflare-vrp.json"
VRP_TTL_SECONDS = 6 * 3600  # VRP updates every ~10min upstream; 6h is conservative


class RPKIStatus(str, Enum):
    VALID = "valid"
    INVALID_ASN = "invalid_asn"      # ROA covers prefix but origin AS doesn't match
    INVALID_LENGTH = "invalid_length"  # ROA covers prefix but length > maxLength
    NOT_FOUND = "not_found"           # no covering ROA


@dataclass
class PrefixValidation:
    prefix: str
    origin_asn: int
    status: RPKIStatus
    matching_roas: list[dict] = field(default_factory=list)  # the ROAs that covered it


@dataclass
class RPKIAuditResult:
    """Result of validating every announced prefix for an ASN against the VRP set."""
    asn: int
    total_prefixes: int
    valid: int
    invalid_asn: int
    invalid_length: int
    not_found: int
    invalids: list[PrefixValidation]  # full detail for invalids (for evidence display)
    vrp_built_at: str  # buildtime from VRP metadata, for "as-of" provenance

    @property
    def coverage_percent(self) -> float:
        if self.total_prefixes == 0:
            return 0.0
        return 100.0 * self.valid / self.total_prefixes

    @property
    def total_invalids(self) -> int:
        return self.invalid_asn + self.invalid_length


class RPKIError(Exception):
    pass


class RPKIValidator:
    """Bulk RPKI validator. Loads the global VRP once, validates prefixes in O(log n).

    Usage::

        async with RPKIValidator() as v:
            result = v.audit(announced_prefixes, origin_asn=13335)
            print(result.coverage_percent, result.total_invalids)
    """

    def __init__(self, vrp_url: str = VRP_URL, cache_ttl: int = VRP_TTL_SECONDS, timeout: float = 60.0):
        self.vrp_url = vrp_url
        self.cache_ttl = cache_ttl
        self.timeout = timeout
        self._tree: radix.Radix | None = None
        self._vrp_buildtime: str = ""
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> "RPKIValidator":
        self._client = httpx.AsyncClient(timeout=self.timeout)
        await self._load_vrp()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        if self._client:
            await self._client.aclose()

    async def _load_vrp(self) -> None:
        data = await self._fetch_vrp_cached()
        self._vrp_buildtime = data.get("metadata", {}).get("buildtime", "")
        roas = data.get("roas", [])
        if not roas:
            raise RPKIError("VRP dump contained no ROAs")

        tree = radix.Radix()
        for roa in roas:
            prefix = roa.get("prefix")
            asn = roa.get("asn")
            max_length = roa.get("maxLength")
            if not prefix or asn is None:
                continue
            node = tree.search_exact(prefix) or tree.add(prefix)
            roas_at_node = node.data.setdefault("roas", [])
            roas_at_node.append({
                "asn": int(asn),
                "maxLength": int(max_length) if max_length is not None else int(prefix.split("/")[1]),
                "ta": roa.get("ta"),
            })
        self._tree = tree

    async def _fetch_vrp_cached(self) -> dict:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        if VRP_CACHE_FILE.exists():
            age = time.time() - VRP_CACHE_FILE.stat().st_mtime
            if age < self.cache_ttl:
                try:
                    return json.loads(VRP_CACHE_FILE.read_text())
                except json.JSONDecodeError:
                    pass  # fall through to fetch

        if not self._client:
            raise RPKIError("Client not initialised — use 'async with'")
        r = await self._client.get(self.vrp_url)
        r.raise_for_status()
        VRP_CACHE_FILE.write_bytes(r.content)
        return r.json()

    def validate_prefix(self, prefix: str, origin_asn: int) -> PrefixValidation:
        """Validate a single (prefix, origin) pair against the VRP."""
        if self._tree is None:
            raise RPKIError("VRP not loaded")

        announced_length = int(prefix.split("/")[1])

        # search_covering: all nodes whose prefix is a prefix-of or equal-to this prefix
        covering = self._tree.search_covering(prefix)
        all_roas = []
        for node in covering:
            all_roas.extend(node.data.get("roas", []))

        if not all_roas:
            return PrefixValidation(prefix=prefix, origin_asn=origin_asn, status=RPKIStatus.NOT_FOUND)

        # Any ROA with matching ASN AND length within maxLength = VALID
        has_asn_match = False
        for roa in all_roas:
            if roa["asn"] == origin_asn:
                has_asn_match = True
                if announced_length <= roa["maxLength"]:
                    return PrefixValidation(
                        prefix=prefix, origin_asn=origin_asn,
                        status=RPKIStatus.VALID, matching_roas=[roa],
                    )

        # ROA covers it but no asn-match → INVALID_ASN
        # ROA covers it, asn matches, but length > maxLength → INVALID_LENGTH
        if has_asn_match:
            return PrefixValidation(
                prefix=prefix, origin_asn=origin_asn,
                status=RPKIStatus.INVALID_LENGTH, matching_roas=all_roas,
            )
        return PrefixValidation(
            prefix=prefix, origin_asn=origin_asn,
            status=RPKIStatus.INVALID_ASN, matching_roas=all_roas,
        )

    def audit(self, announced_prefixes: list[str], origin_asn: int) -> RPKIAuditResult:
        """Validate every prefix and return aggregate counts + invalid detail."""
        valid = invalid_asn = invalid_length = not_found = 0
        invalids: list[PrefixValidation] = []
        for p in announced_prefixes:
            r = self.validate_prefix(p, origin_asn)
            if r.status == RPKIStatus.VALID:
                valid += 1
            elif r.status == RPKIStatus.INVALID_ASN:
                invalid_asn += 1
                invalids.append(r)
            elif r.status == RPKIStatus.INVALID_LENGTH:
                invalid_length += 1
                invalids.append(r)
            else:
                not_found += 1
        return RPKIAuditResult(
            asn=origin_asn,
            total_prefixes=len(announced_prefixes),
            valid=valid,
            invalid_asn=invalid_asn,
            invalid_length=invalid_length,
            not_found=not_found,
            invalids=invalids,
            vrp_built_at=self._vrp_buildtime,
        )
