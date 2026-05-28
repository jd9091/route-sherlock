"""Operational contact completeness check.

A network that hasn't published NOC + abuse contacts cannot be reached during
incidents. RFC 2142 and BCP for incident coordination treat this as a hard
operational requirement. We measure two distinct surfaces:

1. **PeeringDB POCs** — voluntary, operationally meaningful (this is what
   peering coordinators look up first)
2. **RIR WHOIS** — mandatory abuse-c / tech-c on the resource registration
   (ARIN POC handles, RIPE persons, APNIC ROLE objects)

Both are externally observable. We do NOT test responsiveness in v1 — that
introduces real-time variance and is deferred to v2.
"""
from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass, field
from typing import Any

import httpx


@dataclass
class ContactPoint:
    role: str           # NOC | Abuse | Technical | Policy | Sales | Maintenance
    source: str         # "peeringdb" | "rir-whois"
    email: str | None = None
    phone: str | None = None
    name: str | None = None


@dataclass
class ContactCheckResult:
    asn: int
    contacts: list[ContactPoint] = field(default_factory=list)
    error: str | None = None

    @property
    def has_noc(self) -> bool:
        return any(c.role.lower() in {"noc", "operations"} for c in self.contacts)

    @property
    def has_abuse(self) -> bool:
        return any(c.role.lower() == "abuse" for c in self.contacts)

    @property
    def has_technical(self) -> bool:
        return any(c.role.lower() in {"technical", "tech"} for c in self.contacts)

    @property
    def has_policy(self) -> bool:
        return any(c.role.lower() == "policy" for c in self.contacts)

    @property
    def noc_email(self) -> str | None:
        for c in self.contacts:
            if c.role.lower() in {"noc", "operations"} and c.email:
                return c.email
        return None

    @property
    def abuse_email(self) -> str | None:
        for c in self.contacts:
            if c.role.lower() == "abuse" and c.email:
                return c.email
        return None


async def get_peeringdb_pocs(asn: int, api_key: str | None = None) -> list[ContactPoint]:
    """Fetch POC (Point of Contact) records from PeeringDB.

    Without auth, PeeringDB redacts email/phone. With an API key the fields
    are returned in full.
    """
    headers = {"Accept": "application/json"}
    if api_key:
        headers["Authorization"] = f"Api-Key {api_key}"

    async with httpx.AsyncClient(timeout=30.0, headers=headers) as client:
        # First fetch the network by asn to get net_id
        r = await client.get("https://www.peeringdb.com/api/net", params={"asn": asn})
        r.raise_for_status()
        nets = r.json().get("data") or []
        if not nets:
            return []
        net_id = nets[0]["id"]

        # Then fetch all POCs for that network
        r = await client.get("https://www.peeringdb.com/api/poc",
                             params={"net_id": net_id})
        r.raise_for_status()
        poc_data = r.json().get("data") or []

    contacts: list[ContactPoint] = []
    for p in poc_data:
        contacts.append(ContactPoint(
            role=p.get("role") or "",
            source="peeringdb",
            email=p.get("email") or None,
            phone=p.get("phone") or None,
            name=p.get("name") or None,
        ))
    return contacts


async def check_contacts(asn: int, api_key: str | None = None) -> ContactCheckResult:
    """Aggregate contact info from PeeringDB POCs.

    RIR WHOIS scraping is deferred — PeeringDB POCs are what operators
    actually consult when opening peering sessions, so they're the
    higher-leverage signal.
    """
    if api_key is None:
        api_key = os.environ.get("PEERINGDB_API_KEY")

    try:
        contacts = await get_peeringdb_pocs(asn, api_key)
    except (httpx.HTTPError, asyncio.TimeoutError) as e:
        return ContactCheckResult(asn=asn, error=f"PeeringDB POC fetch failed: {e}")

    return ContactCheckResult(asn=asn, contacts=contacts)
