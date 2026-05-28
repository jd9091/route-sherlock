"""Bogon detection against IANA Special-Use Registry (RFC 6890).

We deliberately use the IANA static special-use list rather than Team Cymru's
fullbogons feed. Special-use space is RFC-defined and unconditionally must not
appear in BGP — announcing 10.0.0.0/8 is a filter failure regardless of date.
Fullbogons includes IANA-unallocated space which can be allocated next day,
producing false positives that would undermine the tool's credibility.

When a peer announces special-use space, the inference is unambiguous: their
egress filters are broken. That is exactly the kind of evidence the peer-risk
score should weight heavily.
"""
from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_network, IPv4Network, IPv6Network


# RFC 6890 IANA IPv4 Special-Purpose Address Registry — entries marked as
# "False" for "Forwardable" or "Globally Reachable" are bogons in BGP context.
IANA_SPECIAL_USE_V4 = [
    ("0.0.0.0/8", "RFC 1122 — 'This network'"),
    ("10.0.0.0/8", "RFC 1918 — Private-Use"),
    ("100.64.0.0/10", "RFC 6598 — Shared Address Space (CGN)"),
    ("127.0.0.0/8", "RFC 1122 — Loopback"),
    ("169.254.0.0/16", "RFC 3927 — Link Local"),
    ("172.16.0.0/12", "RFC 1918 — Private-Use"),
    ("192.0.0.0/24", "RFC 6890 — IETF Protocol Assignments"),
    ("192.0.2.0/24", "RFC 5737 — Documentation (TEST-NET-1)"),
    ("192.168.0.0/16", "RFC 1918 — Private-Use"),
    ("198.18.0.0/15", "RFC 2544 — Benchmarking"),
    ("198.51.100.0/24", "RFC 5737 — Documentation (TEST-NET-2)"),
    ("203.0.113.0/24", "RFC 5737 — Documentation (TEST-NET-3)"),
    ("224.0.0.0/4", "RFC 5771 — Multicast"),
    ("240.0.0.0/4", "RFC 1112 — Reserved for Future Use"),
    ("255.255.255.255/32", "RFC 8190 — Limited Broadcast"),
]

# RFC 8190 IANA IPv6 Special-Purpose Address Registry
IANA_SPECIAL_USE_V6 = [
    ("::/128", "RFC 4291 — Unspecified Address"),
    ("::1/128", "RFC 4291 — Loopback"),
    ("::ffff:0:0/96", "RFC 4291 — IPv4-Mapped"),
    ("64:ff9b:1::/48", "RFC 8215 — IPv4-IPv6 Translation"),
    ("100::/64", "RFC 6666 — Discard"),
    ("2001:db8::/32", "RFC 3849 — Documentation"),
    ("2001:20::/28", "RFC 7343 — ORCHIDv2"),
    ("fc00::/7", "RFC 4193 — Unique Local"),
    ("fe80::/10", "RFC 4291 — Link Local"),
    ("ff00::/8", "RFC 4291 — Multicast"),
]


@dataclass
class BogonMatch:
    announced_prefix: str
    bogon_block: str
    reason: str


@dataclass
class BogonCheckResult:
    asn: int
    total_prefixes_checked: int
    matches: list[BogonMatch]

    @property
    def has_bogons(self) -> bool:
        return len(self.matches) > 0


def _is_subnet_of(child: str, parent: str) -> bool:
    """True if ``child`` is fully contained in ``parent``."""
    try:
        c = ip_network(child, strict=False)
        p = ip_network(parent, strict=False)
    except ValueError:
        return False
    if c.version != p.version:
        return False
    return c.subnet_of(p)


def check_bogons(announced_prefixes: list[str], asn: int) -> BogonCheckResult:
    """Flag any announced prefixes that fall within IANA special-use space.

    A match means the AS is leaking reserved space into BGP — direct evidence
    of broken egress filtering.
    """
    matches: list[BogonMatch] = []
    for ap in announced_prefixes:
        try:
            net = ip_network(ap, strict=False)
        except ValueError:
            continue
        reserved_list = IANA_SPECIAL_USE_V4 if net.version == 4 else IANA_SPECIAL_USE_V6
        for block, reason in reserved_list:
            if _is_subnet_of(ap, block):
                matches.append(BogonMatch(announced_prefix=ap, bogon_block=block, reason=reason))
                break  # one match per announced prefix is enough
    return BogonCheckResult(
        asn=asn,
        total_prefixes_checked=len(announced_prefixes),
        matches=matches,
    )
