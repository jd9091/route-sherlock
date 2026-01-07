#!/usr/bin/env python3
"""
Route Sherlock Demo.

Demonstrates the BGP intelligence capabilities.
"""

import asyncio
import sys
sys.path.insert(0, "src")

from route_sherlock.collectors.ripestat import RIPEstatClient
from route_sherlock.collectors.peeringdb import PeeringDBClient, PeeringDBNotFoundError
from route_sherlock.collectors.atlas import AtlasClient


def header(text: str) -> None:
    print(f"\n{'='*60}")
    print(f"  {text}")
    print('='*60)


async def demo_ripestat():
    """Demo RIPEstat client."""
    header("RIPEstat: Cloudflare (AS13335)")

    async with RIPEstatClient() as client:
        # AS Overview
        overview = await client.get_as_overview("13335")
        print(f"\nAS Overview:")
        print(f"  Name: {overview.holder}")
        print(f"  RIR: {overview.rir}")
        print(f"  Announced: {overview.announced}")

        # Routing Status
        status = await client.get_routing_status("13335")
        print(f"\nRouting Status:")
        print(f"  Observed Neighbours: {status.observed_neighbours}")
        print(f"  Observed Prefixes: {status.visibility.get('v4', {}).get('ris_peers_seeing', 'N/A')}")

        # Announced Prefixes
        prefixes = await client.get_announced_prefixes("13335")
        print(f"\nAnnounced Prefixes:")
        print(f"  IPv4: {len(prefixes.ipv4_prefixes)}")
        print(f"  IPv6: {len(prefixes.ipv6_prefixes)}")
        print(f"  Sample: {prefixes.ipv4_prefixes[:3]}")

        # Neighbours
        neighbours = await client.get_as_neighbours("13335")
        print(f"\nAS Neighbours:")
        print(f"  Upstreams: {len(neighbours.upstreams)}")
        print(f"  Downstreams: {len(neighbours.downstreams)}")
        if neighbours.upstreams:
            top_upstream = neighbours.upstreams[0]
            print(f"  Top Upstream: AS{top_upstream.asn}")


async def demo_peeringdb():
    """Demo PeeringDB client."""
    header("PeeringDB: Cloudflare (AS13335)")

    async with PeeringDBClient() as client:
        try:
            # Network info
            network = await client.get_network_by_asn(13335)
            print(f"\nNetwork Info:")
            print(f"  Name: {network.name}")
            print(f"  Type: {network.info_type}")
            print(f"  Peering Policy: {network.policy_general}")
            print(f"  IPv4 Prefixes: {network.info_prefixes4}")
            print(f"  IPv6 Prefixes: {network.info_prefixes6}")
            print(f"  IRR as-set: {network.irr_as_set}")

            # IX Connections
            ixlans = await client.get_network_ixlans(13335)
            unique_ixes = set(c.ix_id for c in ixlans)
            print(f"\nIX Presence:")
            print(f"  Total Connections: {len(ixlans)}")
            print(f"  Unique IXes: {len(unique_ixes)}")

            # Get details of first few IXes
            print(f"  Sample IXes:")
            for ix_id in list(unique_ixes)[:5]:
                try:
                    ix = await client.get_ix(ix_id)
                    print(f"    - {ix.name} ({ix.country})")
                except Exception:
                    pass

            # Common IXes with Google
            print(f"\nCommon IXes with Google (AS15169):")
            try:
                common = await client.find_common_ixes(13335, 15169)
                print(f"  Found {len(common)} common IXes")
                for cix in common[:5]:
                    print(f"    - {cix.ix.name}: can_peer={cix.can_peer}")
            except Exception as e:
                print(f"  Skipped (rate limit)")

        except PeeringDBNotFoundError as e:
            print(f"  Error: {e}")
        except Exception as e:
            print(f"  Error: {e}")


async def demo_atlas():
    """Demo RIPE Atlas client."""
    header("RIPE Atlas: Probes in Cloudflare (AS13335)")

    async with AtlasClient() as client:
        # Get probes by ASN
        probes = await client.get_probes_by_asn(13335, connected_only=True)
        print(f"\nProbes in AS13335:")
        print(f"  Connected: {len(probes)}")

        if probes:
            # Show sample probes
            print(f"  Sample Probes:")
            for probe in probes[:5]:
                print(f"    - Probe {probe.id}: {probe.country_code}, anchor={probe.is_anchor}")

        # Get anchors
        anchors = await client.get_anchor_by_asn(13335)
        print(f"\nAnchors in AS13335:")
        print(f"  Count: {len(anchors)}")
        for anchor in anchors[:3]:
            print(f"    - {anchor.fqdn} ({anchor.city}, {anchor.country_code})")


async def demo_analysis():
    """Demo combined analysis (quick version)."""
    header("Quick Analysis: AS13335 vs AS15169")

    async with RIPEstatClient() as ripestat:
        # Compare two major networks
        cf_overview = await ripestat.get_as_overview("13335")
        google_overview = await ripestat.get_as_overview("15169")

        cf_prefixes = await ripestat.get_announced_prefixes("13335")
        google_prefixes = await ripestat.get_announced_prefixes("15169")

        cf_neighbours = await ripestat.get_as_neighbours("13335")
        google_neighbours = await ripestat.get_as_neighbours("15169")

        print(f"\n{'Metric':<25} {'Cloudflare':<20} {'Google':<20}")
        print("-" * 65)
        print(f"{'Name':<25} {cf_overview.holder[:18]:<20} {google_overview.holder[:18]:<20}")
        print(f"{'IPv4 Prefixes':<25} {len(cf_prefixes.ipv4_prefixes):<20} {len(google_prefixes.ipv4_prefixes):<20}")
        print(f"{'IPv6 Prefixes':<25} {len(cf_prefixes.ipv6_prefixes):<20} {len(google_prefixes.ipv6_prefixes):<20}")
        print(f"{'Upstreams':<25} {len(cf_neighbours.upstreams):<20} {len(google_neighbours.upstreams):<20}")
        print(f"{'Downstreams':<25} {len(cf_neighbours.downstreams):<20} {len(google_neighbours.downstreams):<20}")


async def demo_prefix_check():
    """Demo prefix analysis."""
    header("Prefix Check: 1.1.1.0/24 (Cloudflare DNS)")

    async with RIPEstatClient() as client:
        # Get looking glass data
        lg = await client.get_looking_glass("1.1.1.0/24")

        print(f"\nLooking Glass Results:")
        print(f"  RRCs reporting: {len(lg.rrcs)}")

        # Collect unique paths
        paths = set()
        for rrc in lg.rrcs:
            for peer in rrc.peers:
                if peer.as_path:
                    paths.add(peer.as_path)

        print(f"  Unique AS paths: {len(paths)}")
        print(f"  Sample paths:")
        for path in list(paths)[:5]:
            print(f"    {path}")

        # RPKI validation
        try:
            rpki = await client.get_rpki_validation("1.1.1.0/24", "13335")
            print(f"\nRPKI Validation:")
            print(f"  Status: {rpki.status}")
            print(f"  Validated ROAs: {len(rpki.roas) if rpki.roas else 0}")
        except Exception as e:
            print(f"\nRPKI Validation: skipped (API requires different format)")


async def main():
    print("\n" + "="*60)
    print("        ROUTE SHERLOCK - BGP Intelligence Demo")
    print("="*60)

    try:
        await demo_ripestat()
        await demo_peeringdb()
        await demo_atlas()
        await demo_prefix_check()
        await demo_analysis()

        header("Demo Complete!")
        print("\nRoute Sherlock provides unified access to:")
        print("  - RIPEstat: Routing data, RPKI, BGP updates")
        print("  - PeeringDB: IX presence, peering policy, facilities")
        print("  - RIPE Atlas: Global measurement network")
        print("\nUse RouteSherlock for combined analysis:")
        print("  async with RouteSherlock() as sherlock:")
        print("      report = await sherlock.full_analysis(13335)")
        print()

    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())
