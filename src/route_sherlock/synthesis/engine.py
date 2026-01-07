"""
AI Synthesis Engine.

Uses Claude to generate human-readable reports from raw BGP data.
"""
from __future__ import annotations

import os
from datetime import datetime
from typing import Any

INCIDENT_PROMPT = """You are a network engineer analyzing a BGP routing incident.

Given the following data, write a clear incident report that:
1. Summarizes what happened in plain English
2. Identifies the timeline of events
3. Assesses the impact
4. Suggests probable cause
5. Notes any concerning patterns

Be concise but thorough. Use bullet points where appropriate.
Include specific ASNs, prefixes, and timestamps from the data.

DATA:
{data}

Write the incident report:"""

PEERING_PROMPT = """You are a network peering consultant analyzing a peering opportunity.

Given the following data about two networks, write a recommendation that:
1. Summarizes both networks' profiles
2. Identifies where they can peer (common IXes/facilities)
3. Estimates the benefits of peering
4. Provides a clear recommendation (peer or not)
5. Lists concrete next steps

Be practical and actionable. Focus on business value.

DATA:
{data}

Write the peering recommendation:"""

INVESTIGATION_PROMPT = """You are a BGP expert investigating routing behavior.

Given the following BGP data, provide analysis that:
1. Explains what the data shows in plain English
2. Identifies any anomalies or concerning patterns
3. Correlates events across different data sources
4. Suggests what might have caused any issues
5. Recommends monitoring or actions

Be specific - cite ASNs, timestamps, and prefix counts from the data.

DATA:
{data}

Write your analysis:"""

PEER_RISK_PROMPT = """You are a network peering risk analyst helping operators decide whether to establish BGP peering sessions.

Given the following risk assessment data, write a clear risk analysis that:

1. **Executive Summary** (2-3 sentences): Should they peer? Yes/No/Conditional with brief reasoning.

2. **Key Risk Factors**: List the top 3 concerns or strengths, citing specific data points.

3. **Operational Recommendations**:
   - If low risk: Standard peering process steps
   - If moderate risk: Specific safeguards to implement (prefix limits, monitoring, etc.)
   - If high risk: Either decline or list mandatory requirements before peering

4. **Technical Safeguards**: Based on the data, recommend specific:
   - Max-prefix limits (based on their announced prefix count)
   - IRR filtering requirements
   - RPKI policy recommendations
   - Monitoring alerts to configure

Be practical and actionable. Network operators need clear guidance, not vague advice.
Reference specific ASNs, scores, and metrics from the data.

DATA:
{data}

Write your risk assessment:"""


class Synthesizer:
    """
    AI-powered synthesis engine for BGP analysis.

    Uses Claude to transform raw data into human-readable reports.

    Example:
        synth = Synthesizer()
        report = await synth.synthesize_incident(incident_data)
        print(report)
    """

    def __init__(self, api_key: str | None = None, model: str = "claude-sonnet-4-20250514"):
        """
        Initialize synthesizer.

        Args:
            api_key: Anthropic API key (defaults to ANTHROPIC_API_KEY env var)
            model: Claude model to use
        """
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        self.model = model
        self._client = None

    def _get_client(self):
        """Lazy-load Anthropic client."""
        if self._client is None:
            try:
                import anthropic
                self._client = anthropic.Anthropic(api_key=self.api_key)
            except ImportError:
                raise ImportError(
                    "anthropic package required for AI synthesis. "
                    "Install with: pip install 'route-sherlock[ai]'"
                )
        return self._client

    async def synthesize(self, prompt: str, data: dict[str, Any]) -> str:
        """
        Generate synthesis from data using Claude.

        Args:
            prompt: Prompt template with {data} placeholder
            data: Data to include in prompt

        Returns:
            Generated text from Claude
        """
        if not self.api_key:
            return self._fallback_synthesis(data)

        client = self._get_client()

        # Format data for prompt
        data_str = self._format_data(data)
        full_prompt = prompt.format(data=data_str)

        try:
            message = client.messages.create(
                model=self.model,
                max_tokens=2000,
                messages=[
                    {"role": "user", "content": full_prompt}
                ]
            )
            return message.content[0].text
        except Exception as e:
            return f"AI synthesis unavailable: {e}\n\n{self._fallback_synthesis(data)}"

    async def synthesize_incident(self, data: dict[str, Any]) -> str:
        """Generate incident report from data."""
        return await self.synthesize(INCIDENT_PROMPT, data)

    async def synthesize_peering(self, data: dict[str, Any]) -> str:
        """Generate peering recommendation from data."""
        return await self.synthesize(PEERING_PROMPT, data)

    async def synthesize_investigation(self, data: dict[str, Any]) -> str:
        """Generate investigation analysis from data."""
        return await self.synthesize(INVESTIGATION_PROMPT, data)

    def _format_data(self, data: dict[str, Any], indent: int = 0) -> str:
        """Format nested data structure for prompt."""
        lines = []
        prefix = "  " * indent

        for key, value in data.items():
            if isinstance(value, dict):
                lines.append(f"{prefix}{key}:")
                lines.append(self._format_data(value, indent + 1))
            elif isinstance(value, list):
                lines.append(f"{prefix}{key}:")
                for item in value[:20]:  # Limit list items
                    if isinstance(item, dict):
                        lines.append(self._format_data(item, indent + 1))
                    else:
                        lines.append(f"{prefix}  - {item}")
                if len(value) > 20:
                    lines.append(f"{prefix}  ... and {len(value) - 20} more")
            else:
                lines.append(f"{prefix}{key}: {value}")

        return "\n".join(lines)

    def _fallback_synthesis(self, data: dict[str, Any]) -> str:
        """Generate basic synthesis without AI."""
        lines = ["## Summary (AI synthesis unavailable)", ""]

        if "asn" in data:
            lines.append(f"**ASN:** {data['asn']}")
        if "name" in data:
            lines.append(f"**Name:** {data['name']}")
        if "prefixes" in data:
            lines.append(f"**Prefixes:** {data['prefixes']}")
        if "update_count" in data:
            lines.append(f"**BGP Updates:** {data['update_count']}")
        if "common_ixes" in data:
            lines.append(f"**Common IXes:** {len(data['common_ixes'])}")

        lines.append("")
        lines.append("*Set ANTHROPIC_API_KEY for AI-powered analysis*")

        return "\n".join(lines)


class IncidentSynthesizer(Synthesizer):
    """Specialized synthesizer for incident reports."""

    async def synthesize_from_raw(
        self,
        asn: str,
        updates: list[dict],
        history: dict | None,
        start_time: datetime,
        end_time: datetime,
    ) -> str:
        """
        Generate incident report from raw collected data.

        Args:
            asn: ASN being investigated
            updates: List of BGP update events
            history: Routing history data
            start_time: Investigation start time
            end_time: Investigation end time

        Returns:
            Formatted incident report
        """
        data = {
            "asn": asn,
            "timeframe": {
                "start": start_time.isoformat(),
                "end": end_time.isoformat(),
                "duration_hours": (end_time - start_time).total_seconds() / 3600,
            },
            "bgp_updates": {
                "total_count": len(updates),
                "announcements": sum(1 for u in updates if u.get("type") == "A"),
                "withdrawals": sum(1 for u in updates if u.get("type") == "W"),
                "sample_events": updates[:10],
            },
            "routing_history": history,
        }

        return await self.synthesize_incident(data)


class PeeringSynthesizer(Synthesizer):
    """Specialized synthesizer for peering recommendations."""

    async def synthesize_from_raw(
        self,
        my_asn: int,
        target_asn: int,
        my_network: dict,
        target_network: dict,
        common_ixes: list[dict],
        common_facilities: list[dict],
        current_paths: list[str],
    ) -> str:
        """
        Generate peering recommendation from raw collected data.

        Args:
            my_asn: Your ASN
            target_asn: Target ASN
            my_network: Your network's PeeringDB info
            target_network: Target network's PeeringDB info
            common_ixes: List of common IXes
            common_facilities: List of common facilities
            current_paths: Current AS paths to target

        Returns:
            Formatted peering recommendation
        """
        data = {
            "your_network": {
                "asn": my_asn,
                **my_network,
            },
            "target_network": {
                "asn": target_asn,
                **target_network,
            },
            "peering_opportunities": {
                "common_ixes": common_ixes,
                "common_facilities": common_facilities,
                "ix_count": len(common_ixes),
                "facility_count": len(common_facilities),
            },
            "current_routing": {
                "paths": current_paths[:5],
                "path_count": len(current_paths),
            },
        }

        return await self.synthesize_peering(data)
