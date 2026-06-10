#!/usr/bin/env python3
"""ADP Agent Discovery CLI tool.

Usage:
    python examples/discover_agent.py alice.agent
    python examples/discover_agent.py alice.agent --full

Discovers an agent through the three-layer ADP discovery process:
    1. DNS TXT query → v/pk/wk
    2. HTTP well-known agent.json
    3. Fingerprint verification

Requires dnspython for DNS resolution and aiohttp for HTTP.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from typing import Any

try:
    import dns.asyncresolver
except ImportError:
    print("dnspython is required. Install with: pip install dnspython")
    sys.exit(1)

try:
    import aiohttp
except ImportError:
    print("aiohttp is required. Install with: pip install aiohttp")
    sys.exit(1)

from adpsdk.discover import HttpResponse, discover_agent


async def _resolve_txt(name: str) -> list[str]:
    """Resolve DNS TXT records using dnspython."""
    resolver = dns.asyncresolver.Resolver()
    try:
        answer = await resolver.resolve(name, "TXT")
        return [
            s.decode("utf-8") if isinstance(s, bytes) else s
            for rdata in answer
            for s in rdata.strings
        ]
    except Exception:
        return []


async def _resolve_srv(name: str) -> list[dict[str, Any]]:
    """Resolve DNS SRV records using dnspython."""
    resolver = dns.asyncresolver.Resolver()
    try:
        answer = await resolver.resolve(name, "SRV")
        results = []
        for rdata in answer:
            results.append({
                "priority": rdata.priority,
                "weight": rdata.weight,
                "port": rdata.port,
                "target": str(rdata.target).rstrip("."),
            })
        return results
    except Exception:
        return []


async def _http_fetch(
    url: str, headers: dict[str, str] | None = None
) -> HttpResponse:
    """Fetch a URL using aiohttp."""
    async with aiohttp.ClientSession() as session:
        async with session.get(
            url,
            headers=headers or {},
            timeout=aiohttp.ClientTimeout(total=10),
        ) as response:
            try:
                body = await response.json()
            except Exception:
                body = None
            return HttpResponse(
                status=response.status,
                body=body,
                ok=200 <= response.status < 300,
            )


def _format_result(result) -> str:
    """Format a discovery result for display."""
    lines = []
    lines.append("=" * 60)
    lines.append(f"  Agent Discovery: {result.domain}")
    lines.append("=" * 60)

    # Trust badge
    badges = {
        "unverified": "❌",
        "dns-verified": "🔍",
        "key-verified": "✅",
        "peer-verified": "🤝",
    }
    badge = badges.get(result.trust_level, "❓")
    lines.append(f"\n  Trust Level: {badge} {result.trust_level}")

    # TXT
    if result.txt:
        lines.append(f"\n  ── Layer 1: DNS TXT ──")
        lines.append(f"  Protocol:  {result.txt.get('v', '?')}")
        lines.append(f"  Key FP:    {result.txt.get('pk', '?')}")
        lines.append(f"  Well-Known: {result.txt.get('wk', '?')}")
        if result.txt.get("rel"):
            lines.append(f"  Relations: {result.txt['rel']}")
        if result.txt.get("note"):
            lines.append(f"  Note:      {result.txt['note']}")

    # SRV
    if result.srv:
        lines.append(f"\n  ── Layer 1b: DNS SRV ──")
        for srv in result.srv:
            lines.append(
                f"  {srv.target}:{srv.port} "
                f"(priority={srv.priority}, weight={srv.weight})"
            )

    # Meta
    if result.meta:
        lines.append(f"\n  ── Layer 2: Well-Known ──")
        identity = result.meta.get("identity", {})
        lines.append(f"  ID:        {identity.get('id', '?')}")
        lines.append(f"  Name:      {identity.get('name', '?')}")
        lines.append(f"  Owner:     {identity.get('owner', '?')}")

        caps = result.meta.get("capabilities", [])
        if caps:
            lines.append(f"\n  Capabilities ({len(caps)}):")
            for cap in caps:
                pricing = cap.get("pricing", {}).get("model", "free")
                lines.append(
                    f"    • {cap['name']} [{pricing}] — {cap.get('description', '')}"
                )

        endpoints = result.meta.get("endpoints", {})
        if endpoints:
            lines.append(f"\n  Endpoints:")
            for name, url in sorted(endpoints.items()):
                lines.append(f"    • {name}: {url}")

    # Errors
    if result.errors:
        lines.append(f"\n  ⚠ Errors:")
        for err in result.errors:
            lines.append(f"    • {err}")

    return "\n".join(lines)


async def main() -> None:
    parser = argparse.ArgumentParser(
        description="Discover an ADP agent by domain",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python discover_agent.py alice.agent
    python discover_agent.py alice.agent --json
        """,
    )
    parser.add_argument("domain", help="Agent domain to discover, e.g. alice.agent")
    parser.add_argument(
        "--json", action="store_true", help="Output raw JSON instead of formatted text"
    )
    parser.add_argument(
        "--full",
        action="store_true",
        help="Output the complete agent.json metadata",
    )
    args = parser.parse_args()

    domain = args.domain.lower().strip()

    print(f"Discovering agent at {domain}...")
    result = await discover_agent(
        domain,
        dns_resolve_txt=_resolve_txt,
        dns_resolve_srv=_resolve_srv,
        http_fetch=_http_fetch,
    )

    if args.json:
        output: dict[str, Any] = {
            "domain": result.domain,
            "trust_level": result.trust_level,
            "txt": result.txt,
            "srv": [vars(s) for s in result.srv] if result.srv else None,
            "meta": result.meta if args.full else None,
            "errors": result.errors,
        }
        print(json.dumps(output, indent=2, default=str))
    else:
        print(_format_result(result))
        if args.full and result.meta:
            print("\n  ── Full agent.json ──")
            print(json.dumps(result.meta, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
