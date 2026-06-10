"""ADP SDK v1.1 — Agent discovery client.

SVCB-first discovery with TXT+SRV fallback.
Trust levels: unverified → dns-verified → dane-verified → key-verified → peer-verified
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Coroutine

from adpsdk.dns_records import parse_svcb_records, parse_txt_record, validate_txt_record

# Type aliases for injectable resolvers.
DnsSvcbResolver = Callable[[str], Coroutine[Any, Any, list[dict[str, Any]]]]
DnsTlsaResolver = Callable[[str], Coroutine[Any, Any, list[str]]]
DnsTxtResolver = Callable[[str], Coroutine[Any, Any, list[str]]]
DnsSrvResolver = Callable[[str], Coroutine[Any, Any, list[dict[str, Any]]]]
HttpFetcher = Callable[[str, dict[str, str] | None], Coroutine[Any, Any, "HttpResponse"]]


@dataclass
class HttpResponse:
    """Minimal HTTP response wrapper for dependency injection."""
    status: int
    body: dict[str, Any] | None = None
    ok: bool = False

    @staticmethod
    async def from_aiohttp(response: Any) -> "HttpResponse":
        try:
            body = await response.json()
            return HttpResponse(
                status=response.status, body=body, ok=200 <= response.status < 300
            )
        except Exception:
            return HttpResponse(status=response.status, ok=False)


@dataclass
class SrvRecord:
    """A parsed SRV record."""
    priority: int
    weight: int
    port: int
    target: str


@dataclass
class DiscoveryResult:
    """Result of a complete agent discovery (v1.1).

    Attributes:
        domain: The queried domain.
        dns: Parsed DNS info (SVCB or TXT fallback).
        srv: List of SRV records from fallback.
        meta: Full agent.json metadata.
        trust_level: Trust level reached.
        fallback_used: True if TXT+SRV fallback was used.
        dane_available: True if TLSA records exist.
        errors: List of error messages.
    """
    domain: str
    dns: dict[str, Any] | None = None
    srv: list[SrvRecord] | None = None
    meta: dict[str, Any] | None = None
    trust_level: str = "unverified"
    fallback_used: bool = False
    dane_available: bool = False
    errors: list[str] = field(default_factory=list)


async def discover_agent(
    domain: str,
    *,
    dns_resolve_svcb: DnsSvcbResolver | None = None,
    dns_resolve_tlsa: DnsTlsaResolver | None = None,
    dns_resolve_txt: DnsTxtResolver | None = None,
    dns_resolve_srv: DnsSrvResolver | None = None,
    http_fetch: HttpFetcher | None = None,
    verify_tlsa: bool = True,
) -> DiscoveryResult:
    """Discover an Agent via ADP v1.1 (SVCB-first, TXT+SRV fallback).

    Layer 1: SVCB query → parse target, port, ALPN, well-known.
    Layer 1b: TLSA query for DANE verification.
    Layer 1f: TXT+SRV fallback if SVCB unavailable.
    Layer 2: Fetch well-known agent.json.
    Layer 3: Verify fingerprint consistency.

    Args:
        domain: Agent domain, e.g. "alice.example.com".
        dns_resolve_svcb: Async resolver for SVCB records.
        dns_resolve_tlsa: Async resolver for TLSA records.
        dns_resolve_txt: Async resolver for TXT records (fallback).
        dns_resolve_srv: Async resolver for SRV records (fallback).
        http_fetch: Async HTTP fetch function.
        verify_tlsa: Whether to query TLSA (default True).

    Returns:
        DiscoveryResult with full discovery state.
    """
    result = DiscoveryResult(domain=domain)

    # ─── Layer 1: SVCB query (primary) ────────────────────────
    if dns_resolve_svcb is not None:
        try:
            svcb_records = await dns_resolve_svcb(domain)
            parsed = parse_svcb_records(svcb_records)
            if parsed and parsed.get("type") == "service":
                result.dns = parsed
                result.trust_level = "dns-verified"
            elif parsed and parsed.get("type") == "alias":
                result.dns = parsed
                result.errors.append("SVCB returned AliasMode only")
        except Exception as exc:
            result.errors.append(f"SVCB query: {exc}")

    # ─── Layer 1b: TXT+SRV fallback ───────────────────────────
    if not result.dns or result.dns.get("type") == "alias":
        if dns_resolve_txt is not None:
            try:
                txt_name = f"_agent.{domain}"
                txt_strings = await dns_resolve_txt(txt_name)
                if txt_strings:
                    parsed = parse_txt_record(txt_strings)
                    validation = validate_txt_record(parsed)
                    if validation["valid"]:
                        target = domain
                        port = 443
                        if dns_resolve_srv:
                            try:
                                srv_records = await dns_resolve_srv(
                                    f"_agent._tcp.{domain}"
                                )
                                if srv_records:
                                    srv = srv_records[0]
                                    target = srv.get("target", domain).rstrip(".")
                                    port = srv.get("port", 443)
                                    result.srv = [
                                        SrvRecord(
                                            priority=r.get("priority", 10),
                                            weight=r.get("weight", 5),
                                            port=r.get("port", 443),
                                            target=r.get("target", "").rstrip("."),
                                        )
                                        for r in srv_records
                                    ]
                            except Exception:
                                pass
                        result.dns = {
                            "type": "service",
                            "target": target,
                            "port": port,
                            "publicKey": parsed.get("pk"),
                            "wellKnown": parsed.get("wk"),
                            "svcFallback": True,
                        }
                        result.trust_level = "dns-verified"
                        result.fallback_used = True
            except Exception as exc:
                result.errors.append(f"TXT fallback: {exc}")

    if not result.dns or not result.dns.get("wellKnown"):
        result.errors.append("No usable DNS discovery data")
        return result

    # ─── Layer 1c: TLSA/DANE ──────────────────────────────────
    if verify_tlsa and dns_resolve_tlsa is not None:
        try:
            target = result.dns.get("target", domain)
            if target in (".", ""):
                target = domain
            tlsa_name = f"_{result.dns.get('port', 443)}._tcp.{target}"
            tlsa_records = await dns_resolve_tlsa(tlsa_name)
            if tlsa_records:
                result.dns["tlsa"] = tlsa_records
                result.dane_available = True
        except Exception:
            pass

    # ─── Layer 2: Well-Known ──────────────────────────────────
    if http_fetch is None:
        result.errors.append("No HTTP fetcher configured")
        return result

    wk = result.dns.get("wellKnown", "agent.json")
    if result.fallback_used and wk.startswith("https://"):
        wk_url = wk
    else:
        target = result.dns.get("target", domain)
        if target in (".", ""):
            target = domain
        wk_url = f"https://{target}/.well-known/{wk}"

    try:
        response = await http_fetch(wk_url, headers={"Accept": "application/json"})
    except Exception as exc:
        result.errors.append(f"Well-Known fetch: {exc}")
        return result

    if not response.ok:
        result.errors.append(f"Well-Known HTTP {response.status}")
        return result

    meta = response.body
    if meta is None:
        result.errors.append("Empty Well-Known body")
        return result

    from adpsdk.agent_json import validate_agent_json

    meta_validation = validate_agent_json(meta)
    if not meta_validation["valid"]:
        result.errors.extend(meta_validation["errors"])
        return result

    # ─── Fingerprint verification ─────────────────────────────
    dns_fp = result.dns.get("publicKey") or result.dns.get("capSha256")
    meta_fp = meta.get("identity", {}).get("publicKey", {}).get("fingerprint")
    if dns_fp and meta_fp and dns_fp != meta_fp:
        result.errors.append(f"Fingerprint mismatch: DNS={dns_fp} meta={meta_fp}")
        return result

    result.meta = meta
    result.trust_level = "key-verified"
    return result


async def discover_agents(
    domains: list[str],
    *,
    dns_resolve_svcb: DnsSvcbResolver | None = None,
    dns_resolve_tlsa: DnsTlsaResolver | None = None,
    dns_resolve_txt: DnsTxtResolver | None = None,
    dns_resolve_srv: DnsSrvResolver | None = None,
    http_fetch: HttpFetcher | None = None,
    verify_tlsa: bool = True,
) -> list[DiscoveryResult]:
    """Discover multiple agents concurrently."""
    import asyncio

    tasks = [
        discover_agent(
            d,
            dns_resolve_svcb=dns_resolve_svcb,
            dns_resolve_tlsa=dns_resolve_tlsa,
            dns_resolve_txt=dns_resolve_txt,
            dns_resolve_srv=dns_resolve_srv,
            http_fetch=http_fetch,
            verify_tlsa=verify_tlsa,
        )
        for d in domains
    ]
    return list(await asyncio.gather(*tasks))
