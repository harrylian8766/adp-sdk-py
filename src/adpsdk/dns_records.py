"""ADP SDK v1.1 — DNS record generation and parsing module.

SVCB-first (primary): Generates SVCB ServiceMode and AliasMode records.
TLSA: DANE-based TLS endpoint authentication.
TXT + SRV: Documented fallback for SVCB-unavailable environments.

SVCB SvcParamKeys: alpn, port, ipv4hint, ipv6hint, bap, cap, cap-sha256, well-known
Aligned with DNS-AID (draft-mozleywilliams-dnsop-dnsaid).
"""

from __future__ import annotations

from typing import Any


# ═══════════════════════════════════════════════════════════════
# SVCB (v1.1 主要机制)
# ═══════════════════════════════════════════════════════════════

def generate_svcb_record(
    domain: str,
    *,
    target: str = ".",
    alpn: list[str] | None = None,
    port: int = 443,
    ipv4hint: list[str] | None = None,
    ipv6hint: list[str] | None = None,
    bap: str = "a2a",
    well_known: str = "agent.json",
    cap: str | None = None,
    cap_sha256: str | None = None,
) -> str:
    """Generate an SVCB ServiceMode DNS zone entry.

    Args:
        domain: Agent domain, e.g. "alice.example.com".
        target: Target hostname, "." for self-hosted.
        alpn: ALPN protocol list (default: ["a2a", "h2"]).
        port: Service port (default 443).
        ipv4hint: IPv4 address hints.
        ipv6hint: IPv6 address hints.
        bap: Agent protocol identifier (e.g. "a2a").
        well_known: Well-Known URI path (default "agent.json").
        cap: Capabilities descriptor URI.
        cap_sha256: SHA-256 digest of cap.

    Returns:
        Fully formatted SVCB zone file entry.
    """
    if alpn is None:
        alpn = ["a2a", "h2"]

    params = [
        f'alpn="{",".join(alpn)}"',
        f"port={port}",
    ]
    if ipv4hint:
        params.append(f"ipv4hint={','.join(ipv4hint)}")
    if ipv6hint:
        params.append(f"ipv6hint={','.join(ipv6hint)}")
    if bap:
        params.append(f"bap={bap}")
    if well_known:
        params.append(f"well-known={well_known}")
    if cap:
        params.append(f"cap={cap}")
    if cap_sha256:
        params.append(f"cap-sha256={cap_sha256}")

    param_str = "\n        ".join(params)
    return f"{domain}.  3600  IN  SVCB  1  {target}  (\n        {param_str}\n    )"


def generate_svcb_index_record(
    domain: str,
    targets: list[str],
) -> str:
    """Generate SVCB AliasMode records for an organization index.

    Args:
        domain: Index domain, e.g. "_agents.example.com".
        targets: List of agent domain names.

    Returns:
        Multi-line zone file entries.
    """
    return "\n".join(
        f"{domain}.  3600  IN  SVCB  0  {t}." for t in targets
    )


def build_svcb_info(
    domain: str,
    *,
    target: str = ".",
    alpn: list[str] | None = None,
    port: int = 443,
    bap: str = "a2a",
    well_known: str = "agent.json",
    **kwargs,
) -> dict[str, Any]:
    """Build a structured SVCB info dict for programmatic use.

    Returns:
        Dict with zone, params, and wellKnownUrl keys.
    """
    effective = domain if target == "." else target
    alpn = alpn or ["a2a", "h2"]
    return {
        "zone": generate_svcb_record(
            domain=domain, target=target, alpn=alpn, port=port,
            bap=bap, well_known=well_known, **kwargs,
        ),
        "params": dict(
            target=effective, port=port, alpn=alpn, bap=bap,
            wellKnown=well_known,
            ipv4hint=kwargs.get("ipv4hint", []),
            ipv6hint=kwargs.get("ipv6hint", []),
            cap=kwargs.get("cap"),
            capSha256=kwargs.get("cap_sha256"),
        ),
        "wellKnownUrl": f"https://{effective}/.well-known/{well_known}",
    }


# ═══════════════════════════════════════════════════════════════
# TLSA (v1.1 DANE)
# ═══════════════════════════════════════════════════════════════

def generate_tlsa_record(
    domain: str,
    cert_sha256: str,
    *,
    port: int = 443,
    proto: str = "tcp",
    usage: int = 3,
    selector: int = 1,
    matching_type: int = 1,
) -> str:
    """Generate a TLSA DNS zone entry for DANE verification.

    Default: DANE-EE (3) / SPKI (1) / SHA-256 (1).

    Args:
        domain: Agent domain.
        cert_sha256: Hex-encoded SHA-256 of the certificate's SPKI.
        port: TLS port (default 443).
        proto: Transport protocol ("tcp" or "udp").
        usage: Certificate usage (1=CA, 2=Service, 3=DANE-EE).
        selector: Certificate association (0=Full, 1=SPKI).
        matching_type: Hash type (0=Exact, 1=SHA-256, 2=SHA-512).

    Returns:
        Zone file TLSA entry.
    """
    return (
        f"_{port}._{proto}.{domain}.  3600  IN  TLSA  "
        f"{usage}  {selector}  {matching_type}  (\n    {cert_sha256}\n)"
    )


# ═══════════════════════════════════════════════════════════════
# TXT + SRV fallback (v1.0 兼容)
# ═══════════════════════════════════════════════════════════════

def generate_txt_record(
    domain: str,
    fingerprint: str,
    *,
    well_known: str | None = None,
    rel: str | None = None,
    note: str | None = None,
) -> str:
    """Generate the content of an `_agent` TXT record (fallback).

    Uses v=ADP1.1 for protocol version.
    """
    wk = well_known or f"https://{domain}/.well-known/agent.json"
    parts = ["v=ADP1.1", f"pk={fingerprint}", f"wk={wk}"]
    if rel:
        parts.append(f"rel={rel}")
    if note:
        parts.append(f"note={note[:64]}")
    return "; ".join(parts)


def generate_txt_zone_entry(
    domain: str,
    fingerprint: str,
    *,
    well_known: str | None = None,
    rel: str | None = None,
    note: str | None = None,
) -> str:
    """Generate a complete `_agent` TXT DNS zone entry (fallback)."""
    content = generate_txt_record(
        domain, fingerprint, well_known=well_known, rel=rel, note=note
    )
    return f'_agent.{domain}.  IN  TXT  "{content}"'


def generate_srv_zone_entry(
    domain: str,
    target: str,
    *,
    port: int = 443,
    priority: int = 10,
    weight: int = 5,
    proto: str = "_tcp",
) -> str:
    """Generate an `_agent` SRV DNS zone entry (fallback)."""
    return (
        f"_agent.{proto}.{domain}.  IN  SRV  "
        f"{priority} {weight} {port} {target}."
    )


def generate_all_dns_records(
    domain: str,
    fingerprint: str,
    *,
    target: str | None = None,
    port: int = 443,
    well_known: str | None = None,
    rel: str | None = None,
    note: str | None = None,
    svcb: dict[str, Any] | None = None,
    tlsa: dict[str, Any] | None = None,
    fallback: bool = True,
) -> dict[str, Any]:
    """Generate all recommended DNS records for ADP v1.1.

    Including SVCB (primary), TLSA (DANE), and TXT+SRV (fallback).

    Args:
        domain: Agent domain.
        fingerprint: Public key fingerprint.
        target: SRV target FQDN.
        port: Service port.
        well_known: Well-Known URL.
        svcb: Optional SVCB params dict with keys: target, alpn, bap, well_known.
        tlsa: Optional TLSA params dict with key: cert_sha256.
        fallback: Whether to include TXT+SRV fallback records.

    Returns:
        Dict with svcb_zone, tlsa_zone, txt, txt_zone, srv_tcp_zone, etc.
    """
    tgt = target or domain
    records: dict[str, Any] = {}

    # SVCB primary
    svcb_params = svcb or {}
    records["svcb_zone"] = generate_svcb_record(
        domain=domain,
        target=svcb_params.get("target", "."),
        alpn=svcb_params.get("alpn"),
        port=svcb_params.get("port", port),
        bap=svcb_params.get("bap", "a2a"),
        well_known=svcb_params.get("well_known", "agent.json"),
        cap_sha256=svcb_params.get("cap_sha256"),
    )

    # TLSA
    if tlsa and "cert_sha256" in tlsa:
        records["tlsa_zone"] = generate_tlsa_record(
            domain=domain, cert_sha256=tlsa["cert_sha256"], port=port
        )

    # Fallback
    if fallback:
        records["txt"] = generate_txt_record(
            domain, fingerprint, well_known=well_known, rel=rel, note=note
        )
        records["txt_zone"] = generate_txt_zone_entry(
            domain, fingerprint, well_known=well_known, rel=rel, note=note
        )
        records["srv_tcp_zone"] = generate_srv_zone_entry(domain, tgt, port=port)

    return records


# ═══════════════════════════════════════════════════════════════
# 解析
# ═══════════════════════════════════════════════════════════════

def parse_svcb_records(
    svcb_records: list[dict[str, Any]],
) -> dict[str, Any] | None:
    """Parse DNS SVCB query results into structured info.

    Args:
        svcb_records: List of SVCB record dicts with keys:
            priority, target, param_map (dict of SvcParam keys).

    Returns:
        Dict with type, target, port, alpn, bap, wellKnown, etc.,
        or None if no ServiceMode record exists.
    """
    if not svcb_records:
        return None

    service_modes = [r for r in svcb_records if r.get("priority", 0) > 0]
    alias_modes = [r for r in svcb_records if r.get("priority", 0) == 0]

    if not service_modes:
        return {
            "type": "alias",
            "targets": [r["target"] for r in alias_modes],
        }

    best = sorted(service_modes, key=lambda r: r.get("priority", 999))[0]
    params = best.get("param_map", best.get("params", {}))

    def _split(val):
        if isinstance(val, list):
            return val
        if isinstance(val, str):
            return [v.strip() for v in val.split(",")]
        return []

    return {
        "type": "service",
        "target": best.get("target", "."),
        "port": params.get("port", 443),
        "alpn": _split(params.get("alpn", "")),
        "bap": params.get("bap"),
        "wellKnown": params.get("well-known", "agent.json"),
        "cap": params.get("cap"),
        "capSha256": params.get("cap-sha256"),
        "ipv4hint": _split(params.get("ipv4hint", "")),
        "ipv6hint": _split(params.get("ipv6hint", "")),
    }


def parse_txt_record(txt_strings: list[str]) -> dict[str, str]:
    """Parse DNS TXT record strings into a key-value dict.

    Handles multi-string TXT records, splitting on `;`.
    """
    combined = "".join(txt_strings)
    result: dict[str, str] = {}
    for pair in combined.split(";"):
        trimmed = pair.strip()
        idx = trimmed.find("=")
        if idx == -1:
            continue
        result[trimmed[:idx]] = trimmed[idx + 1:]
    return result


def validate_txt_record(parsed: dict[str, str]) -> dict[str, Any]:
    """Validate a parsed TXT record for required fields."""
    errors: list[str] = []
    v = parsed.get("v", "")
    if not v or not (v.startswith("ADP1") or v.startswith("ADP/")):
        errors.append(f"Unsupported protocol: {v or 'missing'}")
    pk = parsed.get("pk", "")
    if not pk or not pk.startswith("ed25519:"):
        errors.append(f"Missing/invalid fingerprint: {pk or 'missing'}")
    wk = parsed.get("wk", "")
    if not wk or not wk.startswith("https://"):
        errors.append(f"Missing/invalid well-known: {wk or 'missing'}")
    return {"valid": len(errors) == 0, "errors": errors, "parsed": parsed}
