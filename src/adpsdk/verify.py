"""ADP SDK v1.1 — Verification chain module.

Trust chain (v1.1): dns-verified → dane-verified → key-verified → peer-verified
"""

from __future__ import annotations

from typing import Any


def verify_fingerprint_chain(
    dns_info: dict[str, Any],
    agent_json: dict[str, Any],
) -> dict[str, Any]:
    """Verify DNS fingerprint matches agent.json (v1.1).

    Supports both SVCB capSha256 and TXT fallback pk.

    Args:
        dns_info: DNS info dict from discovery.
        agent_json: Full agent.json metadata dict.

    Returns:
        Dict with valid, dns_fingerprint, meta_fingerprint, source.
    """
    dns_fp = dns_info.get("publicKey") or dns_info.get("capSha256", "")
    meta_fp = (
        agent_json.get("identity", {}).get("publicKey", {}).get("fingerprint", "")
    )
    source = "txt-fallback" if dns_info.get("svcFallback") else "svcb"
    return {
        "valid": dns_fp != "" and dns_fp == meta_fp,
        "dns_fingerprint": dns_fp,
        "meta_fingerprint": meta_fp,
        "source": source,
    }


def verify_tlsa(
    tlsa_records: list[str],
    cert_spki_sha256: str,
) -> dict[str, Any]:
    """Verify TLSA records against a TLS certificate's SPKI hash (DANE).

    Checks for DANE-EE (3) / SPKI (1) / SHA-256 (1) matching.

    Args:
        tlsa_records: TLSA record data strings.
        cert_spki_sha256: SHA-256 hash of the certificate's SPKI.

    Returns:
        Dict with valid, matched, errors.
    """
    if not tlsa_records:
        return {"valid": False, "matched": None, "errors": ["No TLSA records"]}
    if not cert_spki_sha256:
        return {"valid": False, "matched": None, "errors": ["No SPKI hash provided"]}

    for record in tlsa_records:
        parts = record.strip().split()
        if len(parts) < 4:
            continue
        usage, selector, matching_type, cert_data = parts[:4]
        if usage == "3" and selector == "1" and matching_type == "1":
            if cert_data == cert_spki_sha256:
                return {
                    "valid": True,
                    "matched": f"3 1 1 {cert_data}",
                    "errors": [],
                }

    return {
        "valid": False,
        "matched": None,
        "errors": [f"No TLSA record matching SPKI {cert_spki_sha256}"],
    }


def verify_public_key_integrity(agent_json: dict[str, Any]) -> dict[str, Any]:
    """Verify full public key's SHA-256 matches declared fingerprint.

    Args:
        agent_json: Full agent.json dict.

    Returns:
        Dict with valid, computed, declared, or error.
    """
    pubkey_info = agent_json.get("identity", {}).get("publicKey", {})
    declared_fp = pubkey_info.get("fingerprint", "")
    full_key = pubkey_info.get("full")
    if not full_key:
        return {"valid": False, "error": "Full public key not provided"}

    try:
        from adpsdk.crypto import compute_fingerprint

        key_bytes = _decode_public_key(full_key)
        computed_fp = compute_fingerprint(key_bytes)
        return {
            "valid": computed_fp == declared_fp,
            "computed": computed_fp,
            "declared": declared_fp,
        }
    except Exception as exc:
        return {"valid": False, "error": str(exc)}


def run_verification_chain(
    dns_info: dict[str, Any],
    agent_json: dict[str, Any],
    cert_spki_sha256: str | None = None,
) -> dict[str, Any]:
    """Run the complete v1.1 verification chain (up to 4 steps).

    1. Fingerprint chain: DNS → Well-Known.
    2. DANE/TLSA (if TLSA records + cert available).
    3. Public key integrity.
    4. Protocol version.

    Args:
        dns_info: DNS info from discovery.
        agent_json: Full agent.json.
        cert_spki_sha256: Optional cert SPKI hash for DANE.

    Returns:
        Dict with valid, trust_level, results.
    """
    results: list[dict[str, Any]] = []
    trust_level = "unverified"

    # Step 1: Fingerprint chain
    r1 = verify_fingerprint_chain(dns_info, agent_json)
    results.append({"step": "fingerprint-chain", **r1})
    if not r1["valid"]:
        return {"valid": False, "trust_level": trust_level, "results": results}
    trust_level = "dns-verified"

    # Step 2: DANE/TLSA (if available)
    tlsa_records = dns_info.get("tlsa", [])
    if tlsa_records and cert_spki_sha256:
        r2 = verify_tlsa(tlsa_records, cert_spki_sha256)
        results.append({"step": "tlsa-dane", **r2})
        if r2["valid"]:
            trust_level = "dane-verified"

    # Step 3: Public key integrity
    r3 = verify_public_key_integrity(agent_json)
    results.append({"step": "pubkey-integrity", **r3})
    if not r3["valid"]:
        return {"valid": False, "trust_level": trust_level, "results": results}
    trust_level = "key-verified"

    # Step 4: Protocol version
    protocol = agent_json.get("protocol", "")
    r4 = {
        "step": "protocol-version",
        "valid": protocol in ("ADP/1.0", "ADP/1.1"),
        "declared": protocol,
    }
    results.append(r4)

    overall = r1["valid"] and r3["valid"] and r4["valid"]
    return {"valid": overall, "trust_level": trust_level, "results": results}


# ─── Internal helpers ──────────────────────────────────────

def _decode_public_key(full_key: str) -> bytes:
    """Decode a full public key from PEM or base64url format to raw 32 bytes."""
    import base64

    if full_key.startswith("-----BEGIN"):
        from cryptography.hazmat.primitives import serialization

        pub_key = serialization.load_pem_public_key(full_key.encode("ascii"))
        return pub_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    # base64url
    pad = 4 - len(full_key) % 4
    if pad != 4:
        full_key += "=" * pad
    decoded = base64.urlsafe_b64decode(full_key)

    if len(decoded) == 32:
        return decoded

    # SPKI-encoded
    from cryptography.hazmat.primitives import serialization

    pub_key = serialization.load_der_public_key(decoded)
    return pub_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
