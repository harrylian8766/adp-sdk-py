"""ADP SDK — Agent Discovery Protocol v1.1 Python SDK.

SVCB-first DNS discovery with TXT+SRV fallback.
DANE/TLSA TLS endpoint verification.
Trust chain: unverified → dns-verified → dane-verified → key-verified → peer-verified

Usage:
    import adpsdk
    kp = adpsdk.generate_key_pair()
    svcb_zone = adpsdk.generate_svcb_record(domain="alice.example.com")
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from adpsdk.dns_records import (  # noqa: E402
    generate_svcb_record,
    generate_svcb_index_record,
    build_svcb_info,
    generate_tlsa_record,
    generate_txt_record,
    generate_txt_zone_entry,
    generate_srv_zone_entry,
    generate_all_dns_records,
    parse_svcb_records,
    parse_txt_record,
    validate_txt_record,
)
from adpsdk.landing_page import generate_landing_page  # noqa: E402

if TYPE_CHECKING:
    from adpsdk.agent_json import build_agent_json, validate_agent_json
    from adpsdk.connect import AgentConnection
    from adpsdk.crypto import (
        compute_fingerprint,
        export_key,
        generate_key_pair,
        import_key,
        sign,
        verify,
    )
    from adpsdk.discover import discover_agent, discover_agents
    from adpsdk.verify import (
        run_verification_chain,
        verify_fingerprint_chain,
        verify_public_key_integrity,
        verify_tlsa,
    )


def __getattr__(name: str):
    """Lazy import for modules with heavy dependencies."""
    crypto_attrs = {
        "generate_key_pair": "crypto",
        "compute_fingerprint": "crypto",
        "sign": "crypto",
        "verify": "crypto",
        "export_key": "crypto",
        "import_key": "crypto",
    }
    if name in crypto_attrs:
        mod = __import__(f"adpsdk.{crypto_attrs[name]}", fromlist=[name])
        return getattr(mod, name)

    lazy_map = {
        "build_agent_json": "agent_json",
        "validate_agent_json": "agent_json",
        "discover_agent": "discover",
        "discover_agents": "discover",
        "AgentConnection": "connect",
        "verify_fingerprint_chain": "verify",
        "verify_public_key_integrity": "verify",
        "verify_tlsa": "verify",
        "run_verification_chain": "verify",
    }
    if name in lazy_map:
        mod = __import__(f"adpsdk.{lazy_map[name]}", fromlist=[name])
        return getattr(mod, name)

    raise AttributeError(f"module 'adpsdk' has no attribute {name!r}")


__all__ = [
    # crypto
    "generate_key_pair", "compute_fingerprint", "sign", "verify",
    "export_key", "import_key",
    # dns_records — SVCB + TLSA (v1.1)
    "generate_svcb_record", "generate_svcb_index_record", "build_svcb_info",
    "generate_tlsa_record",
    # dns_records — TXT/SRV fallback
    "generate_txt_record", "generate_txt_zone_entry",
    "generate_srv_zone_entry", "generate_all_dns_records",
    "parse_svcb_records", "parse_txt_record", "validate_txt_record",
    # agent_json
    "build_agent_json", "validate_agent_json",
    # landing_page
    "generate_landing_page",
    # discover
    "discover_agent", "discover_agents",
    # connect
    "AgentConnection",
    # verify
    "verify_fingerprint_chain", "verify_tlsa",
    "verify_public_key_integrity", "run_verification_chain",
]
