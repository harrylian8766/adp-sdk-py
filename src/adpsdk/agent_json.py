"""ADP SDK v1.1 — Agent JSON metadata builder and validator.

Builds and validates agent.json objects matching the ADP v1.1 schema.
Adds 'dns' block (svcbRecord, tlsaRecord, dnssec) and DANE auth method.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

try:
    from pydantic import BaseModel, Field, field_validator, model_validator
    _has_pydantic = True
except ImportError:
    _has_pydantic = False

    class _StubBase:
        model_config = {}
        @classmethod
        def model_validate(cls, *a, **kw):
            raise ImportError("pydantic is required")
        def model_dump(self, *a, **kw):
            raise ImportError("pydantic is required")
    BaseModel = _StubBase
    def Field(*a, **kw): return None
    def field_validator(*a, **kw): return lambda f: f
    def model_validator(*a, **kw): return lambda f: f


# ─── v1.1 Models ────────────────────────────────────────────

class PublicKey(BaseModel):
    algorithm: str = Field(default="ed25519") if _has_pydantic else "ed25519"
    fingerprint: str = Field(...) if _has_pydantic else ""
    full: str | None = Field(default=None) if _has_pydantic else None

class Identity(BaseModel):
    id: str = Field(...) if _has_pydantic else ""
    domain: str | None = Field(default=None) if _has_pydantic else None
    name: str | None = Field(default=None) if _has_pydantic else None
    owner: str | None = Field(default=None) if _has_pydantic else None
    created: str | None = Field(default=None) if _has_pydantic else None
    public_key: PublicKey = Field(alias="publicKey") if _has_pydantic else PublicKey()

class Pricing(BaseModel):
    model: str = Field(default="free") if _has_pydantic else "free"
    details: str | None = Field(default=None) if _has_pydantic else None

class Capability(BaseModel):
    id: str = Field(...) if _has_pydantic else ""
    name: str = Field(...) if _has_pydantic else ""
    description: str = Field(default="") if _has_pydantic else ""
    input: list[str] = Field(default_factory=lambda: ["text"]) if _has_pydantic else ["text"]
    output: list[str] = Field(default_factory=lambda: ["text"]) if _has_pydantic else ["text"]
    interfaces: list[str] = Field(default_factory=lambda: ["chat"]) if _has_pydantic else ["chat"]
    languages: list[str] = Field(default_factory=lambda: ["en"]) if _has_pydantic else ["en"]
    pricing: Pricing = Field(default_factory=lambda: Pricing(model="free")) if _has_pydantic else Pricing()

class Endpoints(BaseModel):
    discovery: str | None = Field(default=None) if _has_pydantic else None
    well_known: str | None = Field(default=None, alias="wellKnown") if _has_pydantic else None
    chat: str | None = Field(default=None) if _has_pydantic else None
    tasks: str | None = Field(default=None) if _has_pydantic else None
    swarm: str | None = Field(default=None) if _has_pydantic else None
    webhook: str | None = Field(default=None) if _has_pydantic else None

class Interfaces(BaseModel):
    html: str | None = Field(default=None) if _has_pydantic else None
    api: str | None = Field(default=None) if _has_pydantic else None
    chat: str | None = Field(default=None) if _has_pydantic else None

class Relationship(BaseModel):
    type: str = Field(...) if _has_pydantic else ""
    id: str = Field(...) if _has_pydantic else ""
    name: str | None = Field(default=None) if _has_pydantic else None
    trust: str | None = Field(default=None) if _has_pydantic else None
    since: str | None = Field(default=None) if _has_pydantic else None

class RateLimit(BaseModel):
    requests_per_minute: int = Field(default=60, alias="requestsPerMinute") if _has_pydantic else 60
    burst_size: int = Field(default=10, alias="burstSize") if _has_pydantic else 10

class Security(BaseModel):
    tls_required: bool = Field(default=True, alias="tlsRequired") if _has_pydantic else True
    min_protocol_version: str = Field(default="ADP/1.1", alias="minProtocolVersion") if _has_pydantic else "ADP/1.1"
    auth_methods: list[str] = Field(default_factory=lambda: ["pubkey"], alias="authMethods") if _has_pydantic else ["pubkey"]
    rate_limit: RateLimit = Field(default_factory=lambda: RateLimit(requests_per_minute=60, burst_size=10), alias="rateLimit") if _has_pydantic else RateLimit()

class DnsInfo(BaseModel):
    svcb_record: str | None = Field(default=None, alias="svcbRecord") if _has_pydantic else None
    tlsa_record: str | None = Field(default=None, alias="tlsaRecord") if _has_pydantic else None
    dnssec: bool = Field(default=False) if _has_pydantic else False

class Policies(BaseModel):
    privacy: str | None = Field(default=None) if _has_pydantic else None
    terms: str | None = Field(default=None) if _has_pydantic else None
    data_retention: str | None = Field(default=None, alias="dataRetention") if _has_pydantic else None
    third_party_sharing: bool = Field(default=False, alias="thirdPartySharing") if _has_pydantic else False

class Availability(BaseModel):
    status: str = Field(default="unknown") if _has_pydantic else "unknown"
    uptime: str | None = Field(default=None) if _has_pydantic else None
    maintenance_window: str | None = Field(default=None, alias="maintenanceWindow") if _has_pydantic else None
    status_endpoint: str | None = Field(default=None, alias="statusEndpoint") if _has_pydantic else None

class Meta(BaseModel):
    updated: str | None = Field(default=None) if _has_pydantic else None
    version: str | None = Field(default=None) if _has_pydantic else None
    generator: str | None = Field(default=None) if _has_pydantic else None
    documentation: str | None = Field(default=None) if _has_pydantic else None

class AgentJSON(BaseModel):
    schema_: str = Field(default="https://raw.githubusercontent.com/harrylian8766/adp-protocol/main/schemas/v1.1/agent.json", alias="$schema") if _has_pydantic else "https://raw.githubusercontent.com/harrylian8766/adp-protocol/main/schemas/v1.1/agent.json"
    protocol: str = Field(default="ADP/1.1") if _has_pydantic else "ADP/1.1"
    identity: Identity = Field(...) if _has_pydantic else Identity()
    endpoints: Endpoints = Field(...) if _has_pydantic else Endpoints()
    capabilities: list[Capability] = Field(min_length=1) if _has_pydantic else []
    interfaces: Interfaces | None = Field(default=None) if _has_pydantic else None
    relationships: list[Relationship] = Field(default_factory=list) if _has_pydantic else []
    security: Security | None = Field(default=None) if _has_pydantic else None
    dns: DnsInfo | None = Field(default=None) if _has_pydantic else None
    policies: Policies | None = Field(default=None) if _has_pydantic else None
    availability: Availability | None = Field(default=None) if _has_pydantic else None
    meta: Meta | None = Field(default=None) if _has_pydantic else None


if _has_pydantic:
    @field_validator("protocol")
    @classmethod
    def _validate_protocol(cls, v: str) -> str:
        if v not in ("ADP/1.0", "ADP/1.1"):
            raise ValueError(f"Protocol must be ADP/1.0 or ADP/1.1, got {v}")
        return v
    AgentJSON.validate_protocol = _validate_protocol

    @model_validator(mode="after")
    def _check_required_fields(self: "AgentJSON") -> "AgentJSON":
        if not self.identity.id:
            raise ValueError("identity.id is required")
        if not self.identity.public_key.fingerprint:
            raise ValueError("identity.publicKey.fingerprint is required")
        return self
    AgentJSON.check_required_fields = _check_required_fields


# ─── Builder ────────────────────────────────────────────────

def build_agent_json(
    domain: str,
    *,
    name: str,
    owner: str,
    public_key_fingerprint: str,
    public_key_full: str | None = None,
    version: str = "1.0.0",
    generator: str = "adpsdk/1.1.0",
    capabilities: list[dict[str, Any]] | None = None,
    custom_endpoints: dict[str, str] | None = None,
    relationships: list[dict[str, Any]] | None = None,
    dns: dict[str, Any] | None = None,
    policies: dict[str, Any] | None = None,
    availability: dict[str, Any] | None = None,
    documentation: str | None = None,
) -> dict[str, Any]:
    """Build a complete agent.json dict matching the ADP v1.1 schema.

    Args:
        domain: Agent domain.
        name: Human-readable name.
        owner: Owner name.
        public_key_fingerprint: Ed25519 fingerprint.
        public_key_full: Optional PEM-encoded full public key.
        version: Agent software version.
        generator: SDK/generator string.
        capabilities: List of capability dicts.
        custom_endpoints: Override default endpoints.
        relationships: List of relationship dicts.
        dns: DNS verification info dict with svcbRecord, tlsaRecord, dnssec keys.
        policies: Policy configuration dict.
        availability: Availability dict.
        documentation: Documentation URL.

    Returns:
        Complete agent.json dict.
    """
    base_url = f"https://{domain}"
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    default_endpoints = {
        "discovery": f"{base_url}/",
        "wellKnown": f"{base_url}/.well-known/agent.json",
        "chat": f"wss://{domain}/agent/chat",
        "tasks": f"{base_url}/agent/tasks",
        "swarm": f"{base_url}/agent/swarm",
    }
    endpoints = {**default_endpoints, **(custom_endpoints or {})}

    caps = capabilities or []
    built_caps = [
        {
            "id": c.get("id", f"cap-{i}"),
            "name": c.get("name", f"Capability {i}"),
            "description": c.get("description", ""),
            "input": c.get("input", ["text"]),
            "output": c.get("output", ["text"]),
            "interfaces": c.get("interfaces", ["chat"]),
            "languages": c.get("languages", ["en"]),
            "pricing": c.get("pricing", {"model": "free", "details": None}),
        }
        for i, c in enumerate(caps)
    ]

    pol = policies or {}
    avail = availability or {}
    dns_info = dns or {}

    # v1.1: auth methods include "dane" if TLSA is configured
    auth_methods = ["pubkey"]
    if dns_info.get("tlsaRecord"):
        auth_methods.append("dane")

    result: dict[str, Any] = {
        "$schema": "https://raw.githubusercontent.com/harrylian8766/adp-protocol/main/schemas/v1.1/agent.json",
        "protocol": "ADP/1.1",
        "identity": {
            "id": f"agent:{domain}",
            "domain": domain,
            "name": name,
            "owner": owner,
            "created": now,
            "publicKey": {
                "algorithm": "ed25519",
                "fingerprint": public_key_fingerprint,
                "full": public_key_full,
            },
        },
        "endpoints": endpoints,
        "capabilities": built_caps,
        "interfaces": {
            "html": f"{base_url}/",
            "api": f"{base_url}/agent/",
            "chat": f"wss://{domain}/agent/chat",
        },
        "relationships": relationships or [],
        "security": {
            "tlsRequired": True,
            "minProtocolVersion": "ADP/1.1",
            "authMethods": auth_methods,
            "rateLimit": {"requestsPerMinute": 60, "burstSize": 10},
        },
        "dns": {
            "svcbRecord": dns_info.get("svcbRecord", domain),
            "tlsaRecord": dns_info.get("tlsaRecord"),
            "dnssec": dns_info.get("dnssec", False),
        },
        "policies": {
            "privacy": pol.get("privacy", f"{base_url}/policies/privacy"),
            "terms": pol.get("terms", f"{base_url}/policies/terms"),
            "dataRetention": pol.get("dataRetention", "7 days"),
            "thirdPartySharing": pol.get("thirdPartySharing", False),
        },
        "availability": {
            "status": avail.get("status", "unknown"),
            "uptime": avail.get("uptime"),
            "maintenanceWindow": avail.get("maintenanceWindow"),
            "statusEndpoint": avail.get("statusEndpoint"),
        },
        "meta": {
            "updated": now,
            "version": version,
            "generator": generator,
            "documentation": documentation,
        },
    }

    if _has_pydantic:
        validated = AgentJSON.model_validate(result)
        return validated.model_dump(by_alias=True)

    return result


def validate_agent_json(data: dict[str, Any]) -> dict[str, Any]:
    """Validate an agent.json dict (v1.0 and v1.1 compatible).

    Returns:
        Dict with keys: valid (bool), errors (list).
    """
    errors: list[str] = []

    protocol = data.get("protocol", "")
    if protocol not in ("ADP/1.0", "ADP/1.1"):
        errors.append(f"Expected ADP/1.0 or ADP/1.1, got {protocol}")
    if not data.get("identity", {}).get("id"):
        errors.append("Missing identity.id")
    if not data.get("identity", {}).get("publicKey", {}).get("fingerprint"):
        errors.append("Missing identity.publicKey.fingerprint")
    if not data.get("endpoints") or not isinstance(data.get("endpoints"), dict):
        errors.append("Missing or invalid endpoints")
    caps = data.get("capabilities")
    if not caps or not isinstance(caps, list) or len(caps) == 0:
        errors.append("At least one capability required")

    if errors:
        return {"valid": False, "errors": errors}

    if _has_pydantic:
        try:
            AgentJSON.model_validate(data)
            return {"valid": True, "errors": []}
        except Exception as e:
            return {"valid": False, "errors": [str(e)]}

    return {"valid": True, "errors": []}
