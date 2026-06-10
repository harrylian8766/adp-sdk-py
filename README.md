# ADP SDK for Python 🐍

**Python SDK for the Agent Discovery Protocol (ADP) v1.0**

A complete Python implementation of the ADP specification — discover, verify, and connect to AI agents using DNS, HTTPS, and WebSocket.

## Features

- 🔑 **Ed25519 Cryptography** — Key generation, signing, verification, fingerprint computation
- 🌐 **DNS Records** — Generate and parse `_agent` TXT and SRV records
- 📋 **Agent Metadata** — Build and validate `agent.json` with Pydantic models
- 🎨 **Landing Page** — Generate dark-themed HTML discovery pages with JSON-LD
- 🔍 **Three-Layer Discovery** — DNS → Well-Known → Verification
- 🔗 **WebSocket Connection** — Signature-based handshake and secure chat
- ✅ **Verification Chain** — Full fingerprint, integrity, and protocol validation

## Installation

```bash
pip install -e /path/to/adp-sdk-py
```

Or install with all optional dependencies:

```bash
pip install -e "/path/to/adp-sdk-py[dev]"
```

Dependencies:
- `cryptography` — Ed25519 key operations
- `dnspython` — DNS record resolution
- `aiohttp` — HTTP client/server
- `websockets` — WebSocket connections
- `pydantic` — Schema validation

## Quick Start

### 1. Generate Keys

```python
from adpsdk import generate_key_pair

kp = generate_key_pair()
print(kp.fingerprint)  # ed25519:BASE64URL...
```

### 2. Generate DNS Records

```python
from adpsdk import generate_all_dns_records

records = generate_all_dns_records(
    domain="alice.agent",
    fingerprint=kp.fingerprint,
)
print(records["txt_zone"])      # Zone file TXT entry
print(records["srv_tcp_zone"])  # Zone file SRV entry
```

### 3. Build agent.json

```python
from adpsdk import build_agent_json

agent = build_agent_json(
    domain="alice.agent",
    name="Alice's Agent",
    owner="Alice",
    public_key_fingerprint=kp.fingerprint,
    capabilities=[
        {
            "id": "chat",
            "name": "Conversation",
            "input": ["text"],
            "output": ["text"],
        }
    ],
)
```

### 4. Generate Landing Page

```python
from adpsdk import generate_landing_page

html = generate_landing_page(agent)
with open("index.html", "w") as f:
    f.write(html)
```

### 5. Discover an Agent

```python
import asyncio
import dns.asyncresolver
import aiohttp
from adpsdk import discover_agent

async def main():
    async def resolve_txt(name):
        resolver = dns.asyncresolver.Resolver()
        ans = await resolver.resolve(name, "TXT")
        return [s.decode() for rdata in ans for s in rdata.strings]

    async def fetch(url, headers):
        async with aiohttp.ClientSession() as s:
            async with s.get(url, headers=headers) as r:
                body = await r.json()
                from adpsdk.discover import HttpResponse
                return HttpResponse(status=r.status, body=body, ok=r.ok)

    result = await discover_agent(
        "alice.agent",
        dns_resolve_txt=resolve_txt,
        http_fetch=fetch,
    )
    print(f"Trust: {result.trust_level}")
    print(f"Capabilities: {len(result.meta['capabilities'])}")

asyncio.run(main())
```

### 6. Connect via WebSocket

```python
import asyncio
from adpsdk import generate_key_pair, AgentConnection

async def main():
    kp = generate_key_pair()
    conn = AgentConnection(
        "wss://alice.agent/agent/chat",
        private_key=kp.private_key_bytes,
        public_key=kp.public_key_bytes,
        agent_id="bob.agent",
        remote_agent_id="alice.agent",
    )

    conn.on("message", lambda msg: print(f"Received: {msg}"))
    conn.on("verified", lambda info: print(f"Trust: {info['trust_level']}"))

    await conn.connect()
    await conn.send("Hello Alice!")
    await conn.listen()

asyncio.run(main())
```

## Module Overview

| Module | Description |
|--------|-------------|
| `adpsdk.crypto` | Ed25519 key generation, signing, verification, fingerprint |
| `adpsdk.dns_records` | TXT/SRV record generation and parsing |
| `adpsdk.agent_json` | Build and validate agent.json (Pydantic models) |
| `adpsdk.landing_page` | HTML landing page with dark theme |
| `adpsdk.discover` | Three-layer discovery client |
| `adpsdk.connect` | WebSocket AgentConnection with handshake |
| `adpsdk.verify` | Full verification chain (fingerprint, integrity, protocol) |

## Discovery Flow

```
┌─────────────────────────────────────────────┐
│  Layer 1: DNS TXT Query                      │
│  _agent.{domain} → v=ADP1, pk=ed25519:...,  │
│                     wk=https://...             │
├─────────────────────────────────────────────┤
│  Layer 2: Well-Known JSON                    │
│  GET /.well-known/agent.json                 │
│  → identity, capabilities, endpoints          │
├─────────────────────────────────────────────┤
│  Layer 3: Verification                       │
│  DNS pk == agent.json fingerprint            │
│  SHA-256(raw pubkey) matches declared fp      │
│  Protocol version ADP/1.0                     │
└─────────────────────────────────────────────┘
```

## Trust Levels

| Level | Verification | Meaning |
|-------|-------------|---------|
| `unverified` | None | Initial discovery, not verified |
| `dns-verified` | DNS TXT pk found | Public key fingerprint obtained |
| `key-verified` | Fingerprint matches + signature verified | Trusted connection established |
| `peer-verified` | Bidirectional signature + human confirmation | Full mutual trust |

## Examples

### CLI Discovery Tool

```bash
python examples/discover_agent.py alice.agent
python examples/discover_agent.py alice.agent --json --full
```

### Agent Host Server

```bash
# Start the agent host with auto-generated keys
python examples/agent_host/server.py --port 8080 --generate-keys

# Visit http://localhost:8080/ in your browser
# Agent.json at http://localhost:8080/.well-known/agent.json
# WebSocket chat at ws://localhost:8080/agent/chat
```

## Protocol Reference

- **Protocol identifier:** `urn:adp:1`
- **Well-Known URI:** `/.well-known/agent.json`
- **DNS TXT name:** `_agent.{domain}`
- **DNS SRV name:** `_agent._tcp.{domain}`
- **Default signature algorithm:** Ed25519
- **Transport:** TLS 1.3 + WSS

See [PROTOCOL.md](https://github.com/agent-discovery/adp-protocol/blob/main/PROTOCOL.md) for the full specification.

## License

MIT
