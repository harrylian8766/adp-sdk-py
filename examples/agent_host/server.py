#!/usr/bin/env python3
"""ADP Agent Host — Reference Implementation Server.

Serves an ADP-compliant agent endpoint with:
  - Landing page (GET /)
  - Well-Known agent.json (GET /.well-known/agent.json)
  - Agent API status (GET /agent/)
  - WebSocket chat (WSS /agent/chat)

Usage:
    python examples/agent_host/server.py
    python examples/agent_host/server.py --port 8080
    python examples/agent_host/server.py --config ./my-agent.json

Requirements:
    pip install aiohttp websockets
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
import uuid
from pathlib import Path

# Ensure the adpsdk package is importable
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from adpsdk.agent_json import build_agent_json
from adpsdk.crypto import (
    compute_fingerprint,
    generate_key_pair,
    sign,
    verify,
)
from adpsdk.landing_page import generate_landing_page

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("agent-host")

# ─── Configuration ─────────────────────────────────────────────


def load_config(config_path: str) -> dict:
    """Load agent configuration from agent.json."""
    with open(config_path, "r") as f:
        config = json.load(f)

    # Rebuild with the builder to ensure all fields
    agent = build_agent_json(
        domain=config["domain"],
        name=config["name"],
        owner=config["owner"],
        public_key_fingerprint=config["publicKey"]["fingerprint"],
        public_key_full=config["publicKey"].get("full"),
        version=config.get("version", "1.0.0"),
        generator=config.get("generator", "adpsdk/1.0.0"),
        capabilities=config.get("capabilities", []),
        relationships=config.get("relationships", []),
        policies=config.get("policies", {}),
        availability=config.get("availability", {}),
    )
    return agent


# ─── WebSocket Chat Handler ────────────────────────────────────


class ChatServer:
    """Manages WebSocket chat connections and message routing."""

    def __init__(self, keys: dict, agent_json: dict):
        self.private_key = keys["private_key_bytes"]
        self.public_key = keys["public_key_bytes"]
        self.fingerprint = keys["fingerprint"]
        self.agent_json = agent_json
        self.peers: dict[str, "ChatPeer"] = {}

    async def handle_connection(self, ws, request):
        """Handle a new WebSocket chat connection."""
        peer_id = uuid.uuid4().hex[:8]
        peer = ChatPeer(ws, peer_id, self)
        self.peers[peer_id] = peer
        logger.info("Peer %s connected", peer_id)

        try:
            async for raw in ws:
                try:
                    msg = json.loads(raw) if isinstance(raw, str) else json.loads(raw.decode())
                except json.JSONDecodeError:
                    await ws.send(json.dumps({
                        "type": "system",
                        "body": {"action": "error", "message": "Invalid JSON"},
                    }))
                    continue

                await peer.handle_message(msg)

        except Exception as exc:
            logger.info("Peer %s disconnected: %s", peer_id, exc)
        finally:
            self.peers.pop(peer_id, None)


class ChatPeer:
    """Represents a connected peer agent."""

    def __init__(self, ws, peer_id: str, server: ChatServer):
        self.ws = ws
        self.peer_id = peer_id
        self.server = server
        self.remote_public_key: bytes | None = None
        self.remote_agent_id: str | None = None
        self.handshake_complete = False

    async def handle_message(self, msg: dict):
        """Process an incoming message."""
        msg_type = msg.get("type", "")
        body = msg.get("body", {})

        # Handle handshake
        if body.get("action") == "adp_handshake":
            await self._on_handshake(msg)
            return

        # Handle regular chat messages
        if msg_type == "chat":
            content = body.get("content", "")
            logger.info("Chat from %s: %s", self.remote_agent_id or self.peer_id, content)
            # Echo back as a simple echo bot
            reply = {
                "id": uuid.uuid4().hex,
                "from": f"agent:{self.server.agent_json['identity']['domain']}",
                "to": msg.get("from", "unknown"),
                "type": "chat",
                "timestamp": _utcnow(),
                "body": {
                    "content": f"Echo: {content}",
                    "contentType": "text/plain",
                    "replyTo": msg.get("id"),
                },
            }
            # Sign the reply
            payload = json.dumps(reply["body"], sort_keys=True)
            reply["signature"] = sign(self.server.private_key, payload)
            await self.ws.send(json.dumps(reply))

    async def _on_handshake(self, msg: dict):
        """Handle an incoming ADP handshake."""
        body = msg.get("body", {})
        remote_id = body.get("agent_id", "unknown")
        remote_pk_hex = body.get("public_key", "")
        protocol = body.get("protocol", "")

        logger.info(
            "Handshake from %s (protocol=%s)",
            remote_id, protocol,
        )

        # Store remote info
        self.remote_agent_id = remote_id.replace("agent:", "")
        if remote_pk_hex:
            try:
                self.remote_public_key = bytes.fromhex(remote_pk_hex)
            except (ValueError, TypeError):
                pass

        # Verify signature if we have the remote key
        if self.remote_public_key and msg.get("signature"):
            payload = json.dumps(body, sort_keys=True)
            if verify(self.remote_public_key, payload, msg["signature"]):
                self.handshake_complete = True
                logger.info("Handshake verified for %s", remote_id)
            else:
                logger.warning("Handshake signature verification failed for %s", remote_id)

        # Send acknowledgement
        ack = {
            "id": uuid.uuid4().hex,
            "from": f"agent:{self.server.agent_json['identity']['domain']}",
            "to": msg.get("from", remote_id),
            "type": "system",
            "timestamp": _utcnow(),
            "body": {
                "action": "adp_handshake_ack",
                "protocol": "ADP/1.0",
                "agent_id": f"agent:{self.server.agent_json['identity']['domain']}",
                "public_key": self.server.public_key.hex(),
                "status": "ok",
            },
        }
        # Sign ack
        payload = json.dumps(ack["body"], sort_keys=True)
        ack["signature"] = sign(self.server.private_key, payload)
        await self.ws.send(json.dumps(ack))


def _utcnow() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


# ─── HTTP Handlers ─────────────────────────────────────────────


async def handle_landing(request):
    """Serve the ADP landing page (GET /)."""
    agent = request.app["agent"]
    html = generate_landing_page(agent)
    return aiohttp.web.Response(text=html, content_type="text/html; charset=utf-8")


async def handle_well_known(request):
    """Serve agent.json (GET /.well-known/agent.json)."""
    agent = request.app["agent"]
    return aiohttp.web.json_response(agent)


async def handle_agent_status(request):
    """Serve agent API status (GET /agent/)."""
    agent = request.app["agent"]
    return aiohttp.web.json_response({
        "status": "ok",
        "agent": agent["identity"]["id"],
        "protocol": "ADP/1.0",
        "endpoints": agent["endpoints"],
        "fingerprint": agent["identity"]["publicKey"]["fingerprint"],
    })


async def handle_websocket(request):
    """Handle WebSocket upgrade (GET /agent/chat)."""
    ws = aiohttp.web.WebSocketResponse()
    await ws.prepare(request)
    chat_server = request.app["chat_server"]
    await chat_server.handle_connection(ws, request)
    return ws


# ─── Main ──────────────────────────────────────────────────────


async def main():
    parser = argparse.ArgumentParser(description="ADP Agent Host Server")
    parser.add_argument(
        "--host", default="0.0.0.0", help="Bind address (default: 0.0.0.0)"
    )
    parser.add_argument(
        "--port", type=int, default=8080, help="Bind port (default: 8080)"
    )
    parser.add_argument(
        "--config",
        default=None,
        help="Path to agent.json config (default: examples/agent_host/agent.json)",
    )
    parser.add_argument(
        "--generate-keys",
        action="store_true",
        help="Generate new Ed25519 keys instead of using config keys",
    )
    args = parser.parse_args()

    # Import aiohttp here to make it a lazy dependency
    try:
        import aiohttp.web
    except ImportError:
        print("aiohttp is required. Install with: pip install aiohttp")
        sys.exit(1)

    # Load config
    config_path = args.config
    if config_path is None:
        config_path = os.path.join(os.path.dirname(__file__), "agent.json")

    if not os.path.exists(config_path):
        print(f"Config file not found: {config_path}")
        print("Create an agent.json file first (see examples/agent_host/agent.json).")
        sys.exit(1)

    agent = load_config(config_path)

    # Generate or load keys
    if args.generate_keys:
        kp = generate_key_pair()
        logger.info("Generated new Ed25519 key pair")
        logger.info("  Public key (hex): %s", kp.public_key_bytes.hex())
        logger.info("  Fingerprint:      %s", kp.fingerprint)
    else:
        kp = generate_key_pair()
        # Use config key if available
        fp = agent["identity"]["publicKey"]["fingerprint"]
        if fp and not fp.startswith("ed25519:REPLACE_"):
            # We need the actual key bytes — for demo, generate new keys
            logger.info("Using auto-generated keys (add --generate-keys to see them)")
            logger.info("  Fingerprint: %s", kp.fingerprint)
        else:
            logger.info("Generated demo keys")
            logger.info("  Fingerprint: %s", kp.fingerprint)

    keys = {
        "private_key_bytes": kp.private_key_bytes,
        "public_key_bytes": kp.public_key_bytes,
        "fingerprint": kp.fingerprint,
    }

    # Build app
    app = aiohttp.web.Application()
    app["agent"] = agent
    app["chat_server"] = ChatServer(keys, agent)

    # Routes
    app.router.add_get("/", handle_landing)
    app.router.add_get("/.well-known/agent.json", handle_well_known)
    app.router.add_get("/agent/", handle_agent_status)
    app.router.add_get("/agent/chat", handle_websocket)

    # Start
    logger.info("=" * 60)
    logger.info("  ADP Agent Host Server")
    logger.info("  Agent:  %s", agent["identity"]["id"])
    logger.info("  Domain: %s", agent["identity"]["domain"])
    logger.info("  Listening on http://%s:%d", args.host, args.port)
    logger.info("  Well-Known: /.well-known/agent.json")
    logger.info("  Chat:       /agent/chat (WebSocket)")
    logger.info("=" * 60)

    runner = aiohttp.web.AppRunner(app)
    await runner.setup()
    site = aiohttp.web.TCPSite(runner, args.host, args.port)
    await site.start()

    # Keep running
    try:
        await asyncio.Event().wait()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        await runner.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
