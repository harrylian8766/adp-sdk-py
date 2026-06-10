"""ADP SDK — Agent WebSocket connection client.

Provides an AgentConnection class for secure WebSocket connections
between agents, with signature-based handshake per the ADP spec.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from logging import getLogger
from typing import Any, Callable

try:
    import websockets  # noqa: F401
    from websockets.asyncio.client import ClientConnection
except ImportError:
    websockets = None
    ClientConnection = None  # type: ignore

# Lazy crypto import — only used when actual crypto functions are called
_sign = None
_verify = None


def _get_sign():
    """Lazy-load the sign function from adpsdk.crypto."""
    global _sign
    if _sign is None:
        from adpsdk.crypto import sign as s

        _sign = s
    return _sign


def _get_verify():
    """Lazy-load the verify function from adpsdk.crypto."""
    global _verify
    if _verify is None:
        from adpsdk.crypto import verify as v

        _verify = v
    return _verify

logger = getLogger(__name__)

EventHandler = Callable[[Any], None]


@dataclass
class AgentMessage:
    """A structured agent-to-agent message per the ADP spec."""

    id: str
    from_: str
    to: str
    type: str  # chat, task, swarm, system
    timestamp: str
    body: dict[str, Any]
    signature: str | None = None
    attachments: list[dict[str, Any]] | None = None


class AgentConnection:
    """WebSocket connection to a remote ADP agent.

    Handles signature-based handshake and message signing/verification
    per the ADP Agent Gateway Protocol (AGP) spec.

    Attributes:
        url: WebSocket URL (wss://).
        ws: Underlying websockets connection.
        agent_id: Local agent identifier.
        remote_agent_id: Remote agent identifier.
        trust_level: Current trust level.
        listeners: Registered event handlers.
    """

    def __init__(
        self,
        ws_url: str,
        *,
        private_key: bytes | None = None,
        public_key: bytes | None = None,
        remote_fingerprint: str | None = None,
        agent_id: str = "unknown",
        remote_agent_id: str | None = None,
    ) -> None:
        """Initialize an AgentConnection.

        Args:
            ws_url: WebSocket URL for the remote agent, e.g. "wss://alice.agent/agent/chat".
            private_key: 32-byte raw Ed25519 private key (for signing outgoing messages).
            public_key: 32-byte raw Ed25519 public key (to send in handshake).
            remote_fingerprint: Expected remote agent fingerprint for verification.
            agent_id: Local agent identifier (e.g. "bob.agent").
            remote_agent_id: Remote agent identifier (e.g. "alice.agent").
        """
        self.url = ws_url
        self.private_key = private_key
        self.public_key = public_key
        self.remote_fingerprint = remote_fingerprint
        self.agent_id = agent_id
        self.remote_agent_id = remote_agent_id or agent_id
        self.ws: ClientConnection | None = None
        self._remote_public_key: bytes | None = None
        self._listeners: dict[str, list[EventHandler]] = {}
        self._running = False
        self.trust_level: str = "unverified"

    # ─── Public API ───────────────────────────────────────

    async def connect(self) -> None:
        """Open the WebSocket connection and perform the ADP handshake.

        Sends an `adp_handshake` system message with protocol version,
        agent ID, public key, and a signed nonce.
        """
        if websockets is None:
            raise ImportError(
                "websockets package is required for AgentConnection. "
                "Install with: pip install websockets"
            )
        self.ws = await websockets.connect(self.url)
        self._running = True

        # Send handshake if we have keys
        if self.private_key and self.public_key:
            await self._send_handshake()

        # Start the receive loop in the background
        # (caller should await self.listen() or run it as a task)

    async def listen(self) -> None:
        """Listen for incoming messages (blocking loop).

        Must be called after connect(). Runs until the connection is closed.
        """
        if self.ws is None:
            raise RuntimeError("Not connected. Call connect() first.")

        try:
            async for raw in self.ws:
                await self._handle_message(raw)
        except websockets.exceptions.ConnectionClosed:
            self._emit("close", {"reason": "Connection closed"})
            self._running = False

    async def send(
        self,
        body: dict[str, Any] | str,
        msg_type: str = "chat",
    ) -> str:
        """Send a signed message to the remote agent.

        Args:
            body: Message body dict, or a plain string (wrapped as content).
            msg_type: Message type — chat, task, swarm, or system.

        Returns:
            The message UUID.
        """
        if self.ws is None:
            raise RuntimeError("Not connected. Call connect() first.")

        if isinstance(body, str):
            body = {"content": body, "contentType": "text/plain"}

        msg_id = uuid.uuid4().hex
        msg: dict[str, Any] = {
            "id": msg_id,
            "from": f"agent:{self.agent_id}",
            "to": f"agent:{self.remote_agent_id}",
            "type": msg_type,
            "timestamp": _utcnow(),
            "body": body,
        }

        # Sign if we have a private key
        if self.private_key:
            payload = json.dumps(body, sort_keys=True)
            msg["signature"] = _get_sign()(self.private_key, payload)

        await self.ws.send(json.dumps(msg))
        return msg_id

    def on(self, event: str, handler: EventHandler) -> None:
        """Register an event handler.

        Supported events:
            - "message": called with parsed message dict.
            - "close": called with close info dict.
            - "error": called with exception or error dict.
            - "verified": called with trust level info.
            - "handshake_ack": called with handshake response dict.
        """
        self._listeners.setdefault(event, []).append(handler)

    async def close(self) -> None:
        """Close the WebSocket connection."""
        self._running = False
        if self.ws is not None:
            await self.ws.close()
            self.ws = None

    @property
    def connected(self) -> bool:
        """Check if the connection is active."""
        return self._running and self.ws is not None

    # ─── Internal methods ─────────────────────────────────

    async def _send_handshake(self) -> None:
        """Send the ADP handshake message."""
        assert self.ws is not None
        assert self.private_key is not None
        assert self.public_key is not None

        nonce = uuid.uuid4().hex
        handshake_body = {
            "action": "adp_handshake",
            "protocol": "ADP/1.0",
            "agent_id": f"agent:{self.agent_id}",
            "public_key": self.public_key.hex(),
            "nonce": nonce,
        }

        payload = json.dumps(handshake_body, sort_keys=True)
        signature = _get_sign()(self.private_key, payload)

        handshake_msg = {
            "id": uuid.uuid4().hex,
            "from": f"agent:{self.agent_id}",
            "to": f"agent:{self.remote_agent_id}",
            "type": "system",
            "timestamp": _utcnow(),
            "body": handshake_body,
            "signature": signature,
        }

        await self.ws.send(json.dumps(handshake_msg))

    async def _handle_message(self, raw: str | bytes) -> None:
        """Parse and handle an incoming WebSocket message."""
        try:
            msg_data = json.loads(raw) if isinstance(raw, str) else json.loads(raw.decode())
        except json.JSONDecodeError as exc:
            self._emit("error", {"error": f"Invalid JSON: {exc}"})
            return

        # Check for handshake acknowledgement
        body = msg_data.get("body", {})
        if body.get("action") == "adp_handshake_ack":
            if "public_key" in body:
                try:
                    self._remote_public_key = bytes.fromhex(body["public_key"])
                except (ValueError, TypeError):
                    self._emit("error", {"error": "Invalid remote public key in handshake"})
                    return
            self._emit("handshake_ack", body)
            return

        # Verify signature if present
        if msg_data.get("signature") and self._remote_public_key:
            payload = json.dumps(body, sort_keys=True)
            sig = msg_data["signature"]
            valid = _get_verify()(self._remote_public_key, payload, sig)
            if valid and self.trust_level != "peer-verified":
                self.trust_level = "key-verified"
                self._emit("verified", {"trust_level": "key-verified"})

        self._emit("message", msg_data)

    def _emit(self, event: str, data: Any) -> None:
        """Emit an event to all registered handlers."""
        for handler in self._listeners.get(event, []):
            try:
                handler(data)
            except Exception as exc:
                logger.warning("Error in %s handler: %s", event, exc)


def _utcnow() -> str:
    """Return an ISO 8601 UTC timestamp."""
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
