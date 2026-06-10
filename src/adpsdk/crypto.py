"""ADP SDK — Cryptography module.

Ed25519 key generation, signing, verification, and fingerprint computation.

Fingerprint format: SHA-256 of raw 32-byte Ed25519 public key,
base64url-encoded, prefixed with "ed25519:".

Dependencies are loaded lazily — import this module without ``cryptography``
installed and you will only get an error when calling a function that needs it.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass

# ─── Lazy cryptography imports ─────────────────────────────────

_crypto_imports: dict = {}
_crypto_loaded = False


def _load_crypto():
    """Import cryptography lazily."""
    global _crypto_loaded, _crypto_imports
    if _crypto_loaded:
        return
    try:
        from cryptography.exceptions import InvalidSignature

        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519

        _crypto_imports = {
            "InvalidSignature": InvalidSignature,
            "serialization": serialization,
            "ed25519": ed25519,
        }
        _crypto_loaded = True
    except ImportError:
        raise ImportError(
            "cryptography package is required for adpsdk.crypto. "
            "Install with: pip install cryptography"
        )


# ─── Dataclass ─────────────────────────────────────────────────


@dataclass
class KeyPair:
    """Ed25519 key pair with fingerprint."""

    public_key_bytes: bytes  # raw 32-byte public key
    private_key_bytes: bytes  # raw 32-byte seed
    fingerprint: str  # "ed25519:BASE64URL"


# ─── Public API ────────────────────────────────────────────────


def generate_key_pair() -> KeyPair:
    """Generate a new Ed25519 key pair and compute its fingerprint.

    Returns:
        KeyPair with raw key bytes and base64url fingerprint.
    """
    _load_crypto()
    ed = _crypto_imports["ed25519"]
    ser = _crypto_imports["serialization"]

    private_key = ed.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    priv_bytes = private_key.private_bytes(
        encoding=ser.Encoding.Raw,
        format=ser.PrivateFormat.Raw,
        encryption_algorithm=ser.NoEncryption(),
    )
    pub_bytes = public_key.public_bytes(
        encoding=ser.Encoding.Raw,
        format=ser.PublicFormat.Raw,
    )

    fingerprint = compute_fingerprint(pub_bytes)
    return KeyPair(
        public_key_bytes=pub_bytes,
        private_key_bytes=priv_bytes,
        fingerprint=fingerprint,
    )


def compute_fingerprint(public_key_bytes: bytes) -> str:
    """Compute the Ed25519 fingerprint from raw public key bytes.

    Fingerprint = "ed25519:" + base64url(SHA-256(raw_public_key))

    Args:
        public_key_bytes: 32-byte raw Ed25519 public key.

    Returns:
        Fingerprint string like "ed25519:dGhpcyBpcyBhIHRlc3Q...".
    """
    digest = hashlib.sha256(public_key_bytes).digest()
    return f"ed25519:{_bytes_to_base64url(digest)}"


def sign(private_key_bytes: bytes, message: bytes | str) -> str:
    """Sign a message using an Ed25519 private key.

    Args:
        private_key_bytes: 32-byte raw Ed25519 seed.
        message: Message to sign (bytes or string, UTF-8 encoded).

    Returns:
        Base64url-encoded signature string.
    """
    _load_crypto()
    ed = _crypto_imports["ed25519"]

    private_key = ed.Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    msg_bytes = message.encode("utf-8") if isinstance(message, str) else message
    sig = private_key.sign(msg_bytes)
    return _bytes_to_base64url(sig)


def verify(public_key_bytes: bytes, message: bytes | str, signature: str) -> bool:
    """Verify a signature against a message and Ed25519 public key.

    Args:
        public_key_bytes: 32-byte raw Ed25519 public key.
        message: Original signed message (bytes or string, UTF-8 encoded).
        signature: Base64url-encoded signature.

    Returns:
        True if the signature is valid.
    """
    _load_crypto()
    ed = _crypto_imports["ed25519"]

    public_key = ed.Ed25519PublicKey.from_public_bytes(public_key_bytes)
    msg_bytes = message.encode("utf-8") if isinstance(message, str) else message
    sig_bytes = _base64url_to_bytes(signature)
    try:
        public_key.verify(sig_bytes, msg_bytes)
        return True
    except _crypto_imports["InvalidSignature"]:
        return False


def export_key(key_bytes: bytes) -> str:
    """Export raw key bytes as a base64url string."""
    return _bytes_to_base64url(key_bytes)


def import_key(encoded: str) -> bytes:
    """Import a base64url-encoded key string to raw bytes."""
    return _base64url_to_bytes(encoded)


def export_public_key_pem(public_key_bytes: bytes) -> str:
    """Export a raw public key to PEM format (SPKI)."""
    _load_crypto()
    ed = _crypto_imports["ed25519"]
    ser = _crypto_imports["serialization"]

    pub_key = ed.Ed25519PublicKey.from_public_bytes(public_key_bytes)
    return pub_key.public_bytes(
        encoding=ser.Encoding.PEM,
        format=ser.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def export_private_key_pem(private_key_bytes: bytes) -> str:
    """Export a raw private key to PEM format (PKCS8)."""
    _load_crypto()
    ed = _crypto_imports["ed25519"]
    ser = _crypto_imports["serialization"]

    priv_key = ed.Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    return priv_key.private_bytes(
        encoding=ser.Encoding.PEM,
        format=ser.PrivateFormat.PKCS8,
        encryption_algorithm=ser.NoEncryption(),
    ).decode("ascii")


# ─── Base64url helpers ─────────────────────────────────────────


def _bytes_to_base64url(data: bytes) -> str:
    """Encode bytes to a base64url string (no padding)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _base64url_to_bytes(encoded: str) -> bytes:
    """Decode a base64url string to bytes."""
    pad = 4 - len(encoded) % 4
    if pad != 4:
        encoded += "=" * pad
    return base64.urlsafe_b64decode(encoded)
