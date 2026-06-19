"""
veritrail.crypto
================
Cryptographic primitives for Veritrail.

Design choices are deliberately conservative and standards-aligned:

* Signatures: Ed25519 (EdDSA) — NIST FIPS 186-5 approved, deterministic,
  resistant to the nonce-reuse failures that plague ECDSA.
* Hashing: SHA-256 — NIST FIPS 180-4.
* Canonical serialization: RFC 8785-style sorted, separator-tight JSON so
  that the bytes signed by a producer are *exactly* the bytes verified by a
  consumer. Any ambiguity here is a forgery vector, so it is centralized.

This module never logs, prints, or persists private key material.
"""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

__all__ = [
    "canonical_bytes",
    "sha256_hex",
    "generate_keypair",
    "sign",
    "verify",
    "public_key_to_b64",
    "public_key_from_b64",
    "private_key_to_b64",
    "private_key_from_b64",
]


def canonical_bytes(obj: Any) -> bytes:
    """Deterministically serialize an object to bytes for hashing/signing.

    Keys are sorted, whitespace is stripped, and non-ASCII is preserved as
    UTF-8. The same logical object always yields identical bytes, which is the
    bedrock of a tamper-evident, signature-verifiable ledger.
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    """Return the lowercase hex SHA-256 digest of ``data``."""
    return hashlib.sha256(data).hexdigest()


def generate_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Generate a fresh Ed25519 keypair using the OS CSPRNG."""
    private_key = Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()


def sign(private_key: Ed25519PrivateKey, message: bytes) -> str:
    """Sign ``message`` and return a base64 (urlsafe, no padding) signature."""
    raw = private_key.sign(message)
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def verify(public_key: Ed25519PublicKey, message: bytes, signature_b64: str) -> bool:
    """Verify a base64 signature over ``message``. Returns True/False only.

    Verification failures are treated as a normal (False) result rather than
    an exception so callers cannot accidentally crash on attacker-supplied
    input — but they also can never silently treat an invalid signature as
    valid.
    """
    try:
        padded = signature_b64 + "=" * (-len(signature_b64) % 4)
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
        public_key.verify(raw, message)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def public_key_to_b64(public_key: Ed25519PublicKey) -> str:
    """Serialize a public key to base64 (urlsafe, no padding)."""
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def public_key_from_b64(b64: str) -> Ed25519PublicKey:
    """Deserialize a public key from base64."""
    padded = b64 + "=" * (-len(b64) % 4)
    raw = base64.urlsafe_b64decode(padded.encode("ascii"))
    return Ed25519PublicKey.from_public_bytes(raw)


def private_key_to_b64(private_key: Ed25519PrivateKey) -> str:
    """Serialize a private key to base64. Handle the result as a secret."""
    raw = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def private_key_from_b64(b64: str) -> Ed25519PrivateKey:
    """Deserialize a private key from base64."""
    padded = b64 + "=" * (-len(b64) % 4)
    raw = base64.urlsafe_b64decode(padded.encode("ascii"))
    return Ed25519PrivateKey.from_private_bytes(raw)
