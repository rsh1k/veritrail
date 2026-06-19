"""
veritrail.delegation
====================
Delegations are signed capability grants. They are the links of the
authorization chain.

A delegation says: *issuer* grants *subject* the authority described by
*scope*, for *purpose*, until *expires_at*, anchored to *parent_id* (the
delegation the issuer is itself acting under, or ``None`` if the issuer is a
human acting as a root).

Two cryptographic invariants make a chain trustworthy:

1. **Authenticity** — each delegation is signed by its issuer's private key,
   so it cannot be forged or altered.
2. **Attenuation** — a non-root delegation's scope must be contained by its
   parent's scope (see :meth:`Scope.contains`). Authority can only shrink as
   it flows down the chain.

Together these let a verifier walk any action back to the human who started
it, proving every hop — the multi-hop attribution problem that off-the-shelf
OAuth cannot solve.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from . import crypto
from .errors import ValidationError
from .principals import new_id
from .scope import Scope

_PURPOSE_MAX = 1024


@dataclass(frozen=True)
class Delegation:
    id: str
    issuer_id: str          # who grants authority (human root, or an agent)
    subject_id: str         # who receives authority
    scope: Scope
    purpose: str            # human-readable intent; used by intent-drift detection
    parent_id: str | None   # the delegation the issuer acts under (None => root)
    issued_at: float
    expires_at: float
    signature: str = ""     # issuer's Ed25519 signature over the signing payload

    # ---- canonical signing payload ---------------------------------------
    def _signing_payload(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "issuer_id": self.issuer_id,
            "subject_id": self.subject_id,
            "scope": self.scope.to_dict(),
            "purpose": self.purpose,
            "parent_id": self.parent_id,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
        }

    def signing_bytes(self) -> bytes:
        return crypto.canonical_bytes(self._signing_payload())

    @property
    def is_root(self) -> bool:
        return self.parent_id is None

    def expired(self, now: float | None = None) -> bool:
        return (now if now is not None else time.time()) >= self.expires_at

    def verify_signature(self, issuer_public_key) -> bool:
        return crypto.verify(issuer_public_key, self.signing_bytes(), self.signature)

    def to_dict(self) -> dict[str, Any]:
        d = self._signing_payload()
        d["signature"] = self.signature
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Delegation":
        if not isinstance(d, dict):
            raise ValidationError("delegation payload must be an object")
        try:
            return cls(
                id=d["id"],
                issuer_id=d["issuer_id"],
                subject_id=d["subject_id"],
                scope=Scope.from_dict(d["scope"]),
                purpose=d["purpose"],
                parent_id=d.get("parent_id"),
                issued_at=float(d["issued_at"]),
                expires_at=float(d["expires_at"]),
                signature=d.get("signature", ""),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ValidationError(f"malformed delegation payload: {exc}") from None


def build_signed_delegation(
    *,
    issuer_private_key,
    issuer_id: str,
    subject_id: str,
    scope: Scope,
    purpose: str,
    parent_id: str | None,
    ttl_seconds: float,
    now: float | None = None,
) -> Delegation:
    """Construct and sign a delegation. Validates inputs before signing."""
    if not isinstance(purpose, str) or len(purpose) == 0 or len(purpose) > _PURPOSE_MAX:
        raise ValidationError("purpose must be a non-empty string <= 1024 chars")
    if not isinstance(ttl_seconds, (int, float)) or ttl_seconds <= 0:
        raise ValidationError("ttl_seconds must be positive")
    issued = now if now is not None else time.time()
    delegation = Delegation(
        id=new_id("del"),
        issuer_id=issuer_id,
        subject_id=subject_id,
        scope=scope,
        purpose=purpose,
        parent_id=parent_id,
        issued_at=issued,
        expires_at=issued + float(ttl_seconds),
    )
    sig = crypto.sign(issuer_private_key, delegation.signing_bytes())
    # dataclass is frozen; rebuild with signature.
    return Delegation(
        id=delegation.id,
        issuer_id=delegation.issuer_id,
        subject_id=delegation.subject_id,
        scope=delegation.scope,
        purpose=delegation.purpose,
        parent_id=delegation.parent_id,
        issued_at=delegation.issued_at,
        expires_at=delegation.expires_at,
        signature=sig,
    )
