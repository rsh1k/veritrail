"""
veritrail.revocation
====================
Revocation of delegations and principals.

A signature proves a grant was authentic *when issued*; it says nothing about
whether that authority is still valid now. Long-lived agents, leaked keys, and
off-boarded humans all require the ability to revoke. When a delegation or a
principal is revoked, any action whose chain of custody passes through it stops
verifying immediately — even though every signature in the chain is still
cryptographically valid.

Revocations are themselves timestamped records, so "when was this revoked, and
by whom" is part of the audit trail rather than a silent side effect.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Revocation:
    target_id: str          # delegation id or principal id
    target_kind: str        # "delegation" | "principal"
    reason: str
    revoked_at: float
    revoked_by: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_id": self.target_id,
            "target_kind": self.target_kind,
            "reason": self.reason,
            "revoked_at": self.revoked_at,
            "revoked_by": self.revoked_by,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Revocation":
        return cls(
            target_id=d["target_id"],
            target_kind=d["target_kind"],
            reason=d["reason"],
            revoked_at=float(d["revoked_at"]),
            revoked_by=d.get("revoked_by"),
        )


class RevocationRegistry:
    """Tracks revoked delegation and principal ids."""

    def __init__(self) -> None:
        self._revocations: dict[str, Revocation] = {}

    def revoke(
        self,
        target_id: str,
        target_kind: str,
        reason: str,
        *,
        revoked_by: str | None = None,
        now: float | None = None,
    ) -> Revocation:
        if target_kind not in ("delegation", "principal"):
            raise ValueError("target_kind must be 'delegation' or 'principal'")
        rec = Revocation(
            target_id=target_id,
            target_kind=target_kind,
            reason=reason,
            revoked_at=now if now is not None else time.time(),
            revoked_by=revoked_by,
        )
        # First revocation wins; re-revoking is a no-op that keeps the original.
        self._revocations.setdefault(target_id, rec)
        return self._revocations[target_id]

    def is_revoked(self, target_id: str) -> bool:
        return target_id in self._revocations

    def get(self, target_id: str) -> Revocation | None:
        return self._revocations.get(target_id)

    def all(self) -> list[Revocation]:
        return list(self._revocations.values())

    def load(self, revocations: list[Revocation]) -> None:
        for r in revocations:
            self._revocations.setdefault(r.target_id, r)
