"""
veritrail.action
================
An :class:`ActionRecord` is the signed statement "principal X performed this
action under delegation D". It is the leaf of the provenance tree — the thing
a forensic investigator starts from when asking "who authorized this, and was
the chain hijacked?".
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from . import crypto
from .errors import ValidationError
from .principals import new_id

_TOOL_MAX = 256
_DESC_MAX = 2048


@dataclass(frozen=True)
class ActionRecord:
    id: str
    actor_id: str           # the principal taking the action
    delegation_id: str      # the delegation authorizing it
    tool: str               # tool/capability invoked (e.g. "payments.transfer")
    action: str             # action type (e.g. "write", "read", "execute")
    risk: int               # 0-100 risk band the caller assigns this action
    description: str        # what the agent believes it is doing / params digest
    params_digest: str      # sha256 of the concrete parameters (no raw secrets)
    occurred_at: float
    signature: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.tool, str) or not (0 < len(self.tool) <= _TOOL_MAX):
            raise ValidationError("tool invalid")
        if not isinstance(self.action, str) or not (0 < len(self.action) <= _TOOL_MAX):
            raise ValidationError("action invalid")
        if not isinstance(self.risk, int) or not (0 <= self.risk <= 100):
            raise ValidationError("risk must be int in [0,100]")
        if not isinstance(self.description, str) or len(self.description) > _DESC_MAX:
            raise ValidationError("description too long")

    def _signing_payload(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "actor_id": self.actor_id,
            "delegation_id": self.delegation_id,
            "tool": self.tool,
            "action": self.action,
            "risk": self.risk,
            "description": self.description,
            "params_digest": self.params_digest,
            "occurred_at": self.occurred_at,
        }

    def signing_bytes(self) -> bytes:
        return crypto.canonical_bytes(self._signing_payload())

    def verify_signature(self, actor_public_key) -> bool:
        return crypto.verify(actor_public_key, self.signing_bytes(), self.signature)

    def to_dict(self) -> dict[str, Any]:
        d = self._signing_payload()
        d["signature"] = self.signature
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ActionRecord":
        if not isinstance(d, dict):
            raise ValidationError("action payload must be an object")
        try:
            return cls(
                id=d["id"],
                actor_id=d["actor_id"],
                delegation_id=d["delegation_id"],
                tool=d["tool"],
                action=d["action"],
                risk=int(d["risk"]),
                description=d["description"],
                params_digest=d["params_digest"],
                occurred_at=float(d["occurred_at"]),
                signature=d.get("signature", ""),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ValidationError(f"malformed action payload: {exc}") from None


def build_signed_action(
    *,
    actor_private_key,
    actor_id: str,
    delegation_id: str,
    tool: str,
    action: str,
    risk: int,
    description: str,
    params: dict[str, Any] | None = None,
    now: float | None = None,
) -> ActionRecord:
    """Construct and sign an action record.

    ``params`` are hashed, never stored raw, so the ledger carries proof-of-
    parameters without becoming a secrets repository (OWASP A02/A09 hygiene).
    """
    params_digest = crypto.sha256_hex(crypto.canonical_bytes(params or {}))
    rec = ActionRecord(
        id=new_id("act"),
        actor_id=actor_id,
        delegation_id=delegation_id,
        tool=tool,
        action=action,
        risk=risk,
        description=description,
        params_digest=params_digest,
        occurred_at=now if now is not None else time.time(),
    )
    sig = crypto.sign(actor_private_key, rec.signing_bytes())
    return ActionRecord(
        id=rec.id, actor_id=rec.actor_id, delegation_id=rec.delegation_id,
        tool=rec.tool, action=rec.action, risk=rec.risk, description=rec.description,
        params_digest=rec.params_digest, occurred_at=rec.occurred_at, signature=sig,
    )
