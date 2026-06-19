"""
veritrail.principals
====================
Identity for the two kinds of actors Veritrail tracks:

* HUMAN  — a person; the only valid *root* of an authorization chain.
* AGENT  — an autonomous/AI actor; may act only under a delegation that traces
           back to a human.

Each principal holds an Ed25519 public key. Private keys live with the actor
(human's IdP / agent's secure enclave), never in the registry. The registry is
the trust anchor: a signature only means something if we know whose key it is.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from enum import Enum
from typing import Any

from .crypto import public_key_from_b64, public_key_to_b64
from .errors import UnknownPrincipal, ValidationError

_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_NAME_MAX = 256


class PrincipalKind(str, Enum):
    HUMAN = "human"
    AGENT = "agent"


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex}"


@dataclass(frozen=True)
class Principal:
    id: str
    kind: PrincipalKind
    name: str
    public_key_b64: str

    def __post_init__(self) -> None:
        if not _ID_RE.match(self.id):
            raise ValidationError("principal id has invalid format")
        if not isinstance(self.name, str) or len(self.name) > _NAME_MAX:
            raise ValidationError("principal name invalid")
        # Will raise if the key is malformed.
        public_key_from_b64(self.public_key_b64)

    @property
    def public_key(self):
        return public_key_from_b64(self.public_key_b64)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind.value,
            "name": self.name,
            "public_key_b64": self.public_key_b64,
        }


class PrincipalRegistry:
    """In-memory trust anchor. Swap for a DB-backed store in production."""

    def __init__(self) -> None:
        self._by_id: dict[str, Principal] = {}

    def register(self, principal: Principal) -> Principal:
        if principal.id in self._by_id:
            raise ValidationError(f"principal {principal.id} already registered")
        self._by_id[principal.id] = principal
        return principal

    def register_human(self, name: str, public_key, *, id: str | None = None) -> Principal:
        p = Principal(
            id=id or new_id("human"),
            kind=PrincipalKind.HUMAN,
            name=name,
            public_key_b64=public_key_to_b64(public_key),
        )
        return self.register(p)

    def register_agent(self, name: str, public_key, *, id: str | None = None) -> Principal:
        p = Principal(
            id=id or new_id("agent"),
            kind=PrincipalKind.AGENT,
            name=name,
            public_key_b64=public_key_to_b64(public_key),
        )
        return self.register(p)

    def get(self, principal_id: str) -> Principal:
        p = self._by_id.get(principal_id)
        if p is None:
            raise UnknownPrincipal(f"unknown principal: {principal_id}")
        return p

    def __contains__(self, principal_id: object) -> bool:
        return principal_id in self._by_id

    def all(self) -> list[Principal]:
        return list(self._by_id.values())
