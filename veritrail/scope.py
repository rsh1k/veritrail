"""
veritrail.scope
===============
The capability model.

A :class:`Scope` is the set of authorities a principal may exercise: which
tools it may call, which action types it may perform, the maximum risk level
it may reach, and arbitrary key/value constraints (e.g. ``max_amount_usd``).

The critical security property is **attenuation**: when authority is
delegated onward, the child scope must be a *subset* of the parent scope. A
sub-agent can only ever lose authority, never gain it. This is the same
principle behind capability systems like SPKI/SDSI and macaroons, and it is
what stops a deep delegation chain from silently escalating privilege.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .errors import ValidationError

# A sentinel meaning "all tools" / "all actions". Use sparingly; a root human
# grant may use it, but every delegation should narrow it.
WILDCARD = "*"

_MAX_SET_SIZE = 4096
_MAX_STR_LEN = 512


def _validate_token_set(values: set[str], name: str) -> set[str]:
    if len(values) > _MAX_SET_SIZE:
        raise ValidationError(f"{name} exceeds maximum size {_MAX_SET_SIZE}")
    for v in values:
        if not isinstance(v, str):
            raise ValidationError(f"{name} entries must be strings")
        if len(v) == 0 or len(v) > _MAX_STR_LEN:
            raise ValidationError(f"{name} entry has invalid length")
    return set(values)


@dataclass(frozen=True)
class Scope:
    """An immutable set of authorities.

    ``max_risk`` is a 0-100 band used by detectors and approval gates; lower
    is safer. ``constraints`` carries numeric/string limits; numeric values are
    attenuated by "child must be <= parent".
    """

    allowed_tools: frozenset[str] = field(default_factory=frozenset)
    allowed_actions: frozenset[str] = field(default_factory=frozenset)
    max_risk: int = 0
    constraints: tuple[tuple[str, Any], ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        _validate_token_set(set(self.allowed_tools), "allowed_tools")
        _validate_token_set(set(self.allowed_actions), "allowed_actions")
        if not isinstance(self.max_risk, int) or not (0 <= self.max_risk <= 100):
            raise ValidationError("max_risk must be an int in [0, 100]")

    # ---- constructors -----------------------------------------------------
    @classmethod
    def make(
        cls,
        tools: set[str] | None = None,
        actions: set[str] | None = None,
        max_risk: int = 0,
        constraints: dict[str, Any] | None = None,
    ) -> "Scope":
        return cls(
            allowed_tools=frozenset(tools or set()),
            allowed_actions=frozenset(actions or set()),
            max_risk=max_risk,
            constraints=tuple(sorted((constraints or {}).items())),
        )

    @property
    def constraint_map(self) -> dict[str, Any]:
        return dict(self.constraints)

    # ---- capability checks ------------------------------------------------
    def _tool_allowed(self, tool: str) -> bool:
        return WILDCARD in self.allowed_tools or tool in self.allowed_tools

    def _action_allowed(self, action: str) -> bool:
        return WILDCARD in self.allowed_actions or action in self.allowed_actions

    def permits_action(self, tool: str, action: str, risk: int) -> bool:
        """Whether a concrete action is within this scope."""
        return (
            self._tool_allowed(tool)
            and self._action_allowed(action)
            and 0 <= risk <= self.max_risk
        )

    def contains(self, child: "Scope") -> bool:
        """True iff ``child`` is an attenuation (subset) of ``self``.

        This is the recursive-delegation safety check.
        """
        # Tools: every child tool must be permitted by parent.
        if WILDCARD not in self.allowed_tools:
            if WILDCARD in child.allowed_tools:
                return False
            if not child.allowed_tools.issubset(self.allowed_tools):
                return False
        # Actions: same rule.
        if WILDCARD not in self.allowed_actions:
            if WILDCARD in child.allowed_actions:
                return False
            if not child.allowed_actions.issubset(self.allowed_actions):
                return False
        # Risk must not increase.
        if child.max_risk > self.max_risk:
            return False
        # Numeric constraints follow capability/caveat semantics: a parent cap
        # always binds the child via the chain (see effective_constraints), so a
        # child that omits a cap *inherits* it — that is not escalation. A child
        # may only ever tighten. Therefore the only violation is a child that
        # *states* a looser (larger) value than the parent's cap.
        parent_c = self.constraint_map
        child_c = child.constraint_map
        for key, parent_val in parent_c.items():
            if isinstance(parent_val, (int, float)) and not isinstance(parent_val, bool):
                if key in child_c:
                    child_val = child_c[key]
                    if not isinstance(child_val, (int, float)) or child_val > parent_val:
                        return False
        return True

    @staticmethod
    def effective_constraints(chain_scopes: "list[Scope]") -> dict[str, Any]:
        """Tightest numeric cap for each key across a chain of scopes.

        Because caps are inherited, the authority actually in force at the leaf
        is the minimum of every ancestor's cap. Action-time enforcement uses
        this so an omitted cap still binds.
        """
        effective: dict[str, Any] = {}
        for s in chain_scopes:
            for key, val in s.constraint_map.items():
                if isinstance(val, (int, float)) and not isinstance(val, bool):
                    effective[key] = min(effective.get(key, val), val)
        return effective

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed_tools": sorted(self.allowed_tools),
            "allowed_actions": sorted(self.allowed_actions),
            "max_risk": self.max_risk,
            "constraints": dict(self.constraints),
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Scope":
        return cls.make(
            tools=set(d.get("allowed_tools", [])),
            actions=set(d.get("allowed_actions", [])),
            max_risk=int(d.get("max_risk", 0)),
            constraints=dict(d.get("constraints", {})),
        )
