"""
veritrail.detection
===================
Behavioral detectors that flag when an authorization chain has been corrupted
between the human's intent and the action taken. Each finding is mapped to the
OWASP Top 10 for Agentic Applications (ASI 2026) so security teams can triage
in a familiar taxonomy.

Detectors implemented (per-action, in this module):

* ASI01 Goal Hijack / ASI02 Tool Misuse  -> action exceeds delegated scope.
* ASI03 Identity & Privilege Abuse        -> actor mismatch / bad signature /
                                             action under expired (lapsed) authority.
* ASI06 Memory & Context Poisoning        -> action intent diverges from the
                                             delegated purpose (lexical heuristic;
                                             pluggable to an embedding model).
* ASI09 Human-Agent Trust Exploitation    -> a high-risk action approved inside
                                             a burst of low-risk approvals (consent
                                             fatigue).

Chain-level detectors (ASI07 inter-agent integrity, ASI08 cascading-failure
fan-out, ASI10 rogue-agent drift, and revocation) are evaluated in the engine,
which holds the cross-action context they need.

These are intentionally explainable, deterministic checks. They are a strong
baseline; an enterprise deployment layers a learned anomaly model on top via
the same :class:`Finding` interface.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .action import ActionRecord
from .delegation import Delegation


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


_SEV_ORDER = {s: i for i, s in enumerate(
    [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
)}


@dataclass(frozen=True)
class Finding:
    code: str               # OWASP ASI code or detector id
    title: str
    severity: Severity
    message: str
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "title": self.title,
            "severity": self.severity.value,
            "message": self.message,
            "evidence": self.evidence,
        }


_WORD_RE = re.compile(r"[a-z0-9]+")


def _tokens(text: str) -> set[str]:
    return set(_WORD_RE.findall(text.lower()))


def _jaccard(a: set[str], b: set[str]) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


class DetectionEngine:
    """Runs detectors against a fully reconstructed action context."""

    def __init__(
        self,
        *,
        intent_drift_threshold: float = 0.05,
        fatigue_window_seconds: float = 300.0,
        fatigue_low_risk_max: int = 25,
        fatigue_high_risk_min: int = 70,
        fatigue_burst_count: int = 5,
    ) -> None:
        self.intent_drift_threshold = intent_drift_threshold
        self.fatigue_window_seconds = fatigue_window_seconds
        self.fatigue_low_risk_max = fatigue_low_risk_max
        self.fatigue_high_risk_min = fatigue_high_risk_min
        self.fatigue_burst_count = fatigue_burst_count

    def evaluate_action(
        self,
        *,
        action: ActionRecord,
        authorizing_delegation: Delegation,
        chain: list[Delegation],
        actor_signature_valid: bool,
        recent_actions: list[ActionRecord] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        recent_actions = recent_actions or []

        # --- ASI03: identity abuse ----------------------------------------
        if not actor_signature_valid:
            findings.append(Finding(
                code="ASI03",
                title="Identity Abuse: invalid actor signature",
                severity=Severity.CRITICAL,
                message="Action signature did not verify against the actor's registered key.",
                evidence={"action_id": action.id, "actor_id": action.actor_id},
            ))
        if action.actor_id != authorizing_delegation.subject_id:
            findings.append(Finding(
                code="ASI03",
                title="Identity Abuse: actor is not the delegation subject",
                severity=Severity.CRITICAL,
                message="The acting principal was not the subject the delegation was issued to.",
                evidence={
                    "action_actor": action.actor_id,
                    "delegation_subject": authorizing_delegation.subject_id,
                },
            ))

        # --- ASI01/ASI02: goal hijack / tool misuse (scope) ---------------
        scope = authorizing_delegation.scope
        if not scope.permits_action(action.tool, action.action, action.risk):
            findings.append(Finding(
                code="ASI02",
                title="Tool Misuse / Goal Hijack: action outside delegated scope",
                severity=Severity.HIGH,
                message=(
                    f"Action {action.action} on tool '{action.tool}' at risk "
                    f"{action.risk} is not within the delegated scope."
                ),
                evidence={
                    "tool": action.tool,
                    "action": action.action,
                    "risk": action.risk,
                    "allowed_tools": sorted(scope.allowed_tools),
                    "allowed_actions": sorted(scope.allowed_actions),
                    "max_risk": scope.max_risk,
                },
            ))

        # --- ASI03: acting on expired (lapsed) authority -------------------
        if authorizing_delegation.expired(now=action.occurred_at):
            findings.append(Finding(
                code="ASI03",
                title="Privilege Abuse: action under expired authority",
                severity=Severity.HIGH,
                message="Action occurred after its authorizing delegation expired.",
                evidence={
                    "occurred_at": action.occurred_at,
                    "expires_at": authorizing_delegation.expires_at,
                },
            ))

        # --- ASI06: intent drift / memory poisoning -----------------------
        # Compare the action's stated intent to the chain of delegated purposes.
        chain_purpose_tokens: set[str] = set()
        for d in chain:
            chain_purpose_tokens |= _tokens(d.purpose)
        action_tokens = _tokens(action.description) | _tokens(action.tool) | _tokens(action.action)
        similarity = _jaccard(action_tokens, chain_purpose_tokens)
        if similarity < self.intent_drift_threshold and action.risk >= 40:
            findings.append(Finding(
                code="ASI06",
                title="Intent Drift: action diverges from delegated purpose",
                severity=Severity.MEDIUM,
                message=(
                    "The action's stated intent has low overlap with the purpose it was "
                    "delegated for — possible goal redirection or memory poisoning."
                ),
                evidence={
                    "similarity": round(similarity, 3),
                    "threshold": self.intent_drift_threshold,
                    "action_description": action.description[:200],
                },
            ))

        # --- ASI09: consent fatigue (human-agent trust exploitation) ------
        if action.risk >= self.fatigue_high_risk_min:
            window_start = action.occurred_at - self.fatigue_window_seconds
            low_risk_burst = [
                a for a in recent_actions
                if window_start <= a.occurred_at < action.occurred_at
                and a.risk <= self.fatigue_low_risk_max
            ]
            if len(low_risk_burst) >= self.fatigue_burst_count:
                findings.append(Finding(
                    code="ASI09",
                    title="Human-Agent Trust Exploitation: consent fatigue",
                    severity=Severity.HIGH,
                    message=(
                        "A high-risk action was approved immediately after a burst of "
                        "low-risk approvals — a classic human-in-the-loop bypass pattern."
                    ),
                    evidence={
                        "high_risk": action.risk,
                        "preceding_low_risk_count": len(low_risk_burst),
                        "window_seconds": self.fatigue_window_seconds,
                    },
                ))

        return findings


def max_severity(findings: list[Finding]) -> Severity:
    if not findings:
        return Severity.INFO
    return max((f.severity for f in findings), key=lambda s: _SEV_ORDER[s])
