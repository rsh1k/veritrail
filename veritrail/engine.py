"""
veritrail.engine
================
The Veritrail engine — the public SDK surface most integrations use.

Responsibilities:

* Issue root delegations (human -> agent) and sub-delegations (agent -> agent),
  enforcing attenuation at issue time so an over-broad grant can never be
  written in the first place.
* Record actions, enforcing scope and running the detection engine.
* Reconstruct and cryptographically verify the full authorization chain for any
  action, all the way back to the originating human — the multi-hop attribution
  guarantee.
* Verify the integrity of the whole ledger.

Everything that mutates state is appended to the tamper-evident ledger.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from .action import ActionRecord, build_signed_action
from .delegation import Delegation, build_signed_delegation
from .detection import DetectionEngine, Finding, Severity, max_severity
from .errors import (
    ChainBroken,
    ExpiredGrant,
    ScopeViolation,
    SignatureError,
    UnknownPrincipal,
    ValidationError,
)
from .ledger import Ledger
from .principals import Principal, PrincipalKind, PrincipalRegistry
from .revocation import RevocationRegistry
from .audit import NullSink, make_event
from .scope import Scope

_MAX_CHAIN_DEPTH = 64  # defense against malicious/cyclic delegation graphs


@dataclass
class ChainResult:
    ok: bool
    action_id: str
    human_root_id: str | None
    human_root_name: str | None
    chain: list[dict[str, Any]] = field(default_factory=list)  # leaf -> root
    hops: int = 0
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "action_id": self.action_id,
            "human_root_id": self.human_root_id,
            "human_root_name": self.human_root_name,
            "hops": self.hops,
            "chain": self.chain,
            "errors": self.errors,
        }


@dataclass
class VerdictResult:
    action_id: str
    authorized: bool          # chain reconstructs to a human AND no critical/high findings
    chain: ChainResult
    findings: list[dict[str, Any]]
    max_severity: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_id": self.action_id,
            "authorized": self.authorized,
            "max_severity": self.max_severity,
            "chain": self.chain.to_dict(),
            "findings": self.findings,
        }


class Engine:
    def __init__(
        self,
        *,
        registry: PrincipalRegistry | None = None,
        ledger: Ledger | None = None,
        detector: DetectionEngine | None = None,
        store: Any | None = None,
        revocations: RevocationRegistry | None = None,
        audit_sink: Any | None = None,
        cascade_window_seconds: float = 60.0,
        cascade_fanout_threshold: int = 25,
        rogue_strike_threshold: int = 3,
    ) -> None:
        self.registry = registry or PrincipalRegistry()
        self.detector = detector or DetectionEngine()
        self.revocations = revocations or RevocationRegistry()
        self.store = store
        self.audit = audit_sink or NullSink()
        self._delegations: dict[str, Delegation] = {}
        self._actions: dict[str, ActionRecord] = {}
        self._actor_strikes: dict[str, int] = {}
        self._struck_actions: set[str] = set()
        self.cascade_window_seconds = cascade_window_seconds
        self.cascade_fanout_threshold = cascade_fanout_threshold
        self.rogue_strike_threshold = rogue_strike_threshold

        # The ledger holds the in-memory view. When a store is present, durable
        # appends are coordinated by the store (see _append_ledger) and mirrored
        # here; the store stays the source of truth for verification.
        self.ledger = ledger or Ledger()

        if self.store is not None:
            self._rehydrate()

    def _rehydrate(self) -> None:
        """Load durable state into the in-memory working set on startup."""
        data = self.store.load()
        for p in data["principals"]:
            if p.id not in self.registry:
                self.registry.register(p)
        for d in data["delegations"]:
            self._delegations[d.id] = d
        for a in data["actions"]:
            self._actions[a.id] = a
        self.revocations.load(data["revocations"])
        if data["ledger_entries"]:
            self.ledger.load_entries(data["ledger_entries"])

    def _emit(self, operation: str, **fields: Any) -> None:
        try:
            self.audit.emit(make_event(operation, **fields))
        except Exception:
            pass

    # ---- identity ---------------------------------------------------------
    def register_human(self, name: str, public_key, *, id: str | None = None) -> Principal:
        p = self.registry.register_human(name, public_key, id=id)
        if self.store is not None:
            self.store.save_principal(p)
        self._emit("register_principal", **{"gen_ai.agent.id": p.id, "veritrail.kind": "human"})
        return p

    def register_agent(self, name: str, public_key, *, id: str | None = None) -> Principal:
        p = self.registry.register_agent(name, public_key, id=id)
        if self.store is not None:
            self.store.save_principal(p)
        self._emit("register_principal", **{"gen_ai.agent.id": p.id, "veritrail.kind": "agent"})
        return p

    # ---- revocation -------------------------------------------------------
    def revoke_delegation(self, delegation_id: str, reason: str, *, revoked_by: str | None = None):
        r = self.revocations.revoke(delegation_id, "delegation", reason, revoked_by=revoked_by)
        if self.store is not None:
            self.store.save_revocation(r)
        self._emit("revoke", **{"veritrail.target": delegation_id, "veritrail.target_kind": "delegation"})
        return r

    def revoke_principal(self, principal_id: str, reason: str, *, revoked_by: str | None = None):
        r = self.revocations.revoke(principal_id, "principal", reason, revoked_by=revoked_by)
        if self.store is not None:
            self.store.save_revocation(r)
        self._emit("revoke", **{"veritrail.target": principal_id, "veritrail.target_kind": "principal"})
        return r

    # ---- read helpers (read-through to the store so one replica sees the
    #      records another replica wrote) -----------------------------------
    def has_action(self, action_id: str) -> bool:
        return self._get_action(action_id) is not None

    def get_action(self, action_id: str) -> ActionRecord | None:
        return self._get_action(action_id)

    def get_delegation(self, delegation_id: str) -> Delegation | None:
        return self._get_delegation(delegation_id)

    def _get_action(self, action_id: str) -> ActionRecord | None:
        a = self._actions.get(action_id)
        if a is None and self.store is not None:
            a = self.store.get_action(action_id)
            if a is not None:
                self._actions[a.id] = a
        return a

    def _get_delegation(self, delegation_id: str) -> Delegation | None:
        d = self._delegations.get(delegation_id)
        if d is None and self.store is not None:
            d = self.store.get_delegation(delegation_id)
            if d is not None:
                self._delegations[d.id] = d
        return d

    def _get_principal(self, principal_id: str) -> Principal:
        if principal_id in self.registry:
            return self.registry.get(principal_id)
        if self.store is not None:
            p = self.store.get_principal(principal_id)
            if p is not None:
                if p.id not in self.registry:
                    self.registry.register(p)
                return p
        raise UnknownPrincipal(f"unknown principal: {principal_id}")

    def _append_ledger(self, kind: str, payload: dict[str, Any]) -> None:
        """Append to the tamper-evident ledger. With a store, the append is
        coordinated and persisted by the store (correct across replicas) and
        mirrored into the in-memory view; without one, it is purely in-memory."""
        if self.store is not None:
            entry = self.store.append_ledger(kind, payload)
            self.ledger.append_prebuilt(entry)
        else:
            self.ledger.append(kind, payload)


    # ---- delegation -------------------------------------------------------
    def issue_root_delegation(
        self,
        *,
        human_private_key,
        human_id: str,
        agent_id: str,
        scope: Scope,
        purpose: str,
        ttl_seconds: float,
        now: float | None = None,
    ) -> Delegation:
        """A human grants authority to an agent. The only valid chain root."""
        human = self._get_principal(human_id)
        if human.kind != PrincipalKind.HUMAN:
            raise ValidationError("root delegations must be issued by a HUMAN principal")
        self._get_principal(agent_id)  # ensure subject exists
        delegation = build_signed_delegation(
            issuer_private_key=human_private_key,
            issuer_id=human_id,
            subject_id=agent_id,
            scope=scope,
            purpose=purpose,
            parent_id=None,
            ttl_seconds=ttl_seconds,
            now=now,
        )
        if not delegation.verify_signature(human.public_key):
            raise SignatureError("root delegation signature failed to verify")
        self._store_delegation(delegation)
        return delegation

    def sub_delegate(
        self,
        *,
        issuer_private_key,
        issuer_id: str,
        subject_id: str,
        parent_delegation_id: str,
        scope: Scope,
        purpose: str,
        ttl_seconds: float,
        now: float | None = None,
    ) -> Delegation:
        """An agent delegates a *subset* of its authority to another agent.

        Attenuation and expiry are enforced here so an invalid sub-delegation
        is rejected before it can ever enter the ledger.
        """
        parent = self._get_delegation(parent_delegation_id)
        if parent is None:
            raise ChainBroken(f"unknown parent delegation: {parent_delegation_id}")
        if parent.subject_id != issuer_id:
            raise ScopeViolation(
                "issuer is not the subject of the parent delegation — cannot delegate authority it was not given"
            )
        when = now if now is not None else time.time()
        if parent.expired(now=when):
            raise ExpiredGrant("parent delegation has expired")
        if not parent.scope.contains(scope):
            raise ScopeViolation("sub-delegation scope is not contained by parent scope (privilege escalation)")
        # Child TTL cannot outlive the parent.
        effective_ttl = min(ttl_seconds, max(0.0, parent.expires_at - when))
        if effective_ttl <= 0:
            raise ExpiredGrant("no remaining lifetime on parent to delegate")
        issuer = self._get_principal(issuer_id)
        self._get_principal(subject_id)
        delegation = build_signed_delegation(
            issuer_private_key=issuer_private_key,
            issuer_id=issuer_id,
            subject_id=subject_id,
            scope=scope,
            purpose=purpose,
            parent_id=parent_delegation_id,
            ttl_seconds=effective_ttl,
            now=when,
        )
        if not delegation.verify_signature(issuer.public_key):
            raise SignatureError("sub-delegation signature failed to verify")
        self._store_delegation(delegation)
        return delegation

    def _store_delegation(self, delegation: Delegation) -> None:
        self._delegations[delegation.id] = delegation
        if self.store is not None:
            self.store.save_delegation(delegation)
        self._append_ledger("delegation", delegation.to_dict())
        self._emit("issue_delegation", **{
            "veritrail.delegation.id": delegation.id,
            "gen_ai.agent.id": delegation.subject_id,
            "veritrail.issuer.id": delegation.issuer_id,
            "veritrail.is_root": delegation.is_root,
        })

    def ingest_delegation(self, delegation: Delegation, *, now: float | None = None) -> Delegation:
        """Accept a delegation that was signed by a client (service mode).

        Re-verifies signature, parent linkage, attenuation, and expiry exactly
        as if the service had issued it — the server trusts nothing it cannot
        re-check. Private keys never reach the server.
        """
        issuer = self._get_principal(delegation.issuer_id)
        self._get_principal(delegation.subject_id)
        if not delegation.verify_signature(issuer.public_key):
            raise SignatureError("delegation signature failed to verify")
        when = now if now is not None else time.time()
        if delegation.is_root:
            if issuer.kind != PrincipalKind.HUMAN:
                raise ValidationError("root delegation must be issued by a human")
        else:
            parent = self._get_delegation(delegation.parent_id)
            if parent is None:
                raise ChainBroken(f"unknown parent delegation: {delegation.parent_id}")
            if parent.subject_id != delegation.issuer_id:
                raise ScopeViolation("issuer was not the subject of the parent delegation")
            if parent.expired(now=when):
                raise ExpiredGrant("parent delegation has expired")
            if not parent.scope.contains(delegation.scope):
                raise ScopeViolation("sub-delegation scope exceeds parent (privilege escalation)")
            if delegation.expires_at > parent.expires_at:
                raise ScopeViolation("sub-delegation outlives its parent")
        if self._get_delegation(delegation.id) is not None:
            raise ValidationError("delegation id already exists")
        self._store_delegation(delegation)
        return delegation

    def ingest_action(self, action: ActionRecord) -> tuple[ActionRecord, VerdictResult]:
        """Accept a client-signed action, record it, and return the verdict."""
        if self._get_delegation(action.delegation_id) is None:
            raise ChainBroken(f"unknown delegation: {action.delegation_id}")
        if self._get_action(action.id) is not None:
            raise ValidationError("action id already exists")
        self._actions[action.id] = action
        if self.store is not None:
            self.store.save_action(action)
        self._append_ledger("action", action.to_dict())
        return action, self.verify_action(action.id)

    # ---- actions ----------------------------------------------------------
    def record_action(
        self,
        *,
        actor_private_key,
        actor_id: str,
        delegation_id: str,
        tool: str,
        action: str,
        risk: int,
        description: str,
        params: dict[str, Any] | None = None,
        enforce: bool = True,
        now: float | None = None,
    ) -> tuple[ActionRecord, VerdictResult]:
        """Record an action, append it to the ledger, and return the verdict.

        With ``enforce=True`` (default), an action that fails verification still
        gets recorded (you want forensic evidence of attempted abuse) but the
        verdict's ``authorized`` flag is False, which a calling guard uses to
        block the side effect.
        """
        delegation = self._get_delegation(delegation_id)
        if delegation is None:
            raise ChainBroken(f"unknown delegation: {delegation_id}")
        rec = build_signed_action(
            actor_private_key=actor_private_key,
            actor_id=actor_id,
            delegation_id=delegation_id,
            tool=tool,
            action=action,
            risk=risk,
            description=description,
            params=params,
            now=now,
        )
        self._actions[rec.id] = rec
        if self.store is not None:
            self.store.save_action(rec)
        self._append_ledger("action", rec.to_dict())
        verdict = self.verify_action(rec.id)
        return rec, verdict

    # ---- verification -----------------------------------------------------
    def reconstruct_chain(self, action_id: str) -> ChainResult:
        """Walk an action back to a human root, verifying every hop."""
        action = self._get_action(action_id)
        if action is None:
            return ChainResult(ok=False, action_id=action_id, human_root_id=None,
                               human_root_name=None, errors=["unknown action"])
        result = ChainResult(ok=True, action_id=action_id, human_root_id=None, human_root_name=None)

        # 1. Verify the action's own signature.
        try:
            actor = self._get_principal(action.actor_id)
            if not action.verify_signature(actor.public_key):
                result.ok = False
                result.errors.append("action signature invalid")
        except UnknownPrincipal:
            result.ok = False
            result.errors.append("action actor is not a registered principal")
        if self.revocations.is_revoked(action.actor_id):
            result.ok = False
            result.errors.append(f"actor {action.actor_id} has been revoked")

        # 2. Walk the delegation chain leaf -> root.
        current = self._get_delegation(action.delegation_id)
        if current is None:
            result.ok = False
            result.errors.append("authorizing delegation not found")
            return result

        seen: set[str] = set()
        depth = 0
        while current is not None:
            depth += 1
            if depth > _MAX_CHAIN_DEPTH:
                result.ok = False
                result.errors.append("chain exceeds maximum depth (possible cycle)")
                break
            if current.id in seen:
                result.ok = False
                result.errors.append("cycle detected in delegation chain")
                break
            seen.add(current.id)

            # Revocation: a still-valid signature on a revoked grant or principal
            # must not authorize anything.
            if self.revocations.is_revoked(current.id):
                result.ok = False
                result.errors.append(f"delegation {current.id} has been revoked")
            if self.revocations.is_revoked(current.issuer_id):
                result.ok = False
                result.errors.append(f"issuer {current.issuer_id} has been revoked")

            # Verify issuer signature on this delegation.
            try:
                issuer = self._get_principal(current.issuer_id)
            except UnknownPrincipal:
                result.ok = False
                result.errors.append(f"issuer {current.issuer_id} not registered")
                break
            if not current.verify_signature(issuer.public_key):
                result.ok = False
                result.errors.append(f"delegation {current.id} signature invalid")

            result.chain.append(current.to_dict())

            if current.is_root:
                # Root must be issued by a human.
                if issuer.kind != PrincipalKind.HUMAN:
                    result.ok = False
                    result.errors.append("root delegation not issued by a human")
                else:
                    result.human_root_id = issuer.id
                    result.human_root_name = issuer.name
                break

            parent = self._get_delegation(current.parent_id)
            if parent is None:
                result.ok = False
                result.errors.append(f"parent delegation {current.parent_id} missing")
                break
            # The issuer of the child must have been the subject of the parent.
            if parent.subject_id != current.issuer_id:
                result.ok = False
                result.errors.append(
                    f"delegation {current.id} issued by {current.issuer_id} "
                    f"but parent granted authority to {parent.subject_id}"
                )
            # Attenuation must hold across the hop.
            if not parent.scope.contains(current.scope):
                result.ok = False
                result.errors.append(f"privilege escalation at delegation {current.id}")
            current = parent

        result.hops = len(result.chain)
        if result.human_root_id is None and not any("root" in e for e in result.errors):
            result.ok = False
            result.errors.append("chain did not terminate at a human root")
        return result

    def verify_action(self, action_id: str) -> VerdictResult:
        """Full verdict: chain reconstruction + behavioral detection."""
        action = self._get_action(action_id)
        chain = self.reconstruct_chain(action_id)
        authorizing = self._get_delegation(action.delegation_id)

        actor_sig_valid = False
        try:
            actor = self._get_principal(action.actor_id)
            actor_sig_valid = action.verify_signature(actor.public_key)
        except UnknownPrincipal:
            actor_sig_valid = False

        chain_delegations = [Delegation.from_dict(d) for d in chain.chain]
        recent = [
            a for a in self._actions.values()
            if a.actor_id == action.actor_id and a.id != action.id
        ]

        findings: list[Finding] = []
        if authorizing is not None:
            findings = self.detector.evaluate_action(
                action=action,
                authorizing_delegation=authorizing,
                chain=chain_delegations,
                actor_signature_valid=actor_sig_valid,
                recent_actions=recent,
            )

        # Chain-level detectors that need cross-action / chain context.
        findings.extend(self._chain_level_findings(action, chain, chain_delegations, recent))

        sev = max_severity(findings)
        blocking = sev in (Severity.HIGH, Severity.CRITICAL)
        authorized = chain.ok and not blocking

        # Rogue-agent accounting: a blocking verdict is a "strike" against the
        # actor, counted once per action (re-verifying is idempotent). Repeated
        # strikes flag the actor as rogue (ASI10).
        if (blocking or not chain.ok) and action_id not in self._struck_actions:
            self._struck_actions.add(action_id)
            self._actor_strikes[action.actor_id] = self._actor_strikes.get(action.actor_id, 0) + 1
        if self._actor_strikes.get(action.actor_id, 0) >= self.rogue_strike_threshold:
            findings.append(Finding(
                code="ASI10",
                title="Rogue Agent: repeated authorization violations",
                severity=Severity.HIGH,
                message=(
                    "This actor has accumulated multiple blocking findings — its behavior "
                    "has drifted from authorized bounds and it should be quarantined."
                ),
                evidence={"strikes": self._actor_strikes[action.actor_id],
                          "threshold": self.rogue_strike_threshold},
            ))
            sev = max_severity(findings)
            authorized = chain.ok and sev not in (Severity.HIGH, Severity.CRITICAL)

        verdict = VerdictResult(
            action_id=action_id,
            authorized=authorized,
            chain=chain,
            findings=[f.to_dict() for f in findings],
            max_severity=sev.value,
        )
        self._emit("verify_action", **{
            "gen_ai.agent.id": action.actor_id,
            "gen_ai.tool.name": action.tool,
            "veritrail.action.id": action.id,
            "veritrail.authorized": authorized,
            "veritrail.max_severity": sev.value,
            "veritrail.human_root": chain.human_root_id,
            "veritrail.finding_codes": [f["code"] for f in verdict.findings],
        })
        return verdict

    def _chain_level_findings(self, action, chain, chain_delegations, recent) -> list[Finding]:
        out: list[Finding] = []

        # Revocation surfaced as ASI03 (privilege abuse via revoked authority).
        revoked_hits = [e for e in chain.errors if "revoked" in e]
        for msg in revoked_hits:
            out.append(Finding(
                code="ASI03",
                title="Privilege Abuse: revoked authority used",
                severity=Severity.CRITICAL,
                message=msg,
                evidence={"action_id": action.id},
            ))

        # ASI07: insecure inter-agent communication — a signature failure on an
        # agent-issued (non-root) hop means a spoofed/forged inter-agent grant.
        for err in chain.errors:
            if "signature invalid" in err and "delegation" in err:
                out.append(Finding(
                    code="ASI07",
                    title="Insecure Inter-Agent Communication: forged delegation in chain",
                    severity=Severity.CRITICAL,
                    message="A delegation passed between agents failed signature verification.",
                    evidence={"detail": err},
                ))

        # ASI08: cascading failures — abnormally high fan-out of actions sharing
        # the same authorizing delegation within a short window (blast radius).
        window_start = action.occurred_at - self.cascade_window_seconds
        same_grant_burst = [
            a for a in recent
            if a.delegation_id == action.delegation_id and a.occurred_at >= window_start
        ]
        if len(same_grant_burst) + 1 >= self.cascade_fanout_threshold:
            out.append(Finding(
                code="ASI08",
                title="Cascading Failure risk: high action fan-out",
                severity=Severity.MEDIUM,
                message=(
                    "An unusually large number of actions fired under a single grant in a "
                    "short window — a fault here would cascade across the workflow."
                ),
                evidence={"fanout": len(same_grant_burst) + 1,
                          "window_seconds": self.cascade_window_seconds,
                          "threshold": self.cascade_fanout_threshold},
            ))
        return out

    # ---- integrity --------------------------------------------------------
    def _authoritative_ledger(self) -> Ledger:
        """The ledger to verify against. With a store, rebuild from durable
        storage so the check covers what every replica wrote (and catches
        storage-level tampering); otherwise use the in-memory ledger."""
        if self.store is not None:
            led = Ledger()
            led.load_entries(self.store.load_ledger())
            return led
        return self.ledger

    def verify_ledger(self) -> bool:
        return self._authoritative_ledger().verify_integrity()

    def stats(self) -> dict[str, Any]:
        if self.store is not None:
            led = self._authoritative_ledger()
            counts = self.store.counts()
            return {
                **counts,
                "ledger_head": led.head_hash,
                "merkle_root": led.merkle_root(),
            }
        return {
            "principals": len(self.registry.all()),
            "delegations": len(self._delegations),
            "actions": len(self._actions),
            "revocations": len(self.revocations.all()),
            "ledger_entries": len(self.ledger),
            "ledger_head": self.ledger.head_hash,
            "merkle_root": self.ledger.merkle_root(),
        }
