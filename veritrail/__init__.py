"""
Veritrail — verifiable provenance and forensics for autonomous AI agents.

Veritrail is the "flight recorder and chain-of-custody" for agentic actions.
For any action an agent (or a sub-agent it spawned, N hops deep) takes, it can
answer the three questions every CISO, auditor, and court will ask:

    1. Who authorized this?  -> cryptographically reconstruct the chain to the
       originating human.
    2. Was the chain hijacked? -> detect goal-hijack, tool poisoning, intent
       drift, expired authority, identity abuse, and consent fatigue.
    3. Can you prove it later? -> a tamper-evident, hash-chained ledger.

Quick start::

    from veritrail import Engine, Scope, crypto

    eng = Engine()
    h_priv, h_pub = crypto.generate_keypair()
    a_priv, a_pub = crypto.generate_keypair()
    human = eng.register_human("Alice (CFO)", h_pub)
    agent = eng.register_agent("FinanceBot", a_pub)

    grant = eng.issue_root_delegation(
        human_private_key=h_priv, human_id=human.id, agent_id=agent.id,
        scope=Scope.make(tools={"payments.read"}, actions={"read"}, max_risk=20),
        purpose="reconcile invoices", ttl_seconds=3600,
    )
    rec, verdict = eng.record_action(
        actor_private_key=a_priv, actor_id=agent.id, delegation_id=grant.id,
        tool="payments.read", action="read", risk=10, description="read invoice 42",
    )
    assert verdict.authorized
"""

from __future__ import annotations

from . import crypto
from .action import ActionRecord, build_signed_action
from .audit import AuditSink, JsonlSink, NullSink, make_event
from .delegation import Delegation, build_signed_delegation
from .detection import DetectionEngine, Finding, Severity
from .engine import ChainResult, Engine, VerdictResult
from .errors import (
    ChainBroken,
    ExpiredGrant,
    ScopeViolation,
    SignatureError,
    TamperDetected,
    UnknownPrincipal,
    ValidationError,
    VeritrailError,
)
from .ledger import Ledger, LedgerEntry
from .persistence import SqliteStore
from .principals import Principal, PrincipalKind, PrincipalRegistry
from .revocation import Revocation, RevocationRegistry
from .scope import Scope

__version__ = "0.2.3"

__all__ = [
    "crypto",
    "Engine",
    "Scope",
    "Delegation",
    "build_signed_delegation",
    "ActionRecord",
    "build_signed_action",
    "DetectionEngine",
    "Finding",
    "Severity",
    "ChainResult",
    "VerdictResult",
    "Ledger",
    "LedgerEntry",
    "Principal",
    "PrincipalKind",
    "PrincipalRegistry",
    "Revocation",
    "RevocationRegistry",
    "SqliteStore",
    "AuditSink",
    "JsonlSink",
    "NullSink",
    "make_event",
    "VeritrailError",
    "ChainBroken",
    "ExpiredGrant",
    "ScopeViolation",
    "SignatureError",
    "TamperDetected",
    "UnknownPrincipal",
    "ValidationError",
    "__version__",
]
