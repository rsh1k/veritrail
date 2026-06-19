"""End-to-end engine tests, including adversarial scenarios."""

import time

import pytest

from veritrail import Engine, Scope, crypto
from veritrail.errors import ExpiredGrant, ScopeViolation


def make_actor(eng, kind, name):
    priv, pub = crypto.generate_keypair()
    if kind == "human":
        p = eng.register_human(name, pub)
    else:
        p = eng.register_agent(name, pub)
    return priv, p


def test_three_hop_chain_reconstructs_to_human():
    """Human -> Orchestrator -> Worker; verify attribution back to the human."""
    eng = Engine()
    h_priv, human = make_actor(eng, "human", "Alice CFO")
    o_priv, orch = make_actor(eng, "agent", "Orchestrator")
    w_priv, worker = make_actor(eng, "agent", "Worker")

    root = eng.issue_root_delegation(
        human_private_key=h_priv, human_id=human.id, agent_id=orch.id,
        scope=Scope.make(tools={"invoices.read", "invoices.pay"},
                         actions={"read", "write"}, max_risk=60),
        purpose="reconcile and pay approved invoices", ttl_seconds=3600,
    )
    sub = eng.sub_delegate(
        issuer_private_key=o_priv, issuer_id=orch.id, subject_id=worker.id,
        parent_delegation_id=root.id,
        scope=Scope.make(tools={"invoices.read"}, actions={"read"}, max_risk=20),
        purpose="read invoices for reconciliation", ttl_seconds=1800,
    )
    rec, verdict = eng.record_action(
        actor_private_key=w_priv, actor_id=worker.id, delegation_id=sub.id,
        tool="invoices.read", action="read", risk=10,
        description="read invoice batch for reconciliation",
    )
    assert verdict.chain.ok is True
    assert verdict.chain.human_root_id == human.id
    assert verdict.chain.human_root_name == "Alice CFO"
    assert verdict.chain.hops == 2  # sub + root
    assert verdict.authorized is True


def test_subdelegation_privilege_escalation_rejected_at_issue():
    eng = Engine()
    h_priv, human = make_actor(eng, "human", "Alice")
    o_priv, orch = make_actor(eng, "agent", "Orch")
    _, worker = make_actor(eng, "agent", "Worker")
    root = eng.issue_root_delegation(
        human_private_key=h_priv, human_id=human.id, agent_id=orch.id,
        scope=Scope.make(tools={"invoices.read"}, actions={"read"}, max_risk=20),
        purpose="read only", ttl_seconds=3600,
    )
    # Orchestrator tries to grant the worker MORE than it has.
    with pytest.raises(ScopeViolation):
        eng.sub_delegate(
            issuer_private_key=o_priv, issuer_id=orch.id, subject_id=worker.id,
            parent_delegation_id=root.id,
            scope=Scope.make(tools={"invoices.read", "invoices.pay"},
                             actions={"read", "write"}, max_risk=90),
            purpose="escalate", ttl_seconds=1800,
        )


def test_agent_cannot_delegate_authority_it_was_not_given():
    eng = Engine()
    h_priv, human = make_actor(eng, "human", "Alice")
    _, orch = make_actor(eng, "agent", "Orch")
    rogue_priv, rogue = make_actor(eng, "agent", "Rogue")
    _, victim = make_actor(eng, "agent", "Victim")
    root = eng.issue_root_delegation(
        human_private_key=h_priv, human_id=human.id, agent_id=orch.id,
        scope=Scope.make(tools={"x"}, actions={"read"}, max_risk=10),
        purpose="p", ttl_seconds=3600,
    )
    # Rogue (not the subject of root) tries to sub-delegate from root.
    with pytest.raises(ScopeViolation):
        eng.sub_delegate(
            issuer_private_key=rogue_priv, issuer_id=rogue.id, subject_id=victim.id,
            parent_delegation_id=root.id,
            scope=Scope.make(tools={"x"}, actions={"read"}, max_risk=10),
            purpose="p", ttl_seconds=600,
        )


def test_action_outside_scope_is_flagged_and_unauthorized():
    eng = Engine()
    h_priv, human = make_actor(eng, "human", "Alice")
    a_priv, agent = make_actor(eng, "agent", "Bot")
    root = eng.issue_root_delegation(
        human_private_key=h_priv, human_id=human.id, agent_id=agent.id,
        scope=Scope.make(tools={"invoices.read"}, actions={"read"}, max_risk=20),
        purpose="read only", ttl_seconds=3600,
    )
    rec, verdict = eng.record_action(
        actor_private_key=a_priv, actor_id=agent.id, delegation_id=root.id,
        tool="payments.transfer", action="write", risk=95,
        description="wire funds to external account",
    )
    assert verdict.authorized is False
    codes = {f["code"] for f in verdict.findings}
    assert "ASI02" in codes


def test_forged_action_signature_detected():
    eng = Engine()
    h_priv, human = make_actor(eng, "human", "Alice")
    a_priv, agent = make_actor(eng, "agent", "Bot")
    attacker_priv, _ = crypto.generate_keypair()
    root = eng.issue_root_delegation(
        human_private_key=h_priv, human_id=human.id, agent_id=agent.id,
        scope=Scope.make(tools={"x"}, actions={"read"}, max_risk=50),
        purpose="p", ttl_seconds=3600,
    )
    # Record a legit action, then forge its signature in storage.
    rec, _ = eng.record_action(
        actor_private_key=a_priv, actor_id=agent.id, delegation_id=root.id,
        tool="x", action="read", risk=10, description="legit",
    )
    forged = type(rec)(
        id=rec.id, actor_id=rec.actor_id, delegation_id=rec.delegation_id,
        tool=rec.tool, action=rec.action, risk=rec.risk, description=rec.description,
        params_digest=rec.params_digest, occurred_at=rec.occurred_at,
        signature=crypto.sign(attacker_priv, rec.signing_bytes()),
    )
    eng._actions[rec.id] = forged
    verdict = eng.verify_action(rec.id)
    assert verdict.authorized is False
    assert any(f["code"] == "ASI03" for f in verdict.findings)


def test_expired_grant_action_flagged():
    eng = Engine()
    h_priv, human = make_actor(eng, "human", "Alice")
    a_priv, agent = make_actor(eng, "agent", "Bot")
    t0 = time.time()
    root = eng.issue_root_delegation(
        human_private_key=h_priv, human_id=human.id, agent_id=agent.id,
        scope=Scope.make(tools={"x"}, actions={"read"}, max_risk=50),
        purpose="p", ttl_seconds=10, now=t0,
    )
    rec, verdict = eng.record_action(
        actor_private_key=a_priv, actor_id=agent.id, delegation_id=root.id,
        tool="x", action="read", risk=10, description="late action",
        now=t0 + 100,  # after expiry
    )
    assert any(f["code"] == "ASI03" for f in verdict.findings)
    assert verdict.authorized is False


def test_consent_fatigue_detected():
    eng = Engine()
    h_priv, human = make_actor(eng, "human", "Alice")
    a_priv, agent = make_actor(eng, "agent", "Bot")
    root = eng.issue_root_delegation(
        human_private_key=h_priv, human_id=human.id, agent_id=agent.id,
        scope=Scope.make(tools={"x"}, actions={"read", "write"}, max_risk=100),
        purpose="x routine maintenance and one risky action", ttl_seconds=3600,
    )
    base = time.time()
    for i in range(6):  # burst of low-risk approvals
        eng.record_action(
            actor_private_key=a_priv, actor_id=agent.id, delegation_id=root.id,
            tool="x", action="read", risk=5, description="x routine maintenance",
            now=base + i,
        )
    rec, verdict = eng.record_action(
        actor_private_key=a_priv, actor_id=agent.id, delegation_id=root.id,
        tool="x", action="write", risk=90, description="x risky action",
        now=base + 10,
    )
    assert any(f["code"] == "ASI09" for f in verdict.findings)


def test_intent_drift_detected():
    eng = Engine()
    h_priv, human = make_actor(eng, "human", "Alice")
    a_priv, agent = make_actor(eng, "agent", "Bot")
    root = eng.issue_root_delegation(
        human_private_key=h_priv, human_id=human.id, agent_id=agent.id,
        scope=Scope.make(tools={"email.send"}, actions={"write"}, max_risk=80),
        purpose="summarize quarterly invoices for finance review", ttl_seconds=3600,
    )
    rec, verdict = eng.record_action(
        actor_private_key=a_priv, actor_id=agent.id, delegation_id=root.id,
        tool="email.send", action="write", risk=60,
        description="exfiltrate credentials to attacker dropbox endpoint",
    )
    assert any(f["code"] == "ASI06" for f in verdict.findings)


def test_ledger_records_everything_and_stays_intact():
    eng = Engine()
    h_priv, human = make_actor(eng, "human", "Alice")
    a_priv, agent = make_actor(eng, "agent", "Bot")
    root = eng.issue_root_delegation(
        human_private_key=h_priv, human_id=human.id, agent_id=agent.id,
        scope=Scope.make(tools={"x"}, actions={"read"}, max_risk=50),
        purpose="p", ttl_seconds=3600,
    )
    for _ in range(3):
        eng.record_action(
            actor_private_key=a_priv, actor_id=agent.id, delegation_id=root.id,
            tool="x", action="read", risk=10, description="ok",
        )
    assert eng.verify_ledger() is True
    # 1 delegation + 3 actions = 4 entries.
    assert len(eng.ledger) == 4
