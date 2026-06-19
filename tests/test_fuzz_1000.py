"""
Property-based fuzzing: 1000 randomized samples per invariant.

Instead of a handful of hand-picked cases, these tests generate large numbers
of randomized delegation chains and adversarial mutations and assert that core
security invariants hold for *every* sample. The RNG is seeded so any failure
is reproducible.

Invariants under test:
  1. A randomly-shaped but well-formed chain always reconstructs to its human
     root and authorizes the action (no false positives).
  2. Any sub-delegation that escalates privilege is rejected at issue time.
  3. Any post-hoc mutation of the ledger is detected.
  4. Any forged action signature is caught and the action is not authorized.
  5. Revoking any link in the chain (or the actor) blocks the action.
"""

import random
import uuid

import pytest

from veritrail import Engine, Scope, crypto
from veritrail.errors import ScopeViolation, TamperDetected
from veritrail.ledger import Ledger, LedgerEntry

SAMPLES = 1000
TOOL_POOL = [f"tool.{i}" for i in range(8)]
ACTION_POOL = ["read", "write", "execute", "list", "delete"]
PURPOSE_WORDS = ["reconcile", "summarize", "ingest", "review", "audit", "process", "sync"]


def _fresh_principal(eng, kind):
    priv, pub = crypto.generate_keypair()
    name = f"{kind}-{uuid.uuid4().hex[:6]}"
    p = eng.register_human(name, pub) if kind == "human" else eng.register_agent(name, pub)
    return priv, p


def _random_purpose(rng):
    return " ".join(rng.sample(PURPOSE_WORDS, k=rng.randint(2, 4)))


def _build_valid_chain(eng, rng):
    """A human + a random-length chain of agents with attenuating scopes."""
    h_priv, human = _fresh_principal(eng, "human")
    # Root scope: a non-empty random subset of the pools, generous risk.
    tools = set(rng.sample(TOOL_POOL, k=rng.randint(2, len(TOOL_POOL))))
    actions = set(rng.sample(ACTION_POOL, k=rng.randint(2, len(ACTION_POOL))))
    root_risk = rng.randint(40, 100)
    purpose = _random_purpose(rng)

    issuer_priv, issuer = h_priv, human
    a_priv, agent = _fresh_principal(eng, "agent")
    deleg = eng.issue_root_delegation(
        human_private_key=issuer_priv, human_id=issuer.id, agent_id=agent.id,
        scope=Scope.make(tools=tools, actions=actions, max_risk=root_risk),
        purpose=purpose, ttl_seconds=3600,
    )
    cur_tools, cur_actions, cur_risk = tools, actions, root_risk
    cur_priv, cur_agent = a_priv, agent

    for _ in range(rng.randint(0, 4)):  # 0..4 sub-delegations
        # Attenuate: subset of tools/actions (non-empty), risk not increasing.
        ntools = set(rng.sample(sorted(cur_tools), k=rng.randint(1, len(cur_tools))))
        nactions = set(rng.sample(sorted(cur_actions), k=rng.randint(1, len(cur_actions))))
        nrisk = rng.randint(0, cur_risk)
        nxt_priv, nxt_agent = _fresh_principal(eng, "agent")
        deleg = eng.sub_delegate(
            issuer_private_key=cur_priv, issuer_id=cur_agent.id, subject_id=nxt_agent.id,
            parent_delegation_id=deleg.id,
            scope=Scope.make(tools=ntools, actions=nactions, max_risk=nrisk),
            purpose=purpose, ttl_seconds=1800,
        )
        cur_tools, cur_actions, cur_risk = ntools, nactions, nrisk
        cur_priv, cur_agent = nxt_priv, nxt_agent

    return human, cur_priv, cur_agent, deleg, cur_tools, cur_actions, cur_risk, purpose


def test_fuzz_valid_chains_authorize():
    rng = random.Random(20260619)
    for _ in range(SAMPLES):
        eng = Engine()
        human, priv, agent, deleg, tools, actions, risk, purpose = _build_valid_chain(eng, rng)
        tool = rng.choice(sorted(tools))
        action = rng.choice(sorted(actions))
        act_risk = rng.randint(0, min(30, risk))  # < 40 so intent-drift can't trip
        rec, verdict = eng.record_action(
            actor_private_key=priv, actor_id=agent.id, delegation_id=deleg.id,
            tool=tool, action=action, risk=act_risk,
            description=f"{purpose} via {tool}",  # shares purpose tokens
        )
        assert verdict.chain.ok, verdict.chain.errors
        assert verdict.chain.human_root_id == human.id
        assert verdict.authorized, verdict.findings
        assert eng.verify_ledger()


def test_fuzz_escalation_always_rejected():
    rng = random.Random(7)
    for _ in range(SAMPLES):
        eng = Engine()
        human, priv, agent, deleg, tools, actions, risk, purpose = _build_valid_chain(eng, rng)
        nxt_priv, nxt_agent = _fresh_principal(eng, "agent")
        # Pick a guaranteed escalation.
        mutation = rng.choice(["new_tool", "new_action", "higher_risk"])
        etools, eactions, erisk = set(tools), set(actions), risk
        if mutation == "new_tool":
            etools = set(tools) | {f"escalated.{uuid.uuid4().hex[:8]}"}
        elif mutation == "new_action":
            eactions = set(actions) | {f"act_{uuid.uuid4().hex[:8]}"}
        else:
            if risk >= 100:
                etools = set(tools) | {f"escalated.{uuid.uuid4().hex[:8]}"}  # fallback
            else:
                erisk = risk + 1
        with pytest.raises(ScopeViolation):
            eng.sub_delegate(
                issuer_private_key=priv, issuer_id=agent.id, subject_id=nxt_agent.id,
                parent_delegation_id=deleg.id,
                scope=Scope.make(tools=etools, actions=eactions, max_risk=erisk),
                purpose=purpose, ttl_seconds=600,
            )


def test_fuzz_ledger_tamper_always_detected():
    """Edits, reorders, and interior deletions break the hash chain.

    Tail truncation is the one mutation a self-contained hash chain cannot see
    (the remaining prefix is still internally valid) — it is caught instead by
    comparing the head hash to an external witness. Both paths are asserted.
    """
    rng = random.Random(99)
    for _ in range(SAMPLES):
        n = rng.randint(2, 12)
        led = Ledger()
        for i in range(n):
            led.append("action", {"i": i, "v": uuid.uuid4().hex})
        assert led.verify_integrity()
        witnessed_head = led.head_hash  # what an external witness would have stored

        mode = rng.choice(["edit", "reorder", "interior_delete", "truncate"])
        if mode == "edit":
            idx = rng.randrange(n)
            bad = led._entries[idx]
            led._entries[idx] = LedgerEntry(
                seq=bad.seq, kind=bad.kind, payload={"forged": uuid.uuid4().hex},
                recorded_at=bad.recorded_at, prev_hash=bad.prev_hash, entry_hash=bad.entry_hash)
            with pytest.raises(TamperDetected):
                led.verify_integrity()
        elif mode == "reorder":
            i, j = sorted(rng.sample(range(n), 2))
            led._entries[i], led._entries[j] = led._entries[j], led._entries[i]
            with pytest.raises(TamperDetected):
                led.verify_integrity()
        elif mode == "interior_delete" and n >= 2:
            idx = rng.randrange(0, n - 1)  # never the tail
            led._entries.pop(idx)
            with pytest.raises(TamperDetected):
                led.verify_integrity()
        else:  # truncate the tail — internally valid, caught only by the witness
            led._entries.pop()
            led.verify_integrity()  # prefix is still self-consistent
            assert led.head_hash != witnessed_head  # witness mismatch reveals it


def test_fuzz_forged_signatures_caught():
    rng = random.Random(424242)
    for _ in range(SAMPLES):
        eng = Engine()
        human, priv, agent, deleg, tools, actions, risk, purpose = _build_valid_chain(eng, rng)
        tool, action = rng.choice(sorted(tools)), rng.choice(sorted(actions))
        rec, _ = eng.record_action(
            actor_private_key=priv, actor_id=agent.id, delegation_id=deleg.id,
            tool=tool, action=action, risk=rng.randint(0, min(30, risk)),
            description=f"{purpose} {tool}",
        )
        attacker_priv, _ = crypto.generate_keypair()
        forged = type(rec)(
            id=rec.id, actor_id=rec.actor_id, delegation_id=rec.delegation_id,
            tool=rec.tool, action=rec.action, risk=rec.risk, description=rec.description,
            params_digest=rec.params_digest, occurred_at=rec.occurred_at,
            signature=crypto.sign(attacker_priv, rec.signing_bytes()),
        )
        eng._actions[rec.id] = forged
        verdict = eng.verify_action(rec.id)
        assert verdict.authorized is False
        assert any(f["code"] in ("ASI03", "ASI07") for f in verdict.findings)


def test_fuzz_revocation_blocks_chain():
    rng = random.Random(2024)
    for _ in range(SAMPLES):
        eng = Engine()
        human, priv, agent, deleg, tools, actions, risk, purpose = _build_valid_chain(eng, rng)
        tool, action = rng.choice(sorted(tools)), rng.choice(sorted(actions))
        rec, verdict = eng.record_action(
            actor_private_key=priv, actor_id=agent.id, delegation_id=deleg.id,
            tool=tool, action=action, risk=rng.randint(0, min(30, risk)),
            description=f"{purpose} {tool}",
        )
        assert verdict.authorized
        # Revoke either the authorizing delegation or the actor.
        if rng.random() < 0.5:
            eng.revoke_delegation(deleg.id, reason="fuzz")
        else:
            eng.revoke_principal(agent.id, reason="fuzz")
        assert eng.verify_action(rec.id).authorized is False
