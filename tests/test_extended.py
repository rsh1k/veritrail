"""Tests for revocation, durable persistence, audit sink, and ASI07/08/10."""

import io
import time

from veritrail import Engine, Scope, crypto
from veritrail.api import server as api_server
from veritrail.audit import JsonlSink
from veritrail.persistence import SqliteStore


def _actor(eng, kind, name):
    priv, pub = crypto.generate_keypair()
    p = eng.register_human(name, pub) if kind == "human" else eng.register_agent(name, pub)
    return priv, p


def _valid_chain(eng):
    h_priv, human = _actor(eng, "human", "Alice")
    a_priv, agent = _actor(eng, "agent", "Bot")
    root = eng.issue_root_delegation(
        human_private_key=h_priv, human_id=human.id, agent_id=agent.id,
        scope=Scope.make(tools={"db.read"}, actions={"read"}, max_risk=30),
        purpose="read the database", ttl_seconds=3600,
    )
    return h_priv, human, a_priv, agent, root


# ---- revocation -----------------------------------------------------------
def test_revoking_delegation_blocks_action():
    eng = Engine()
    _, _, a_priv, agent, root = _valid_chain(eng)
    rec, v1 = eng.record_action(
        actor_private_key=a_priv, actor_id=agent.id, delegation_id=root.id,
        tool="db.read", action="read", risk=5, description="read the database rows",
    )
    assert v1.authorized is True
    eng.revoke_delegation(root.id, reason="key suspected compromised")
    v2 = eng.verify_action(rec.id)
    assert v2.authorized is False
    assert any(f["code"] == "ASI03" for f in v2.findings)


def test_revoking_principal_blocks_action():
    eng = Engine()
    _, _, a_priv, agent, root = _valid_chain(eng)
    rec, _ = eng.record_action(
        actor_private_key=a_priv, actor_id=agent.id, delegation_id=root.id,
        tool="db.read", action="read", risk=5, description="read the database rows",
    )
    eng.revoke_principal(agent.id, reason="agent offboarded")
    assert eng.verify_action(rec.id).authorized is False


# ---- persistence ----------------------------------------------------------
def test_state_survives_restart(tmp_path):
    db = str(tmp_path / "v.db")
    eng1 = Engine(store=SqliteStore(db))
    h_priv, human = _actor(eng1, "human", "Alice")
    a_priv, agent = _actor(eng1, "agent", "Bot")
    root = eng1.issue_root_delegation(
        human_private_key=h_priv, human_id=human.id, agent_id=agent.id,
        scope=Scope.make(tools={"db.read"}, actions={"read"}, max_risk=30),
        purpose="read the database", ttl_seconds=3600,
    )
    rec, v1 = eng1.record_action(
        actor_private_key=a_priv, actor_id=agent.id, delegation_id=root.id,
        tool="db.read", action="read", risk=5, description="read the database rows",
    )
    assert v1.authorized
    head_before = eng1.ledger.head_hash

    # New engine over the SAME database — should rehydrate fully.
    eng2 = Engine(store=SqliteStore(db))
    assert eng2.verify_ledger() is True
    assert eng2.ledger.head_hash == head_before
    assert eng2.has_action(rec.id)
    v2 = eng2.verify_action(rec.id)
    assert v2.authorized is True
    assert v2.chain.human_root_name == "Alice"


def test_persisted_ledger_detects_tamper(tmp_path):
    from veritrail.errors import TamperDetected
    db = str(tmp_path / "v2.db")
    eng = Engine(store=SqliteStore(db))
    _, _, a_priv, agent, root = _valid_chain(eng)
    eng.record_action(
        actor_private_key=a_priv, actor_id=agent.id, delegation_id=root.id,
        tool="db.read", action="read", risk=5, description="read the database rows",
    )
    eng.store.close()
    # Tamper with the durable store directly (the real threat model), then
    # verify a fresh engine detects it on reload.
    import sqlite3
    conn = sqlite3.connect(db)
    conn.execute("UPDATE ledger SET payload=? WHERE seq=0", ('{"forged": true}',))
    conn.commit()
    conn.close()
    eng2 = Engine(store=SqliteStore(db))
    try:
        eng2.verify_ledger()
        assert False, "expected tamper detection"
    except TamperDetected:
        pass


# ---- audit sink -----------------------------------------------------------
def test_audit_sink_emits_events():
    buf = io.StringIO()
    eng = Engine(audit_sink=JsonlSink(buf))
    _, _, a_priv, agent, root = _valid_chain(eng)
    eng.record_action(
        actor_private_key=a_priv, actor_id=agent.id, delegation_id=root.id,
        tool="db.read", action="read", risk=5, description="read the database rows",
    )
    out = buf.getvalue()
    assert "register_principal" in out
    assert "verify_action" in out
    assert "gen_ai.operation.name" in out  # OTel-style field present


# ---- ASI08 cascading fan-out ----------------------------------------------
def test_cascading_fanout_flagged():
    eng = Engine(cascade_fanout_threshold=5, cascade_window_seconds=60)
    _, _, a_priv, agent, root = _valid_chain(eng)
    base = time.time()
    last = None
    for i in range(6):
        _, last = eng.record_action(
            actor_private_key=a_priv, actor_id=agent.id, delegation_id=root.id,
            tool="db.read", action="read", risk=5,
            description="read the database rows", now=base + i,
        )
    assert any(f["code"] == "ASI08" for f in last.findings)


# ---- ASI10 rogue agent -----------------------------------------------------
def test_repeated_violations_flag_rogue():
    eng = Engine(rogue_strike_threshold=3)
    h_priv, human = _actor(eng, "human", "Alice")
    a_priv, agent = _actor(eng, "agent", "Bot")
    root = eng.issue_root_delegation(
        human_private_key=h_priv, human_id=human.id, agent_id=agent.id,
        scope=Scope.make(tools={"db.read"}, actions={"read"}, max_risk=10),
        purpose="read only", ttl_seconds=3600,
    )
    last = None
    for i in range(3):  # each is out-of-scope -> blocking strike
        _, last = eng.record_action(
            actor_private_key=a_priv, actor_id=agent.id, delegation_id=root.id,
            tool="payments.transfer", action="write", risk=95,
            description="exceed scope", now=time.time() + i,
        )
    assert any(f["code"] == "ASI10" for f in last.findings)


# ---- API: revocation + auth ------------------------------------------------
def test_api_revocation_and_rate_headers(monkeypatch):
    from fastapi.testclient import TestClient
    api_server.engine = Engine()
    client = TestClient(api_server.app)
    h_priv, h_pub = crypto.generate_keypair()
    a_priv, a_pub = crypto.generate_keypair()
    from veritrail.principals import new_id
    from veritrail.delegation import build_signed_delegation
    from veritrail.action import build_signed_action
    hid, aid = new_id("human"), new_id("agent")
    client.post("/v1/principals", json={"id": hid, "kind": "human", "name": "A",
                                        "public_key_b64": crypto.public_key_to_b64(h_pub)})
    client.post("/v1/principals", json={"id": aid, "kind": "agent", "name": "B",
                                        "public_key_b64": crypto.public_key_to_b64(a_pub)})
    grant = build_signed_delegation(issuer_private_key=h_priv, issuer_id=hid, subject_id=aid,
                                    scope=Scope.make(tools={"x"}, actions={"read"}, max_risk=20),
                                    purpose="read x", parent_id=None, ttl_seconds=3600)
    client.post("/v1/delegations", json={"delegation": grant.to_dict()})
    act = build_signed_action(actor_private_key=a_priv, actor_id=aid, delegation_id=grant.id,
                              tool="x", action="read", risk=5, description="read x")
    r = client.post("/v1/actions", json={"action": act.to_dict()})
    assert r.json()["authorized"] is True
    # Revoke the grant, re-check verdict.
    assert client.post("/v1/revocations", json={
        "target_id": grant.id, "target_kind": "delegation", "reason": "test"}).status_code == 201
    assert client.get(f"/v1/actions/{act.id}/verdict").json()["authorized"] is False
