"""
PostgreSQL backend integration tests.

These run only when VERITRAIL_TEST_PG is set to a Postgres connection string,
so the normal suite (and CI, which has no Postgres) skips them cleanly. They
exercise the things that matter for a multi-replica deployment: durability,
one replica reading another's writes, a globally-linear coordinated ledger,
concurrent appends, and storage-level tamper detection.
"""

import os
import threading

import pytest

from veritrail import Engine, Scope, crypto
from veritrail.errors import TamperDetected
from veritrail.persistence import PostgresStore, open_store

PG = os.environ.get("VERITRAIL_TEST_PG")
pytestmark = pytest.mark.skipif(not PG, reason="set VERITRAIL_TEST_PG to run Postgres tests")


@pytest.fixture()
def clean_pg():
    store = PostgresStore(PG)
    with store._pool.connection() as conn:
        conn.execute("TRUNCATE principals, delegations, actions, revocations, ledger")
    store.close()
    return PG


def _actor(eng, kind, name):
    priv, pub = crypto.generate_keypair()
    p = eng.register_human(name, pub) if kind == "human" else eng.register_agent(name, pub)
    return priv, p


def _seed_chain(eng):
    h_priv, human = _actor(eng, "human", "Alice")
    a_priv, agent = _actor(eng, "agent", "Bot")
    root = eng.issue_root_delegation(
        human_private_key=h_priv, human_id=human.id, agent_id=agent.id,
        scope=Scope.make(tools={"db.read"}, actions={"read"}, max_risk=30),
        purpose="read the database", ttl_seconds=3600,
    )
    return h_priv, human, a_priv, agent, root


def test_pg_durability_and_restart(clean_pg):
    eng = Engine(store=open_store(clean_pg))
    _, human, a_priv, agent, root = _seed_chain(eng)
    rec, v = eng.record_action(
        actor_private_key=a_priv, actor_id=agent.id, delegation_id=root.id,
        tool="db.read", action="read", risk=5, description="read the database rows")
    assert v.authorized
    eng.store.close()

    eng2 = Engine(store=open_store(clean_pg))   # simulate a restart / fresh replica
    assert eng2.verify_ledger() is True
    v2 = eng2.verify_action(rec.id)
    assert v2.authorized is True
    assert v2.chain.human_root_name == "Alice"
    eng2.store.close()


def test_pg_multi_replica_read_your_writes(clean_pg):
    # Replica A writes; replica B (separate Engine, shared DB) must verify it.
    a = Engine(store=open_store(clean_pg))
    b = Engine(store=open_store(clean_pg))
    _, human, a_priv, agent, root = _seed_chain(a)
    rec, _ = a.record_action(
        actor_private_key=a_priv, actor_id=agent.id, delegation_id=root.id,
        tool="db.read", action="read", risk=5, description="read the database rows")

    # B never saw any of this in memory — it must read-through to the store.
    assert b.has_action(rec.id)
    vb = b.verify_action(rec.id)
    assert vb.authorized is True
    assert vb.chain.human_root_id == human.id
    a.store.close()
    b.store.close()


def test_pg_coordinated_ledger_stays_linear(clean_pg):
    # Two engines appending to the same ledger must produce one valid chain.
    a = Engine(store=open_store(clean_pg))
    b = Engine(store=open_store(clean_pg))
    _, human, a_priv, agent, root = _seed_chain(a)
    for i in range(5):
        a.record_action(actor_private_key=a_priv, actor_id=agent.id, delegation_id=root.id,
                        tool="db.read", action="read", risk=5, description="read rows A")
        b_action_eng = b
        b_action_eng.record_action(actor_private_key=a_priv, actor_id=agent.id, delegation_id=root.id,
                                   tool="db.read", action="read", risk=5, description="read rows B")
    # Whole chain (written by both) verifies, with no seq gaps or broken links.
    assert a.verify_ledger() is True
    assert b.verify_ledger() is True
    a.store.close()
    b.store.close()


def test_pg_concurrent_appends_are_serialized(clean_pg):
    eng = Engine(store=open_store(clean_pg))
    _, human, a_priv, agent, root = _seed_chain(eng)
    errors = []

    def worker():
        try:
            for _ in range(10):
                eng.record_action(actor_private_key=a_priv, actor_id=agent.id,
                                  delegation_id=root.id, tool="db.read", action="read",
                                  risk=5, description="concurrent read")
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors, errors
    # 80 actions + 1 root delegation = 81 ledger entries, chain intact.
    assert eng.verify_ledger() is True
    assert eng.stats()["ledger_entries"] == 81
    eng.store.close()


def test_pg_storage_tamper_detected(clean_pg):
    eng = Engine(store=open_store(clean_pg))
    _, human, a_priv, agent, root = _seed_chain(eng)
    eng.record_action(actor_private_key=a_priv, actor_id=agent.id, delegation_id=root.id,
                      tool="db.read", action="read", risk=5, description="read rows")
    # Corrupt a stored ledger row directly.
    with eng.store._pool.connection() as conn:
        conn.execute("UPDATE ledger SET payload=%s WHERE seq=0", ('{"forged": true}',))
    with pytest.raises(TamperDetected):
        eng.verify_ledger()
    eng.store.close()


def test_pg_revocation_visible_across_replicas(clean_pg):
    a = Engine(store=open_store(clean_pg))
    b = Engine(store=open_store(clean_pg))
    _, human, a_priv, agent, root = _seed_chain(a)
    rec, _ = a.record_action(actor_private_key=a_priv, actor_id=agent.id, delegation_id=root.id,
                             tool="db.read", action="read", risk=5, description="read rows")
    a.revoke_delegation(root.id, reason="leaked")
    # B must see the revocation (it reads revocations at startup; reload to model
    # a fresh replica picking up the revocation).
    b2 = Engine(store=open_store(clean_pg))
    assert b2.verify_action(rec.id).authorized is False
    a.store.close(); b.store.close(); b2.store.close()
