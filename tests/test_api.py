"""HTTP-level tests for the Veritrail service."""


import pytest
from fastapi.testclient import TestClient

from veritrail import Scope, crypto
from veritrail.action import build_signed_action
from veritrail.delegation import build_signed_delegation
from veritrail.principals import new_id


@pytest.fixture()
def client():
    # Fresh engine per test to avoid cross-test ledger state.
    from veritrail.api import server
    from veritrail.engine import Engine
    server.engine = Engine()
    return TestClient(server.app)


def test_healthz(client):
    assert client.get("/healthz").json() == {"status": "ok"}


def test_security_headers_present(client):
    r = client.get("/healthz")
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Frame-Options"] == "DENY"
    assert "default-src 'none'" in r.headers["Content-Security-Policy"]


def test_full_signed_flow_over_http(client):
    h_priv, h_pub = crypto.generate_keypair()
    a_priv, a_pub = crypto.generate_keypair()
    human_id = new_id("human")
    agent_id = new_id("agent")

    assert client.post("/v1/principals", json={
        "id": human_id, "kind": "human", "name": "Alice",
        "public_key_b64": crypto.public_key_to_b64(h_pub),
    }).status_code == 201
    assert client.post("/v1/principals", json={
        "id": agent_id, "kind": "agent", "name": "Bot",
        "public_key_b64": crypto.public_key_to_b64(a_pub),
    }).status_code == 201

    grant = build_signed_delegation(
        issuer_private_key=h_priv, issuer_id=human_id, subject_id=agent_id,
        scope=Scope.make(tools={"db.read"}, actions={"read"}, max_risk=20),
        purpose="read the analytics database", parent_id=None, ttl_seconds=3600,
    )
    r = client.post("/v1/delegations", json={"delegation": grant.to_dict()})
    assert r.status_code == 201

    act = build_signed_action(
        actor_private_key=a_priv, actor_id=agent_id, delegation_id=grant.id,
        tool="db.read", action="read", risk=10, description="read analytics rows",
    )
    r = client.post("/v1/actions", json={"action": act.to_dict()})
    assert r.status_code == 201
    verdict = r.json()
    assert verdict["authorized"] is True
    assert verdict["chain"]["human_root_name"] == "Alice"

    # Forensic report renders.
    rep = client.get(f"/v1/actions/{act.id}/report")
    assert rep.status_code == 200
    assert "Chain of custody" in rep.text

    # Ledger intact.
    assert client.get("/v1/ledger/verify").json()["intact"] is True


def test_forged_delegation_rejected_over_http(client):
    h_priv, h_pub = crypto.generate_keypair()
    attacker_priv, _ = crypto.generate_keypair()
    human_id = new_id("human")
    agent_id = new_id("agent")
    client.post("/v1/principals", json={"id": human_id, "kind": "human", "name": "Alice",
                                        "public_key_b64": crypto.public_key_to_b64(h_pub)})
    a_priv, a_pub = crypto.generate_keypair()
    client.post("/v1/principals", json={"id": agent_id, "kind": "agent", "name": "Bot",
                                        "public_key_b64": crypto.public_key_to_b64(a_pub)})
    # Sign the "human" delegation with an attacker key, not the human's key.
    forged = build_signed_delegation(
        issuer_private_key=attacker_priv, issuer_id=human_id, subject_id=agent_id,
        scope=Scope.make(tools={"x"}, actions={"read"}, max_risk=10),
        purpose="forged", parent_id=None, ttl_seconds=600,
    )
    r = client.post("/v1/delegations", json={"delegation": forged.to_dict()})
    assert r.status_code == 422
    assert "SignatureError" in r.json()["detail"]


def test_invalid_principal_kind_rejected(client):
    r = client.post("/v1/principals", json={
        "kind": "robot", "name": "x", "public_key_b64": "abc"})
    assert r.status_code == 422


def test_malformed_inputs_return_422_not_500(client):
    # A bogus public key must not leak a 500.
    r = client.post("/v1/principals", json={
        "kind": "human", "name": "Alice", "public_key_b64": "not-a-real-key"})
    assert r.status_code == 422
    # Malformed delegation / action payloads are clean 422s too.
    assert client.post("/v1/delegations", json={"delegation": {"bogus": 1}}).status_code == 422
    assert client.post("/v1/actions", json={"action": {"nope": True}}).status_code == 422


def test_unhandled_error_is_sanitized_500(monkeypatch):
    # Force an unexpected (non-Veritrail) error inside an endpoint and confirm
    # the global handler returns a clean 500 with no stack trace in the body.
    from fastapi.testclient import TestClient
    from veritrail.api import server
    from veritrail.engine import Engine
    server.engine = Engine()

    def boom():
        raise RuntimeError("internal detail that must not leak")

    monkeypatch.setattr(server.engine, "stats", boom)
    # raise_server_exceptions=False mirrors how a real HTTP client sees the
    # response (the default test client re-raises instead of returning it).
    client = TestClient(server.app, raise_server_exceptions=False)
    r = client.get("/v1/stats")
    assert r.status_code == 500
    assert r.json() == {"detail": "internal server error"}
    assert "must not leak" not in r.text
    assert "Traceback" not in r.text
    assert r.headers["X-Content-Type-Options"] == "nosniff"


def test_docs_route_has_relaxed_csp(client):
    r = client.get("/openapi.json")
    assert r.status_code == 200
    assert "cdn.jsdelivr.net" in r.headers["Content-Security-Policy"]


def test_api_route_has_strict_csp(client):
    r = client.get("/healthz")
    assert r.headers["Content-Security-Policy"] == "default-src 'none'; frame-ancestors 'none'"
