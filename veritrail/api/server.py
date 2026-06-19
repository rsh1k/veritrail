"""
veritrail.api.server
====================
The Veritrail REST service.

Security posture:
* Clients sign delegations/actions locally with the SDK; this service only ever
  receives public keys and signatures. No private key material is accepted,
  stored, or logged (OWASP A02 Cryptographic Failures, A09 Logging).
* All inputs are validated by Pydantic models with strict bounds.
* Security headers are applied to every response.
* Errors return typed, non-leaky messages (OWASP A04 Insecure Design).

Run:  uvicorn veritrail.api.server:app --host 0.0.0.0 --port 8080
Docs: http://localhost:8080/docs
"""

from __future__ import annotations

import os
import time
from collections import defaultdict, deque
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

from veritrail.action import ActionRecord
from veritrail.delegation import Delegation
from veritrail.engine import Engine
from veritrail.errors import (
    ChainBroken,
    ExpiredGrant,
    ScopeViolation,
    SignatureError,
    UnknownPrincipal,
    ValidationError,
    VeritrailError,
)
from veritrail.forensics import build_report
from veritrail.persistence import SqliteStore
from veritrail.principals import Principal, PrincipalKind, new_id

app = FastAPI(
    title="Veritrail",
    version="0.2.0",
    description="Verifiable provenance and forensics for autonomous AI agents.",
)

# Optional durable persistence: set VERITRAIL_DB to a file path to enable SQLite.
_db_path = os.environ.get("VERITRAIL_DB")
_store = SqliteStore(_db_path) if _db_path else None
engine = Engine(store=_store)

# Optional API-key auth: set VERITRAIL_API_KEY to require a bearer token.
_API_KEY = os.environ.get("VERITRAIL_API_KEY")

# Simple in-process rate limiter (requests per IP per window). For multi-node,
# put a real gateway / API manager in front; this is a backstop, not the plan.
_RATE_LIMIT = int(os.environ.get("VERITRAIL_RATE_LIMIT", "240"))   # requests
_RATE_WINDOW = 60.0                                                # seconds
_hits: dict[str, deque] = defaultdict(deque)


def _check_auth(authorization: str | None) -> None:
    if _API_KEY is None:
        return
    expected = f"Bearer {_API_KEY}"
    # Constant-time comparison to avoid leaking the key via timing.
    import hmac
    if authorization is None or not hmac.compare_digest(authorization, expected):
        raise HTTPException(status_code=401, detail="missing or invalid API key")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    # Rate limit per client IP (skip health checks).
    if request.url.path != "/healthz":
        client = request.client.host if request.client else "unknown"
        now = time.time()
        dq = _hits[client]
        while dq and dq[0] < now - _RATE_WINDOW:
            dq.popleft()
        if len(dq) >= _RATE_LIMIT:
            return JSONResponse(status_code=429, content={"detail": "rate limit exceeded"})
        dq.append(now)

    resp = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'"
    return resp


def _handle(exc: Exception) -> HTTPException:
    if isinstance(exc, (ScopeViolation, ExpiredGrant, SignatureError, ChainBroken, ValidationError)):
        return HTTPException(status_code=422, detail=f"{type(exc).__name__}: {exc}")
    if isinstance(exc, UnknownPrincipal):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, VeritrailError):
        return HTTPException(status_code=400, detail=str(exc))
    raise exc


# ---- models ---------------------------------------------------------------
class RegisterPrincipal(BaseModel):
    id: str | None = Field(default=None, max_length=128)
    kind: str = Field(pattern="^(human|agent)$")
    name: str = Field(min_length=1, max_length=256)
    public_key_b64: str = Field(min_length=1, max_length=128)


class DelegationIn(BaseModel):
    delegation: dict[str, Any]


class ActionIn(BaseModel):
    action: dict[str, Any]


class RevokeIn(BaseModel):
    target_id: str = Field(min_length=1, max_length=256)
    target_kind: str = Field(pattern="^(delegation|principal)$")
    reason: str = Field(min_length=1, max_length=512)
    revoked_by: str | None = Field(default=None, max_length=256)


# ---- endpoints ------------------------------------------------------------
@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/v1/stats")
def stats() -> dict[str, Any]:
    return engine.stats()


@app.post("/v1/principals", status_code=201)
def register_principal(body: RegisterPrincipal, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _check_auth(authorization)
    try:
        p = Principal(
            id=body.id or new_id(body.kind),
            kind=PrincipalKind(body.kind),
            name=body.name,
            public_key_b64=body.public_key_b64,
        )
        engine.registry.register(p)
        if engine.store is not None:
            engine.store.save_principal(p)
        return p.to_dict()
    except Exception as exc:
        raise _handle(exc)


@app.get("/v1/principals")
def list_principals() -> list[dict[str, Any]]:
    return [p.to_dict() for p in engine.registry.all()]


@app.post("/v1/delegations", status_code=201)
def ingest_delegation(body: DelegationIn, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _check_auth(authorization)
    try:
        d = Delegation.from_dict(body.delegation)
        engine.ingest_delegation(d)
        return {"id": d.id, "status": "accepted"}
    except Exception as exc:
        raise _handle(exc)


@app.post("/v1/actions", status_code=201)
def ingest_action(body: ActionIn, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _check_auth(authorization)
    try:
        a = ActionRecord.from_dict(body.action)
        _, verdict = engine.ingest_action(a)
        return verdict.to_dict()
    except Exception as exc:
        raise _handle(exc)


@app.post("/v1/revocations", status_code=201)
def revoke(body: RevokeIn, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _check_auth(authorization)
    try:
        if body.target_kind == "delegation":
            r = engine.revoke_delegation(body.target_id, body.reason, revoked_by=body.revoked_by)
        else:
            r = engine.revoke_principal(body.target_id, body.reason, revoked_by=body.revoked_by)
        return r.to_dict()
    except Exception as exc:
        raise _handle(exc)


@app.get("/v1/revocations")
def list_revocations() -> list[dict[str, Any]]:
    return [r.to_dict() for r in engine.revocations.all()]


@app.get("/v1/actions/{action_id}/verdict")
def get_verdict(action_id: str) -> dict[str, Any]:
    if not engine.has_action(action_id):
        raise HTTPException(status_code=404, detail="unknown action")
    return engine.verify_action(action_id).to_dict()


@app.get("/v1/actions/{action_id}/chain")
def get_chain(action_id: str) -> dict[str, Any]:
    if not engine.has_action(action_id):
        raise HTTPException(status_code=404, detail="unknown action")
    return engine.reconstruct_chain(action_id).to_dict()


@app.get("/v1/actions/{action_id}/report", response_class=HTMLResponse)
def get_report(action_id: str) -> HTMLResponse:
    if not engine.has_action(action_id):
        raise HTTPException(status_code=404, detail="unknown action")
    verdict = engine.verify_action(action_id)
    return HTMLResponse(content=build_report(engine, verdict))


@app.get("/v1/ledger/verify")
def verify_ledger() -> dict[str, Any]:
    try:
        ok = engine.verify_ledger()
        return {"intact": ok, "entries": len(engine.ledger), "head": engine.ledger.head_hash}
    except VeritrailError as exc:
        return {"intact": False, "error": str(exc)}
