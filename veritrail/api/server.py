"""
veritrail.api.server
====================
The Veritrail REST service.

Security & robustness posture:
* Clients sign delegations/actions locally with the SDK; the service only ever
  receives public keys and signatures. No private key material is accepted,
  stored, or logged (OWASP A02 Cryptographic Failures, A09 Logging).
* Domain errors are raised as typed ``VeritrailError`` subclasses at the source
  and mapped to HTTP status codes by global exception handlers. A catch-all
  handler guarantees no unhandled exception ever leaks a stack trace to a
  client (OWASP A04/A05). Stack traces are logged server-side only.
* Strict security headers on every response, including error responses.
* Optional bearer-token auth on writes; per-client rate limiting with bounded
  memory; optional trusted-host enforcement.

Run:  uvicorn veritrail.api.server:app --host 0.0.0.0 --port 8080
Docs: http://localhost:8080/docs   (or the machine-readable /openapi.json)

Environment variables:
  VERITRAIL_DB             path to a SQLite file to enable durable persistence
  VERITRAIL_API_KEY        if set, writes require "Authorization: Bearer <key>"
  VERITRAIL_RATE_LIMIT     max requests per client IP per 60s window (default 240)
  VERITRAIL_ALLOWED_HOSTS  comma-separated Host allowlist (TrustedHostMiddleware)
  VERITRAIL_DISABLE_DOCS   set to "1" to disable the interactive docs in prod
"""

from __future__ import annotations

import logging
import os
import time
from collections import defaultdict, deque
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

from veritrail import __version__
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
from veritrail.persistence import open_store
from veritrail.principals import Principal, PrincipalKind, new_id

logger = logging.getLogger("veritrail")

# --- configuration ---------------------------------------------------------
_DISABLE_DOCS = os.environ.get("VERITRAIL_DISABLE_DOCS") == "1"

app = FastAPI(
    title="Veritrail",
    version=__version__,
    description="Verifiable provenance and forensics for autonomous AI agents.",
    docs_url=None if _DISABLE_DOCS else "/docs",
    redoc_url=None if _DISABLE_DOCS else "/redoc",
)

# Optional durable persistence.
_db_path = os.environ.get("VERITRAIL_DB")
_store = open_store(_db_path) if _db_path else None
engine = Engine(store=_store)

# Optional API-key auth for write endpoints.
_API_KEY = os.environ.get("VERITRAIL_API_KEY")

# Optional trusted-host enforcement.
_allowed_hosts = os.environ.get("VERITRAIL_ALLOWED_HOSTS")
if _allowed_hosts:
    from fastapi.middleware.trustedhost import TrustedHostMiddleware
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=[h.strip() for h in _allowed_hosts.split(",") if h.strip()],
    )

# Rate limiter (bounded-memory, per client IP).
_RATE_LIMIT = int(os.environ.get("VERITRAIL_RATE_LIMIT", "240"))
_RATE_WINDOW = 60.0
_MAX_TRACKED_IPS = 100_000
_hits: dict[str, deque] = defaultdict(deque)
_last_prune = 0.0

# Security headers applied to *every* response, including errors.
_BASE_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}
_STRICT_CSP = "default-src 'none'; frame-ancestors 'none'"
# The interactive docs load Swagger UI assets from a CDN, so they need a
# relaxed policy. This applies ONLY to the docs routes; the API stays strict.
_DOCS_CSP = (
    "default-src 'none'; "
    "script-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
    "style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
    "img-src 'self' https://fastapi.tiangolo.com data:; "
    "connect-src 'self'"
)
_DOCS_PATHS = ("/docs", "/redoc", "/openapi.json")


def _security_headers_for(path: str) -> dict[str, str]:
    headers = dict(_BASE_SECURITY_HEADERS)
    headers["Content-Security-Policy"] = _DOCS_CSP if path in _DOCS_PATHS else _STRICT_CSP
    return headers


def _check_auth(authorization: str | None) -> None:
    if _API_KEY is None:
        return
    import hmac
    expected = f"Bearer {_API_KEY}"
    if authorization is None or not hmac.compare_digest(authorization, expected):
        raise HTTPException(status_code=401, detail="missing or invalid API key")


def _prune_rate_limiter(now: float) -> None:
    """Drop stale per-IP buckets so memory cannot grow without bound."""
    global _last_prune
    if now - _last_prune < _RATE_WINDOW:
        return
    _last_prune = now
    stale = [ip for ip, dq in _hits.items() if not dq or dq[-1] < now - _RATE_WINDOW]
    for ip in stale:
        _hits.pop(ip, None)
    # Hard cap as a final backstop against a flood of unique IPs.
    if len(_hits) > _MAX_TRACKED_IPS:
        _hits.clear()


@app.middleware("http")
async def security_and_rate_limit(request: Request, call_next):
    path = request.url.path
    if path != "/healthz":
        client = request.client.host if request.client else "unknown"
        now = time.time()
        _prune_rate_limiter(now)
        dq = _hits[client]
        while dq and dq[0] < now - _RATE_WINDOW:
            dq.popleft()
        if len(dq) >= _RATE_LIMIT:
            return JSONResponse(
                status_code=429,
                content={"detail": "rate limit exceeded"},
                headers=_security_headers_for(path),
            )
        dq.append(now)

    response = await call_next(request)
    for k, v in _security_headers_for(path).items():
        response.headers[k] = v
    return response


# --- global exception handlers --------------------------------------------
def _status_and_detail(exc: VeritrailError) -> tuple[int, str]:
    if isinstance(exc, (ScopeViolation, ExpiredGrant, SignatureError, ChainBroken, ValidationError)):
        return 422, f"{type(exc).__name__}: {exc}"
    if isinstance(exc, UnknownPrincipal):
        return 404, str(exc)
    return 400, str(exc)


@app.exception_handler(VeritrailError)
async def veritrail_error_handler(request: Request, exc: VeritrailError) -> JSONResponse:
    status, detail = _status_and_detail(exc)
    return JSONResponse(
        status_code=status, content={"detail": detail},
        headers=_security_headers_for(request.url.path),
    )


@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    return JSONResponse(
        status_code=422, content={"detail": "invalid request body", "errors": exc.errors()},
        headers=_security_headers_for(request.url.path),
    )


@app.exception_handler(Exception)
async def unhandled_error_handler(request: Request, exc: Exception) -> JSONResponse:
    # Log the full context server-side; return a sanitized message to the client.
    logger.exception("unhandled error on %s %s", request.method, request.url.path)
    return JSONResponse(
        status_code=500, content={"detail": "internal server error"},
        headers=_security_headers_for(request.url.path),
    )


# --- request models --------------------------------------------------------
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


# --- endpoints -------------------------------------------------------------
@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/v1/stats")
def stats() -> dict[str, Any]:
    return engine.stats()


@app.post("/v1/principals", status_code=201)
def register_principal(body: RegisterPrincipal, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _check_auth(authorization)
    # Principal construction validates the key and raises ValidationError on
    # malformed input, which the global handler maps to 422.
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


@app.get("/v1/principals")
def list_principals() -> list[dict[str, Any]]:
    return [p.to_dict() for p in engine.registry.all()]


@app.post("/v1/delegations", status_code=201)
def ingest_delegation(body: DelegationIn, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _check_auth(authorization)
    d = Delegation.from_dict(body.delegation)   # raises ValidationError if malformed
    engine.ingest_delegation(d)                 # raises typed errors on failure
    return {"id": d.id, "status": "accepted"}


@app.post("/v1/actions", status_code=201)
def ingest_action(body: ActionIn, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _check_auth(authorization)
    a = ActionRecord.from_dict(body.action)
    _, verdict = engine.ingest_action(a)
    return verdict.to_dict()


@app.post("/v1/revocations", status_code=201)
def revoke(body: RevokeIn, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _check_auth(authorization)
    if body.target_kind == "delegation":
        r = engine.revoke_delegation(body.target_id, body.reason, revoked_by=body.revoked_by)
    else:
        r = engine.revoke_principal(body.target_id, body.reason, revoked_by=body.revoked_by)
    return r.to_dict()


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
