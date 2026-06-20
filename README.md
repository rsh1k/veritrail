<div align="center">

# 🛡️ Veritrail

### Provenance & forensics for AI agents — prove who authorized any agent action, catch hijacked agents, and keep an audit trail you can trust.

*A tamper-evident flight recorder and cryptographic chain-of-custody for autonomous AI agents. Built around the OWASP Top 10 for Agentic Applications (ASI 2026) and NIST cryptographic standards.*

[![PyPI version](https://img.shields.io/pypi/v/veritrail.svg)](https://pypi.org/project/veritrail/)
[![CI](https://github.com/rsh1k/veritrail/actions/workflows/ci.yml/badge.svg)](https://github.com/rsh1k/veritrail/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)
[![GitHub stars](https://img.shields.io/github/stars/rsh1k/veritrail?style=social)](https://github.com/rsh1k/veritrail)

[**Quick start**](#-quick-start) · [**Why Veritrail**](#-the-problem-nobody-else-is-solving) · [**What it catches**](#-what-it-catches) · [**How it works**](#-how-it-works) · [**Standards**](#-standards-alignment) · [**FAQ**](#-faq)

</div>

---

## ⚡ Quick start

Install from PyPI:

```bash
pip install veritrail
```

Prove, in 30 seconds, that an AI agent acted within the authority a human granted — and that a hijacked agent gets caught. Save this as `quickstart.py`:

```python
from veritrail import Engine, Scope, crypto

eng = Engine()

# Enroll a human and two agents (the registry holds only public keys).
h_priv, h_pub = crypto.generate_keypair()
o_priv, o_pub = crypto.generate_keypair()
w_priv, w_pub = crypto.generate_keypair()
cfo  = eng.register_human("Alice (CFO)", h_pub)
orch = eng.register_agent("Orchestrator", o_pub)
work = eng.register_agent("Worker", w_pub)

# CFO delegates to an orchestrator; the orchestrator sub-delegates a NARROWER,
# read-only scope to a worker. Authority can only shrink down the chain.
root = eng.issue_root_delegation(
    human_private_key=h_priv, human_id=cfo.id, agent_id=orch.id,
    scope=Scope.make(tools={"invoices.read", "invoices.pay"},
                     actions={"read", "write"}, max_risk=60),
    purpose="reconcile and pay invoices", ttl_seconds=3600)
sub = eng.sub_delegate(
    issuer_private_key=o_priv, issuer_id=orch.id, subject_id=work.id,
    parent_delegation_id=root.id,
    scope=Scope.make(tools={"invoices.read"}, actions={"read"}, max_risk=20),
    purpose="read invoices", ttl_seconds=1800)

# A legitimate read — authorized, and traced all the way back to the human.
_, ok = eng.record_action(actor_private_key=w_priv, actor_id=work.id, delegation_id=sub.id,
    tool="invoices.read", action="read", risk=10, description="read invoice batch")
print("legit :", ok.authorized, "| traced to:", ok.chain.human_root_name)

# A hijack — the worker tries to pay, outside its scope — blocked and flagged.
_, bad = eng.record_action(actor_private_key=w_priv, actor_id=work.id, delegation_id=sub.id,
    tool="invoices.pay", action="write", risk=95, description="wire funds out")
print("hijack:", bad.authorized, "| findings:", [f["code"] for f in bad.findings])

print("ledger intact:", eng.verify_ledger())
```

```bash
python quickstart.py
# legit : True | traced to: Alice (CFO)
# hijack: False | findings: ['ASI02']
# ledger intact: True
```

That's the whole value proposition — *who authorized this, was it hijacked, can you prove it* — in one file.

---

## 🧩 The problem nobody else is solving

AI agents have stopped just answering questions. They file tickets, move money, deploy code, and spawn other agents to help. The moment an agent **acts**, a question appears that traditional security tooling can't answer: **when something goes wrong, who actually authorized it?**

OAuth and API keys prove a single hop — "this token is valid right now." They say nothing about the agent three delegations deep that inherited that authority, drifted from its original goal, and wired money to the wrong account. By then the trail is a pile of unstructured logs that anyone with database access could have quietly rewritten.

Veritrail closes that gap. It treats every delegation of authority as a signed, attenuating capability, records every action in a tamper-evident ledger, and lets you reconstruct and cryptographically verify the entire chain back to a human — on demand, for any action, forever.

---

## ✨ Features

| | |
|---|---|
| 🔐 **Cryptographic provenance** | Reconstruct and verify the full delegation chain for any action, back to the human who started it — even many hops deep. |
| 📉 **Attenuated delegation** | Ed25519-signed capabilities where a sub-agent's scope must be a *subset* of its delegator's. Privilege escalation is rejected at issue time. |
| 🧾 **Tamper-evident ledger** | A hash-chained, append-only log. Any edit, reorder, or deletion breaks the chain and is caught in a single pass. |
| 🚨 **Hijack detection** | Explainable detectors mapped to the OWASP Top 10 for Agentic Applications (ASI 2026) — goal hijack, tool misuse, identity abuse, intent drift, consent fatigue, rogue agents. |
| ↩️ **Revocation** | Revoke a leaked key or an offboarded human; every action whose chain runs through them stops verifying immediately. |
| 🗄️ **SQLite & PostgreSQL** | Zero-ops SQLite for a single node, or PostgreSQL with advisory-lock-coordinated appends for multi-replica deployments. |
| 🔭 **OpenTelemetry-ready** | Structured audit events using GenAI semantic-convention field names, for any SIEM or tracing pipeline. |
| 🧰 **SDK · REST API · CLI · Docker** | Use it however you deploy — a Python library, a hardened FastAPI service, or a one-command container. |

---

## 🎯 What it catches

Veritrail's detectors cover **eight of the ten** OWASP ASI 2026 risk categories. Every finding is deterministic and explainable — no black-box score you can't defend in an incident review.

| OWASP code | Risk | How Veritrail detects it |
|------------|------|--------------------------|
| **ASI01 / ASI02** | Goal Hijack / Tool Misuse | Action falls outside the tools, actions, or risk ceiling the chain granted |
| **ASI03** | Identity & Privilege Abuse | Bad signature, actor isn't the delegation's subject, expired authority, or a revoked grant/principal |
| **ASI06** | Memory & Context Poisoning | The action's stated intent diverges from the purpose it was delegated for |
| **ASI07** | Insecure Inter-Agent Communication | A delegation handed between agents fails signature verification (a spoofed grant) |
| **ASI08** | Cascading Failures | Abnormally high action fan-out under a single grant in a short window |
| **ASI09** | Human-Agent Trust Exploitation | Consent fatigue — a high-risk action slipped through a burst of low-risk approvals |
| **ASI10** | Rogue Agents | An actor accumulates repeated blocking findings — behavioral drift |

ASI04 (supply chain) and ASI05 (unexpected code execution) are deliberately left to complementary controls — MCP manifest signing and execution sandboxing — because they belong at a different layer than provenance.

---

## 🚀 Run it as a service

Clients sign locally; the service only ever sees public keys and signatures, so **no private key material is accepted, stored, or logged.**

```bash
pip install "veritrail[postgres]"            # add the Postgres backend
uvicorn veritrail.api.server:app --port 8080
```

Or with Docker:

```bash
docker run -p 8080:8080 ghcr.io/rsh1k/veritrail:latest
```

Configure with environment variables:

```bash
export VERITRAIL_DB=/data/veritrail.db                       # SQLite (single node)
# export VERITRAIL_DB=postgresql://user:pass@host:5432/db    # Postgres (multi-replica)
export VERITRAIL_API_KEY=your-secret-key                     # require Bearer auth on writes
```

| Method & path | Purpose |
|---------------|---------|
| `GET /healthz` | Liveness probe |
| `POST /v1/principals` | Register a human or agent (public key only) |
| `POST /v1/delegations` | Ingest a client-signed delegation; re-verified server-side |
| `POST /v1/actions` | Ingest a client-signed action; returns the verdict |
| `POST /v1/revocations` | Revoke a delegation or principal |
| `GET /v1/actions/{id}/verdict` | Authorization verdict + findings |
| `GET /v1/actions/{id}/chain` | The reconstructed chain of custody |
| `GET /v1/actions/{id}/report` | A self-contained forensic HTML report |
| `GET /v1/ledger/verify` | Tamper-evidence check across the whole ledger |

---

## 🛠️ How it works

```
            sign locally (private keys never leave the client)
 Human ─────────────────────────────────────────────────────┐
   │  root delegation (Ed25519-signed)                       │
   ▼                                                          │
 Agent A ── sub-delegate (child scope ⊆ parent scope) ─► Agent B
                                                   │          │
                                                   ▼          │
                                             Action record    │
                                                   │          │
        ┌──────────────────────────────────────────┘          │
        ▼                                                       ▼
  ┌──────────────┐    verify    ┌──────────────────────────────────┐
  │ Engine       │ ───────────► │ reconstruct chain → human root    │
  │  registry    │              │ check revocations                 │
  │  revocations │              │ run detectors → OWASP ASI findings│
  │  ledger      │              │ verdict: authorized? yes / no     │
  └──────────────┘              └──────────────────────────────────┘
        │ append-only, hash-chained, coordinated across replicas
        ▼
  ┌──────────────┐
  │ Tamper-      │  merkle_root() / head hash → external witness
  │ evident log  │
  └──────────────┘
```

---

## 📐 Standards alignment

**NIST** — Ed25519 signatures (FIPS 186-5), SHA-256 hashing (FIPS 180-4) across the ledger and Merkle tree, an append-only audit log in the spirit of SP 800-92, human-vs-agent identity separation reflecting SP 800-63, and a map/measure/manage loop that mirrors the NIST AI Risk Management Framework.

**OWASP** — detectors map to the OWASP Top 10 for Agentic Applications (ASI 2026); the REST surface follows OWASP API hardening (strict validation, typed non-leaky errors, security headers, no private keys ever handled).

---

## 🏢 Production hardening

Veritrail is a production-grade **open-source reference implementation**. It has not had an independent third-party security audit. Before betting a regulated workload on it:

- **Scale:** use the PostgreSQL backend and run multiple stateless replicas — ledger appends are serialized across replicas by a Postgres advisory lock, so the chain stays correct.
- **External witness:** publish the ledger head / Merkle root to an independent timestamping authority so even an insider with database access can't rewrite history undetected.
- **Key management:** keep agent keys in an HSM/KMS; rotate and revoke.
- **Network:** put the service behind mTLS or an API gateway; the built-in API key and rate limiter are backstops, not your whole access story.
- **Audit:** commission an independent cryptographic and application-security review.

> Note: the deterministic authorization checks (signature, chain, scope, expiry, revocation, ledger integrity) are globally correct across replicas; the behavioral heuristics (consent fatigue, fan-out) use a per-replica recent view and are best-effort across replicas.

---

## 🧪 Testing

```bash
git clone https://github.com/rsh1k/veritrail.git
cd veritrail
pip install -e ".[dev]"
pytest -q
```

The suite is adversarial by design. Five property-based tests each run **1,000 randomized samples** — asserting that well-formed chains always authorize, escalation is always rejected, ledger tampering is always detected, forged signatures are always caught, and revocation always blocks. A separate suite runs **live PostgreSQL** integration tests (durability, multi-replica read-your-writes, a coordinated ledger under concurrent writers). CI runs everything on Python 3.10, 3.11, and 3.12.

---

## ❓ FAQ

**What is Veritrail in one sentence?** It gives every action an AI agent takes a verifiable, tamper-evident chain of custody back to the human who authorized it, and flags the action when that chain has been hijacked.

**How is this different from AI agent observability tools?** Observability tells you *what happened*. Veritrail tells you *whether it was authorized*, proves it cryptographically, and makes the record impossible to quietly alter. They're complementary — Veritrail even emits OpenTelemetry-style events.

**Does the server ever see my private keys?** No. Clients sign locally; the server only receives public keys and signatures and re-verifies everything itself.

**Which OWASP agentic risks does it cover?** Eight of ten ASI 2026 categories: ASI01, ASI02, ASI03, ASI06, ASI07, ASI08, ASI09, ASI10.

**What stacks does it work with?** A Python SDK plus a language-agnostic REST API — any agent framework that can make an HTTP request can use it.

**Is it production ready?** The core engine is production-grade and thoroughly tested. See [Production hardening](#-production-hardening) for the operational pieces to put in place before a regulated rollout.

---

## 🤝 Contributing & security

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). To report a vulnerability, please use private disclosure as described in [SECURITY.md](SECURITY.md).

## 📄 License

[Apache-2.0](LICENSE).

---

<div align="center">

**Keywords:** AI agent security · AI agent provenance · agentic AI · OWASP agentic AI (ASI 2026) · AI agent audit log · tamper-evident ledger · LLM agent governance · delegation chain of custody · Ed25519 · Python

If Veritrail is useful to you, a ⭐ helps others find it.

</div>
