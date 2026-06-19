# Veritrail — Provenance and Forensics for AI Agents

**A tamper-evident flight recorder and cryptographic chain-of-custody for autonomous AI agents.** Veritrail proves which human authorized which agent to take which action — even five delegations deep — detects when an agent's authority has been hijacked, and keeps an audit trail you can still trust months later.

> Built around the OWASP Top 10 for Agentic Applications (2026) and NIST cryptographic standards. Ships as a Python SDK, a REST service, and a one-command Docker deployment.

---

## The problem nobody else is solving

AI agents have stopped just answering questions. They file tickets, move money, deploy code, and spin up other agents to help. The moment an agent *acts*, a question appears that traditional security tooling can't answer: **when something goes wrong, who actually authorized it?**

OAuth and API keys prove a single hop — "this token is valid right now." They say nothing about the agent three delegations down the chain that inherited that authority, drifted from its original goal, and wired money to the wrong account. By the time an auditor asks "show me the human who approved this," the trail is a pile of unstructured logs that anyone with database access could have rewritten.

This is the gap Veritrail closes. It treats every delegation of authority as a signed, attenuating capability, records every action in a tamper-evident ledger, and lets you reconstruct and cryptographically verify the entire chain back to a human being — on demand, for any action, forever.

Nearly four in ten organizations have already had an AI agent exceed its intended access. If you are putting agents into production in a regulated industry — banking, insurance, healthcare, anything with an audit committee — this is the layer your CISO is going to ask for.

---

## How Veritrail is different

Most agent-security products watch traffic and score prompts. Veritrail works one layer deeper: it makes **authority itself** verifiable and **history** impossible to quietly rewrite.

- **Attenuated delegation.** Every grant is an Ed25519-signed capability. When an agent delegates to a sub-agent, the child's scope must be a subset of the parent's — authority can only ever shrink as it flows down a chain. Privilege escalation is rejected the moment someone tries to issue it, not discovered later.
- **Cryptographic chain reconstruction.** Point Veritrail at any action and it walks every hop, checks every signature and every attenuation step, confirms nothing in the chain has been revoked, and verifies the chain ends at a real human. No human root, a broken link, or a revoked grant means the action is *not authorized* — full stop.
- **A tamper-evident ledger.** Every record carries the hash of the one before it. Edit, reorder, or delete any past entry and the chain breaks; a single pass detects it. Publish the head hash to an external witness and even truncation of recent history becomes detectable.
- **Explainable hijack detection.** Findings map to the OWASP Top 10 for Agentic Applications (2026), so your SOC triages in a vocabulary it already speaks rather than yet another vendor taxonomy.

---

## What it catches

Veritrail's detectors cover eight of the ten OWASP ASI 2026 risk categories. Each finding is deterministic and explainable — no black-box score you can't defend in an incident review.

| OWASP code | Risk | How Veritrail detects it |
|------------|------|--------------------------|
| **ASI01 / ASI02** | Agent Goal Hijack / Tool Misuse | Action falls outside the tools, actions, or risk ceiling the chain granted |
| **ASI03** | Identity & Privilege Abuse | Bad signature, actor isn't the delegation's subject, expired authority, or a revoked grant/principal |
| **ASI06** | Memory & Context Poisoning | The action's stated intent diverges from the purpose it was delegated for |
| **ASI07** | Insecure Inter-Agent Communication | A delegation handed between agents fails signature verification (a spoofed grant) |
| **ASI08** | Cascading Failures | Abnormally high action fan-out under a single grant in a short window — the blast radius of a fault |
| **ASI09** | Human-Agent Trust Exploitation | Consent fatigue — a high-risk action slipped through inside a burst of low-risk approvals |
| **ASI10** | Rogue Agents | An actor accumulates repeated blocking findings, signalling behavioral drift |

ASI04 (supply chain) and ASI05 (unexpected code execution) are deliberately left to complementary controls — MCP manifest signing and execution sandboxing — because they belong at a different layer than provenance. Veritrail is honest about its boundaries.

---

## Install and run in five minutes

### As a Python SDK

```bash
pip install -e .
```

```python
from veritrail import Engine, Scope, crypto

eng = Engine()

# Enroll a human and two agents. The registry only ever holds public keys.
h_priv, h_pub = crypto.generate_keypair()
o_priv, o_pub = crypto.generate_keypair()
w_priv, w_pub = crypto.generate_keypair()
cfo    = eng.register_human("Alice (CFO)", h_pub)
orch   = eng.register_agent("Orchestrator", o_pub)
worker = eng.register_agent("Worker", w_pub)

# The CFO grants the orchestrator scoped authority.
root = eng.issue_root_delegation(
    human_private_key=h_priv, human_id=cfo.id, agent_id=orch.id,
    scope=Scope.make(tools={"invoices.read", "invoices.pay"},
                     actions={"read", "write"}, max_risk=60),
    purpose="reconcile and pay approved invoices", ttl_seconds=3600,
)

# The orchestrator sub-delegates a narrower, read-only scope.
sub = eng.sub_delegate(
    issuer_private_key=o_priv, issuer_id=orch.id, subject_id=worker.id,
    parent_delegation_id=root.id,
    scope=Scope.make(tools={"invoices.read"}, actions={"read"}, max_risk=20),
    purpose="read invoices for reconciliation", ttl_seconds=1800,
)

# The worker records an action and gets back a verdict.
rec, verdict = eng.record_action(
    actor_private_key=w_priv, actor_id=worker.id, delegation_id=sub.id,
    tool="invoices.read", action="read", risk=10,
    description="read approved invoice batch",
)

assert verdict.authorized                                # passed every check
assert verdict.chain.human_root_name == "Alice (CFO)"    # attributed to the human
assert eng.verify_ledger()                               # history is intact
```

Want to see a hijack get caught? Run the narrated demo — it walks a clean three-hop chain and a compromised agent side by side, and writes two forensic HTML reports:

```bash
python -m examples.demo
```

### As a REST service

Clients sign locally; the service only ever sees public keys and signatures, so **no private key material is ever sent to, stored by, or logged by the server.**

```bash
pip install -r requirements.txt
uvicorn veritrail.api.server:app --host 0.0.0.0 --port 8080
# interactive API docs at http://localhost:8080/docs
```

| Method & path | What it does |
|---------------|--------------|
| `GET /healthz` | Liveness probe |
| `POST /v1/principals` | Register a human or agent (public key only) |
| `POST /v1/delegations` | Ingest a client-signed delegation; re-verified server-side |
| `POST /v1/actions` | Ingest a client-signed action; returns the verdict |
| `POST /v1/revocations` | Revoke a delegation or principal |
| `GET /v1/actions/{id}/verdict` | Authorization verdict plus findings |
| `GET /v1/actions/{id}/chain` | The reconstructed chain of custody |
| `GET /v1/actions/{id}/report` | A self-contained forensic HTML report |
| `GET /v1/ledger/verify` | Tamper-evidence check across the whole ledger |
| `GET /v1/stats` | Counts, ledger head, Merkle root |

Turn on durable storage and an API key with two environment variables:

```bash
export VERITRAIL_DB=/data/veritrail.db      # enables SQLite persistence
export VERITRAIL_API_KEY=your-secret-key    # requires Bearer auth on writes
uvicorn veritrail.api.server:app --host 0.0.0.0 --port 8080
```

### As a container

```bash
docker compose up --build
```

The image runs as a non-root user with a read-only root filesystem, every Linux capability dropped, `no-new-privileges` set, and a built-in health check.

---

## Built for the enterprise

- **Durable by default when you want it.** A write-through SQLite store keeps a fast in-memory working set and mirrors every change to disk, so nothing is lost on restart and the ledger validates after reload. The storage interface is deliberately small — porting it to Postgres or append-only object storage is mechanical.
- **Revocation that actually revokes.** A signature proves a grant was authentic when issued; it says nothing about whether that authority is still valid. Revoke a leaked agent key or an offboarded employee and every action whose chain runs through them stops verifying immediately.
- **Observability that drops into your stack.** Veritrail emits structured audit events using OpenTelemetry GenAI semantic-convention field names (`gen_ai.agent.id`, `gen_ai.operation.name`, `gen_ai.tool.name`), so they flow into an OTel collector, Datadog, Splunk, or Elastic without remapping.
- **Hardened API surface.** Strict input validation, security headers on every response, optional bearer-token auth with constant-time comparison, and per-client rate limiting.

---

## How it works

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
  │  ledger      │              │ verdict: authorized? yes/no       │
  └──────────────┘              └──────────────────────────────────┘
        │ append-only, hash-chained, write-through to SQLite
        ▼
  ┌──────────────┐
  │ Tamper-      │  merkle_root() / head hash → external witness
  │ evident log  │
  └──────────────┘
```

Module map: `crypto` (Ed25519, SHA-256, canonical serialization) · `scope` (capabilities and attenuation) · `principals` (registry / trust anchor) · `delegation` (signed grants) · `action` (signed action records) · `ledger` (tamper-evident log) · `revocation` (revoked grants and principals) · `detection` (per-action ASI detectors) · `engine` (the SDK, plus chain-level detectors and verdicts) · `forensics` (HTML report) · `persistence` (SQLite store) · `audit` (OpenTelemetry-friendly events) · `api` (REST service) · `cli`.

---

## Standards alignment

**NIST.** Signatures are Ed25519 (FIPS 186-5). Hashing is SHA-256 (FIPS 180-4) across the ledger, parameter digests, and Merkle tree. The append-only, integrity-verifiable audit log follows the spirit of SP 800-92; the human-versus-agent identity separation reflects SP 800-63; and the map / measure / manage loop maps onto the NIST AI Risk Management Framework — delegated purpose and scope are the *map*, detector findings are the *measure*, and blocking plus a forensic record are the *manage*.

**OWASP.** Detectors map to the OWASP Top 10 for Agentic Applications (2026), as in the table above. The REST surface follows OWASP API security guidance: strict input validation, typed and non-leaky errors, security headers, and a hard rule that private keys are never accepted, stored, or logged.

---

## Testing

```bash
pip install -e ".[dev]"
pytest -q
```

The suite is built to be adversarial, not just to chase coverage. Alongside the unit and HTTP-level tests, five property-based tests each run **1,000 randomized samples** — five thousand scenarios in total — asserting that core invariants hold for every one:

1. A randomly-shaped but well-formed chain always reconstructs to its human root and authorizes.
2. Any sub-delegation that escalates privilege is rejected at issue time.
3. Any edit, reorder, or interior deletion of the ledger is detected (and tail truncation is caught by the head-witness check).
4. Any forged action signature is caught and the action is refused.
5. Revoking any link in a chain — or the actor — blocks the action.

That third invariant is there because the fuzzer found it: a self-contained hash chain cannot detect truncation of its most recent entries on its own, which is exactly why Veritrail exposes `verify_against_head()` for external-witness verification.

---

## Production hardening

Veritrail is a production-grade reference implementation of the core engine. It is not a turnkey, independently-audited SaaS, and it would be dishonest to pretend otherwise. Before you bet a regulated workload on it:

- **Persistence and scale.** Use the SQLite backend for a single node or a shared volume; move to Postgres or append-only object storage for multi-node, high-write deployments. Run several stateless API replicas over shared storage and let the storage layer serialize ledger appends.
- **External witness.** Publish the ledger head or Merkle root to an independent timestamping authority or transparency log on a schedule, so you can prove the log was not rewritten even by an insider with database access.
- **Key management.** Keep agent keys in an HSM or KMS, or a per-agent enclave; rotate and revoke them.
- **AuthN/Z and network.** Put the service behind mTLS or an API gateway; the built-in API key and rate limiter are backstops, not your whole access-control story.
- **Learned detection.** The detectors here are deterministic by design. Layer an anomaly model on top through the same `Finding` interface when you want behavioral coverage beyond the deterministic rules.
- **Independent audit.** Commission a third-party cryptographic and application-security review before production use.

---

## FAQ

**What does Veritrail actually do in one sentence?** It gives every action an AI agent takes a verifiable, tamper-evident chain of custody back to the human who authorized it, and flags the action when that chain has been hijacked.

**How is this different from agent observability tools?** Observability tools tell you *what happened*. Veritrail tells you *whether it was authorized*, proves it cryptographically, and makes the record impossible to quietly alter. They are complementary — Veritrail even emits OpenTelemetry-style events so it sits alongside your existing tracing.

**Does the server ever see my private keys?** No. Clients sign delegations and actions locally; the server only receives public keys and signatures and re-verifies everything itself.

**Which OWASP agentic risks does it cover?** Eight of the ten ASI 2026 categories: ASI01, ASI02, ASI03, ASI06, ASI07, ASI08, ASI09, and ASI10. Supply chain (ASI04) and code execution (ASI05) are left to complementary controls.

**What languages and frameworks does it work with?** The reference implementation is Python and exposes both an SDK and a language-agnostic REST API, so any agent stack that can make an HTTP request can use it.

**Is it ready for production?** The core engine is production-grade and thoroughly tested. Read the Production Hardening section above for the specific operational pieces — persistence backend, external witness, key management, independent audit — to put in place first.

---

## License

Apache-2.0.
