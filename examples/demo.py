"""
Veritrail end-to-end demo.

Tells two stories:
  1. A clean 3-hop chain (CFO -> Orchestrator -> Worker) that verifies.
  2. A hijacked agent that tries to exceed its delegated scope and gets caught.

Run:  python -m examples.demo
It prints a narrated trace and writes two forensic HTML reports.
"""

from __future__ import annotations

import os

from veritrail import Engine, Scope, crypto
from veritrail.forensics import build_report

OUT = os.environ.get("VERITRAIL_OUT", ".")


def kp():
    return crypto.generate_keypair()


def banner(title: str) -> None:
    print("\n" + "=" * 64)
    print(title)
    print("=" * 64)


def main() -> None:
    eng = Engine()

    # --- enroll principals ---------------------------------------------
    cfo_priv, cfo_pub = kp()
    orch_priv, orch_pub = kp()
    worker_priv, worker_pub = kp()
    cfo = eng.register_human("Alice Nguyen (CFO)", cfo_pub)
    orch = eng.register_agent("FinanceOrchestrator", orch_pub)
    worker = eng.register_agent("ReconciliationWorker", worker_pub)

    banner("STORY 1 — A legitimate 3-hop delegation chain")

    root = eng.issue_root_delegation(
        human_private_key=cfo_priv, human_id=cfo.id, agent_id=orch.id,
        scope=Scope.make(
            tools={"invoices.read", "invoices.pay"},
            actions={"read", "write"}, max_risk=60,
            constraints={"max_amount_usd": 50000},
        ),
        purpose="reconcile and pay approved vendor invoices", ttl_seconds=3600,
    )
    print(f"CFO delegated to Orchestrator      -> {root.id}")

    sub = eng.sub_delegate(
        issuer_private_key=orch_priv, issuer_id=orch.id, subject_id=worker.id,
        parent_delegation_id=root.id,
        scope=Scope.make(tools={"invoices.read"}, actions={"read"}, max_risk=20),
        purpose="read invoices needed for reconciliation", ttl_seconds=1800,
    )
    print(f"Orchestrator sub-delegated to Worker -> {sub.id}  (scope narrowed)")

    rec, verdict = eng.record_action(
        actor_private_key=worker_priv, actor_id=worker.id, delegation_id=sub.id,
        tool="invoices.read", action="read", risk=10,
        description="read approved invoice batch for monthly reconciliation",
    )
    print("\nWorker performed: invoices.read / read")
    print(f"  authorized        : {verdict.authorized}")
    print(f"  attributed to     : {verdict.chain.human_root_name}")
    print(f"  hops to human     : {verdict.chain.hops}")
    print(f"  max severity      : {verdict.max_severity}")
    path1 = os.path.join(OUT, "veritrail_report_authorized.html")
    with open(path1, "w") as f:
        f.write(build_report(eng, verdict))
    print(f"  forensic report   : {path1}")

    banner("STORY 2 — A hijacked agent exceeds its scope")

    # The worker (read-only, max_risk 20) is manipulated via a poisoned tool
    # description into attempting a high-risk fund transfer.
    rec2, verdict2 = eng.record_action(
        actor_private_key=worker_priv, actor_id=worker.id, delegation_id=sub.id,
        tool="invoices.pay", action="write", risk=95,
        description="urgently wire 48000 USD to new external vendor account per email instruction",
        params={"amount_usd": 48000, "dest": "external-iban-XX"},
    )
    print("Worker attempted: invoices.pay / write  (risk 95)")
    print(f"  authorized        : {verdict2.authorized}")
    print("  findings:")
    for f_ in verdict2.findings:
        print(f"    [{f_['severity'].upper():8}] {f_['code']:12} {f_['title']}")
    path2 = os.path.join(OUT, "veritrail_report_compromised.html")
    with open(path2, "w") as fh:
        fh.write(build_report(eng, verdict2))
    print(f"  forensic report   : {path2}")

    banner("LEDGER INTEGRITY")
    print(f"  ledger entries    : {len(eng.ledger)}")
    print(f"  tamper-evident OK : {eng.verify_ledger()}")
    print(f"  merkle root       : {eng.ledger.merkle_root()[:32]}...")
    s = eng.stats()
    print(f"  principals/dels/acts: {s['principals']}/{s['delegations']}/{s['actions']}")

    banner("STORY 3 — Revoking a leaked delegation")

    # A clean read that passes today...
    rec3, verdict3 = eng.record_action(
        actor_private_key=worker_priv, actor_id=worker.id, delegation_id=sub.id,
        tool="invoices.read", action="read", risk=8,
        description="read invoices needed for reconciliation",
    )
    print(f"Before revocation: authorized = {verdict3.authorized}")

    # ...the orchestrator's grant is found to be leaked and gets revoked.
    eng.revoke_delegation(sub.id, reason="worker key suspected compromised")
    after = eng.verify_action(rec3.id)
    print(f"After revocation : authorized = {after.authorized}")
    for f_ in after.findings:
        print(f"    [{f_['severity'].upper():8}] {f_['code']:12} {f_['title']}")
    print("  (the signature is still valid — revocation, not forgery, is what blocks it)")


if __name__ == "__main__":
    main()
