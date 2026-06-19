"""
veritrail.persistence
=====================
Durable storage for Veritrail state, backed by SQLite.

Design: a **write-through** store. The engine keeps a fast in-memory working
set and mirrors every mutation to durable storage, so reads stay in-RAM (low
latency under load) while nothing is lost on restart. The ledger table is
append-only by contract — rows are only ever inserted, never updated — which
preserves the tamper-evidence property at the storage layer too.

SQLite is the reference backend: zero-ops, transactional, and good for a single
node or a shared volume. For multi-node, high-write deployments, implement the
same small surface against Postgres or an append-only object store (see the
README "Production hardening" section). Every method here is intentionally
narrow so that port is mechanical.
"""

from __future__ import annotations

import sqlite3
import threading
from typing import Any

from .action import ActionRecord
from .delegation import Delegation
from .ledger import LedgerEntry
from .principals import Principal, PrincipalKind
from .revocation import Revocation


class SqliteStore:
    def __init__(self, path: str = "veritrail.db") -> None:
        # check_same_thread=False + a lock lets a threaded server share one conn.
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._lock = threading.Lock()
        self._create_schema()

    def _create_schema(self) -> None:
        with self._lock:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS principals (
                    id TEXT PRIMARY KEY, kind TEXT NOT NULL,
                    name TEXT NOT NULL, public_key_b64 TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS delegations (
                    id TEXT PRIMARY KEY, body TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS actions (
                    id TEXT PRIMARY KEY, body TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS revocations (
                    target_id TEXT PRIMARY KEY, body TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS ledger (
                    seq INTEGER PRIMARY KEY, kind TEXT NOT NULL,
                    payload TEXT NOT NULL, recorded_at REAL NOT NULL,
                    prev_hash TEXT NOT NULL, entry_hash TEXT NOT NULL
                );
                """
            )
            self._conn.commit()

    # ---- write-through saves ---------------------------------------------
    def save_principal(self, p: Principal) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR IGNORE INTO principals(id,kind,name,public_key_b64) VALUES (?,?,?,?)",
                (p.id, p.kind.value, p.name, p.public_key_b64),
            )
            self._conn.commit()

    def save_delegation(self, d: Delegation) -> None:
        import json
        with self._lock:
            self._conn.execute(
                "INSERT OR IGNORE INTO delegations(id,body) VALUES (?,?)",
                (d.id, json.dumps(d.to_dict())),
            )
            self._conn.commit()

    def save_action(self, a: ActionRecord) -> None:
        import json
        with self._lock:
            self._conn.execute(
                "INSERT OR IGNORE INTO actions(id,body) VALUES (?,?)",
                (a.id, json.dumps(a.to_dict())),
            )
            self._conn.commit()

    def save_revocation(self, r: Revocation) -> None:
        import json
        with self._lock:
            self._conn.execute(
                "INSERT OR IGNORE INTO revocations(target_id,body) VALUES (?,?)",
                (r.target_id, json.dumps(r.to_dict())),
            )
            self._conn.commit()

    def save_ledger_entry(self, e: LedgerEntry) -> None:
        import json
        with self._lock:
            # Append-only: INSERT, never UPDATE. A duplicate seq is a programming
            # error and should surface loudly, so we do not silently ignore it.
            self._conn.execute(
                "INSERT INTO ledger(seq,kind,payload,recorded_at,prev_hash,entry_hash) VALUES (?,?,?,?,?,?)",
                (e.seq, e.kind, json.dumps(e.payload), e.recorded_at, e.prev_hash, e.entry_hash),
            )
            self._conn.commit()

    # ---- rehydrate --------------------------------------------------------
    def load(self) -> dict[str, Any]:
        import json
        with self._lock:
            principals = [
                Principal(id=r[0], kind=PrincipalKind(r[1]), name=r[2], public_key_b64=r[3])
                for r in self._conn.execute("SELECT id,kind,name,public_key_b64 FROM principals")
            ]
            delegations = [
                Delegation.from_dict(json.loads(r[0]))
                for r in self._conn.execute("SELECT body FROM delegations")
            ]
            actions = [
                ActionRecord.from_dict(json.loads(r[0]))
                for r in self._conn.execute("SELECT body FROM actions")
            ]
            revocations = [
                Revocation.from_dict(json.loads(r[0]))
                for r in self._conn.execute("SELECT body FROM revocations")
            ]
            ledger_entries = [
                LedgerEntry(seq=r[0], kind=r[1], payload=json.loads(r[2]),
                            recorded_at=r[3], prev_hash=r[4], entry_hash=r[5])
                for r in self._conn.execute(
                    "SELECT seq,kind,payload,recorded_at,prev_hash,entry_hash FROM ledger ORDER BY seq")
            ]
        return {
            "principals": principals,
            "delegations": delegations,
            "actions": actions,
            "revocations": revocations,
            "ledger_entries": ledger_entries,
        }

    def close(self) -> None:
        with self._lock:
            self._conn.close()
