"""
veritrail.persistence
=====================
Durable storage for Veritrail state.

Two backends implement one small interface:

* :class:`SqliteStore`   — zero-ops, single-node, good for evaluation and a
  single instance with a persistent volume.
* :class:`PostgresStore` — shared, concurrent-safe storage for horizontally
  scaled, multi-replica deployments.

Both follow a **write-through** model: the engine keeps a fast in-memory
working set and mirrors every mutation to durable storage. Two properties make
the multi-writer case correct:

1. **Coordinated, append-only ledger.** ``append_ledger`` assigns the sequence
   number, reads the current head, computes the hash, and inserts the row as a
   single serialized operation. SQLite serializes with a process lock plus an
   ``IMMEDIATE`` transaction; Postgres serializes *across replicas* with a
   transaction-scoped advisory lock (``pg_advisory_xact_lock``). The hash chain
   therefore stays linear and verifiable no matter how many writers there are.
2. **Read-through lookups.** ``get_delegation`` / ``get_action`` /
   ``get_principal`` let one replica resolve records another replica wrote, so
   authorization decisions are globally correct rather than per-process.

Use :func:`open_store` to construct the right backend from a URL.
"""

from __future__ import annotations

import json
import threading
import time
from typing import Any

from .action import ActionRecord
from .delegation import Delegation
from .ledger import GENESIS_PREV_HASH, LedgerEntry
from .principals import Principal, PrincipalKind
from .revocation import Revocation

# A fixed 64-bit key used for the Postgres advisory lock that serializes
# ledger appends across all replicas. Arbitrary but stable.
_LEDGER_LOCK_KEY = 0x5645524954_5241494C & 0x7FFFFFFFFFFFFFFF


def _build_entry(seq: int, kind: str, payload: dict[str, Any], prev_hash: str) -> LedgerEntry:
    """Construct a ledger entry and compute its hash (same logic as Ledger)."""
    partial = LedgerEntry(
        seq=seq, kind=kind, payload=payload,
        recorded_at=time.time(), prev_hash=prev_hash, entry_hash="",
    )
    return LedgerEntry(
        seq=seq, kind=kind, payload=payload,
        recorded_at=partial.recorded_at, prev_hash=prev_hash,
        entry_hash=partial.compute_hash(),
    )


# ===========================================================================
# SQLite backend
# ===========================================================================
class SqliteStore:
    backend = "sqlite"

    def __init__(self, path: str = "veritrail.db") -> None:
        import sqlite3
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._lock = threading.Lock()
        self._create_schema()

    def _create_schema(self) -> None:
        with self._lock:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS principals (
                    id TEXT PRIMARY KEY, kind TEXT NOT NULL,
                    name TEXT NOT NULL, public_key_b64 TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS delegations (id TEXT PRIMARY KEY, body TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS actions (id TEXT PRIMARY KEY, body TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS revocations (target_id TEXT PRIMARY KEY, body TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS ledger (
                    seq INTEGER PRIMARY KEY, kind TEXT NOT NULL, payload TEXT NOT NULL,
                    recorded_at REAL NOT NULL, prev_hash TEXT NOT NULL, entry_hash TEXT NOT NULL);
                """
            )
            self._conn.commit()

    def save_principal(self, p: Principal) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR IGNORE INTO principals(id,kind,name,public_key_b64) VALUES (?,?,?,?)",
                (p.id, p.kind.value, p.name, p.public_key_b64))
            self._conn.commit()

    def save_delegation(self, d: Delegation) -> None:
        with self._lock:
            self._conn.execute("INSERT OR IGNORE INTO delegations(id,body) VALUES (?,?)",
                               (d.id, json.dumps(d.to_dict())))
            self._conn.commit()

    def save_action(self, a: ActionRecord) -> None:
        with self._lock:
            self._conn.execute("INSERT OR IGNORE INTO actions(id,body) VALUES (?,?)",
                               (a.id, json.dumps(a.to_dict())))
            self._conn.commit()

    def save_revocation(self, r: Revocation) -> None:
        with self._lock:
            self._conn.execute("INSERT OR IGNORE INTO revocations(target_id,body) VALUES (?,?)",
                               (r.target_id, json.dumps(r.to_dict())))
            self._conn.commit()

    def append_ledger(self, kind: str, payload: dict[str, Any]) -> LedgerEntry:
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._conn.execute(
                    "SELECT seq, entry_hash FROM ledger ORDER BY seq DESC LIMIT 1").fetchone()
                if row is None:
                    seq, prev = 0, GENESIS_PREV_HASH
                else:
                    seq, prev = row[0] + 1, row[1]
                entry = _build_entry(seq, kind, payload, prev)
                self._conn.execute(
                    "INSERT INTO ledger(seq,kind,payload,recorded_at,prev_hash,entry_hash) "
                    "VALUES (?,?,?,?,?,?)",
                    (entry.seq, entry.kind, json.dumps(entry.payload),
                     entry.recorded_at, entry.prev_hash, entry.entry_hash))
                self._conn.commit()
                return entry
            except Exception:
                self._conn.rollback()
                raise

    def load_ledger(self) -> list[LedgerEntry]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT seq,kind,payload,recorded_at,prev_hash,entry_hash FROM ledger ORDER BY seq"
            ).fetchall()
        return [LedgerEntry(seq=r[0], kind=r[1], payload=json.loads(r[2]),
                            recorded_at=r[3], prev_hash=r[4], entry_hash=r[5]) for r in rows]

    def get_delegation(self, delegation_id: str) -> Delegation | None:
        with self._lock:
            row = self._conn.execute("SELECT body FROM delegations WHERE id=?",
                                     (delegation_id,)).fetchone()
        return Delegation.from_dict(json.loads(row[0])) if row else None

    def get_action(self, action_id: str) -> ActionRecord | None:
        with self._lock:
            row = self._conn.execute("SELECT body FROM actions WHERE id=?", (action_id,)).fetchone()
        return ActionRecord.from_dict(json.loads(row[0])) if row else None

    def get_principal(self, principal_id: str) -> Principal | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT id,kind,name,public_key_b64 FROM principals WHERE id=?",
                (principal_id,)).fetchone()
        if not row:
            return None
        return Principal(id=row[0], kind=PrincipalKind(row[1]), name=row[2], public_key_b64=row[3])

    def counts(self) -> dict[str, int]:
        with self._lock:
            def c(t):
                return self._conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
            return {"principals": c("principals"), "delegations": c("delegations"),
                    "actions": c("actions"), "revocations": c("revocations"),
                    "ledger_entries": c("ledger")}

    def load(self) -> dict[str, Any]:
        with self._lock:
            principals = [Principal(id=r[0], kind=PrincipalKind(r[1]), name=r[2], public_key_b64=r[3])
                          for r in self._conn.execute(
                              "SELECT id,kind,name,public_key_b64 FROM principals")]
            delegations = [Delegation.from_dict(json.loads(r[0]))
                           for r in self._conn.execute("SELECT body FROM delegations")]
            actions = [ActionRecord.from_dict(json.loads(r[0]))
                       for r in self._conn.execute("SELECT body FROM actions")]
            revocations = [Revocation.from_dict(json.loads(r[0]))
                           for r in self._conn.execute("SELECT body FROM revocations")]
        return {"principals": principals, "delegations": delegations, "actions": actions,
                "revocations": revocations, "ledger_entries": self.load_ledger()}

    def close(self) -> None:
        with self._lock:
            self._conn.close()


# ===========================================================================
# PostgreSQL backend
# ===========================================================================
class PostgresStore:
    backend = "postgres"

    def __init__(self, conninfo: str, *, min_size: int = 1, max_size: int = 10) -> None:
        try:
            from psycopg_pool import ConnectionPool
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                "PostgresStore requires psycopg: pip install 'psycopg[binary]' psycopg_pool"
            ) from exc
        self._pool = ConnectionPool(conninfo, min_size=min_size, max_size=max_size,
                                    kwargs={"autocommit": True}, open=True)
        self._create_schema()

    def _create_schema(self) -> None:
        with self._pool.connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS principals (
                    id TEXT PRIMARY KEY, kind TEXT NOT NULL,
                    name TEXT NOT NULL, public_key_b64 TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS delegations (id TEXT PRIMARY KEY, body JSONB NOT NULL);
                CREATE TABLE IF NOT EXISTS actions (id TEXT PRIMARY KEY, body JSONB NOT NULL);
                CREATE TABLE IF NOT EXISTS revocations (target_id TEXT PRIMARY KEY, body JSONB NOT NULL);
                CREATE TABLE IF NOT EXISTS ledger (
                    seq BIGINT PRIMARY KEY, kind TEXT NOT NULL, payload JSONB NOT NULL,
                    recorded_at DOUBLE PRECISION NOT NULL, prev_hash TEXT NOT NULL,
                    entry_hash TEXT NOT NULL);
                """
            )

    def save_principal(self, p: Principal) -> None:
        with self._pool.connection() as conn:
            conn.execute("INSERT INTO principals(id,kind,name,public_key_b64) VALUES (%s,%s,%s,%s) "
                         "ON CONFLICT (id) DO NOTHING",
                         (p.id, p.kind.value, p.name, p.public_key_b64))

    def save_delegation(self, d: Delegation) -> None:
        with self._pool.connection() as conn:
            conn.execute("INSERT INTO delegations(id,body) VALUES (%s,%s) ON CONFLICT (id) DO NOTHING",
                         (d.id, json.dumps(d.to_dict())))

    def save_action(self, a: ActionRecord) -> None:
        with self._pool.connection() as conn:
            conn.execute("INSERT INTO actions(id,body) VALUES (%s,%s) ON CONFLICT (id) DO NOTHING",
                         (a.id, json.dumps(a.to_dict())))

    def save_revocation(self, r: Revocation) -> None:
        with self._pool.connection() as conn:
            conn.execute("INSERT INTO revocations(target_id,body) VALUES (%s,%s) "
                         "ON CONFLICT (target_id) DO NOTHING",
                         (r.target_id, json.dumps(r.to_dict())))

    def append_ledger(self, kind: str, payload: dict[str, Any]) -> LedgerEntry:
        with self._pool.connection() as conn:
            with conn.transaction():
                # Serialize all appenders across every replica.
                conn.execute("SELECT pg_advisory_xact_lock(%s)", (_LEDGER_LOCK_KEY,))
                row = conn.execute(
                    "SELECT seq, entry_hash FROM ledger ORDER BY seq DESC LIMIT 1").fetchone()
                if row is None:
                    seq, prev = 0, GENESIS_PREV_HASH
                else:
                    seq, prev = row[0] + 1, row[1]
                entry = _build_entry(seq, kind, payload, prev)
                conn.execute(
                    "INSERT INTO ledger(seq,kind,payload,recorded_at,prev_hash,entry_hash) "
                    "VALUES (%s,%s,%s,%s,%s,%s)",
                    (entry.seq, entry.kind, json.dumps(entry.payload),
                     entry.recorded_at, entry.prev_hash, entry.entry_hash))
        return entry

    def load_ledger(self) -> list[LedgerEntry]:
        with self._pool.connection() as conn:
            rows = conn.execute(
                "SELECT seq,kind,payload,recorded_at,prev_hash,entry_hash FROM ledger ORDER BY seq"
            ).fetchall()
        return [LedgerEntry(seq=r[0], kind=r[1],
                            payload=r[2] if isinstance(r[2], dict) else json.loads(r[2]),
                            recorded_at=r[3], prev_hash=r[4], entry_hash=r[5]) for r in rows]

    def _one(self, sql: str, args: tuple) -> Any:
        with self._pool.connection() as conn:
            return conn.execute(sql, args).fetchone()

    @staticmethod
    def _as_dict(body: Any) -> dict:
        return body if isinstance(body, dict) else json.loads(body)

    def get_delegation(self, delegation_id: str) -> Delegation | None:
        row = self._one("SELECT body FROM delegations WHERE id=%s", (delegation_id,))
        return Delegation.from_dict(self._as_dict(row[0])) if row else None

    def get_action(self, action_id: str) -> ActionRecord | None:
        row = self._one("SELECT body FROM actions WHERE id=%s", (action_id,))
        return ActionRecord.from_dict(self._as_dict(row[0])) if row else None

    def get_principal(self, principal_id: str) -> Principal | None:
        row = self._one("SELECT id,kind,name,public_key_b64 FROM principals WHERE id=%s",
                        (principal_id,))
        if not row:
            return None
        return Principal(id=row[0], kind=PrincipalKind(row[1]), name=row[2], public_key_b64=row[3])

    def counts(self) -> dict[str, int]:
        with self._pool.connection() as conn:
            def c(t):
                return conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
            return {"principals": c("principals"), "delegations": c("delegations"),
                    "actions": c("actions"), "revocations": c("revocations"),
                    "ledger_entries": c("ledger")}

    def load(self) -> dict[str, Any]:
        with self._pool.connection() as conn:
            principals = [Principal(id=r[0], kind=PrincipalKind(r[1]), name=r[2], public_key_b64=r[3])
                          for r in conn.execute("SELECT id,kind,name,public_key_b64 FROM principals")]
            delegations = [Delegation.from_dict(self._as_dict(r[0]))
                           for r in conn.execute("SELECT body FROM delegations")]
            actions = [ActionRecord.from_dict(self._as_dict(r[0]))
                       for r in conn.execute("SELECT body FROM actions")]
            revocations = [Revocation.from_dict(self._as_dict(r[0]))
                           for r in conn.execute("SELECT body FROM revocations")]
        return {"principals": principals, "delegations": delegations, "actions": actions,
                "revocations": revocations, "ledger_entries": self.load_ledger()}

    def close(self) -> None:
        self._pool.close()


# ===========================================================================
# Factory
# ===========================================================================
def open_store(url: str):
    """Construct a store from a URL.

    * ``postgresql://...`` / ``postgres://...``  -> :class:`PostgresStore`
    * ``sqlite:///path/to.db`` or a bare file path -> :class:`SqliteStore`
    """
    if url.startswith("postgresql://") or url.startswith("postgres://"):
        return PostgresStore(url)
    if url.startswith("sqlite:///"):
        return SqliteStore(url[len("sqlite:///"):])
    return SqliteStore(url)  # back-compat: treat a bare value as a file path
