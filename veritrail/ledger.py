"""
veritrail.ledger
================
An append-only, hash-chained ledger — the "black box flight recorder".

Every entry stores the hash of the entry before it, so the whole log forms a
chain anchored in a genesis hash. Changing, removing, or reordering any past
entry changes its hash, which breaks every subsequent link. A single
:meth:`Ledger.verify_integrity` pass over the chain detects tampering
anywhere in history — this is the property auditors and incident responders
need and that ordinary application logs lack (NIST SP 800-92).

The ledger stores opaque payload dicts; it neither signs nor interprets them.
Signing lives with the producers (delegations/actions); integrity of *history*
lives here. Separation keeps each concern auditable on its own.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Any, Iterable

from . import crypto
from .errors import TamperDetected

GENESIS_PREV_HASH = "0" * 64


@dataclass(frozen=True)
class LedgerEntry:
    seq: int
    kind: str               # "delegation" | "action" | ...
    payload: dict[str, Any]
    recorded_at: float
    prev_hash: str
    entry_hash: str

    def _hash_input(self) -> bytes:
        return crypto.canonical_bytes(
            {
                "seq": self.seq,
                "kind": self.kind,
                "payload": self.payload,
                "recorded_at": self.recorded_at,
                "prev_hash": self.prev_hash,
            }
        )

    def compute_hash(self) -> str:
        return crypto.sha256_hex(self._hash_input())

    def to_dict(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "kind": self.kind,
            "payload": self.payload,
            "recorded_at": self.recorded_at,
            "prev_hash": self.prev_hash,
            "entry_hash": self.entry_hash,
        }


class Ledger:
    """Thread-safe in-memory append-only ledger.

    For production, back the ``_entries`` list with a WORM store (append-only
    object storage, or an RDBMS table with INSERT-only grants) and periodically
    publish the head hash to an external witness for non-repudiation.
    """

    def __init__(self, on_append=None) -> None:
        self._entries: list[LedgerEntry] = []
        self._lock = threading.Lock()
        # Optional callback invoked with each new entry (used for write-through
        # persistence). It must not raise; the caller guards it.
        self._on_append = on_append

    def load_entries(self, entries: list[LedgerEntry]) -> None:
        """Rehydrate from persisted entries WITHOUT recomputing hashes.

        Persisted hashes are authoritative; call :meth:`verify_integrity`
        afterward to confirm the loaded chain is intact.
        """
        with self._lock:
            self._entries = sorted(entries, key=lambda e: e.seq)

    def append_prebuilt(self, entry: LedgerEntry) -> None:
        """Append an entry whose seq/prev_hash/hash were assigned elsewhere
        (e.g. by a coordinated store). Used to mirror durable appends into the
        in-memory view; the store remains the source of truth for verification."""
        with self._lock:
            self._entries.append(entry)

    @property
    def head_hash(self) -> str:
        return self._entries[-1].entry_hash if self._entries else GENESIS_PREV_HASH

    def __len__(self) -> int:
        return len(self._entries)

    def append(self, kind: str, payload: dict[str, Any]) -> LedgerEntry:
        with self._lock:
            seq = len(self._entries)
            prev_hash = self.head_hash
            partial = LedgerEntry(
                seq=seq,
                kind=kind,
                payload=payload,
                recorded_at=time.time(),
                prev_hash=prev_hash,
                entry_hash="",
            )
            entry = LedgerEntry(
                seq=seq,
                kind=kind,
                payload=payload,
                recorded_at=partial.recorded_at,
                prev_hash=prev_hash,
                entry_hash=partial.compute_hash(),
            )
            self._entries.append(entry)
            if self._on_append is not None:
                try:
                    self._on_append(entry)
                except Exception:
                    # Persistence failures are surfaced by the store's own
                    # health checks, never by corrupting the in-memory chain.
                    pass
            return entry

    def get(self, seq: int) -> LedgerEntry:
        return self._entries[seq]

    def entries(self) -> list[LedgerEntry]:
        return list(self._entries)

    def find(self, kind: str | None = None) -> Iterable[LedgerEntry]:
        for e in self._entries:
            if kind is None or e.kind == kind:
                yield e

    def verify_integrity(self) -> bool:
        """Recompute the whole chain. Raises :class:`TamperDetected` on any break.

        Note: a self-contained hash chain detects edits, reorders, and interior
        deletions, but not truncation of the most recent entries — the remaining
        prefix is still internally valid. Use :meth:`verify_against_head` with an
        externally-witnessed head hash to detect truncation and divergence.
        """
        prev = GENESIS_PREV_HASH
        for i, e in enumerate(self._entries):
            if e.seq != i:
                raise TamperDetected(f"sequence gap/reorder at index {i} (seq={e.seq})")
            if e.prev_hash != prev:
                raise TamperDetected(f"broken link at seq {e.seq}: prev_hash mismatch")
            if e.compute_hash() != e.entry_hash:
                raise TamperDetected(f"altered payload at seq {e.seq}: hash mismatch")
            prev = e.entry_hash
        return True

    def verify_against_head(self, expected_head_hash: str) -> bool:
        """Verify the chain AND that its head matches an external witness.

        This closes the truncation gap: if the most recent entries were dropped,
        the internal chain still validates but the head hash no longer matches
        the value a witness recorded, so this raises.
        """
        self.verify_integrity()
        if self.head_hash != expected_head_hash:
            raise TamperDetected(
                "ledger head does not match the witnessed head — entries may have "
                "been truncated or the ledger forked"
            )
        return True

    def merkle_root(self) -> str:
        """A Merkle root over all entry hashes — a single checkpoint value you
        can anchor externally (e.g. timestamping authority) for non-repudiation."""
        if not self._entries:
            return GENESIS_PREV_HASH
        level = [e.entry_hash for e in self._entries]
        while len(level) > 1:
            nxt = []
            for i in range(0, len(level), 2):
                left = level[i]
                right = level[i + 1] if i + 1 < len(level) else left
                nxt.append(crypto.sha256_hex((left + right).encode("ascii")))
            level = nxt
        return level[0]
