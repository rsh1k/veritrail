"""Tests for tamper-evidence of the hash-chained ledger."""

import pytest

from veritrail.errors import TamperDetected
from veritrail.ledger import Ledger, LedgerEntry


def _populate(n=5):
    led = Ledger()
    for i in range(n):
        led.append("action", {"i": i, "msg": f"event-{i}"})
    return led


def test_clean_ledger_verifies():
    led = _populate()
    assert led.verify_integrity() is True


def test_each_entry_links_to_previous():
    led = _populate(3)
    entries = led.entries()
    assert entries[0].prev_hash == "0" * 64
    assert entries[1].prev_hash == entries[0].entry_hash
    assert entries[2].prev_hash == entries[1].entry_hash


def test_tampering_with_payload_is_detected():
    led = _populate()
    # Forge history: mutate a past entry's payload but keep its old hash.
    bad = led._entries[2]
    led._entries[2] = LedgerEntry(
        seq=bad.seq, kind=bad.kind, payload={"i": 999, "msg": "FORGED"},
        recorded_at=bad.recorded_at, prev_hash=bad.prev_hash, entry_hash=bad.entry_hash,
    )
    with pytest.raises(TamperDetected):
        led.verify_integrity()


def test_reordering_is_detected():
    led = _populate()
    led._entries[1], led._entries[2] = led._entries[2], led._entries[1]
    with pytest.raises(TamperDetected):
        led.verify_integrity()


def test_deletion_is_detected():
    led = _populate()
    del led._entries[2]
    with pytest.raises(TamperDetected):
        led.verify_integrity()


def test_merkle_root_changes_on_any_edit():
    led = _populate()
    root_before = led.merkle_root()
    led.append("action", {"i": 99})
    assert led.merkle_root() != root_before


def test_head_hash_advances():
    led = Ledger()
    assert led.head_hash == "0" * 64
    e = led.append("action", {"x": 1})
    assert led.head_hash == e.entry_hash


def test_verify_against_head_detects_truncation():
    led = _populate(5)
    witnessed = led.head_hash
    assert led.verify_against_head(witnessed) is True
    led._entries.pop()  # drop the tail — internal chain still validates
    assert led.verify_integrity() is True
    with pytest.raises(TamperDetected):
        led.verify_against_head(witnessed)
