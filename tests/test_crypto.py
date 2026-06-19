"""Tests for cryptographic primitives — the trust foundation."""

import pytest

from veritrail import crypto


def test_sign_and_verify_roundtrip():
    priv, pub = crypto.generate_keypair()
    msg = b"authorize transfer of 100 USD"
    sig = crypto.sign(priv, msg)
    assert crypto.verify(pub, msg, sig) is True


def test_verify_rejects_tampered_message():
    priv, pub = crypto.generate_keypair()
    sig = crypto.sign(priv, b"transfer 100")
    assert crypto.verify(pub, b"transfer 100000", sig) is False


def test_verify_rejects_wrong_key():
    priv, _ = crypto.generate_keypair()
    _, other_pub = crypto.generate_keypair()
    sig = crypto.sign(priv, b"hello")
    assert crypto.verify(other_pub, b"hello", sig) is False


def test_verify_rejects_garbage_signature_without_raising():
    _, pub = crypto.generate_keypair()
    # Attacker-controlled junk must never raise, only return False.
    assert crypto.verify(pub, b"hello", "!!!not-base64!!!") is False
    assert crypto.verify(pub, b"hello", "") is False


def test_canonical_bytes_is_order_independent():
    a = crypto.canonical_bytes({"b": 1, "a": 2})
    b = crypto.canonical_bytes({"a": 2, "b": 1})
    assert a == b


def test_canonical_bytes_distinguishes_values():
    assert crypto.canonical_bytes({"a": 1}) != crypto.canonical_bytes({"a": 2})


def test_sha256_known_vector():
    # SHA-256("") well-known digest.
    assert crypto.sha256_hex(b"") == (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )


def test_key_serialization_roundtrip():
    priv, pub = crypto.generate_keypair()
    pub2 = crypto.public_key_from_b64(crypto.public_key_to_b64(pub))
    priv2 = crypto.private_key_from_b64(crypto.private_key_to_b64(priv))
    msg = b"x"
    assert crypto.verify(pub2, msg, crypto.sign(priv2, msg)) is True
