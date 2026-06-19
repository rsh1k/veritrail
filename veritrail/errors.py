"""veritrail.errors — typed exceptions so callers can handle failures precisely."""

from __future__ import annotations


class VeritrailError(Exception):
    """Base class for all Veritrail errors."""


class SignatureError(VeritrailError):
    """A signature failed to verify."""


class ScopeViolation(VeritrailError):
    """A delegation or action exceeded the authority it was granted."""


class ExpiredGrant(VeritrailError):
    """A delegation has passed its expiry timestamp."""


class TamperDetected(VeritrailError):
    """The ledger hash chain is broken — history has been altered."""


class UnknownPrincipal(VeritrailError):
    """Referenced a principal that is not registered."""


class ChainBroken(VeritrailError):
    """A delegation/authorization chain could not be reconstructed to a human root."""


class ValidationError(VeritrailError):
    """Input failed validation (length, type, charset, range)."""
