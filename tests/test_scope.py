"""Tests for scope attenuation and delegation integrity."""

import pytest

from veritrail import Scope
from veritrail.scope import WILDCARD


def test_scope_permits_within_bounds():
    s = Scope.make(tools={"payments.read"}, actions={"read"}, max_risk=30)
    assert s.permits_action("payments.read", "read", 10) is True


def test_scope_denies_unlisted_tool():
    s = Scope.make(tools={"payments.read"}, actions={"read"}, max_risk=30)
    assert s.permits_action("payments.transfer", "read", 10) is False


def test_scope_denies_excess_risk():
    s = Scope.make(tools={"payments.read"}, actions={"read"}, max_risk=30)
    assert s.permits_action("payments.read", "read", 90) is False


def test_attenuation_subset_is_contained():
    parent = Scope.make(tools={"a", "b", "c"}, actions={"read", "write"}, max_risk=50)
    child = Scope.make(tools={"a"}, actions={"read"}, max_risk=20)
    assert parent.contains(child) is True


def test_attenuation_rejects_new_tool():
    parent = Scope.make(tools={"a"}, actions={"read"}, max_risk=50)
    child = Scope.make(tools={"a", "z"}, actions={"read"}, max_risk=50)
    assert parent.contains(child) is False


def test_attenuation_rejects_risk_escalation():
    parent = Scope.make(tools={"a"}, actions={"read"}, max_risk=30)
    child = Scope.make(tools={"a"}, actions={"read"}, max_risk=80)
    assert parent.contains(child) is False


def test_attenuation_rejects_wildcard_expansion():
    parent = Scope.make(tools={"a"}, actions={"read"}, max_risk=30)
    child = Scope.make(tools={WILDCARD}, actions={"read"}, max_risk=30)
    assert parent.contains(child) is False


def test_attenuation_numeric_constraint_cannot_loosen():
    parent = Scope.make(tools={"pay"}, actions={"write"}, max_risk=50,
                        constraints={"max_amount_usd": 1000})
    looser = Scope.make(tools={"pay"}, actions={"write"}, max_risk=50,
                       constraints={"max_amount_usd": 5000})
    tighter = Scope.make(tools={"pay"}, actions={"write"}, max_risk=50,
                        constraints={"max_amount_usd": 500})
    dropped = Scope.make(tools={"pay"}, actions={"write"}, max_risk=50)
    assert parent.contains(looser) is False
    assert parent.contains(tighter) is True
    assert parent.contains(dropped) is True  # omitted cap is inherited via the chain


def test_effective_constraints_takes_tightest():
    s1 = Scope.make(constraints={"max_amount_usd": 1000})
    s2 = Scope.make(constraints={"max_amount_usd": 400})
    s3 = Scope.make()  # omits the cap — still bound by ancestors
    eff = Scope.effective_constraints([s1, s2, s3])
    assert eff["max_amount_usd"] == 400


def test_scope_rejects_invalid_risk():
    with pytest.raises(Exception):
        Scope.make(tools={"a"}, actions={"read"}, max_risk=200)
